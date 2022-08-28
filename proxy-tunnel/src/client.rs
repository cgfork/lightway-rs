use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures::TryFutureExt;
use headers::authorization::Credentials;
use headers::HeaderValue;
use http::Uri;
use hyper::client::HttpConnector as HyperConnector;
use hyper::service::Service as HyperService;
use log::{error, debug};
use pin_project_lite::pin_project;
use proxy::Service;
use proxy_io::{ProxyStream, StreamConnect, TargetAddr};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::io::{poll_read_buf, poll_write_buf};

pub struct HttpConnector {
    connector: HyperConnector,
}

impl HttpConnector {
    pub fn new() -> Self {
        Self {
            connector: HyperConnector::new(),
        }
    }
}

impl Service<TargetAddr> for HttpConnector {
    type Response = TcpStream;

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send + 'a
    where
        Self: 'a;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: TargetAddr) -> Self::Future<'_> {
        let future = Uri::builder()
            .scheme("http")
            .authority(req.to_string())
            .path_and_query("")
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .map(|uri| {
                self.connector
                    .call(uri)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            });
        Box::pin(async move {
            match future {
                Ok(fut) => Ok(fut.await?),
                Err(e) => {
                    error!("unable to build uri for {}, {}", &req, &e);
                    Err(e)
                }
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct Client<C> {
    authorization: Option<Basic>,
    connect: StreamConnect<C>,
}

impl<C> Client<C> {
    pub fn new(target: TargetAddr, connect: C) -> Self {
        Client {
            authorization: None,
            connect: StreamConnect::new(connect, target),
        }
    }

    pub fn set_authorization(&mut self, username: String, password: String) {
        self.authorization = Some(Basic::new(&username, &password))
    }
    
    pub fn enable_tls(&mut self) {
        self.connect.set_tls(true)
    }
}

impl<C> Service<TargetAddr> for Client<C>
where
    C: Service<TargetAddr> + Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C::Error: Into<io::Error> + Send,
{
    type Response = ProxyStream<C::Response>;

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send +'a 
    where
        Self: 'a;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connect.poll_ready(cx).map_err(|e| e.into())
    }

    fn call(&mut self, target: TargetAddr) -> Self::Future<'_> {
        let future = self.connect.call(()).map_err(Into::<io::Error>::into);
        let authorization = self.authorization.clone();
        Box::pin(async move {
            let mut socket  = future.await?;
            let (host, port) = match target {
                TargetAddr::SocketAddr(addr) => (addr.ip().to_string(), addr.port()),
                TargetAddr::Domain(d, p) => (d, p) 
            };
            match proxy_tunnel(&mut socket, &host, port, authorization).await {
                Ok(()) => Ok(socket),
                Err(e) => {
                    error!("unable to proxy tunnel to {}:{}, {}", &host, port, &e);
                    if let Err(e) = socket.shutdown().await {
                        error!("unable to shutdown proxy stream, {}", &e);
                    }
                    Err(e)
                }
            }
        })
    }
}

fn proxy_tunnel<'a, S>(
    io: &'a mut S,
    host: &str,
    port: u16,
    authorization: Option<Basic>,
) -> ProxyTunnel<'a, S> {
    debug!("proxy tunnel for {}:{}", host, port);
    let buf = match authorization {
        Some(value) => format!(
            "CONNECT {0}:{1} HTTP/1.1\r\n\
			Host: {0}:{1}\r\n\
			Proxy-Connection: Keep-Alive\r\n\
			Proxy-Authorization: {2}\r\n\
			\r\n",
            host,
            port,
            value
                .encode()
                .to_str()
                .expect("unknown proxy authorization")
        ),
        None => format!(
            "CONNECT {0}:{1} HTTP/1.1\r\n\
			Host: {0}:{1}\r\n\
			Proxy-Connection: Keep-Alive\r\n\
			\r\n",
            host, port
        ),
    }
    .into_bytes();
    ProxyTunnel {
        io,
        buf: buf.as_slice().into(),
        sending: true,
    }
}

pin_project! {
    pub struct ProxyTunnel<'a, S> {
        #[pin]
        io: &'a mut S,
        buf: BytesMut,
        sending: bool,
    }
}

impl<'a, S> Future for ProxyTunnel<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        loop {
            if *me.sending {
                while me.buf.has_remaining() {
                    let n = ready!(poll_write_buf(Pin::new(&mut me.io), cx, me.buf))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero bytes",
                        )));
                    }
                }

                me.buf.truncate(0);
                *me.sending = false;
            } else {
                if me.buf.remaining() > 12 {
                    let read = &me.buf[..];
                    if (read.starts_with(b"HTTP/1.1 200") || read.starts_with(b"HTTP/1.0 200"))
                        && read.ends_with(b"\r\n\r\n")
                    {
                        return Poll::Ready(Ok(()));
                    }
                }

                let n = ready!(poll_read_buf(Pin::new(&mut me.io), cx, me.buf))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF while tunnel reading",
                    )));
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Basic {
    decoded: String,
    colon_pos: usize,
}

impl Basic {
    pub fn new(username: &str, password: &str) -> Self {
        let colon_pos = username.len();
        let decoded = format!("{}:{}", username, password);
        Basic { decoded, colon_pos }
    }
}

impl Credentials for Basic {
    const SCHEME: &'static str = "Basic";

    fn decode(value: &HeaderValue) -> Option<Self> {
        debug_assert!(
            value.as_bytes().starts_with(b"Basic "),
            "HeaderValue to decode should start with \"Basic ..\", received = {:?}",
            value,
        );

        let bytes = &value.as_bytes()["Basic ".len()..];
        let non_space_pos = bytes.iter().position(|b| *b != b' ')?;
        let bytes = &bytes[non_space_pos..];
        let bytes = base64::decode(bytes).ok()?;

        let decoded = String::from_utf8(bytes).ok()?;

        let colon_pos = decoded.find(':')?;

        Some(Basic { decoded, colon_pos })
    }

    fn encode(&self) -> HeaderValue {
        let mut encoded = String::from("Basic ");
        base64::encode_config_buf(&self.decoded, base64::STANDARD, &mut encoded);

        let bytes = Bytes::from(encoded);
        HeaderValue::from_maybe_shared(bytes)
            .expect("base64 encoding is always a valid HeaderValue")
    }
}
