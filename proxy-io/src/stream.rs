use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::TryFutureExt;
use log::{debug, error};
use proxy::Service;
use proxy_rules::{Decision, Policy};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{lookup_host, TcpStream},
};
#[cfg(feature = "tokio-native-tls")]
use tokio_native_tls::TlsStream;

use crate::TargetAddr;

#[derive(Debug)]
pub enum ProxyStream<S> {
    Tcp(S),
    #[cfg(feature = "tokio-native-tls")]
    Tls(TlsStream<S>),
}

impl<S> AsyncRead for ProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tokio-native-tls")]
            ProxyStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S> AsyncWrite for ProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tokio-native-tls")]
            ProxyStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tokio-native-tls")]
            ProxyStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tokio-native-tls")]
            ProxyStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(feature = "tokio-native-tls")]
            ProxyStream::Tls(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            ProxyStream::Tcp(s) => s.is_write_vectored(),
            #[cfg(feature = "tokio-native-tls")]
            ProxyStream::Tls(s) => s.is_write_vectored(),
        }
    }
}

#[derive(Debug)]
pub enum Connection<S> {
    Proxy(ProxyStream<S>),
    Direct(S),
}

impl<S> AsyncRead for Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Connection::Direct(s) => Pin::new(s).poll_read(cx, buf),
            Connection::Proxy(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S> AsyncWrite for Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Connection::Proxy(s) => Pin::new(s).poll_write(cx, buf),
            Connection::Direct(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Connection::Proxy(s) => Pin::new(s).poll_flush(cx),
            Connection::Direct(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Connection::Proxy(s) => Pin::new(s).poll_shutdown(cx),
            Connection::Direct(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Connection::Proxy(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Connection::Direct(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Connection::Proxy(s) => s.is_write_vectored(),
            Connection::Direct(s) => s.is_write_vectored(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokioConnect {
    // TODO: provide a dns resolver to resolve the domain
}

impl TokioConnect {
    pub fn new() -> Self {
        TokioConnect {}
    }
}

impl Service<TargetAddr> for TokioConnect {
    type Response = TcpStream;

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send + 'a
    where
        Self: 'a;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: TargetAddr) -> Self::Future<'_> {
        Box::pin(async move {
            match &target {
                TargetAddr::SocketAddr(addr) => TcpStream::connect(addr).await,
                TargetAddr::Domain(d, p) => {
                    debug!("resolve the ip for {}:{} with native dns", d, p);
                    let addr = lookup_host((&d[..], *p)).await?.next().ok_or_else(|| {
                        error!("unable to resolve dns for {}:{}", d, p);
                        Into::<io::Error>::into(io::ErrorKind::HostUnreachable)
                    })?;
                    TcpStream::connect(addr).await
                }
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct StreamConnect<C> {
    connect: C,
    tls: bool,
    target: TargetAddr,
}

impl<C> StreamConnect<C> {
    pub fn new(connect: C, target: TargetAddr) -> Self {
        Self {
            connect,
            tls: false,
            target,
        }
    }

    pub fn set_tls(&mut self, tls: bool) {
        self.tls = tls
    }

    pub fn set_target(&mut self, target: TargetAddr) {
        self.target = target
    }
}

impl<C> Service<()> for StreamConnect<C>
where
    C: Service<TargetAddr> + Send + 'static,
    C::Response: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    C::Error: Into<io::Error>,
{
    type Response = ProxyStream<C::Response>;

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send + 'a
    where
        Self: 'a;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connect.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, _req: ()) -> Self::Future<'_> {
        let future = self.connect.call(self.target.clone());
        let tls = self.tls;
        let target = self.target.clone();
        Box::pin(async move {
            let stream = future.await.map_err(Into::into)?;
            if let TargetAddr::Domain(host, _port) = &target {
                if tls {
                    debug!("connect tls to {}", host);
                    #[cfg(feature = "tokio-native-tls")]
                    {
                        match tokio_native_tls::native_tls::TlsConnector::builder().build() {
                            Ok(cx) => match tokio_native_tls::TlsConnector::from(cx)
                                .connect(host, stream)
                                .await
                            {
                                Ok(s) => Ok(ProxyStream::Tls(s)),
                                Err(e) => {
                                    error!("unable to connect {} with tls, {}", host, &e);
                                    Err(io::Error::new(io::ErrorKind::Other, e))
                                }
                            },
                            Err(e) => {
                                error!("unable to initialize TlsConnector, {}", &e);
                                Err(io::Error::new(io::ErrorKind::Other, e))
                            }
                        }
                    }

                    #[cfg(not(feature = "tokio-native-tls"))]
                    Err(io::ErrorKind::Unsupported.into())
                } else {
                    Ok(ProxyStream::Tcp(stream))
                }
            } else {
                Ok(ProxyStream::Tcp(stream))
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConnect<C, PC, P> {
    connect: C,
    proxy_connect: PC,
    policy: Option<P>,
    force_proxy: bool,
    defaut_proxy: bool,
}

impl<C, PC, P> ProxyConnect<C, PC, P> {
    pub fn new(connect: C, proxy_connect: PC) -> Self {
        Self {
            connect,
            proxy_connect,
            policy: None,
            force_proxy: false,
            defaut_proxy: false,
        }
    }

    pub fn set_policy(&mut self, policy: P) {
        self.policy = Some(policy)
    }

    pub fn set_force_proxy(&mut self, force_proxy: bool) {
        self.force_proxy = force_proxy
    }

    pub fn set_default_proxy(&mut self, default_proxy: bool) {
        self.defaut_proxy = default_proxy
    }
}

impl<S, C, PC, P> Service<TargetAddr> for ProxyConnect<C, PC, P>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: Service<TargetAddr, Response = S> + Send + 'static,
    C::Error: Into<io::Error> + Send,
    PC: Service<TargetAddr, Response = ProxyStream<S>> + Send + 'static,
    PC::Error: Into<io::Error> + Send,
    P: Policy + Send,
{
    type Response = Connection<S>;

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send + 'a
    where
        Self: 'a;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.connect.poll_ready(cx) {
            Poll::Ready(Ok(())) => self.proxy_connect.poll_ready(cx).map_err(Into::into),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, target: TargetAddr) -> Self::Future<'_> {
        let decision = if self.force_proxy {
            Decision::Proxy { remote_dns: true }
        } else if let Some(p) = &self.policy {
            p.enforce(&target.to_string())
        } else {
            Decision::Default
        };

        Box::pin(async move {
            match decision {
                Decision::Direct => {
                    debug!("direct connect {}", &target);
                    let future = self.connect.call(target).map_err(Into::into);
                    Ok(Connection::Direct(future.await?))
                }
                Decision::Proxy { .. } => {
                    debug!("proxy connect {}", &target);
                    let future = self.proxy_connect.call(target).map_err(Into::into);
                    Ok(Connection::Proxy(future.await?))
                }
                Decision::Default => {
                    if self.defaut_proxy {
                        debug!("proxy connect {}", &target);
                        let future = self.proxy_connect.call(target).map_err(Into::into);
                        Ok(Connection::Proxy(future.await?))
                    } else {
                        debug!("direct connect {}", &target);
                        let future = self.connect.call(target).map_err(Into::into);
                        Ok(Connection::Direct(future.await?))
                    }
                }
                Decision::Deny => Err(io::ErrorKind::HostUnreachable.into()),
            }
        })
    }
}
