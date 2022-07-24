mod protocol;
pub use protocol::*;

use std::{io, sync::Arc};

use async_trait::async_trait;

use tokio::{
    io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use crate::{
    auth::Authentication,
    dst::{DstAddr, ToLocalAddr},
    error::Error,
    TryConnect,
};

/// Tells the given proxy server to connect the specified target with
/// the proxy autherization provided by `Authentication`.
///
/// The target should be in following formats:
/// 1. www.example.com
/// 2. http://www.example.com
/// 3. https://www.example.com
/// 4. www.example.com:443
///
/// # Connect format
/// ```
/// CONNECT www.google.com:443 HTTP/1.1
/// Host: www.google.com:443
/// Proxy-Connection: keep-alive
/// Proxy-Authorization: Basic <base64(username:password)>
/// User-agent: Proxy/0.1.0
/// ```
///
pub async fn proxy_connect<S>(
    proxy: &mut S,
    target: &str,
    auth: &Authentication,
) -> Result<u16, io::Error>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let (is_http, host) = if let Some(stripped) = target.strip_prefix("http://") {
        (true, stripped)
    } else if let Some(stripped) = target.strip_prefix("https://") {
        (false, stripped)
    } else {
        (false, target)
    };
    let mut connect_host = String::from(host);
    if host.rfind(':').is_none() {
        if is_http {
            connect_host.push_str(":80");
        } else {
            connect_host.push_str(":443");
        }
    }

    proxy
        .write_all(format!("CONNECT {} HTTP/1.1\r\n", &connect_host).as_bytes())
        .await?;
    proxy
        .write_all(format!("Host: {}\r\n", &connect_host).as_bytes())
        .await?;
    proxy.write_all(b"Proxy-Connection: keep-alive\r\n").await?;
    match auth {
        Authentication::NoAuth => {}
        Authentication::Password { username, password } => {
            proxy
                .write_all(
                    format!(
                        "Proxy-Authorization: Basic {}\r\n",
                        base64::encode(format!("{}:{}", &username, &password))
                    )
                    .as_bytes(),
                )
                .await?;
        }
    }
    proxy.write_all(b"User-Agent: easyproxy/1.0.0\r\n").await?;
    proxy.write_all(b"\r\n").await?;
    proxy.flush().await?;

    let mut buf = String::new();
    let status = read_status_line(proxy, &mut buf).await?;
    let mut buf = String::new();
    let headers = read_headers(proxy, &mut buf).await?;

    let mut body_size: usize = 0;
    for h in &headers {
        if h.name.eq_ignore_ascii_case("content-type") {
            body_size = match h.value.parse::<usize>() {
                Ok(size) => size,
                Err(e) => {
                    log::error!("invalid content-length, {}", &e);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }
        }
    }

    if body_size > 0 {
        let mut buf = vec![0u8; body_size];
        proxy.read_exact(&mut buf).await?;
        log::error!("status: {}", &status);
        for h in &headers {
            log::error!("header: {}", h);
        }
        log::error!("content: {}", String::from_utf8_lossy(&buf));
    }

    match status.status.parse::<u16>() {
        Ok(code) => Ok(code),
        Err(e) => {
            log::error!("invalid status, {}", &e);
            Err(io::Error::from(io::ErrorKind::InvalidData))
        }
    }
}

pub struct ProxyServer<Dialer> {
    dialer: Dialer,
}

impl<Dialer> ProxyServer<Dialer> {
    pub fn new(dialer: Dialer) -> Self {
        Self { dialer }
    }
}

impl<D, O, E> ProxyServer<D>
where
    D: TryConnect<Output = O, Error = E>,
    O: ToLocalAddr<Error = E> + AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<Error>,
{
    pub async fn serve<S>(&self, socket: &mut S, auth: &Authentication) -> Result<(u64, u64), Error>
    where
        S: AsyncBufRead + AsyncWrite + Unpin + Send,
    {
        let mut buf = String::new();
        let request = read_request_line(socket, &mut buf).await?;
        let mut buf = String::new();
        let headers = read_headers(socket, &mut buf).await?;
        match auth {
            Authentication::NoAuth => {}
            Authentication::Password { username, password } => {
                // HTTP/1.1 407 Proxy Authentication Required
                // Proxy-Authenticate: Basic realm=Proxy Server
                let mut authed = false;
                for h in headers {
                    if h.name.eq_ignore_ascii_case("Proxy-Authorization") {
                        let encoded = h.value.trim().strip_prefix("Basic ").unwrap_or_default();
                        if let Ok(decoded) = base64::decode(encoded) {
                            if let Ok(pass) = std::str::from_utf8(&decoded) {
                                if pass == format!("{}:{}", username, password) {
                                    authed = true
                                }
                            }
                        }
                    }
                }
                if !authed {
                    write_resp(
                        socket,
                        StatusLine {
                            protocol: "HTTP/1.1",
                            status: "407",
                            message: "Proxy Authentication Required",
                        },
                        vec![Header {
                            name: "Proxy-Authenticate",
                            value: "Basic realm=Proxy Server",
                        }],
                    )
                    .await?;
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
                }
            }
        }
        log::info!("start proxy to {}", &request.host);
        let host = request.host;
        let dst = if let Some(size) = host.rfind(':') {
            let port = host[(size + 1)..].parse::<u16>().unwrap_or_default();
            DstAddr::Domain(host[0..size].to_string(), port)
        } else {
            DstAddr::Domain(host.to_string(), 0)
        };
        match self.dialer.try_connect(dst.clone()).await {
            Ok(mut stream) => {
                // HTTP/1.1 200 OK
                match write_resp(
                    socket,
                    StatusLine {
                        protocol: "HTTP/1.1",
                        status: "200",
                        message: "OK",
                    },
                    vec![],
                )
                .await
                {
                    Ok(()) => match tokio::io::copy_bidirectional(socket, &mut stream).await {
                        Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                            log::warn!("proxy to {} already closed", &request.host);
                            Ok((0, 0))
                        }
                        Err(e) => {
                            log::warn!("copy bidirectional to {} error: {}", &dst, &e);
                            Err(e.into())
                        }
                        Ok((a_2_b, b_2_a)) => {
                            log::info!(
                                "finish proxy to {}, up: {}, down: {}, ",
                                &request.host,
                                a_2_b,
                                b_2_a
                            );
                            Ok((a_2_b, b_2_a))
                        }
                    },
                    Err(e) => {
                        // Shutdown the stream first;
                        if let Err(ioe) = stream.shutdown().await {
                            log::warn!("shutdown outbound stream, {}", ioe);
                        }
                        Err(e.into())
                    }
                }
            }
            Err(e) => {
                let socks_err = e.into();
                // HTTP/1.1 503 Service Unavailable
                write_resp(
                    socket,
                    StatusLine {
                        protocol: "HTTP/1.1",
                        status: "503",
                        message: "Service Uavailable",
                    },
                    vec![],
                )
                .await?;
                Err(socks_err)
            }
        }
    }
}

async fn write_resp<'a, S>(
    socket: &mut S,
    status_line: StatusLine<'a>,
    headers: Vec<Header<'a>>,
) -> Result<(), io::Error>
where
    S: AsyncWrite + Unpin + Send,
{
    socket
        .write_all(
            format!(
                "{} {} {}\r\n",
                status_line.protocol, status_line.status, status_line.message
            )
            .as_bytes(),
        )
        .await?;
    for h in headers {
        socket
            .write_all(format!("{}: {}\r\n", h.name, h.value).as_bytes())
            .await?;
    }
    socket.write(b"\r\n").await?;
    socket.flush().await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ProxyDialer {
    proxy_target: DstAddr,
    auth: Arc<Authentication>,
}

impl ProxyDialer {
    pub fn new(proxy_target: DstAddr, auth: Arc<Authentication>) -> Self {
        Self { proxy_target, auth }
    }
}

#[async_trait]
impl TryConnect for ProxyDialer {
    type Output = BufReader<TcpStream>;
    type Error = Error;
    async fn try_connect(&self, dst: DstAddr) -> Result<Self::Output, Self::Error> {
        let tcp_stream = match &self.proxy_target {
            DstAddr::Domain(domain, port) => {
                TcpStream::connect(format!("{}:{}", domain, *port)).await
            }
            DstAddr::Socket(addr) => TcpStream::connect(addr).await,
        };
        match tcp_stream {
            Ok(stream) => {
                let mut buf = BufReader::new(stream);
                match proxy_connect(&mut buf, &format!("{}", dst), &self.auth).await {
                    Ok(code) if code == 200 => Ok(buf),
                    Ok(code) => {
                        log::error!("proxy connect to {}, code is {}", dst, code);
                        if let Err(e) = buf.shutdown().await {
                            log::error!("shutdown the stream to proxy, {}", e);
                        }
                        Err(Error::ProxyServerUnreachable)
                    }
                    Err(e) => {
                        log::error!("proxy connect to {}, {}", dst, &e);
                        if let Err(e) = buf.shutdown().await {
                            log::error!("shutdown the stream to proxy, {}", e);
                        }
                        Err(Error::ProxyServerUnreachable)
                    }
                }
            }
            Err(_) => Err(Error::ProxyServerUnreachable),
        }
    }
}
