mod protocol;

pub use protocol::*;

use std::sync::Arc;

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    auth::Authentication,
    dst::{DstAddr, ToLocalAddr},
    error::Error,
    TryConnect,
};

/// Try to authenticate the given sock5 socket with specified `Authentication`.
pub async fn auth_socks5_socket<S>(socket: &mut S, auth: &Authentication) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match auth {
        Authentication::NoAuth => {
            MethodRequest(SocksVersion, vec![Method::NoAuthenticationRequired])
                .to_socket(socket)
                .await?;
            let MethodReply(_, method) = MethodReply::from_socket(socket).await?;
            match method {
                Method::NoAuthenticationRequired => Ok(()),
                Method::NoAcceptableMethods => Err(Error::NoAcceptableMethods),
                _ => Err(Error::UnknownMethod),
            }
        }
        Authentication::Password { username, password } => {
            MethodRequest(SocksVersion, vec![Method::UsernameAndPassword])
                .to_socket(socket)
                .await?;
            let MethodReply(_, method) = MethodReply::from_socket(socket).await?;
            match method {
                Method::NoAuthenticationRequired => Ok(()),
                Method::UsernameAndPassword => {
                    PasswordRequest(PasswordVersion, username.clone(), password.clone())
                        .to_socket(socket)
                        .await?;
                    let PasswordReply(_, status) = PasswordReply::from_socket(socket).await?;
                    match status {
                        Status::Ok => Ok(()),
                        Status::Failure(v) => Err(Error::PasswordAuthFailure(v)),
                    }
                }
                Method::NoAcceptableMethods => Err(Error::NoAcceptableMethods),
                _ => Err(Error::UnknownMethod),
            }
        }
    }
}

/// Tells the given proxy server to connect the specified destination with
/// the proxy autherization provided by `Authentication`.
pub async fn proxy_connect<S>(
    proxy: &mut S,
    dst: DstAddr,
    auth: &Authentication,
) -> Result<Rep, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    auth_socks5_socket(proxy, auth).await?;
    DstRequest(SocksVersion, Command::Connect, Rsv, dst)
        .to_socket(proxy)
        .await?;
    let DstReply(_, rep, _, _) = DstReply::from_socket(proxy).await?;
    Ok(rep)
}

pub struct Proxy<Dialer> {
    dialer: Dialer,
}

impl<Dialer> Proxy<Dialer> {
    pub fn new(dialer: Dialer) -> Self {
        Self { dialer }
    }
}

impl<D, O, E> Proxy<D>
where
    D: TryConnect<Output = O, Error = E>,
    O: ToLocalAddr<Error = E> + AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<Error>,
{
    pub async fn serve<S>(&self, socket: &mut S, auth: &Authentication) -> Result<(u64, u64), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let MethodRequest(_, methods) = MethodRequest::from_socket(socket).await?;
        match auth {
            Authentication::NoAuth => {
                MethodReply(SocksVersion, Method::NoAuthenticationRequired)
                    .to_socket(socket)
                    .await?;
            }
            Authentication::Password { username, password } => {
                if !methods.iter().any(|m| m == &Method::UsernameAndPassword) {
                    MethodReply(SocksVersion, Method::NoAcceptableMethods)
                        .to_socket(socket)
                        .await?;
                    return Err(Error::NoAcceptableMethods);
                }
                MethodReply(SocksVersion, Method::UsernameAndPassword)
                    .to_socket(socket)
                    .await?;
                let PasswordRequest(_, u, p) = PasswordRequest::from_socket(socket).await?;
                if username == &u && password == &p {
                    PasswordReply(PasswordVersion, Status::Ok)
                        .to_socket(socket)
                        .await?;
                } else {
                    PasswordReply(PasswordVersion, Status::Failure(0x01))
                        .to_socket(socket)
                        .await?;
                    return Err(Error::PasswordAuthFailure(0x01));
                }
            }
        }

        let DstRequest(_, cmd, _, proxy_dst) = DstRequest::from_socket(socket).await?;
        log::info!("start proxy to {}", &proxy_dst);
        match cmd {
            Command::Connect => match self.dialer.try_connect(proxy_dst.clone()).await {
                Ok(mut stream) => {
                    let dst = stream.to_local_addr().map_err(|e| e.into())?;
                    match DstReply(SocksVersion, Rep::Succeeded, Rsv, dst)
                        .to_socket(socket)
                        .await
                    {
                        Ok(()) => match tokio::io::copy_bidirectional(socket, &mut stream).await {
                            Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                                log::warn!("proxy to {} already closed", &proxy_dst);
                                Ok((0, 0))
                            }
                            Err(e) => {
                                log::warn!("copy bidirectional to {} error: {}", &proxy_dst, &e);
                                Err(e.into())
                            }
                            Ok((a_2_b, b_2_a)) => {
                                log::info!(
                                    "finish proxy to {}, up: {}, down: {}, ",
                                    &proxy_dst,
                                    a_2_b,
                                    b_2_a
                                );
                                Ok((a_2_b, b_2_a))
                            }
                        },
                        Err(e) => {
                            //  log::error!("shutdown outbount stream: {}", &proxy_dst);
                            // Shutdown the stream first;
                            if let Err(ioe) = stream.shutdown().await {
                                log::warn!("shutdown outbound stream, {}", ioe);
                            }
                            Err(e)
                        }
                    }
                }
                Err(e) => {
                    let socks_err = e.into();
                    let rep = Rep::from_err(&socks_err);
                    DstReply(SocksVersion, rep, Rsv, DstAddr::default())
                        .to_socket(socket)
                        .await?;
                    Err(socks_err)
                }
            },
            Command::Bind | Command::Associate => {
                log::warn!("Bind or UdpAssociate command is not implemented");
                DstReply(
                    SocksVersion,
                    Rep::CommandNotSupported,
                    Rsv,
                    DstAddr::default(),
                )
                .to_socket(socket)
                .await?;
                Err(Error::CommandNotSupported)
            }
        }
    }
}

pub struct ProxySocks5 {
    proxy_target: DstAddr,
    auth: Arc<Authentication>,
}

impl ProxySocks5 {
    pub fn new(proxy_target: DstAddr, auth: Arc<Authentication>) -> Self {
        Self { proxy_target, auth }
    }
}

#[async_trait]
impl TryConnect for ProxySocks5 {
    type Output = TcpStream;
    type Error = Error;
    async fn try_connect(&self, dst: DstAddr) -> Result<Self::Output, Self::Error> {
        let tcp_stream = match &self.proxy_target {
            DstAddr::Domain(domain, port) => {
                TcpStream::connect(format!("{}:{}", domain, *port)).await
            }
            DstAddr::Socket(addr) => TcpStream::connect(addr).await,
        };
        match tcp_stream {
            Ok(mut stream) => match proxy_connect(&mut stream, dst.clone(), &self.auth).await {
                Ok(rep) if rep == Rep::Succeeded => Ok(stream),
                Ok(rep) => {
                    log::error!("proxy connect to {}, code is {}", &dst, &rep);
                    if let Err(e) = stream.shutdown().await {
                        log::error!("shutdown the stream to proxy, {}", e);
                    }
                    Err(Error::ProxyServerUnreachable)
                }
                Err(e) => {
                    log::error!("proxy connect to {}, {}", &dst, &e);
                    if let Err(e) = stream.shutdown().await {
                        log::error!("shutdown the stream to proxy, {}", e);
                    }
                    Err(Error::ProxyServerUnreachable)
                }
            },
            Err(_) => Err(Error::ProxyServerUnreachable),
        }
    }
}
