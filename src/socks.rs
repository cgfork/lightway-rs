use std::{io::ErrorKind, sync::Arc};

use anyhow::Result;
use netway::{
    auth::Authentication,
    dst::{DstAddr, ToLocalAddr},
    error::Error,
    Dialer, TryConnect,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};

use crate::rule::Policy;

pub struct AlwaysProxy {
    dialer: Dialer,
    l: TcpListener,
    auth: Arc<Authentication>,
}

impl AlwaysProxy {
    pub fn new(dialer: Dialer, l: TcpListener, auth: Arc<Authentication>) -> Self {
        Self { dialer, l, auth }
    }
}

impl AlwaysProxy {
    pub async fn start_accept(&self) -> Result<()> {
        loop {
            let (mut stream, socket_addr) = self.l.accept().await?;
            let auth = self.auth.clone();
            let dialer = self.dialer.clone();
            tokio::spawn(async move {
                proxy_serve(dialer, &mut stream, &auth, DstAddr::Socket(socket_addr)).await
            });
        }
    }
}

pub struct AlwaysDirect {
    l: TcpListener,
    auth: Arc<Authentication>,
}

impl AlwaysDirect {
    pub fn new(l: TcpListener, auth: Arc<Authentication>) -> Self {
        Self { l, auth }
    }
}

impl AlwaysDirect {
    pub async fn start_accept(&self) -> Result<()> {
        loop {
            let (mut stream, socket_addr) = self.l.accept().await?;
            let auth = self.auth.clone();
            tokio::spawn(async move {
                proxy_serve(
                    netway::DirectDialer,
                    &mut stream,
                    &auth,
                    DstAddr::Socket(socket_addr),
                )
                .await
            });
        }
    }
}

pub struct AutoProxy<P> {
    dialer: Dialer,
    l: TcpListener,
    auth: Arc<Authentication>,
    policy: Arc<P>,
    default_proxy: bool,
}

impl<P> AutoProxy<P> {
    pub fn new(
        dialer: Dialer,
        l: TcpListener,
        auth: Arc<Authentication>,
        policy: Arc<P>,
        default_proxy: bool,
    ) -> Self {
        Self {
            dialer,
            l,
            auth,
            policy,
            default_proxy,
        }
    }
}

impl<P> AutoProxy<P>
where
    P: Policy + Send + Sync + 'static,
{
    pub async fn start_accept(&self) -> Result<()> {
        loop {
            let (mut stream, socket_addr) = self.l.accept().await?;
            let auth = self.auth.clone();
            let dialer = self.dialer.clone();
            let policy = self.policy.clone();
            let default_proxy = self.default_proxy;
            tokio::spawn(async move {
                let dst_addr = DstAddr::Socket(socket_addr);
                let (decision, _) = policy.enforce(&dst_addr);
                match decision {
                    crate::rule::Decision::Direct => {
                        proxy_serve(
                            netway::DirectDialer,
                            &mut stream,
                            &auth,
                            DstAddr::Socket(socket_addr),
                        )
                        .await
                    }
                    crate::rule::Decision::Proxy { .. } => {
                        proxy_serve(dialer, &mut stream, &auth, DstAddr::Socket(socket_addr)).await
                    }
                    crate::rule::Decision::Default => {
                        if default_proxy {
                            proxy_serve(dialer, &mut stream, &auth, DstAddr::Socket(socket_addr))
                                .await
                        } else {
                            proxy_serve(
                                netway::DirectDialer,
                                &mut stream,
                                &auth,
                                DstAddr::Socket(socket_addr),
                            )
                            .await
                        }
                    }
                    crate::rule::Decision::Deny => return Err(Error::ProxyDenied),
                }
            });
        }
    }
}

async fn proxy_serve<D, O, E, S>(
    dialer: D,
    socket: &mut S,
    auth: &Authentication,
    dst_addr: DstAddr,
) -> Result<(), Error>
where
    D: TryConnect<Output = O, Error = E>,
    O: ToLocalAddr<Error = E> + AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<Error>,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let proxy = netway::socks5::Proxy::new(dialer);
    match proxy.serve(socket, &auth).await {
        Ok((a_2_b, b_2_a)) => {
            log::info!(
                "finish sock5 proxy from {}, up: {}, down: {}, ",
                &dst_addr,
                a_2_b,
                b_2_a
            );
            Ok(())
        }
        Err(e) => match e {
            Error::Io(ioe) if ioe.kind() == ErrorKind::UnexpectedEof => Ok(()),
            _ => {
                log::error!("finish sock5 proxy from {}, {}", &dst_addr, &e);
                Err(e)
            }
        },
    }
}
