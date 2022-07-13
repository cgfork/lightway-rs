use std::{io::ErrorKind, net::SocketAddr, sync::Arc};

use anyhow::Result;
use netway::{
    auth::Authentication,
    dst::{DstAddr, ToLocalAddr},
    error::Error,
    socks5, tunnel, DefaultDialer, TryConnect,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    task::JoinHandle,
};

use crate::{
    config::{ParsedConfig, Protocol, ProxyMode},
    rule::{Decision, Dialer, SimplePolicy},
};

pub async fn start_proxy(config: ParsedConfig) -> Result<JoinHandle<Result<(), anyhow::Error>>> {
    let l = TcpListener::bind(&config.general.socks5_listen).await?;
    match &config.general.proxy {
        Some(name) => match config.proxies.get(name) {
            Some((protocol, host, port, auth)) => {
                let dst_addr = match host.parse() {
                    Ok(ip) => DstAddr::Socket(SocketAddr::new(ip, *port)),
                    Err(_) => DstAddr::Domain(host.clone(), *port),
                };
                let policy = match config.general.proxy_mode {
                    ProxyMode::Direct => SimplePolicy::new(Some(Decision::Direct), vec![]),
                    ProxyMode::Proxy => {
                        SimplePolicy::new(Some(Decision::Proxy { remote_dns: false }), vec![])
                    }
                    ProxyMode::Auto => SimplePolicy::new(None, config.rules),
                };
                let auth = Arc::new(auth.clone());
                let policy = Arc::new(policy);
                Ok(match protocol {
                    Protocol::Socks5 => tokio::spawn(async move {
                        loop {
                            let (mut stream, socket_addr) = l.accept().await.unwrap();
                            let dst_addr = dst_addr.clone();
                            let auth = auth.clone();
                            let policy = policy.clone();
                            tokio::spawn(async move {
                                proxy_serve(
                                    Dialer::new(
                                        socks5::ProxyDialer::new(dst_addr, auth),
                                        policy,
                                        false,
                                    ),
                                    &mut stream,
                                    &Authentication::NoAuth,
                                    DstAddr::Socket(socket_addr),
                                )
                                .await
                            });
                        }
                    }),
                    Protocol::HTTP => tokio::spawn(async move {
                        loop {
                            let (mut stream, socket_addr) = l.accept().await.unwrap();
                            let dst_addr = dst_addr.clone();
                            let auth = auth.clone();
                            let policy = policy.clone();
                            tokio::spawn(async move {
                                proxy_serve(
                                    Dialer::new(
                                        tunnel::ProxyDialer::new(dst_addr, auth),
                                        policy,
                                        false,
                                    ),
                                    &mut stream,
                                    &Authentication::NoAuth,
                                    DstAddr::Socket(socket_addr),
                                )
                                .await
                            });
                        }
                    }),
                    #[cfg(feature = "tls")]
                    Protocol::HTTPs => tokio::spawn(async move {
                        loop {
                            let (mut stream, socket_addr) = l.accept().await.unwrap();
                            let dst_addr = dst_addr.clone();
                            let auth = auth.clone();
                            let policy = policy.clone();
                            tokio::spawn(async move {
                                proxy_serve(
                                    Dialer::new(
                                        netway::tunnel_tls::ProxyDialer::new(dst_addr, auth),
                                        policy,
                                        false,
                                    ),
                                    &mut stream,
                                    &Authentication::NoAuth,
                                    DstAddr::Socket(socket_addr),
                                )
                                .await
                            });
                        }
                    }),
                })
            }
            None => panic!("{} not found", name),
        },
        None => Ok(tokio::spawn(async move {
            loop {
                let (mut stream, socket_addr) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    proxy_serve(
                        DefaultDialer,
                        &mut stream,
                        &Authentication::NoAuth,
                        DstAddr::Socket(socket_addr),
                    )
                    .await
                });
            }
        })),
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
    let proxy = netway::socks5::ProxySever::new(dialer);
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
