use std::io;
use std::net::SocketAddr;
use std::task::Poll;
use std::{future::Future, task::Context};

use log::{debug, error};
use proxy::Service;
use proxy_io::{ProxyStream, TargetAddr, TokioConnect};
use proxy_tunnel::client::HttpConnector;
use tokio::net::TcpStream;

use crate::config::{Authorization, Proxy};

#[derive(Debug, Clone)]
pub struct Client {
    proxy: Option<Proxy>,
}

impl Client {
    #[allow(dead_code)]
    pub fn new(proxy: Proxy) -> Client {
        Client { proxy: Some(proxy) }
    }

    pub fn empty() -> Client {
        Client { proxy: None }
    }

    pub fn set_proxy(&mut self, proxy: Proxy) {
        self.proxy = Some(proxy)
    }
}

impl Service<TargetAddr> for Client {
    type Response = ProxyStream<TcpStream>;

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send + 'a
    where
        Self: 'a;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: TargetAddr) -> Self::Future<'_> {
        if self.proxy.is_none() {
            error!("the proxy target does not setup, please check your configuration!!!!");
        }
        let proxy = self
            .proxy
            .clone()
            .expect("the proxy target does not setup, please check you configuration firstly");
        Box::pin(async move {
            debug!(
                "try to proxy {} with {}://{}:{}",
                &req, &proxy.scheme, &proxy.host, proxy.port
            );
            let target = parse_target(&proxy.host, proxy.port);
            if proxy.scheme.eq_ignore_ascii_case("socks5") {
                let mut connect = proxy_socks::client::Client::new(target, TokioConnect::new());
                if let Some(Authorization::Basic { username, password }) = proxy.authorization {
                    connect.set_authorization(username, password);
                }

                connect.call(req).await
            } else {
                let mut connect = proxy_tunnel::client::Client::new(target, HttpConnector::new());
                if let Some(Authorization::Basic { username, password }) = proxy.authorization {
                    connect.set_authorization(username, password);
                }
                if proxy.scheme.eq_ignore_ascii_case("https") {
                    connect.enable_tls()
                }
                connect.call(req).await
            }
        })
    }
}

fn parse_target(host: &str, port: u16) -> TargetAddr {
    if let Ok(addr) = host.parse() {
        TargetAddr::SocketAddr(SocketAddr::new(addr, port))
    } else {
        TargetAddr::Domain(host.to_string(), port)
    }
}
