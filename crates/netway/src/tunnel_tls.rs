use std::sync::Arc;

use async_trait::async_trait;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_native_tls::{native_tls, TlsStream};

use crate::{auth::Authentication, dst::DstAddr, error::Error, tunnel::proxy_connect, TryConnect};

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
    type Output = BufReader<TlsStream<TcpStream>>;
    type Error = Error;
    async fn try_connect(&self, dst: DstAddr) -> Result<Self::Output, Self::Error> {
        match &self.proxy_target {
            DstAddr::Domain(domain, port) => {
                match TcpStream::connect(format!("{}:{}", domain, *port)).await {
                    Ok(mut stream) => {
                        let cx = match native_tls::TlsConnector::builder().build() {
                            Ok(tc) => tc,
                            Err(e) => {
                                log::error!("initialize TlsConnector context error, {}", &e);
                                if let Err(e) = stream.shutdown().await {
                                    log::error!("shutdown the stream to proxy, {}", e);
                                }
                                return Err(Error::ProxyServerUnreachable);
                            }
                        };
                        let cx = tokio_native_tls::TlsConnector::from(cx);
                        let proxy = match cx.connect(domain, stream).await {
                            Ok(v) => v,
                            Err(e) => {
                                log::error!("initialize TlsStream to {} error, {}", &domain, &e);
                                return Err(Error::ProxyServerUnreachable);
                            }
                        };
                        let mut buf = BufReader::new(proxy);
                        match proxy_connect(&mut buf, &format!("{}", &dst), &self.auth).await {
                            Ok(code) if code == 200 => Ok(buf),
                            Ok(code) => {
                                log::error!("proxy connect to {}, code is {}", &dst, code);
                                if let Err(e) = buf.shutdown().await {
                                    log::error!("shutdown the stream to proxy, {}", e);
                                }
                                Err(Error::ProxyServerUnreachable)
                            }
                            Err(e) => {
                                log::error!("proxy connect to {}, {}", &dst, &e);
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
            DstAddr::Socket(_) => Err(Error::ProxyServerUnreachable),
        }
    }
}
