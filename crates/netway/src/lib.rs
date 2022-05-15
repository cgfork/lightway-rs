#![feature(ready_macro)]

pub mod auth;
pub mod dst;
pub mod either;
pub mod error;
pub mod fixed_read;
pub mod socks5;
pub mod tunnel;

use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use async_trait::async_trait;
use auth::Authentication;
use dst::DstAddr;
use either::Either;
use error::Error;
use tokio::{io::BufReader, net::TcpStream};
use tokio_native_tls::TlsStream;

#[async_trait]
pub trait TryConnect {
    type Output;
    type Error;

    async fn try_connect(&self, dst: DstAddr) -> Result<Self::Output, Self::Error>;
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    HTTP,
    HTTPs,
    Socks5,
}

pub struct DirectDialer;

#[async_trait]
impl TryConnect for DirectDialer {
    type Output = TcpStream;
    type Error = Error;

    async fn try_connect(&self, dst: DstAddr) -> Result<Self::Output, Self::Error> {
        match dst.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    TcpStream::connect(addr).await.map_err(|e| e.into())
                } else {
                    Err(Error::InvalidDstAddress("dns unresolved"))
                }
            }
            Err(e) => {
                log::error!("unkwown dst {}", &dst);
                Err(e.into())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Dialer {
    protocol: Protocol,
    host: String,
    port: u16,
    auth: Arc<Authentication>,
}

impl Dialer {
    pub fn new(protocol: Protocol, host: String, port: u16, auth: Arc<Authentication>) -> Self {
        Self {
            protocol,
            host,
            port,
            auth,
        }
    }
}

#[async_trait]
impl TryConnect for Dialer {
    type Output = Either<BufReader<TcpStream>, BufReader<TlsStream<TcpStream>>>;
    type Error = Error;

    async fn try_connect(&self, dst: DstAddr) -> Result<Self::Output, Self::Error> {
        let dst_addr = match self.host.parse() {
            Ok(ip) => DstAddr::Socket(SocketAddr::new(ip, self.port)),
            Err(_) => DstAddr::Domain(self.host.clone(), self.port),
        };
        match self.protocol {
            Protocol::HTTP => {
                let stream = tunnel::ProxyHTTP::new(dst_addr, self.auth.clone())
                    .try_connect(dst)
                    .await?;
                Ok(Either::Left(stream))
            }
            Protocol::HTTPs => {
                let stream = tunnel::ProxyHTTPs::new(dst_addr, self.auth.clone())
                    .try_connect(dst)
                    .await?;
                Ok(Either::Right(stream))
            }

            Protocol::Socks5 => {
                let stream = socks5::ProxySocks5::new(dst_addr, self.auth.clone())
                    .try_connect(dst)
                    .await?;
                Ok(Either::Left(BufReader::new(stream)))
            }
        }
    }
}
