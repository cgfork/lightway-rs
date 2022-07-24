#![feature(ready_macro)]

pub mod auth;
pub mod dst;
pub mod either;
pub mod error;
pub mod fixed_read;
pub mod socks5;
pub mod tunnel;

#[cfg(feature = "tokio-native-tls")]
pub mod tunnel_tls;

use std::net::ToSocketAddrs;

use async_trait::async_trait;
use dst::DstAddr;
use error::Error;
use tokio::net::TcpStream;

#[async_trait]
pub trait TryConnect {
    type Output;
    type Error;

    async fn try_connect(&self, dst: DstAddr) -> Result<Self::Output, Self::Error>;
}

pub struct DefaultDialer;

#[async_trait]
impl TryConnect for DefaultDialer {
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
