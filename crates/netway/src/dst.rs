use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    vec,
};

use tokio::{io::BufReader, net::TcpStream};
use tokio_native_tls::TlsStream;

use crate::error::Error;

/// A Socks5 destination address.
#[derive(Debug, Clone)]
pub enum DstAddr {
    /// Connect to an IP and port addr.
    Socket(SocketAddr),

    /// Connect to a fully-qualified domain.
    Domain(String, u16),
}

pub trait ToLocalAddr {
    type Error;

    fn to_local_addr(&self) -> Result<DstAddr, Self::Error>;
}

impl ToLocalAddr for TcpStream {
    type Error = Error;
    fn to_local_addr(&self) -> Result<DstAddr, Self::Error> {
        self.local_addr().map(|s| s.into()).map_err(|e| e.into())
    }
}

impl ToLocalAddr for BufReader<TcpStream> {
    type Error = Error;
    fn to_local_addr(&self) -> Result<DstAddr, Self::Error> {
        self.get_ref().to_local_addr()
    }
}

impl ToLocalAddr for BufReader<TlsStream<TcpStream>> {
    type Error = Error;
    fn to_local_addr(&self) -> Result<DstAddr, Self::Error> {
        self.get_ref().get_ref().get_ref().get_ref().to_local_addr()
    }
}

impl Default for DstAddr {
    fn default() -> Self {
        DstAddr::Socket(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            0,
        )))
    }
}

impl<'a> fmt::Display for DstAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DstAddr::Socket(sa) => sa.fmt(f),
            DstAddr::Domain(d, p) => write!(f, "{}:{}", d, *p),
        }
    }
}

impl<'a> ToSocketAddrs for DstAddr {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        match self {
            DstAddr::Socket(s) => Ok(vec![*s].into_iter()),
            DstAddr::Domain(d, p) => (d.as_ref(), *p).to_socket_addrs(),
        }
    }
}

impl From<SocketAddr> for DstAddr {
    fn from(addr: SocketAddr) -> Self {
        DstAddr::Socket(addr)
    }
}
