use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    vec,
};

use log::{debug, error};
use tokio::net::lookup_host;

#[derive(Debug, Clone)]
pub enum TargetAddr {
    SocketAddr(SocketAddr),
    Domain(String, u16),
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::SocketAddr(addr) => addr.fmt(f),
            TargetAddr::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl Default for TargetAddr {
    fn default() -> Self {
        TargetAddr::SocketAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
    }
}

impl<'a> ToSocketAddrs for TargetAddr {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        match self {
            TargetAddr::SocketAddr(s) => Ok(vec![*s].into_iter()),
            TargetAddr::Domain(d, p) => (d.as_ref(), *p).to_socket_addrs(),
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        TargetAddr::SocketAddr(addr)
    }
}

impl TargetAddr {
    pub async fn resolve_dns(&self) -> io::Result<TargetAddr> {
        match self {
            TargetAddr::SocketAddr(addr) => Ok(TargetAddr::SocketAddr(*addr)),
            TargetAddr::Domain(d, p) => {
                debug!("resolve the ip for {}:{} with native dns", d, p);
                lookup_host((&d[..], *p))
                    .await?
                    .next()
                    .ok_or_else(|| {
                        error!("unable to resolve dns for {}:{}", d, p);
                        io::ErrorKind::HostUnreachable.into()
                    })
                    .map(|addr| TargetAddr::SocketAddr(addr))
            }
        }
    }
}
