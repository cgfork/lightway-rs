use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use proxy_io::{AsyncFixedReadExt, AsyncFixedWriteExt, TargetAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Kind;
use crate::validate;

// Socks Allowable Methods
pub const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
pub const GSSAPI: u8 = 0x01;
pub const USERNAME_AND_PASSWORD: u8 = 0x02;
pub const IANA_ASSIGNED_MIN: u8 = 0x03; // Reserved start
pub const IANA_ASSIGNED_MAX: u8 = 0x7f; // Reserved stop
pub const NO_ACCEPTABLE_METHODS: u8 = 0xff;

// COMMANDs
pub const CONNECT: u8 = 0x01;
pub const BIND: u8 = 0x02;
pub const UDP_ASSOCIATE: u8 = 0x03;

// ADDR TYPEs
pub const DST_IPV4: u8 = 0x01;
pub const DST_DOMAIN: u8 = 0x03;
pub const DST_IPV6: u8 = 0x04;

// RESPONSE CODEs
pub const SUCCEEDED: u8 = 0x00;
pub const GENERAL_SOCKS_SERVER_FAILURE: u8 = 0x01;
pub const CONNNECTION_NOT_ALLOWED_BY_RULESET: u8 = 0x02;
pub const NETWORK_UNREACHABLE: u8 = 0x03;
pub const HOST_UNREACHABLE: u8 = 0x04;
pub const CONNECTION_REFUSED: u8 = 0x05;
pub const TTL_EXPIRED: u8 = 0x06;
pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

// Socks Version
pub const SOCKS_VERSION: u8 = 0x05;

// Auth Version
pub const AUTH_VERSION: u8 = 0x01;

// Auth Status
pub const AUTH_SUCCEED: u8 = 0x00;

/// Socks authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Method {
    NoAuthenticationRequired,
    Gssapi,
    UsernameAndPassword,
    IanaAssigned(u8),
    Reserved(u8),
    NoAcceptableMethods,
}

impl Method {
    pub(crate) fn from_u8(code: u8) -> Option<Method> {
        match code {
            NO_AUTHENTICATION_REQUIRED => Some(Method::NoAuthenticationRequired),
            GSSAPI => Some(Method::Gssapi),
            USERNAME_AND_PASSWORD => Some(Method::UsernameAndPassword),
            NO_ACCEPTABLE_METHODS => Some(Method::NoAcceptableMethods),
            x if x >= IANA_ASSIGNED_MIN && x <= IANA_ASSIGNED_MAX => Some(Method::IanaAssigned(x)),
            x => Some(Method::Reserved(x)),
        }
    }

    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            Method::NoAuthenticationRequired => NO_AUTHENTICATION_REQUIRED,
            Method::Gssapi => GSSAPI,
            Method::UsernameAndPassword => USERNAME_AND_PASSWORD,
            Method::IanaAssigned(x) => *x,
            Method::Reserved(x) => *x,
            Method::NoAcceptableMethods => NO_ACCEPTABLE_METHODS,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Method::NoAuthenticationRequired => "no authentication required",
            Method::Gssapi => "gssapi",
            Method::UsernameAndPassword => "username and password",
            Method::IanaAssigned(_) => "iana assigned",
            Method::Reserved(_) => "reserved",
            Method::NoAcceptableMethods => "no acceptable methods",
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Command {
    Connect = CONNECT,
    Bind = BIND,
    Associate = UDP_ASSOCIATE,
}

impl Command {
    #[allow(dead_code)]
    pub(crate) fn from_u8(code: u8) -> Option<Command> {
        match code {
            CONNECT | BIND | UDP_ASSOCIATE => Some(unsafe { std::mem::transmute(code) }),
            _ => None,
        }
    }

    pub(crate) fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Command::Connect => "connect",
            Command::Bind => "bind",
            Command::Associate => "associate",
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rep {
    Succeeded = SUCCEEDED,
    GeneralSocksServerFailure = GENERAL_SOCKS_SERVER_FAILURE,
    ConnectionNotAllowedByRuleset = CONNNECTION_NOT_ALLOWED_BY_RULESET,
    NetworkUnreachable = NETWORK_UNREACHABLE,
    HostUnreachable = HOST_UNREACHABLE,
    ConnectionRefused = CONNECTION_REFUSED,
    TtlExpired = TTL_EXPIRED,
    CommandNotSupported = COMMAND_NOT_SUPPORTED,
    AddressTypeNotSupported = ADDRESS_TYPE_NOT_SUPPORTED,
}

impl Default for Rep {
    fn default() -> Rep {
        Rep::Succeeded
    }
}

impl Rep {
    pub(crate) fn from_u8(code: u8) -> Option<Rep> {
        if code <= 0x08 {
            Some(unsafe { std::mem::transmute(code) })
        } else {
            None
        }
    }

    pub(crate) fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for Rep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rep::Succeeded => f.write_str("succeeded"),
            Rep::GeneralSocksServerFailure => f.write_str("general socks server failure"),
            Rep::ConnectionNotAllowedByRuleset => f.write_str("connection not allowed by result"),
            Rep::NetworkUnreachable => f.write_str("network unreachable"),
            Rep::HostUnreachable => f.write_str("host unreachable"),
            Rep::ConnectionRefused => f.write_str("connection refused"),
            Rep::TtlExpired => f.write_str("ttl expired"),
            Rep::CommandNotSupported => f.write_str("command not supported"),
            Rep::AddressTypeNotSupported => f.write_str("address type not supported"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DstAtyp {
    IPv4 = DST_IPV4,         // len = 4
    DomainName = DST_DOMAIN, // fixed string
    IPv6 = DST_IPV6,         // len = 16
}

impl DstAtyp {
    #[allow(dead_code)]
    pub(crate) fn from_u8(code: u8) -> Option<DstAtyp> {
        match code {
            DST_IPV4 | DST_DOMAIN | DST_IPV6 => Some(unsafe { std::mem::transmute(code) }),
            _ => None,
        }
    }

    pub(crate) fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// The client connects to the server, and sends a version
/// identifier/method selection message:
///
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 1  |    1     | 1 to 255 |
/// +----+----------+----------+
///
/// The VER field is set to X05 for this version of the protocol.
/// The NMETHODS field contains the number of method identifier
/// octets that appear in the METHODS field.
#[derive(Debug, Clone)]
pub struct CandidateMethods {
    pub version: u8,
    pub methods: Vec<u8>,
}

/// The server selects from one of the METHODS given in the
/// [`MethodRequest`], and sends a METHOD selection message:
///
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    
/// +----+--------+
///
/// If the selected METHOD is XFF, none of the methods listed by the
/// client are acceptable, and the client MUST close the connection.
///
/// The values currently defined for METHOD are:
/// o  X00 NO AUTHENTICATION REQUIRED
/// o  X01 GSSAPI
/// o  X02 USERNAME/PASSWORD
/// o  X03 to X7F IANA ASSIGNED
/// o  X80 to XFE RESERVED FOR PRIVATE METHODS
/// o  XFF NO ACCEPTABLE METHODS
#[derive(Debug, Clone)]
pub struct Selection {
    pub version: u8,
    pub method: u8,
}

/// The client sends the username and password if the server has selected
/// the USERNAME/PASSWORD method.
///
/// +----+----------+----------+
/// |VER | USERNAME | PASSWORD |
/// +----+----------+----------+
/// | 1  |  1..255  |  1..255  |
/// +----+----------+----------+
///
/// The VER field is set to X01 for this version of the AUTHENTICATION.
/// USERNAME or PASSWORD is a fixed string. The first octet of the field
/// contains the number of octects of string that follow.
#[derive(Debug, Clone)]
pub struct UsernameAndPassword {
    pub version: u8,
    pub username: String,
    pub password: String,
}

/// The server authenticates the USERNAME and PASSWORD, and sends a
/// status message:
///
/// +----+--------+
/// |VER | STATUS |
/// +----+--------+
/// | 1  |    1   |
/// +----+--------+
///
/// The VER field is set to X01 for this version of the AUTHENTICATION.
#[derive(Debug, Clone)]
pub struct Status {
    pub version: u8,
    pub status: u8,
}

/// Once the method-dependent subnegotiation has completed, the client
/// sends the request details.
///
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  |  X00  |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
///
/// Where:
/// o  VER    protocol version: X05
/// o  CMD
///    o  CONNECT X01
///    o  BIND X02
///    o  UDP ASSOCIATE X03
/// o  RSV    RESERVED
/// o  ATYP   address type of following address
///    o  IP V4 address: X01
///    o  DOMAINNAME: X03
///    o  IP V6 address: X04
/// o  DST.ADDR desired destination address
/// o  DST.PORT desired destination port in network octet order
#[derive(Debug, Clone)]
pub struct Request {
    pub version: u8,
    pub command: u8,
    pub target: Option<TargetAddr>,
}

/// The SOCKS request information is sent by the client as soon as it has
/// established a connection to the SOCKS server, and completed the
/// authentication negotiations.  The server evaluates the request, and
/// returns a reply formed as follows:
///
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X00 |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
///
/// Where:
/// o  VER    protocol version: X05
/// o  REP    Reply field:
///    o  X00 succeeded
///    o  X01 general SOCKS server failure
///    o  X02 connection not allowed by ruleset
///    o  X03 Network unreachable
///    o  X04 Host unreachable
///    o  X05 Connection refused
///    o  X06 TTL expired
///    o  X07 Command not supported
///    o  X08 Address type not supported
///    o  X09 to XFF unassigned
/// o  RSV    RESERVED
/// o  ATYP   address type of following address
///    o  IP V4 address: X01
///    o  DOMAINNAME: X03
///    o  IP V6 address: X04
/// o  BND.ADDR       server bound address
/// o  BND.PORT       server bound port in network octet order
///
/// Fields marked RESERVED (RSV) must be set to X00.
#[derive(Debug, Clone)]
pub struct Reply {
    pub version: u8,
    pub rep: u8,
    pub atyp: u8,
    pub target: Option<TargetAddr>,
}

impl CandidateMethods {
    pub fn empty() -> Self {
        CandidateMethods {
            version: SOCKS_VERSION,
            methods: vec![],
        }
    }

    pub fn new(methods: Vec<Method>) -> Self {
        CandidateMethods {
            version: SOCKS_VERSION,
            methods: methods.into_iter().map(|m| m.as_u8()).collect(),
        }
    }

    pub fn add(&mut self, method: Method) {
        self.methods.push(method.as_u8())
    }

    pub fn has(&self, method: Method) -> bool {
        self.methods.iter().any(|m| *m == method.as_u8())
    }

    pub async fn read<S: AsyncRead + Unpin>(socket: &mut S) -> io::Result<Self> {
        let version = socket.read_u8().await?;
        let mut methods = Vec::new();
        socket.read_to_fixed_bytes(&mut methods).await?;
        Ok(Self { version, methods })
    }

    pub async fn write<S: AsyncWrite + Unpin>(&self, socket: &mut S) -> io::Result<()> {
        socket.write_u8(self.version).await?;
        socket.write_fixed(&self.methods).await
    }

    pub fn is_valid(&self) -> io::Result<()> {
        validate!(self.version == SOCKS_VERSION, Kind::InvalidVersion)?;
        for method in &self.methods {
            validate!(Method::from_u8(*method).is_some(), Kind::UnknownMethod)?;
        }
        Ok(())
    }
}

impl Selection {
    pub fn new(method: Method) -> Self {
        Self {
            version: SOCKS_VERSION,
            method: method.as_u8(),
        }
    }

    pub fn method(&self) -> Option<Method> {
        Method::from_u8(self.method)
    }

    pub async fn read<S: AsyncRead + Unpin>(socket: &mut S) -> io::Result<Self> {
        let version = socket.read_u8().await?;
        let method = socket.read_u8().await?;
        Ok(Self { version, method })
    }

    pub async fn write<S: AsyncWrite + Unpin>(&self, socket: &mut S) -> io::Result<()> {
        socket.write_u8(self.version).await?;
        socket.write_u8(self.method).await
    }

    pub fn is_valid(&self) -> io::Result<()> {
        validate!(self.version == SOCKS_VERSION, Kind::InvalidVersion)?;
        validate!(Method::from_u8(self.method).is_some(), Kind::UnknownMethod)
    }
}

impl UsernameAndPassword {
    pub fn new(username: String, password: String) -> Self {
        Self {
            version: SOCKS_VERSION,
            username,
            password,
        }
    }

    pub async fn read<S: AsyncRead + Unpin>(socket: &mut S) -> io::Result<Self> {
        let version = socket.read_u8().await?;
        let mut username = String::new();
        socket.read_to_fixed_string(&mut username).await?;
        let mut password = String::new();
        socket.read_to_fixed_string(&mut password).await?;
        Ok(Self {
            version,
            username,
            password,
        })
    }

    pub async fn write<S: AsyncWrite + Unpin>(&self, socket: &mut S) -> io::Result<()> {
        socket.write_u8(self.version).await?;
        socket.write_fixed(self.username.as_bytes()).await?;
        socket.write_fixed(self.password.as_bytes()).await
    }

    pub fn is_valid(&self) -> io::Result<()> {
        validate!(self.version == AUTH_VERSION, Kind::InvalidVersion)
    }
}

impl Status {
    pub fn new(status: u8) -> Self {
        Self {
            version: AUTH_VERSION,
            status,
        }
    }

    pub async fn read<S: AsyncRead + Unpin>(socket: &mut S) -> io::Result<Self> {
        let version = socket.read_u8().await?;
        let status = socket.read_u8().await?;
        Ok(Self { version, status })
    }

    pub async fn write<S: AsyncWrite + Unpin>(&self, socket: &mut S) -> io::Result<()> {
        socket.write_u8(self.version).await?;
        socket.write_u8(self.status).await
    }

    pub fn is_valid(&self) -> io::Result<()> {
        validate!(self.version == AUTH_VERSION, Kind::InvalidVersion)
    }

    pub fn is_succeed(&self) -> bool {
        self.status == AUTH_SUCCEED
    }
}

impl Request {
    pub fn new(target: TargetAddr) -> Self {
        Self {
            version: SOCKS_VERSION,
            command: Command::Connect.as_u8(),
            target: Some(target),
        }
    }

    pub fn is_valid(&self) -> io::Result<()> {
        validate!(self.version == SOCKS_VERSION, Kind::InvalidVersion)
    }

    pub fn is_connect(&self) -> bool {
        self.command == Command::Connect.as_u8()
    }

    pub async fn read<S: AsyncRead + Unpin>(socket: &mut S) -> io::Result<Self> {
        let version = socket.read_u8().await?;
        let command = socket.read_u8().await?;
        let _reserved = socket.read_u8().await?;
        let atyp = socket.read_u8().await?;
        let target = match atyp {
            DST_IPV4 => {
                let mut ipv4 = [0u8; 4];
                socket.read_exact(&mut ipv4).await?;
                let port = socket.read_u16().await?;
                Some(TargetAddr::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(ipv4[0], ipv4[1], ipv4[2], ipv4[3]),
                    port,
                ))))
            }
            DST_IPV6 => {
                let mut ipv6 = [0u8; 16];
                socket.read_exact(&mut ipv6).await?;
                let port = socket.read_u16().await?;
                Some(TargetAddr::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ipv6),
                    port,
                    0,
                    0,
                ))))
            }
            DST_DOMAIN => {
                let mut domain = String::new();
                socket.read_to_fixed_string(&mut domain).await?;
                let port = socket.read_u16().await?;
                Some(TargetAddr::Domain(domain, port))
            }
            _ => None,
        };
        Ok(Self {
            version,
            command,
            target,
        })
    }

    pub async fn write<S: AsyncWrite + Unpin>(&self, socket: &mut S) -> io::Result<()> {
        socket.write_u8(self.version).await?;
        socket.write_u8(self.command).await?;
        socket.write_u8(0x00).await?;
        if let Some(addr) = &self.target {
            match addr {
                TargetAddr::SocketAddr(SocketAddr::V4(v4)) => {
                    socket.write_u8(DstAtyp::IPv4.as_u8()).await?;
                    socket.write_all(&v4.ip().octets()).await?;
                    socket.write_u16(v4.port()).await?;
                }
                TargetAddr::SocketAddr(SocketAddr::V6(v6)) => {
                    socket.write_u8(DstAtyp::IPv6.as_u8()).await?;
                    socket.write_all(&v6.ip().octets()).await?;
                    socket.write_u16(v6.port()).await?;
                }
                TargetAddr::Domain(domain, port) => {
                    socket.write_u8(DstAtyp::DomainName.as_u8()).await?;
                    socket.write_fixed(domain.as_bytes()).await?;
                    socket.write_u16(*port).await?;
                }
            }
        }
        Ok(())
    }
}

impl Reply {
    pub fn new(rep: Rep) -> Self {
        Self {
            version: SOCKS_VERSION,
            rep: rep.as_u8(),
            atyp: DST_IPV4,
            target: Some(TargetAddr::default()),
        }
    }

    pub fn rep(&self) -> Option<Rep> {
        Rep::from_u8(self.rep)
    }

    pub async fn read<S: AsyncRead + Unpin>(socket: &mut S) -> io::Result<Self> {
        let version = socket.read_u8().await?;
        let rep = socket.read_u8().await?;
        let _reserved = socket.read_u8().await?;
        let atyp = socket.read_u8().await?;
        let target = match atyp {
            DST_IPV4 => {
                let mut ipv4 = [0u8; 4];
                socket.read_exact(&mut ipv4).await?;
                let port = socket.read_u16().await?;
                Some(TargetAddr::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(ipv4[0], ipv4[1], ipv4[2], ipv4[3]),
                    port,
                ))))
            }
            DST_IPV6 => {
                let mut ipv6 = [0u8; 16];
                socket.read_exact(&mut ipv6).await?;
                let port = socket.read_u16().await?;
                Some(TargetAddr::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ipv6),
                    port,
                    0,
                    0,
                ))))
            }
            DST_DOMAIN => {
                let mut domain = String::new();
                socket.read_to_fixed_string(&mut domain).await?;
                let port = socket.read_u16().await?;
                Some(TargetAddr::Domain(domain, port))
            }
            _ => None,
        };
        Ok(Self {
            version,
            rep,
            atyp,
            target,
        })
    }

    pub async fn write<S: AsyncWrite + Unpin>(&self, socket: &mut S) -> io::Result<()> {
        socket.write_u8(self.version).await?;
        socket.write_u8(self.rep).await?;
        socket.write_u8(0x00).await?;
        if let Some(addr) = &self.target {
            match addr {
                TargetAddr::SocketAddr(SocketAddr::V4(v4)) => {
                    socket.write_u8(DstAtyp::IPv4.as_u8()).await?;
                    socket.write_all(&v4.ip().octets()).await?;
                    socket.write_u16(v4.port()).await?;
                }
                TargetAddr::SocketAddr(SocketAddr::V6(v6)) => {
                    socket.write_u8(DstAtyp::IPv6.as_u8()).await?;
                    socket.write_all(&v6.ip().octets()).await?;
                    socket.write_u16(v6.port()).await?;
                }
                TargetAddr::Domain(domain, port) => {
                    socket.write_u8(DstAtyp::DomainName.as_u8()).await?;
                    socket.write_fixed(domain.as_bytes()).await?;
                    socket.write_u16(*port).await?;
                }
            }
        }
        Ok(())
    }

    pub fn is_valid(&self) -> io::Result<()> {
        validate!(self.version == SOCKS_VERSION, Kind::InvalidVersion)
    }
}

#[macro_export]
macro_rules! check_valid {
    ($expr:expr) => {
        match $expr {
            Ok(t) => match t.is_valid() {
                Ok(()) => t,
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        }
    };
}
