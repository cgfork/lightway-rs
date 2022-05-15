use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{dst::DstAddr, error::Error, fixed_read::AsyncReadExt2};

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

/// Types can be deserialized from the socket.
///
/// Socks provides `FromSocket` implementations for many Rust primitive
/// and the Socksv5 types.
#[async_trait]
pub trait FromSocket<S>: Sized {
    /// The error type that can be returned if some error occurs during
    /// deserialization.
    type Error;

    /// Deserializes this value from the given socket.
    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error>;
}

/// Types can serialized into the socket.
///
/// Socks provides `ToSocket` implementations for many Rust primitive
/// and the Socksv5 types.
#[async_trait]
pub trait ToSocket<S>: Sized {
    /// The error type that can be returned if some error occurs during
    /// serialization.
    type Error;

    /// Serializes this value into the given socket.
    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error>;
}

#[async_trait]
impl<S, T> FromSocket<S> for Vec<T>
where
    S: AsyncRead + Unpin + Send,
    T: FromSocket<S, Error = Error> + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let size = socket.read_u8().await? as usize;
        let mut values = Vec::with_capacity(size);
        for _ in 0..size {
            let v = T::from_socket(socket).await?;
            values.push(v);
        }
        Ok(values)
    }
}

#[async_trait]
impl<S, T> ToSocket<S> for Vec<T>
where
    S: AsyncWrite + Unpin + Send,
    T: ToSocket<S, Error = Error> + Sync,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        let size = self.len() as u8;
        socket.write_u8(size).await?;
        for v in self {
            ToSocket::to_socket(v, socket).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl<S> FromSocket<S> for String
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let mut s = String::new();
        socket.read_to_fixed_string(&mut s).await?;
        Ok(s)
    }
}

#[async_trait]
impl<S> ToSocket<S> for String
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        let bytes = self.as_bytes();
        socket.write_u8(bytes.len() as u8).await?;
        socket.write_all(bytes).await?;
        Ok(())
    }
}

#[async_trait]
impl<S> FromSocket<S> for DstAddr
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        match socket.read_u8().await? {
            DST_IPV4 => {
                let mut buf = [0u8; 4];
                socket.read_exact(&mut buf).await?;
                let port = socket.read_u16().await?;
                Ok(DstAddr::Socket(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]),
                    port,
                ))))
            }
            DST_IPV6 => {
                let mut buf = [0u8; 16];
                socket.read_exact(&mut buf).await?;
                let port = socket.read_u16().await?;
                Ok(DstAddr::Socket(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(buf),
                    port,
                    0,
                    0,
                ))))
            }
            DST_DOMAIN => {
                let mut string = String::new();
                socket.read_to_fixed_string(&mut string).await?;
                let port = socket.read_u16().await?;
                Ok(DstAddr::Domain(string, port))
            }
            _ => Err(Error::AddressTypeNotSupported),
        }
    }
}

#[async_trait]
impl<S> ToSocket<S> for DstAddr
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        match self {
            DstAddr::Domain(string, port) => {
                socket.write_u8(DST_DOMAIN).await?;
                let domain = string.as_bytes();
                socket.write_u8(domain.len() as u8).await?;
                socket.write_all(domain).await?;
                socket.write_u16(*port).await?;
            }
            DstAddr::Socket(SocketAddr::V4(v4)) => {
                socket.write_u8(DST_IPV4).await?;
                let ip = v4.ip().octets();
                socket.write_all(&ip).await?;
                socket.write_u16(v4.port()).await?;
            }
            DstAddr::Socket(SocketAddr::V6(v6)) => {
                socket.write_u8(DST_IPV6).await?;
                let ip = v6.ip().octets();
                socket.write_all(&ip).await?;
                socket.write_u16(v6.port()).await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SocksVersion;

#[async_trait]
impl<S> FromSocket<S> for SocksVersion
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let u = socket.read_u8().await?;
        if u == 0x05 {
            Ok(SocksVersion)
        } else {
            Err(Error::InvalidReplyVersion)
        }
    }
}

#[async_trait]
impl<S> ToSocket<S> for SocksVersion
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        socket.write_u8(0x05).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PasswordVersion;

#[async_trait]
impl<S> FromSocket<S> for PasswordVersion
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let u = socket.read_u8().await?;
        if u == 0x01 {
            Ok(PasswordVersion)
        } else {
            Err(Error::InvalidReplyVersion)
        }
    }
}

#[async_trait]
impl<S> ToSocket<S> for PasswordVersion
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        socket.write_u8(0x01).await?;
        Ok(())
    }
}

/// Supported socks authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Method {
    NoAuthenticationRequired,
    Gssapi,
    UsernameAndPassword,
    IanaAssigned(u8),
    NoAcceptableMethods,
}

impl Method {
    pub fn id(&self) -> u8 {
        match self {
            Method::NoAuthenticationRequired => NO_AUTHENTICATION_REQUIRED,
            Method::Gssapi => GSSAPI,
            Method::UsernameAndPassword => USERNAME_AND_PASSWORD,
            Method::IanaAssigned(v) => *v,
            Method::NoAcceptableMethods => NO_ACCEPTABLE_METHODS,
        }
    }
}

impl TryFrom<u8> for Method {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            NO_AUTHENTICATION_REQUIRED => Ok(Method::NoAuthenticationRequired),
            GSSAPI => Ok(Method::Gssapi),
            USERNAME_AND_PASSWORD => Ok(Method::UsernameAndPassword),
            NO_ACCEPTABLE_METHODS => Ok(Method::NoAcceptableMethods),
            n if (IANA_ASSIGNED_MIN..=IANA_ASSIGNED_MAX).contains(&n) => {
                Ok(Method::IanaAssigned(n))
            }
            _ => Err(Error::UnknownMethod),
        }
    }
}

#[async_trait]
impl<S> FromSocket<S> for Method
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let u = socket.read_u8().await?;
        Method::try_from(u)
    }
}

#[async_trait]
impl<S> ToSocket<S> for Method
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        socket.write_u8(self.id()).await?;
        Ok(())
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Command {
    Connect = CONNECT,
    Bind = BIND,
    Associate = UDP_ASSOCIATE,
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            CONNECT | BIND | UDP_ASSOCIATE => Ok(unsafe { std::mem::transmute(value) }),
            _ => Err(Error::CommandNotSupported),
        }
    }
}

#[async_trait]
impl<S> FromSocket<S> for Command
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let u = socket.read_u8().await?;
        Command::try_from(u)
    }
}

#[async_trait]
impl<S> ToSocket<S> for Command
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        socket.write_u8(*self as u8).await?;
        Ok(())
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

impl TryFrom<u8> for Rep {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        if v <= 8 {
            Ok(unsafe { std::mem::transmute(v) })
        } else {
            Err(Error::UnknownError)
        }
    }
}

impl Rep {
    pub fn from_err(e: &Error) -> Self {
        match e {
            Error::Succeed => Rep::Succeeded,
            Error::Io(ioe) => match ioe.kind() {
                // // io_remote_more feature
                // io::ErrorKind::NetworkUnreachable => Rep::NetworkUnreachable,
                // io::ErrorKind::HostUnreachable => Rep::HostUnreachable,
                io::ErrorKind::ConnectionRefused => Rep::ConnectionRefused,
                _ => Rep::AddressTypeNotSupported,
            },
            Error::InvalidDstAddress(_) => Rep::AddressTypeNotSupported,
            Error::ConnectionRefused => Rep::ConnectionRefused,
            Error::NetworkUnreachable => Rep::NetworkUnreachable,
            Error::HostUnreachable => Rep::HostUnreachable,
            Error::CommandNotSupported => Rep::CommandNotSupported,
            Error::TtlExpired => Rep::TtlExpired,
            _ => Rep::GeneralSocksServerFailure,
        }
    }
}

impl From<Rep> for Error {
    fn from(rep: Rep) -> Self {
        match rep {
            Rep::Succeeded => Error::Succeed,
            Rep::GeneralSocksServerFailure => Error::GeneralSocksServerFailure,
            Rep::ConnectionNotAllowedByRuleset => Error::ConnectionNotAllowedByRuleset,
            Rep::NetworkUnreachable => Error::NetworkUnreachable,
            Rep::HostUnreachable => Error::HostUnreachable,
            Rep::ConnectionRefused => Error::ConnectionRefused,
            Rep::TtlExpired => Error::TtlExpired,
            Rep::CommandNotSupported => Error::CommandNotSupported,
            Rep::AddressTypeNotSupported => Error::AddressTypeNotSupported,
        }
    }
}

impl fmt::Display for Rep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Rep::Succeeded => f.write_str("Succeeded"),
            Rep::GeneralSocksServerFailure => f.write_str("General Socks Server Failure"),
            Rep::ConnectionNotAllowedByRuleset => f.write_str("Connection Not Allowed By Ruleset"),
            Rep::NetworkUnreachable => f.write_str("Network Unreachable"),
            Rep::HostUnreachable => f.write_str("Host Unreachable"),
            Rep::ConnectionRefused => f.write_str("Connection Refused"),
            Rep::TtlExpired => f.write_str("Ttl Expired"),
            Rep::CommandNotSupported => f.write_str("Command Not Supported"),
            Rep::AddressTypeNotSupported => f.write_str("Address Type Not Supported"),
        }
    }
}

#[async_trait]
impl<S> FromSocket<S> for Rep
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let u = socket.read_u8().await?;
        Rep::try_from(u)
    }
}

#[async_trait]
impl<S> ToSocket<S> for Rep
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        socket.write_u8(*self as u8).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Status {
    Ok,
    Failure(u8),
}

impl TryFrom<u8> for Status {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Status::Ok),
            n => Ok(Status::Failure(n)),
        }
    }
}

impl Status {
    pub fn code(&self) -> u8 {
        match self {
            Status::Ok => 0x01,
            Status::Failure(c) => *c,
        }
    }
}

#[async_trait]
impl<S> FromSocket<S> for Status
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let u = socket.read_u8().await?;
        Status::try_from(u)
    }
}

#[async_trait]
impl<S> ToSocket<S> for Status
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        socket.write_u8(self.code()).await?;
        Ok(())
    }
}

pub struct Rsv;
#[async_trait]
impl<S> FromSocket<S> for Rsv
where
    S: AsyncRead + Unpin + Send,
{
    type Error = Error;

    async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
        let u = socket.read_u8().await?;
        if u != 0x00 {
            return Err(Error::InvalidReservedByte);
        }
        Ok(Rsv)
    }
}

#[async_trait]
impl<S> ToSocket<S> for Rsv
where
    S: AsyncWrite + Unpin + Send,
{
    type Error = Error;

    async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
        socket.write_u8(0x00).await?;
        Ok(())
    }
}

macro_rules! impls {
    (#[doc = $doc:expr] $name:ident, $($n:tt $t:ty)+) => {
        #[doc = $doc]
        pub struct $name($(pub $t,)+);

        #[async_trait]
        impl<S> FromSocket<S> for $name
        where
            S: AsyncRead + Unpin + Send,
        {
            type Error = Error;

            async fn from_socket(socket: &mut S) -> Result<Self, Self::Error> {
                Ok(
                    $name(
                        $(<$t>::from_socket(socket).await?,)+
                    )
                )
            }
        }

        #[async_trait]
        impl<S> ToSocket<S> for $name
        where
            S: AsyncWrite + Unpin +Send,
        {
            type Error = Error;

            async fn to_socket(&self, socket: &mut S) -> Result<(), Self::Error> {
                $(
                    self.$n.to_socket(socket).await?;
                )+
                Ok(())
            }
        }
    };
}

impls! {
    #[doc = "The client connects to the server, and sends a version
    identifier/method selection message:

    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+

    The VER field is set to X'05' for this version of the protocol.
    The NMETHODS field contains the number of method identifier
    octets that appear in the METHODS field."] 
    MethodRequest, 0 SocksVersion 1 Vec<Method>
}

impls! {
    #[doc = "The server selects from one of the METHODS given in the
    [`MethodRequest`], and sends a METHOD selection message:
   
    +----+--------+
    |VER | METHOD |
    +----+--------+
    | 1  |   1    |
    +----+--------+
   
    If the selected METHOD is X'FF', none of the methods listed by the
    client are acceptable, and the client MUST close the connection.
   
    The values currently defined for METHOD are:
   
        o  X'00' NO AUTHENTICATION REQUIRED
        o  X'01' GSSAPI
        o  X'02' USERNAME/PASSWORD
        o  X'03' to X'7F' IANA ASSIGNED
        o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        o  X'FF' NO ACCEPTABLE METHODS"]
    MethodReply, 0 SocksVersion 1 Method
}

impls! {
    #[doc = "The client sends the username and password if the server has selected
    the USERNAME/PASSWORD method.
   
    +----+----------+----------+
    |VER | USERNAME | PASSWORD |
    +----+----------+----------+
    | 1  |  1..255  |  1..255  |
    +----+----------+----------+
   
    The VER field is set to X'01' for this version of the AUTHENTICATION.
    USERNAME or PASSWORD is a fixed string. The first octet of the field
    contains the number of octects of string that follow."]
    PasswordRequest, 0 PasswordVersion 1 String 2 String
}

impls! {
    #[doc = "The server authenticates the USERNAME and PASSWORD, and sends a
    status message:
    
    +----+--------+
    |VER | STATUS |
    +----+--------+
    | 1  |    1   |
    +----+--------+
    
    The VER field is set to X'01' for this version of the AUTHENTICATION."]
    PasswordReply, 0 PasswordVersion 1 Status
}

impls! {
    #[doc = "Once the method-dependent subnegotiation has completed, the client
    sends the request details.
    
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    
    Where:
    
             o  VER    protocol version: X'05'
             o  CMD
                o  CONNECT X'01'
                o  BIND X'02'
                o  UDP ASSOCIATE X'03'
             o  RSV    RESERVED
             o  ATYP   address type of following address
                o  IP V4 address: X'01'
                o  DOMAINNAME: X'03'
                o  IP V6 address: X'04'
             o  DST.ADDR       desired destination address
             o  DST.PORT desired destination port in network octet
                order"]
    DstRequest, 0 SocksVersion 1 Command 2 Rsv 3 DstAddr
}

impls! {
    #[doc = " The SOCKS request information is sent by the client as soon as it has
    established a connection to the SOCKS server, and completed the
    authentication negotiations.  The server evaluates the request, and
    returns a reply formed as follows:
   
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
   
    Where:
   
             o  VER    protocol version: X'05'
             o  REP    Reply field:
                o  X'00' succeeded
                o  X'01' general SOCKS server failure
                o  X'02' connection not allowed by ruleset
                o  X'03' Network unreachable
                o  X'04' Host unreachable
                o  X'05' Connection refused
                o  X'06' TTL expired
                o  X'07' Command not supported
                o  X'08' Address type not supported
                o  X'09' to X'FF' unassigned
             o  RSV    RESERVED
             o  ATYP   address type of following address
                o  IP V4 address: X'01'
                o  DOMAINNAME: X'03'
                o  IP V6 address: X'04'
             o  BND.ADDR       server bound address
             o  BND.PORT       server bound port in network octet order
   
    Fields marked RESERVED (RSV) must be set to X'00'."]
    DstReply, 0 SocksVersion 1 Rep 2 Rsv 3 DstAddr
}

#[cfg(test)]
mod tests {
    use super::{FromSocket, Method, MethodReply, MethodRequest, SocksVersion, ToSocket};

    #[tokio::test]
    async fn test_method_request() {
        let mut buf = Vec::<u8>::new();
        MethodRequest::to_socket(
            &MethodRequest(SocksVersion, vec![Method::NoAuthenticationRequired]),
            &mut buf,
        )
        .await
        .unwrap();
        assert_eq!(buf.len(), 3);
        let mut bytes = buf.as_slice();
        let req = MethodRequest::from_socket(&mut bytes).await.unwrap();
        assert_eq!(req.1.len(), 1);
        assert_eq!(req.1[0], Method::NoAuthenticationRequired);
    }

    #[tokio::test]
    async fn test_method_request2() {
        let mut buf = Vec::<u8>::new();
        MethodRequest::to_socket(
            &MethodRequest(
                SocksVersion,
                vec![
                    Method::NoAuthenticationRequired,
                    Method::UsernameAndPassword,
                ],
            ),
            &mut buf,
        )
        .await
        .unwrap();
        assert_eq!(buf.len(), 4);
        let mut bytes = buf.as_slice();
        let req = MethodRequest::from_socket(&mut bytes).await.unwrap();
        assert_eq!(req.1.len(), 2);
        assert_eq!(req.1[0], Method::NoAuthenticationRequired);
        assert_eq!(req.1[1], Method::UsernameAndPassword);
    }

    #[tokio::test]
    async fn test_method_reply() {
        let mut buf = Vec::<u8>::new();
        MethodReply(SocksVersion, Method::NoAcceptableMethods)
            .to_socket(&mut buf)
            .await
            .unwrap();
        assert_eq!(buf.len(), 2);
    }
}
