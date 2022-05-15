/// Error for easysocks5.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// A successful error.
    #[error("this is succeed, MUST be not returned")]
    Succeed,
    /// Failure caused by an IO error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Failure when parsing a `String`.
    #[error("{0}")]
    ParseError(#[from] std::string::ParseError),
    /// Failure due to invalid target address. It contains the detailed error
    /// message.
    #[error("Destination address is invalid: {0}")]
    InvalidDstAddress(&'static str),
    /// Proxy server unreachable.
    #[error("Proxy server unreachable")]
    ProxyServerUnreachable,
    /// Proxy server returns an invalid version number.
    #[error("Invalid reply version")]
    InvalidReplyVersion,
    /// No acceptable methods
    #[error("No acceptable methods")]
    NoAcceptableMethods,
    /// Unknown method
    #[error("Unknown method")]
    UnknownMethod,
    /// General SOCKS server failure
    #[error("General SOCKS server failure")]
    GeneralSocksServerFailure,
    /// Connection not allowed by ruleset
    #[error("Connection not allowed by ruleset")]
    ConnectionNotAllowedByRuleset,
    /// Network unreachable
    #[error("Network unreachable")]
    NetworkUnreachable,
    /// Host unreachable
    #[error("Host unreachable")]
    HostUnreachable,
    /// Connection refused
    #[error("Connection refused")]
    ConnectionRefused,
    /// TTL expired
    #[error("TTL expired")]
    TtlExpired,
    /// Command not supported
    #[error("Command not supported")]
    CommandNotSupported,
    /// Address type not supported
    #[error("Address type not supported")]
    AddressTypeNotSupported,
    /// Unknown error
    #[error("Unknown error")]
    UnknownError,
    /// Invalid reserved byte
    #[error("Invalid reserved byte")]
    InvalidReservedByte,
    /// Unknown address type
    #[error("Unknown address type")]
    UnknownAddressType,
    /// Invalid authentication values. It contains the detailed error message.
    #[error("Invalid auth values: {0}")]
    InvalidAuthValues(&'static str),
    /// Password auth failure
    #[error("Password auth failure, code: {0}")]
    PasswordAuthFailure(u8),
    /// Auth failed
    #[error("Authorization required")]
    AuthorizationRequired,
    /// Proxy denied
    #[error("Proxy denied")]
    ProxyDenied,
}
