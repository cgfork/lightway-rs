use std::error::Error as StdError;
use std::fmt;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// It represents all errors which may occur during handling socks requests.
pub struct Error {
    inner: Box<ErrorImpl>,
}

struct ErrorImpl {
    kind: Kind,
    cause: Option<Box<dyn StdError + Send + Sync>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    InvalidVersion,
    UnknownMethod,
    NoAcceptableMethods,
    GeneralSocksServerFailure,
    ConnectionNotAllowedByRuleset,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    UnknownRep,
    Unauthorized,
}

impl Error {
    pub fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: std::error::Error + 'static,
    {
        match self.inner.cause {
            Some(ref r) => r.downcast_ref::<T>(),
            None => None,
        }
    }

    pub(crate) fn new(kind: Kind) -> Error {
        Error {
            inner: Box::new(ErrorImpl { kind, cause: None }),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn with<C: Into<Box<dyn StdError + Sync + Send>>>(mut self, cause: C) -> Error {
        self.inner.cause = Some(cause.into());
        self
    }

    fn description(&self) -> &str {
        match self.inner.kind {
            Kind::InvalidVersion => "invalid version",
            Kind::UnknownMethod => "unknown method",
            Kind::NoAcceptableMethods => "no acceptable methods",
            Kind::GeneralSocksServerFailure => "general socks server failure",
            Kind::ConnectionNotAllowedByRuleset => "connection not allowed by ruleset",
            Kind::TtlExpired => "ttl expired",
            Kind::CommandNotSupported => "command not supported",
            Kind::AddressTypeNotSupported => "address type not supported",
            Kind::UnknownRep => "unknown rep",
            Kind::Unauthorized => "unauthorized",
        }
    }
}

impl StdError for Error {}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("proxy-socks::Error");
        f.field(&self.inner.kind);
        if let Some(ref cause) = self.inner.cause {
            f.field(cause);
        }
        f.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref cause) = self.inner.cause {
            write!(f, "{}: {}", self.description(), cause)
        } else {
            f.write_str(self.description())
        }
    }
}

impl From<Kind> for Error {
    fn from(kind: Kind) -> Self {
        Self::new(kind)
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    message: String,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for Message {}

#[macro_export]
macro_rules! efmt {
    ($($args:tt)*) => {
        let message = format!($($args)*);
        $crate::error::Message { message }
    };
}

#[macro_export]
macro_rules! socks_err {
    ($kind:expr, $($args:tt)+) => {
        let message = format!($($args)*);
        $crate::error::Error::new($kind).with($crate::error::Message { message })
    };

    ($kind:expr) => {
        $crate::error::Error::new($kind)
    };
}

#[macro_export]
macro_rules! io_err {
    ($kind:expr, $($args:tt)+) => {
        std::io::Error::new(std::io::ErrorKind::Other, $crate::socks_err!($kind, $($args)*))
    };

    ($kind:expr) => {
        std::io::Error::new(std::io::ErrorKind::Other, $crate::socks_err!($kind))
    };
}

#[macro_export]
macro_rules! validate {
    ($expr:expr, $kind:expr) => {
        if $expr {
            Ok(())
        } else {
            Err($crate::io_err!($kind))
        }
    };

    ($expr:expr, $kind:expr, $($args:tt)+) => {
        if $expr {
            Ok(())
        } else {
            Err($crate::io_err!($kind, $($args)*))
        }
    }
}
