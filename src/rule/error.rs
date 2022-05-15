use std::{net::AddrParseError, num::ParseIntError};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("{0}")]
    InvalidRule(&'static str),

    #[error("invalid decision")]
    InvalidDecision,

    #[error("{0}")]
    InvalidRegex(#[from] regex::Error),

    #[error("{0}")]
    InvalidAddr(#[from] AddrParseError),

    #[error("invalid subnet")]
    InvalidSubnet,

    #[error("{0}")]
    ParseIntError(#[from] ParseIntError),

    #[error("unknown rule")]
    UnknownRule,
}
