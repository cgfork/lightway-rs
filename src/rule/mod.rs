pub mod error;
pub mod rules;

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use netway::{
    dst::{DstAddr, ToLocalAddr},
    either::Either,
    error::Error,
    DefaultDialer, TryConnect,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use self::rules::Rule;

/// Decision is the result for policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Direct returned from an enforcement method inidicates
    /// that a corresponding rule was found and that access
    /// should request directly.
    Direct,
    /// Proxy returned from an enforcement method inidicates
    /// that a corresponding rule was found and that access
    /// should request via the proxy server.
    Proxy { remote_dns: bool },
    /// Default returned from an enforcement method inidicates
    /// that a corresponding rule was found and that whether
    /// access should request directly or via the proxy server
    /// should be dederred to the default access level.
    Default,
    /// Deny returned from an enforcement method inidicates
    /// that a corresponding rule was found and that access
    /// should be denied.
    Deny,
}
impl Decision {
    pub fn is_default(&self) -> bool {
        matches!(self, Decision::Default)
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Direct => f.write_str("direct"),
            Decision::Proxy { .. } => f.write_str("proxy"),
            Decision::Default => f.write_str("default"),
            Decision::Deny => f.write_str("deny"),
        }
    }
}

pub struct Args(Vec<String>);

/// Policy is the trait for destination access rules.
///
/// Gfwlist is typically used to make decisions.
pub trait Policy {
    /// Try to enforce the rules for the destination address.
    ///
    /// Returns the decision for the Switch or Router to decide which proxy to use.
    fn enforce(&self, dst: &DstAddr) -> (Decision, Option<&Args>);
}

impl<P: Policy> Policy for Vec<P> {
    fn enforce(&self, dst: &DstAddr) -> (Decision, Option<&Args>) {
        for p in self {
            let (d, args) = p.enforce(dst);
            if !d.is_default() {
                return (d, args);
            }
        }
        (Decision::Default, None)
    }
}

impl<P: Policy> Policy for &[P] {
    fn enforce(&self, dst: &DstAddr) -> (Decision, Option<&Args>) {
        for p in *self {
            let (d, args) = p.enforce(dst);
            if !d.is_default() {
                return (d, args);
            }
        }
        (Decision::Default, None)
    }
}

impl<P: Policy> Policy for Arc<P> {
    fn enforce(&self, dst: &DstAddr) -> (Decision, Option<&Args>) {
        self.as_ref().enforce(dst)
    }
}

impl Policy for (Rule, Decision, Option<Args>) {
    fn enforce(&self, dst: &DstAddr) -> (Decision, Option<&Args>) {
        if self.0.is_match(dst) {
            match &self.2 {
                Some(args) => (self.1, Some(args)),
                None => (self.1, None),
            }
        } else {
            (Decision::Default, None)
        }
    }
}

pub struct SimplePolicy {
    always: Option<Decision>,
    rules: Vec<(Rule, Decision, Option<Args>)>,
}

impl SimplePolicy {
    pub fn new(always: Option<Decision>, rules: Vec<(Rule, Decision, Option<Args>)>) -> Self {
        Self { always, rules }
    }
}

impl Policy for SimplePolicy {
    fn enforce(&self, dst: &DstAddr) -> (Decision, Option<&Args>) {
        if let Some(d) = self.always {
            return (d, None);
        }

        self.rules.enforce(dst)
    }
}

pub struct Dialer<D, P> {
    dialer: D,
    policy: P,
    proxy_on_default: bool,
}

impl<D, P> Dialer<D, P> {
    pub fn new(dialer: D, policy: P, proxy_on_default: bool) -> Self {
        Self {
            dialer,
            policy,
            proxy_on_default,
        }
    }
}
#[async_trait]
impl<D, O, P> TryConnect for Dialer<D, P>
where
    D: TryConnect<Output = O, Error = Error> + Send + Sync,
    O: ToLocalAddr<Error = Error> + AsyncRead + AsyncWrite + Unpin + Send,
    P: Policy + Send + Sync,
{
    type Output = Either<TcpStream, O>;

    type Error = Error;

    async fn try_connect(&self, dst: DstAddr) -> Result<Self::Output, Self::Error> {
        let (dec, _) = self.policy.enforce(&dst);
        match dec {
            Decision::Direct => {
                let stream = DefaultDialer.try_connect(dst).await?;
                Ok(Either::Left(stream))
            }
            Decision::Proxy { .. } => {
                let stream = self.dialer.try_connect(dst).await?;
                Ok(Either::Right(stream))
            }
            Decision::Default => {
                if self.proxy_on_default {
                    let stream = DefaultDialer.try_connect(dst).await?;
                    Ok(Either::Left(stream))
                } else {
                    let stream = self.dialer.try_connect(dst).await?;
                    Ok(Either::Right(stream))
                }
            }
            Decision::Deny => Err(Error::ProxyDenied),
        }
    }
}
