use std::{
    fmt,
    net::{IpAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Decision is the result for policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Decision {
    /// Direct returned from an enforcement method inidicates
    /// that a corresponding rule was found and that access
    /// should request directly.
    #[serde(alias = "DIRECT")]
    Direct,
    /// Proxy returned from an enforcement method inidicates
    /// that a corresponding rule was found and that access
    /// should request via the proxy server.
    #[serde(alias = "PROXY")]
    Proxy { remote_dns: bool },
    /// Default returned from an enforcement method inidicates
    /// that a corresponding rule was found and that whether
    /// access should request directly or via the proxy server
    /// should be dederred to the default access level.
    #[serde(alias = "DEFAULT")]
    Default,
    /// Deny returned from an enforcement method inidicates
    /// that a corresponding rule was found and that access
    /// should be denied.
    #[serde(alias = "DENY")]
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
            Decision::Direct => f.write_str("DIRECT"),
            Decision::Proxy { remote_dns } => {
                if *remote_dns {
                    f.write_str("PROXY,force-remote-dns")
                } else {
                    f.write_str("PROXY")
                }
            }
            Decision::Default => f.write_str("DEFAULT"),
            Decision::Deny => f.write_str("DENY"),
        }
    }
}

/// Policy is the trait for destination access rules.
///
/// Gfwlist is typically used to make decisions.
pub trait Policy {
    /// Try to enforce the rules for the destination address.
    ///
    /// Returns the decision for the Switch or Router to decide which proxy to use.
    fn enforce(&self, dst: &str) -> Decision;
}

impl<P: Policy> Policy for Vec<P> {
    fn enforce(&self, dst: &str) -> Decision {
        for p in self {
            let d = p.enforce(dst);
            if !d.is_default() {
                return d;
            }
        }
        Decision::Default
    }
}

impl<P: Policy> Policy for &[P] {
    fn enforce(&self, dst: &str) -> Decision {
        for p in *self {
            let d = p.enforce(dst);
            if !d.is_default() {
                return d;
            }
        }
        Decision::Default
    }
}

impl<P: Policy> Policy for Arc<P> {
    fn enforce(&self, dst: &str) -> Decision {
        self.as_ref().enforce(dst)
    }
}

impl Policy for (Pattern, Decision) {
    fn enforce(&self, dst: &str) -> Decision {
        if self.0.is_match(dst) {
            self.1
        } else {
            Decision::Default
        }
    }
}

#[derive(Debug, Clone)]
pub enum Pattern {
    /// Exact is used to match the domain exactly.
    Exact(String),
    /// Suffix is used to match the suffix of the domain.
    Suffix(String),
    /// Regex is used to match the regex of the domain.
    Regex(Regex),
    /// Keyword is used to match the keyword of the domain.
    Keyword(String),
    /// IpExact is used to match the `SocketAddr` exactly.
    IpExact(IpAddr),
    /// IpExact is used to match the subnet address.
    IpCIDR { ip_addr: IpAddr, mask: usize },
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pattern::Exact(domain) => {
                write!(f, "DOMAIN,{}", domain)
            }
            Pattern::Suffix(suffix) => {
                write!(f, "DOMAIN-SUFFIX,{}", suffix)
            }
            Pattern::Regex(reg) => {
                write!(f, "DOMAIN-REGEX,{}", reg)
            }
            Pattern::Keyword(keyword) => {
                write!(f, "DOMAIN-KEYWORD,{}", keyword)
            }
            Pattern::IpExact(ip_addr) => match ip_addr {
                IpAddr::V4(v4) => write!(f, "IPV4,{}", v4),
                IpAddr::V6(v6) => write!(f, "IPV6,{}", v6),
            },
            Pattern::IpCIDR { ip_addr, mask } => match ip_addr {
                IpAddr::V4(v4) => write!(f, "IP-CIDR,{}/{}", v4, mask),
                IpAddr::V6(v6) => write!(f, "IP-CIDR6,{}/{}", v6, mask),
            },
        }
    }
}

impl Pattern {
    pub fn is_match(&self, dst: &str) -> bool {
        match self {
            Pattern::Exact(domain) => dst.starts_with(domain),
            Pattern::Suffix(suffix) => dst.ends_with(suffix),
            Pattern::Regex(reg) => reg.is_match(dst),
            Pattern::Keyword(keyword) => dst.contains(keyword),
            Pattern::IpExact(ip_addr) => match ip_addr {
                IpAddr::V4(v4) => {
                    if let Ok(addr) = dst.parse::<SocketAddrV4>() {
                        addr.ip() == v4
                    } else {
                        false
                    }
                }
                IpAddr::V6(v6) => {
                    if let Ok(addr) = dst.parse::<SocketAddrV6>() {
                        addr.ip() == v6
                    } else {
                        false
                    }
                }
            },
            Pattern::IpCIDR { ip_addr, mask } => match ip_addr {
                IpAddr::V4(_) => {
                    if let Ok(addr) = dst.parse::<SocketAddrV4>() {
                        is_subnet(IpAddr::V4(*addr.ip()), *ip_addr, *mask)
                    } else {
                        false
                    }
                }
                IpAddr::V6(_) => {
                    if let Ok(addr) = dst.parse::<SocketAddrV6>() {
                        is_subnet(IpAddr::V6(*addr.ip()), *ip_addr, *mask)
                    } else {
                        false
                    }
                }
            },
        }
    }
}

fn is_subnet(ip: IpAddr, subnet: IpAddr, mask: usize) -> bool {
    match subnet {
        IpAddr::V4(v4) => match ip {
            IpAddr::V4(ipv4) => {
                let sub_mask = ipv4_subnet_mask(mask);
                let sub_net = v4.octets();
                let net = ipv4.octets();
                net[0] & sub_mask[0] == sub_net[0] & sub_mask[0]
                    && net[1] & sub_mask[1] == sub_net[1] & sub_mask[1]
                    && net[2] & sub_mask[2] == sub_net[2] & sub_mask[2]
                    && net[3] & sub_mask[3] == sub_net[3] & sub_mask[3]
            }
            IpAddr::V6(_) => false,
        },
        IpAddr::V6(_) => unimplemented!(),
    }
}

fn ipv4_subnet_mask(mask: usize) -> [u8; 4] {
    let n = mask / 8;
    let m = mask % 8;
    let mut sub_mask = match n {
        0 => [0u8, 0, 0, 0],
        1 => [0xff, 0, 0, 0],
        2 => [0xff, 0xff, 0, 0],
        3 => [0xff, 0xff, 0xff, 0],
        _ => return [0xff, 0xff, 0xff, 0xff],
    };
    match m {
        0 => sub_mask[n + 1] = 0,
        1 => sub_mask[n + 1] = 0x80,
        2 => sub_mask[n + 1] = 0xc0,
        3 => sub_mask[n + 1] = 0xe0,
        4 => sub_mask[n + 1] = 0xf0,
        5 => sub_mask[n + 1] = 0xf8,
        6 => sub_mask[n + 1] = 0xfc,
        7 => sub_mask[n + 1] = 0xfe,
        _ => unreachable!(),
    }
    sub_mask
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub pattern: Pattern,
    pub decision: Decision,
}

impl Rule {
    pub fn new(pattern: Pattern, decision: Decision) -> Rule {
        Rule { pattern, decision }
    }
}

impl Policy for Rule {
    fn enforce(&self, dst: &str) -> Decision {
        if self.pattern.is_match(dst) {
            self.decision
        } else {
            Decision::Default
        }
    }
}

impl std::str::FromStr for Rule {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut pat_tag: Option<&str> = None;
        let mut pat: Option<&str> = None;
        let mut decision: Option<&str> = None;
        let mut args: Vec<&str> = Vec::new();
        for split in s.split(',') {
            if pat_tag.is_none() {
                pat_tag = Some(split);
            } else if pat.is_none() {
                pat = Some(split);
            } else if decision.is_none() {
                decision = Some(split);
            } else {
                args.push(split);
            }
        }
        if pat_tag.is_none() || pat.is_none() || decision.is_none() {
            return Err(anyhow::anyhow!("{} is invalid", s));
        }

        let tag = pat_tag.unwrap();
        let pattern = if tag.eq_ignore_ascii_case("DOMAIN") {
            Pattern::Exact(pat.unwrap().to_string())
        } else if tag.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
            Pattern::Suffix(pat.unwrap().to_string())
        } else if tag.eq_ignore_ascii_case("DOMAIN-REGEX") {
            Pattern::Regex(Regex::new(pat.unwrap())?)
        } else if tag.eq_ignore_ascii_case("DOMAIN-KEYWORD") {
            Pattern::Keyword(pat.unwrap().to_string())
        } else if tag.eq_ignore_ascii_case("IPV4") || tag.eq_ignore_ascii_case("IPV6") {
            let addr = pat.unwrap().parse::<IpAddr>()?;
            Pattern::IpExact(addr)
        } else if tag.eq_ignore_ascii_case("IP-CIDR") {
            let slice = pat.unwrap();
            if let Some(n) = slice.find('/') {
                let addr = &slice[..n];
                let mask = &slice[(n + 1)..];
                Pattern::IpCIDR {
                    ip_addr: addr.parse()?,
                    mask: mask.parse()?,
                }
            } else {
                return Err(anyhow::anyhow!("invalid ip-cidr: {}", slice));
            }
        } else {
            return Err(anyhow::anyhow!("unknown pattern tag: {}", tag));
        };

        let dec = decision.unwrap();
        let decision = if dec.eq_ignore_ascii_case("direct") {
            Decision::Direct
        } else if dec.eq_ignore_ascii_case("proxy") {
            let remote_dns = args
                .iter()
                .any(|i| i.eq_ignore_ascii_case("force-remote-dns"));
            Decision::Proxy { remote_dns }
        } else if dec.eq_ignore_ascii_case("default") {
            Decision::Default
        } else if dec.eq_ignore_ascii_case("deny") {
            Decision::Deny
        } else {
            return Err(anyhow::anyhow!("unknown decision: {}", dec));
        };

        Ok(Self { pattern, decision })
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{}", &self.pattern, &self.decision)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub name: Option<String>,
    pub rules: Vec<String>,
    #[serde(skip)]
    parsed: Vec<Rule>,
}

impl RuleSet {
    pub fn new(name: String, rules: Vec<Rule>) -> RuleSet {
        RuleSet {
            name: Some(name),
            rules: rules.iter().map(|r| r.to_string()).collect(),
            parsed: rules,
        }
    }
}

impl Policy for RuleSet {
    fn enforce(&self, dst: &str) -> Decision {
        self.parsed.enforce(dst)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rules {
    pub rules: Vec<RuleSet>,
}

impl Policy for Rules {
    fn enforce(&self, dst: &str) -> Decision {
        self.rules.enforce(dst)
    }
}
