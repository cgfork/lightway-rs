use std::fmt;
use std::net::IpAddr;

use netway::dst::DstAddr;
use regex::Regex;

use super::error::ParseError;
use super::{Args, Decision};

#[derive(Debug, Clone)]
pub enum Rule {
    /// DomainExact is used to match the domain exactly.
    DomainExact(String),
    /// DomainSuffix is used to match the suffix of the domain.
    DomainSuffix(String),
    /// DomainRegex is used to match the regex of the domain.
    DomainRegex(Regex),
    /// DomainKeyward is used to match the keyword of the domain.
    DomainKeyword(String),
    /// IpExact is used to match the `SocketAddr` exactly.
    IpExact(IpAddr),
    /// IpExact is used to match the subnet address.
    IpCIDR { ip_addr: IpAddr, mask: usize },
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::DomainExact(domain) => {
                write!(f, "DOMAIN,{}", domain)
            }
            Rule::DomainSuffix(suffix) => {
                write!(f, "DOMAIN-SUFFIX,{}", suffix)
            }
            Rule::DomainRegex(reg) => {
                write!(f, "DOMAIN-REGEX,{}", reg)
            }
            Rule::DomainKeyword(keyword) => {
                write!(f, "DOMAIN-KEYWORD,{}", keyword)
            }
            Rule::IpExact(ip_addr) => match ip_addr {
                IpAddr::V4(v4) => write!(f, "IPV4,{}", v4),
                IpAddr::V6(v6) => write!(f, "IPV6,{}", v6),
            },
            Rule::IpCIDR { ip_addr, mask } => match ip_addr {
                IpAddr::V4(v4) => write!(f, "IP-CIDR,{}/{}", v4, mask),
                IpAddr::V6(v6) => write!(f, "IP-CIDR6,{}/{}", v6, mask),
            },
        }
    }
}

impl Rule {
    pub fn is_match(&self, dst: &DstAddr) -> bool {
        match self {
            Rule::DomainExact(domain) => match dst {
                DstAddr::Domain(ref d, _) if d == domain => true,
                _ => false,
            },
            Rule::DomainSuffix(suffix) => match dst {
                DstAddr::Domain(ref d, _) if d.ends_with(suffix) => true,
                _ => false,
            },
            Rule::DomainRegex(reg) => match dst {
                DstAddr::Domain(ref d, _) if reg.is_match(d) => true,
                _ => false,
            },
            Rule::DomainKeyword(keyword) => match dst {
                DstAddr::Domain(ref d, _) if d.contains(keyword) => true,
                _ => false,
            },
            Rule::IpExact(ip_addr) => match dst {
                DstAddr::Socket(addr) if addr.ip() == *ip_addr => true,
                _ => false,
            },
            Rule::IpCIDR { ip_addr, mask } => match dst {
                DstAddr::Socket(addr) if is_subnet(addr.ip(), *ip_addr, *mask) => true,
                _ => false,
            },
        }
    }
}

pub fn parse(raw: &str) -> Result<(Rule, Decision, Option<Args>), ParseError> {
    let splits = raw.split(',').collect::<Vec<_>>();
    if splits.len() < 3 {
        return Err(ParseError::InvalidRule("splits is less 3"));
    }

    let rule = match splits[0].to_uppercase().as_str() {
        "DOMAIN" => Rule::DomainExact(splits[1].to_string()),
        "DOMAIN-SUFFIX" => Rule::DomainSuffix(splits[1].to_string()),
        "DOMAIN-REGEX" => Rule::DomainRegex(regex::Regex::new(splits[1])?),
        "DOMAIN-KEYWORD" => Rule::DomainKeyword(splits[1].to_string()),
        "IPV4" | "IPV6" => Rule::IpExact(splits[1].parse()?),
        "IP-CIDR" | "IP-CIDR6" => {
            let ip_mask = splits[1].split('/').collect::<Vec<_>>();
            if ip_mask.len() == 2 {
                Rule::IpCIDR {
                    ip_addr: ip_mask[0].parse()?,
                    mask: ip_mask[1].parse()?,
                }
            } else {
                return Err(ParseError::InvalidSubnet)?;
            }
        }

        _ => return Err(ParseError::UnknownRule),
    };
    let decision = match splits[2].to_lowercase().as_str() {
        "direct" => Decision::Direct,
        "deny" => Decision::Deny,
        "proxy" => Decision::Proxy { remote_dns: false },
        "default" => Decision::Default,
        _ => return Err(ParseError::InvalidDecision),
    };

    let options = if splits.len() > 3 {
        Some(Args(splits[3..].iter().map(|s| s.to_string()).collect()))
    } else {
        None
    };
    Ok((rule, decision, options))
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
