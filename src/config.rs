use anyhow::{anyhow, Result};
use netway::auth::Authentication;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::rule::{self, rules::Rule, Args, Decision};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyMode {
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "proxy")]
    Proxy,
    #[serde(rename = "auto")]
    Auto,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub proxies: HashMap<String, String>,
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct General {
    pub loglevel: String,
    pub skip_proxy: Vec<String>,
    pub http_listen: String,
    pub socks5_listen: String,
    pub dns_server: Option<(String, String)>,
    pub proxy_mode: ProxyMode,
    pub exclude_simple_hostnames: bool,
    pub always_real_ip: Vec<String>,
    pub proxy: Option<String>,
}

impl Default for General {
    fn default() -> Self {
        Self {
            loglevel: "info".to_string(),
            skip_proxy: vec![
                "127.0.0.1".to_string(),
                "10.0.0.0/8".to_string(),
                "localhost".to_string(),
                "*.local".to_string(),
            ],
            http_listen: "127.0.0.1:1235".to_string(),
            socks5_listen: "127.0.0.1:1080".to_string(),
            dns_server: Some(("system".to_string(), "114.114.114.114".to_string())),
            exclude_simple_hostnames: true,
            always_real_ip: vec![
                "*.srv.nintendo.net".to_string(),
                "*.stun.playstation.net".to_string(),
                "*.xboxlive.com".to_string(),
            ],
            proxy_mode: ProxyMode::Proxy,
            proxy: None,
        }
    }
}

impl Config {
    pub fn parse(&self) -> Result<ParsedConfig> {
        let mut proxies = HashMap::new();
        for (k, v) in &self.proxies {
            proxies.insert(k.clone(), parse_proxy(v)?);
        }

        let rules = self
            .rules
            .iter()
            .filter_map(|v| match rule::rules::parse(v) {
                Ok(x) => Some(x),
                Err(_) => {
                    log::error!("unknown rule: {}", v);
                    None
                }
            })
            .collect::<Vec<(Rule, Decision, Option<Args>)>>();
        Ok(ParsedConfig {
            general: self.general.clone(),
            proxies,
            rules,
        })
    }
}

pub enum Protocol {
    Socks5,
    HTTP,
    #[cfg(feature = "tls")]
    HTTPs,
}

pub struct ParsedConfig {
    pub(crate) general: General,
    pub(crate) proxies: HashMap<String, (Protocol, String, u16, Authentication)>,
    pub(crate) rules: Vec<(Rule, Decision, Option<Args>)>,
}

pub(crate) fn parse_proxy(proxy: &str) -> Result<(Protocol, String, u16, Authentication)> {
    let splits: Vec<&str> = proxy.split(',').into_iter().map(|s| s.trim()).collect();
    if splits.len() == 3 {
        return Ok((
            parse_protocol(splits[0])?,
            splits[1].to_string(),
            u16::from_str_radix(splits[2], 10)?,
            Authentication::NoAuth,
        ));
    }

    if splits.len() == 5 {
        return Ok((
            parse_protocol(splits[0])?,
            splits[1].to_string(),
            u16::from_str_radix(splits[2], 10)?,
            Authentication::Password {
                username: splits[3].to_string(),
                password: splits[4].to_string(),
            },
        ));
    }

    Err(anyhow!("unknown proxy format"))
}

fn parse_protocol(s: &str) -> Result<Protocol> {
    if s.eq_ignore_ascii_case("http") {
        Ok(Protocol::HTTP)
    } else if s.eq_ignore_ascii_case("https") {
        #[cfg(feature = "tls")]
        {
            Ok(Protocol::HTTPs)
        }

        #[cfg(not(feature = "tls"))]
        Err(anyhow!("https does not support"))
    } else if s.eq_ignore_ascii_case("socks5") {
        Ok(Protocol::Socks5)
    } else {
        Err(anyhow!("unknown protocol"))
    }
}
