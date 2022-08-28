use std::path::PathBuf;

use etcetera::base_strategy::{choose_base_strategy, BaseStrategy};
use log::info;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub http_listen: String,
    pub socks5_listen: String,
    pub proxy_mode: ProxyMode,
    pub proxy: String,
    pub proxies: Vec<Proxy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyMode {
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "proxy")]
    Proxy,
    #[serde(rename = "auto")]
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proxy {
    pub name: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    #[serde(flatten)]
    pub authorization: Option<Authorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Authorization {
    Basic { username: String, password: String },
}

pub fn user_rules() -> Result<toml::Value, toml::de::Error> {
    let config = local_config_dirs()
        .into_iter()
        .chain([config_dir()].into_iter())
        .map(|path| path.join("rules.toml"))
        .filter_map(|file| {
            info!("load {}", file.display());
            std::fs::read(&file)
                .map(|data| toml::from_slice(&data))
                .ok()
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .chain([default_rules()].into_iter())
        .fold(toml::Value::Table(toml::value::Table::default()), |a, b| {
            merge_toml_values(a, b, 3)
        });
    Ok(config)
}

fn default_rules() -> toml::Value {
    toml::from_slice(include_bytes!("../../rules.toml"))
        .expect("Could not parse built-in rules.toml.")
}

fn local_config_dirs() -> Vec<PathBuf> {
    let dirs = find_root(None, &[".lightway".to_string()])
        .into_iter()
        .map(|path| path.join(".lightway"))
        .collect();
    log::debug!("located configuration folders: {:?}", dirs);
    dirs
}

pub fn config_dir() -> PathBuf {
    let strategy = choose_base_strategy().expect("Unable to find the config directory");
    let mut path = strategy.config_dir();
    path.push("lightway");
    path
}

pub fn cache_dir() -> PathBuf {
    let strategy = choose_base_strategy().expect("Unable to find the cache directory");
    let mut path = strategy.cache_dir();
    path.push("lightway");
    path
}

fn find_root(root: Option<&str>, root_markers: &[String]) -> Vec<PathBuf> {
    let current_dir = std::env::current_dir().expect("Unable to determina current directory");
    let mut dirs = Vec::new();
    let root = match root {
        Some(root) => {
            let root = std::path::Path::new(root);
            if root.is_absolute() {
                root.to_path_buf()
            } else {
                current_dir.join(root)
            }
        }
        None => current_dir,
    };

    for ancestor in root.ancestors() {
        if ancestor.join(".git").is_dir() {
            dirs.push(ancestor.to_path_buf());
        } else if root_markers
            .iter()
            .any(|marker| ancestor.join(marker).exists())
        {
            dirs.push(ancestor.to_path_buf());
        }
    }

    dirs
}

fn merge_toml_values(left: toml::Value, right: toml::Value, merge_depth: usize) -> toml::Value {
    use toml::Value;

    fn get_name(v: &Value) -> Option<&str> {
        v.get("name").and_then(Value::as_str)
    }

    match (left, right) {
        (Value::Array(mut left_items), Value::Array(right_items)) => {
            // The top-level arrays should be merged but nested arrays should
            // act as overrides. For the `languages.toml` config, this means
            // that you can specify a sub-set of languages in an overriding
            // `languages.toml` but that nested arrays like Language Server
            // arguments are replaced instead of merged.
            if merge_depth > 0 {
                left_items.reserve(right_items.len());
                for rvalue in right_items {
                    let lvalue = get_name(&rvalue)
                        .and_then(|rname| {
                            left_items.iter().position(|v| get_name(v) == Some(rname))
                        })
                        .map(|lpos| left_items.remove(lpos));
                    let mvalue = match lvalue {
                        Some(lvalue) => merge_toml_values(lvalue, rvalue, merge_depth - 1),
                        None => rvalue,
                    };
                    left_items.push(mvalue);
                }
                Value::Array(left_items)
            } else {
                Value::Array(right_items)
            }
        }
        (Value::Table(mut left_map), Value::Table(right_map)) => {
            if merge_depth > 0 {
                for (rname, rvalue) in right_map {
                    match left_map.remove(&rname) {
                        Some(lvalue) => {
                            let merged_value = merge_toml_values(lvalue, rvalue, merge_depth - 1);
                            left_map.insert(rname, merged_value);
                        }
                        None => {
                            left_map.insert(rname, rvalue);
                        }
                    }
                }
                Value::Table(left_map)
            } else {
                Value::Table(right_map)
            }
        }
        // Catch everything else we didn't handle, and use the right value
        (_, value) => value,
    }
}

#[cfg(test)]
mod tests {

    use super::{Config, Proxy, ProxyMode};

    #[test]
    fn test_config() {
        let config = Config {
            log_level: "debug".to_string(),
            http_listen: "127.0.0.1:1235".to_string(),
            socks5_listen: "127.0.0.1:1080".to_string(),
            proxy_mode: ProxyMode::Proxy,
            proxy: "cn".to_string(),
            proxies: vec![
                Proxy {
                    name: "cn".to_string(),
                    scheme: "https".to_string(),
                    host: "xyz.com".to_string(),
                    port: 443,
                    authorization: Some(super::Authorization::Basic {
                        username: "u".to_string(),
                        password: "p".to_string(),
                    }),
                },
                Proxy {
                    name: "hk".to_string(),
                    scheme: "https".to_string(),
                    host: "xyz.com".to_string(),
                    port: 443,
                    authorization: Some(super::Authorization::Basic {
                        username: "x".to_string(),
                        password: "k".to_string(),
                    }),
                },
            ],
        };

        let data = toml::to_string_pretty(&config).unwrap();
        let config2: Config = toml::from_str(&data).unwrap();
        assert_eq!(config, config2);
    }
}
