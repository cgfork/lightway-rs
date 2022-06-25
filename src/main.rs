#![feature(async_closure)]
#![allow(dead_code)]

mod config;
mod http;
mod rule;
mod socks;

use config::parse_proxy;
use netway::auth::Authentication;
use rule::{rules::Rule, Args, Decision};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};
use tokio::{net::TcpListener, task::JoinHandle};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && &args[1] == "--daemon" {
        let child = Command::new(&args[0])
            .stdin(Stdio::inherit())
            .stdout(Stdio::null()) // ingore env_logger output
            .stderr(Stdio::null()) // ingore env_logger output
            .spawn()
            .expect("failed to run the lightway as daemon process");
        println!("Pid: {}", child.id());
        return Ok(());
    }
    let proxy_conf = match option_env!("PROXY_CONF") {
        Some(c) => shellexpand::full(c).unwrap(),
        None => shellexpand::full("~/.proxy.yaml").unwrap(),
    };
    
    let f = fs::read(Path::new(proxy_conf.as_ref())).unwrap();
    let config = serde_yaml::from_slice::<config::Config>(&f).unwrap();
    env_logger::builder()
        .parse_filters(&config.general.loglevel)
        .init();
    let rules = config
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
    let dialer = match config.general.proxy {
        Some(name) => match config.proxies.get(&name) {
            Some(p) => parse_proxy(p).unwrap(),
            None => unimplemented!(),
        },
        None => {
            // TODO: random choose
            unimplemented!()
        }
    };

    let (http_task, socks_task) = match config.general.proxy_mode {
        config::ProxyMode::Direct => {
            let always_http_proxy = http::AlwaysDirect::new(
                TcpListener::bind(config.general.http_listen).await?,
                Arc::new(Authentication::NoAuth),
            );
            let http_task = tokio::spawn(async move { always_http_proxy.start_accept().await });

            let always_socks_proxy = socks::AlwaysDirect::new(
                TcpListener::bind(config.general.socks5_listen).await?,
                Arc::new(Authentication::NoAuth),
            );
            let socks_task = tokio::spawn(async move { always_socks_proxy.start_accept().await });
            (http_task, socks_task)
        }
        config::ProxyMode::Proxy => {
            let always_http_proxy = http::AlwaysProxy::new(
                dialer.clone(),
                TcpListener::bind(config.general.http_listen).await?,
                Arc::new(Authentication::NoAuth),
            );
            let http_task = tokio::spawn(async move { always_http_proxy.start_accept().await });

            let always_socks_proxy = socks::AlwaysProxy::new(
                dialer.clone(),
                TcpListener::bind(config.general.socks5_listen).await?,
                Arc::new(Authentication::NoAuth),
            );
            let socks_task = tokio::spawn(async move { always_socks_proxy.start_accept().await });
            (http_task, socks_task)
        }
        config::ProxyMode::Auto => {
            let policy = Arc::new(rules);
            let always_http_proxy = http::AutoProxy::new(
                dialer.clone(),
                TcpListener::bind(config.general.http_listen).await?,
                Arc::new(Authentication::NoAuth),
                policy.clone(),
                false,
            );
            let http_task = tokio::spawn(async move { always_http_proxy.start_accept().await });

            let always_socks_proxy = socks::AutoProxy::new(
                dialer.clone(),
                TcpListener::bind(config.general.socks5_listen).await?,
                Arc::new(Authentication::NoAuth),
                policy.clone(),
                false,
            );
            let socks_task = tokio::spawn(async move { always_socks_proxy.start_accept().await });
            (http_task, socks_task)
        }
    };

    match tokio::try_join!(flattern(http_task), flattern(socks_task)) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("exit error: {}", e);
            std::process::abort()
        }
    }
}

async fn flattern(handle: JoinHandle<Result<(), anyhow::Error>>) -> Result<(), &'static str> {
    match handle.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            log::error!("proxy error, {}", &e);
            Err("proxy failed")
        }
        Err(e) => {
            log::error!("handle task error, {}", &e);
            Err("handle failed")
        }
    }
}
