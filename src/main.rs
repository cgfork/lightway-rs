#![feature(async_closure)]
#![allow(dead_code)]

mod config;
mod http;
mod rule;
mod socks;

use clap::Parser;
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};
use tokio::task::JoinHandle;

/// `lightway` is a simple proxy which supports the http and socks5.
#[derive(Debug, Parser)]
pub struct App {
    /// The config file for starting the lightway.
    #[clap(long, env = "PROXY_CONF", default_value = "~/.proxy.yaml")]
    config: String,

    /// Start lightway as daemon.
    #[clap(long, short)]
    daemon: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = App::parse();
    let args: Vec<String> = std::env::args().collect();
    if app.daemon {
        let child = Command::new(&args[0])
            .arg(format!("--config={}", &app.config))
            .stdin(Stdio::inherit())
            .stdout(Stdio::null()) // ingore env_logger output
            .stderr(Stdio::null()) // ingore env_logger output
            .spawn()
            .expect("failed to run the lightway as daemon process");
        println!("Pid: {}", child.id());
        return Ok(());
    }

    let f = fs::read(Path::new(Path::new(
        shellexpand::full(&app.config).unwrap().as_ref(),
    )))
    .unwrap();
    let config = serde_yaml::from_slice::<config::Config>(&f).unwrap();
    env_logger::builder()
        .parse_filters(&config.general.loglevel)
        .init();
    let http_task = http::start_proxy(config.parse()?).await?;
    let sock_task = socks::start_proxy(config.parse()?).await?;
    match tokio::try_join!(flattern(http_task), flattern(sock_task)) {
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
