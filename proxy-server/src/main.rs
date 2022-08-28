#![feature(type_alias_impl_trait)]
mod client;
mod config;

use std::{convert::Infallible, path::PathBuf};

use anyhow::anyhow;
use clap::Parser;
use client::Client;
use config::{cache_dir, config_dir, Config, ProxyMode};
use hyper::service::{make_service_fn, service_fn};
use log::{error, info};
use proxy::Service;
use proxy_auth::Authentication;
use proxy_io::{ProxyConnect, TokioConnect};
use proxy_rules::Rules;
use tokio::net::TcpListener;

use crate::config::user_rules;

#[derive(Debug, Parser)]
#[command(name = "lwp")]
#[command(author = "cgfork")]
#[command(version = env!("VERSION_AND_GIT_HASH"))]
#[command(next_line_help = true)]
pub struct App {
    /// Increases logging verbosity each use for up to 3 times.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Checks the potential errors in lightway setup.
    #[arg(long)]
    health: bool,

    /// Specifies a file to use for configuration.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Specifies a fiel to use for logging.
    #[arg(short, long)]
    log: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let version = env!("VERSION_AND_GIT_HASH");
    let app = App::parse();
    let logfile = app.log.unwrap_or_else(|| {
        let cache_dir = cache_dir();
        if !cache_dir.exists() {
            std::fs::create_dir_all(&cache_dir).ok();
        }
        cache_dir.join("proxy.log")
    });
    let configfile = app.config.unwrap_or_else(|| {
        let config_dir = config_dir();
        if !config_dir.exists() {
            std::fs::create_dir_all(&config_dir).ok();
        }
        config_dir.join("config.toml")
    });

    if app.health {
        println!("Version: {}", &version);
        println!("Config file: {}", configfile.display());
        println!("Log file: {}", logfile.display());
        return Ok(());
    }

    setup_logging(logfile.clone(), app.verbose)?;
    let config = toml::from_slice::<Config>(
        &std::fs::read(&configfile)
            .map_err(|e| anyhow!("{} does not exist, {}", configfile.display(), e))?,
    )?;

    let rules: Rules = user_rules()?.try_into()?;
    let mut client = Client::empty();
    let connect = match &config.proxy_mode {
        ProxyMode::Direct => ProxyConnect::<_, _, Rules>::new(TokioConnect::new(), client),
        ProxyMode::Proxy => {
            let proxy = config
                .proxies
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(&config.proxy))
                .expect("no proxy for proxy mode");
            client.set_proxy(proxy.clone());
            let mut proxy_connect = ProxyConnect::<_, _, Rules>::new(TokioConnect::new(), client);
            proxy_connect.set_force_proxy(true);
            proxy_connect
        }
        ProxyMode::Auto => {
            let proxy = config
                .proxies
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(&config.proxy))
                .expect("no proxy for auto mode");
            client.set_proxy(proxy.clone());
            let mut proxy_connect = ProxyConnect::<_, _, Rules>::new(TokioConnect::new(), client);
            proxy_connect.set_policy(rules);
            proxy_connect
        }
    };

    let socks_listener = TcpListener::bind(&config.socks5_listen).await?;
    let socks_server = proxy_socks::server::Server::<Authentication, _>::new(connect.clone());
    let socks_join = tokio::spawn(async move {
        loop {
            match socks_listener.accept().await {
                Ok((stream, addr)) => {
                    let mut server = socks_server.clone();
                    tokio::spawn(async move {
                        match server.call(stream).await {
                            Ok(()) => {
                                info!("completed socks proxy({})", &addr);
                            }
                            Err(e) => {
                                error!("an error occurs during socks proxy({}), {}", &addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("unable to accept socks5, {}", e);
                    break;
                }
            }
        }
    });
    let http_server = proxy_tunnel::Server::<Authentication, _>::new(connect.clone());
    let server = hyper::Server::bind(&config.http_listen.parse()?)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service_fn(move |_| {
            let server = http_server.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let mut server = server.clone();
                    async move { server.call(req).await }
                }))
            }
        }));

    let http_join = tokio::spawn(async move {
        if let Err(e) = server.await {
            error!("unable to serve http, {}", &e);
        }
    });

    match tokio::try_join!(socks_join, http_join) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("exit error: {}", e);
            std::process::abort()
        }
    }
}

fn setup_logging(logpath: PathBuf, verbosity: u8) -> anyhow::Result<()> {
    let mut base_config = fern::Dispatch::new();

    base_config = match verbosity {
        0 => base_config.level(log::LevelFilter::Warn),
        1 => base_config.level(log::LevelFilter::Info),
        2 => base_config.level(log::LevelFilter::Debug),
        _3_or_more => base_config.level(log::LevelFilter::Trace),
    };

    // Separate file config so we can include year, month and day in file logs
    let file_config = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} {} [{}] {}",
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                record.target(),
                record.level(),
                message
            ))
        })
        .chain(fern::log_file(logpath)?);

    base_config.chain(file_config).apply()?;

    Ok(())
}
