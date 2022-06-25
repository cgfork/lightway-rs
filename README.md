<div align="center">

[![stable](https://img.shields.io/badge/stable-stable-green.svg)](https://github.com/cgfork/lightway-rs) [![license](https://img.shields.io/github/license/cgfork/lightway-rs.svg?style=plastic)]() [![download_count](https://img.shields.io/github/downloads/cgfork/lightway-rs/total.svg?style=plastic)](https://github.com/cgfork/lightway-rs/releases) [![download](https://img.shields.io/github/release/cgfork/lightway-rs.svg?style=plastic)](https://github.com/cgfork/lightway-rs/releases)

**Lightway** is a high-performance tcp socket proxy which supports Socks5, HTTP and HTTPs.

</div>

# Installation

## Prerequirement

### Ubuntu

```
$ sudo apt-get install build-essential libssl-dev
```

### MacOS

```
$ brew install openssl
```

## Cargo Install

```
$ cargo install --git https://github.com/cgfork/lightway-rs
```

# Configuration

```yaml
---
general:
	loglevel: info
	skip_proxy:
	  - 127.0.0.1
	  - 10.0.0.0/8
	  - localhost
	  - "*.local"
	port: 1235
	socks_port: 1080
	http_listen: "0.0.0.0:1235"
	socks5_listen: "0.0.0.0:1080"
	dns_server:
	  - system
	exclude_simple_hostnames: true
	always_real_ip:
	  - "*.xbox.live.com"
	proxy_mode: direct 
```
