#![feature(type_alias_impl_trait)]
#![feature(io_error_more)]
pub mod client;

use std::{
    future::Future,
    io,
    task::{Context, Poll},
};

use http::{header, uri::Scheme, StatusCode};
use hyper::{client::HttpConnector, Body, Method, Request, Response};
use log::{debug, error};
use proxy::Service;
use proxy_auth::Authenticator;
use proxy_io::{Duplex, TargetAddr};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct Server<A, C> {
    authenticate: Option<A>,
    connect: C,
    client: hyper::Client<HttpConnector>,
}

impl<A, C> Server<A, C> {
    pub fn new(connect: C) -> Self {
        let client = hyper::Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build_http();
        Self {
            authenticate: None,
            connect,
            client,
        }
    }

    pub fn set_authenticate(&mut self, authenticate: A) {
        self.authenticate = Some(authenticate)
    }
}

impl<A, C> Service<Request<Body>> for Server<A, C>
where
    A: Authenticator + Send + Sync,
    C: Service<TargetAddr> + Send + Clone + 'static,
    C::Error: Into<io::Error> + Send,
    C::Response: AsyncWrite + AsyncRead + Send + Unpin,
{
    type Response = Response<Body>;

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send + 'a
    where
        Self: 'a;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connect.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future<'_> {
        let client = self.client.clone();
        let mut connect = self.connect.clone();
        Box::pin(async move {
            debug!("handle req: {:?}", &req);
            if Method::CONNECT == req.method() {
                // Received an HTTP request like:
                // ```
                // CONNECT www.domain.com:443 HTTP/1.1
                // Host: www.domain.com:443
                // Proxy-Connection: Keep-Alive
                // Proxy-Authorization: Basic xxxx
                // ```
                //
                // When HTTP method is CONNECT we should return an empty body
                // then we can eventually upgrade the connection and talk a new protocol.
                //
                // Note: only after client received an empty body with STATUS_OK can the
                // connection be upgraded, so we can't return a response inside
                // `on_upgrade` future.
                if let Some((host, port)) = host_addr(req.uri()) {
                    if let Some(status) = match &self.authenticate {
                        Some(auth) => {
                            let basic = &req.headers()[header::PROXY_AUTHORIZATION];
                            if let Some((u, p)) = basic.to_str().ok().and_then(|a| {
                                a.trim().strip_prefix("Basic ").and_then(|b| {
                                    if let Some(n) = b.find(':') {
                                        Some((&b[..n], &b[(n + 1)..]))
                                    } else {
                                        None
                                    }
                                })
                            }) {
                                if auth.authenticate(u, p) {
                                    None
                                } else {
                                    Some(StatusCode::UNAUTHORIZED)
                                }
                            } else {
                                Some(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                            }
                        }
                        None => None,
                    } {
                        error!("the proxy authentication is required, but it does not provide");
                        match status {
                            StatusCode::PROXY_AUTHENTICATION_REQUIRED => Ok(Response::builder()
                                .status(status.clone())
                                .header(header::PROXY_AUTHENTICATE, "Basic realm=Proxy Server")
                                .body(Body::empty())
                                .unwrap()),
                            _ => Ok(Response::builder()
                                .status(status.clone())
                                .body(Body::empty())
                                .unwrap()),
                        }
                    } else {
                        tokio::task::spawn(async move {
                            match hyper::upgrade::on(req).await {
                                Ok(mut upgraded) => {
                                    match connect.call(TargetAddr::Domain(host.clone(), port)).await
                                    {
                                        Ok(stream) => {
                                            if let Err(e) = Duplex::new(upgraded, stream).await {
                                                error!("copy bidirectional failed, error:{}", e)
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "connect {}:{} failed, error: {}",
                                                &host,
                                                port,
                                                e.into()
                                            );
                                            if let Err(e) = upgraded.shutdown().await {
                                                error!("unable to shutdown the connection, {}", &e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => error!("upgrade error: {}", e),
                            }
                        });

                        Ok(Response::new(Body::empty()))
                    }
                } else {
                    error!("CONNECT host is not socket addr: {:?}", req.uri());
                    let mut resp = Response::new(Body::from("CONNECT must be to a socket address"));
                    *resp.status_mut() = http::StatusCode::BAD_REQUEST;

                    Ok(resp)
                }
            } else {
                Ok(client
                    .request(req)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?)
            }
        })
    }
}

fn host_addr(uri: &http::Uri) -> Option<(String, u16)> {
    let tls = uri.scheme() == Some(&Scheme::HTTPS);
    uri.authority().and_then(|auth| {
        let port = auth
            .port_u16()
            .unwrap_or_else(|| if tls { 443 } else { 80 });
        Some((auth.host().to_string(), port))
    })
}
