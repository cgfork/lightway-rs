use std::{
    future::Future,
    io,
    task::{Context, Poll},
};

use log::{debug, error, warn};
use proxy::Service;
use proxy_auth::Authenticator;
use proxy_io::{Duplex, TargetAddr};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    check_valid,
    error::Kind,
    io_err,
    types::{
        CandidateMethods, Method, Rep, Reply, Request, Selection, Status, UsernameAndPassword,
    },
};

#[derive(Debug, Clone)]
pub struct Server<A, C> {
    authenticate: Option<A>,
    connect: C,
}

impl<A, C> Server<A, C> {
    pub fn new(connect: C) -> Self {
        Self {
            authenticate: None,
            connect,
        }
    }

    pub fn set_authenticate(&mut self, authenticate: A) {
        self.authenticate = Some(authenticate)
    }
}

impl<I, A, C> Service<I> for Server<A, C>
where
    A: Authenticator + Send + Sync,
    I: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    C: Service<TargetAddr> + Send + 'static,
    C::Response: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    C::Error: Into<io::Error> + Send,
{
    type Response = ();

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send + 'a
    where
        Self: 'a;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connect.poll_ready(cx).map_err(|e| e.into())
    }

    fn call(&mut self, mut socket: I) -> Self::Future<'_> {
        Box::pin(async move {
            if let Err(e) = if let Some(auth) = &self.authenticate {
                prepare_with(&mut socket, auth).await
            } else {
                prepare(&mut socket).await
            } {
                if let Err(ioe) = socket.shutdown().await {
                    error!("unable to shutdown the socket, {}", ioe);
                }

                return Err(e);
            };

            match handle(&mut socket).await {
                Ok(target) => {
                    debug!("proxy connect to {}", &target);
                    match self.connect.call(target.clone()).await {
                        Ok(mut conn) => match Reply::new(Rep::Succeeded).write(&mut socket).await {
                            Ok(()) => {
                                debug!("bidirectional copy for {}", &target);
                                // let (a, b) =
                                //     tokio::io::copy_bidirectional(&mut socket, &mut conn).await?;
                                // debug!("{} <> {}", a, b);
                                // Ok(())
                                Duplex::new(socket, conn).await
                            }
                            Err(e) => {
                                error!("unable write succeeded reply to socket, {}", &e);
                                if let Err(ioe) = conn.shutdown().await {
                                    error!("unable to shutdown the proxy socket, {}", ioe);
                                }
                                Err(e)
                            }
                        },
                        Err(e) => {
                            let ioe: io::Error = e.into();
                            error!("proxy connect to {}, {}", &target, &ioe);
                            let rep = match ioe.kind() {
                                io::ErrorKind::ConnectionRefused => Rep::ConnectionRefused,
                                io::ErrorKind::HostUnreachable => Rep::HostUnreachable,
                                io::ErrorKind::NetworkUnreachable => Rep::NetworkUnreachable,
                                _ => Rep::GeneralSocksServerFailure,
                            };
                            if let Err(e) = Reply::new(rep).write(&mut socket).await {
                                error!("unable to write reply to socket, {}", e);
                            }

                            // Don't forget to shutdown the origin socket.
                            if let Err(e) = socket.shutdown().await {
                                error!("unable to shutdown the socket, {}", e);
                            }
                            Err(ioe)
                        }
                    }
                }
                Err(e) => {
                    if let Err(ioe) = socket.shutdown().await {
                        error!("unable to shutdown the socket, {}", ioe);
                    }
                    Err(e)
                }
            }
        })
    }
}

async fn prepare<S>(socket: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("serve without authorization");
    let methods = check_valid!(CandidateMethods::read(socket).await);
    if !methods.has(Method::NoAuthenticationRequired) {
        Selection::new(Method::NoAcceptableMethods)
            .write(socket)
            .await?;
        return Err(io_err!(Kind::NoAcceptableMethods));
    }
    Selection::new(Method::NoAuthenticationRequired)
        .write(socket)
        .await?;
    Ok(())
}

async fn prepare_with<S, A>(socket: &mut S, auth: &A) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
{
    debug!("serve with authorization");
    let methods = check_valid!(CandidateMethods::read(socket).await);
    if !methods.has(Method::UsernameAndPassword) {
        warn!("no authorization method provided");
        Selection::new(Method::NoAcceptableMethods)
            .write(socket)
            .await?;
        return Err(io_err!(Kind::NoAcceptableMethods));
    }
    Selection::new(Method::UsernameAndPassword)
        .write(socket)
        .await?;

    let user_pass = check_valid!(UsernameAndPassword::read(socket).await);
    if !auth.authenticate(&user_pass.username, &user_pass.password) {
        error!("unable to authenticate the socket");
        Status::new(0x01).write(socket).await?;
        return Err(io_err!(Kind::Unauthorized));
    }

    Status::new(0x00).write(socket).await?;
    Ok(())
}

async fn handle<S>(socket: &mut S) -> io::Result<TargetAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("handle socket");
    let req = check_valid!(Request::read(socket).await);
    if req.target.is_none() {
        Reply::new(Rep::AddressTypeNotSupported)
            .write(socket)
            .await?;
        return Err(io_err!(Kind::AddressTypeNotSupported));
    }

    if req.is_connect() {
        Ok(req.target.unwrap())
    } else {
        Reply::new(Rep::CommandNotSupported).write(socket).await?;
        Err(io_err!(Kind::CommandNotSupported))
    }
}
