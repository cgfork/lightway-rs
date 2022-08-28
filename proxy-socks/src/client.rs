use std::{future::Future, task::{Poll, Context}, io};

use log::{error, debug};
use futures::TryFutureExt;
use proxy::Service;
use proxy_io::{StreamConnect, TargetAddr, ProxyStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{types::*, error::Kind, io_err, check_valid};

pub struct Client<C> {
    authorization: Option<(String, String)>,
    connect: StreamConnect<C>,
}

impl <C> Client<C> {
	pub fn new(target: TargetAddr, connect: C) -> Self {
		Client{
			authorization: None,
			connect: StreamConnect::new(connect, target),
		}
	}
	
	pub fn set_authorization(&mut self, username: String, password: String) {
		self.authorization = Some((username, password))
	}
	
	pub fn enable_tls(&mut self) {
		self.connect.set_tls(true)
	}
}

impl<C> Service<TargetAddr> for Client<C>
where
    C: Service<TargetAddr> + Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C::Error: Into<io::Error> + Send,
{
    type Response = ProxyStream<C::Response>;

    type Error = io::Error;

    type Future<'a> = impl Future<Output = Result<Self::Response, Self::Error>> + Send +'a 
    where
        Self: 'a;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.connect.poll_ready(cx).map_err(|e| e.into())
	}

	fn call(&mut self, target: TargetAddr) -> Self::Future<'_> {
		let future = self.connect.call(()).map_err(Into::<io::Error>::into);
		let authorization = self.authorization.clone();
		Box::pin(async move {
			let mut socket  = future.await?;
			match proxy_socks(&mut socket, target.clone(), authorization).await {
				Ok(()) => Ok(socket),
				Err(e) => {
					error!("unable to proxy socks to {}, {}",&target, &e);
					// TODO: check error
					if let Err(e) = socket.shutdown().await {
						error!("unable to shutdown proxy stream, {}", &e);
					}
					Err(e)
				}
			}
		})
	}
}

async fn proxy_socks<S>(socket: &mut S, target: TargetAddr, authorization: Option<(String, String)>) -> io::Result<()>
where 
	S: AsyncRead + AsyncWrite + Unpin,
{
	debug!("proxy socks for {}", &target);
	let mut candidate = CandidateMethods::new(vec![Method::NoAuthenticationRequired]);
	if authorization.is_some() {
		candidate.add(Method::UsernameAndPassword);
	}
	
	debug!("write methods for {}", &target);
	candidate.write(socket).await?;
	let selection = check_valid!(Selection::read(socket).await);
	if let Some(method) = selection.method() {
		match method {
    		Method::NoAuthenticationRequired => Ok(()),
    		Method::UsernameAndPassword => if let Some((u, p)) = authorization {
				UsernameAndPassword::new(u, p).write(socket).await?;
				let status = Status::read(socket).await?;
				if status.is_succeed() {
					Ok(())
				} else {
					error!("authenticate failed for {}", &target);
					Err(io_err!(Kind::Unauthorized))
				}
			} else {
				error!("the username and password is required");
				Err(io_err!(Kind::UnknownMethod))		
			}
    		Method::NoAcceptableMethods => Err(io_err!(Kind::NoAcceptableMethods)),
			n => {
				error!("unexpect method({})", n);
				Err(io_err!(Kind::UnknownMethod))
			}
		}
	} else {
		error!("unknown method({})", selection.method);
		Err(io_err!(Kind::UnknownMethod))
	}?;
	
	debug!("write request for {}", &target);
	Request::new(target).write(socket).await?;
	let reply = check_valid!(Reply::read(socket).await);
	match reply.rep() {
    	Some(Rep::Succeeded) => Ok(()),
		Some(Rep::NetworkUnreachable) => Err(io::ErrorKind::NetworkUnreachable.into()),
		Some(Rep::HostUnreachable) => Err(io::ErrorKind::HostUnreachable.into()),
		Some(Rep::ConnectionRefused) => Err(io::ErrorKind::ConnectionRefused.into()),
		Some(Rep::GeneralSocksServerFailure) => Err(io_err!(Kind::GeneralSocksServerFailure)),
		Some(Rep::TtlExpired) => Err(io_err!(Kind::TtlExpired)),
		Some(Rep::CommandNotSupported) => Err(io_err!(Kind::CommandNotSupported)),
		Some(Rep::AddressTypeNotSupported) => Err(io_err!(Kind::AddressTypeNotSupported)),
		Some(Rep::ConnectionNotAllowedByRuleset) => Err(io_err!(Kind::ConnectionNotAllowedByRuleset)),
		None => Err(io_err!(Kind::UnknownRep)),
	}
}