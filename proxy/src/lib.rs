use std::{
    future::Future,
    task::{Context, Poll}, fmt, 
};

/// An asynchronous function from a `Request` to `Response`.
///
/// The `Service` trait is a simplified interface making it
/// easy to write network applications in a modular and reusable
/// way, decoupled from the underlying protocol. It is inspired
/// by the `Tower` abstraction.
pub trait Service<Request> {
    /// Responses given by the service.
    type Response;

    /// Errors produced by the service.
    type Error;

    /// The future response value.
    type Future<'a>: Future<Output = Result<Self::Response, Self::Error>> + Send + 'a
    where
        Self: 'a;

    /// Returns `Poll::Ready(Ok(()))` when the service is able to process the requests.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Process the request the return the response asynchronously.
    fn call(&mut self, req: Request) -> Self::Future<'_>;
}

impl<'a, S, Request> Service<Request> for &'a mut S
where
    S: Service<Request> + 'a,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future<'b> = S::Future<'b>
    where 
        Self: 'b;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        (**self).poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future<'_> {
        (**self).call(req)
    }
}

impl<S, Request> Service<Request> for Box<S>
where
    S: Service<Request> + ?Sized,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future<'b> = S::Future<'b>
    where 
        Self: 'b;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        (**self).poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future<'_> {
        (**self).call(req)
    }
}

/// Decorates a [`Service`], transforming either the request or the response.
///
/// Ofen, many of the pieces needed for writing network applications can be
/// reused across multiple services. The `Layer` trait can be used to write
/// reusable components that can be applied to services operating on different
/// protocols, and to both the client and server side of a network transaction.
pub trait Layer<I> {
    /// The wrapped service.
    type Service;
    
    /// Wrap the given service with the middleware, returning a new service
    /// that has been decorated with the middleware.
    fn layer(&self, service: I) -> Self::Service;
}

impl <'a, T, S> Layer<S> for &'a T 
where
    T: ?Sized + Layer<S>,
{
    type Service =T::Service;
    
    fn layer(&self, inner: S) -> Self::Service {
        (**self).layer(inner)
    }
}

/// Returns a new [`LayerFn`] that implements [`Layer`] by calling the
/// given function.
pub fn layer_fn<T>(f: T) -> LayerFn<T> {
    LayerFn { f }
}

/// A `Layer` implemented by a closure. See the docs for [`layer_fn`] for more details.
#[derive(Clone, Copy)]
pub struct LayerFn<F> {
    f: F,
}

impl<F, S, Out> Layer<S> for LayerFn<F>
where
    F: Fn(S) -> Out,
{
    type Service = Out;

    fn layer(&self, inner: S) -> Self::Service {
        (self.f)(inner)
    }
}

impl<F> fmt::Debug for LayerFn<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayerFn")
            .field("f", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}
/// Describes a stack target that can produce `T` typed parameters.
///
/// Stacks frequenctly need to be able to obtain configuration from the stack
/// target, but stack modules are decoupled from any concrete target types.
/// The `Param` trait provides a way to statically guarantee that a give target
/// can provide a configuration parameter.
pub trait Param<T> {
    /// Produces a `T` typed stack parameter.
    fn obtain(&self) -> T;
}

/// A strategy for obtaining a `P` typed  parameter from a `T` typed target.
/// 
/// This allows stack modules to be decoupled from whether a parameter is known
/// at construction-time target type.
pub trait ExtractParam<P, T> {
    fn extract(&self, t: &T) -> P;
}

impl <T: ToOwned> Param<T::Owned> for T {
    fn obtain(&self) -> T::Owned{
        self.to_owned()
    }
}

impl <F, P, T> ExtractParam<P, T> for F
where 
    F: Fn(&T) -> P,
{
    fn extract(&self, t: &T) -> P {
        (self)(t)
    }
}
