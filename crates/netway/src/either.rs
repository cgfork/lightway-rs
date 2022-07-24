use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::dst::{DstAddr, ToLocalAddr};

/// The Either type represents values with two possibilities: Left and Right.
///
/// The Either type is sometimes used to represent a value which is
/// either correct or an error. In this scenario, the Either is same with Result.
pub enum Either<L, R> {
    Left(L),
    Right(R),
}

/// Macro for eval the same result expr for both the left and right.
///
/// # Example
/// ```edition2021
/// impl Either<usize, usize> {
///     fn incr(&self) -> usize{
///         either!(self, v => v + 1)
///     }
/// }
/// ```
#[macro_export]
macro_rules! either {
    ($e:expr, $value:pat => $result:expr) => {
        match $e {
            Either::Left($value) => $result,
            Either::Right($value) => $result,
        }
    };
}

impl<L, R> AsyncRead for Either<L, R>
where
    L: AsyncRead + Unpin,
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        unsafe {
            either!(self.get_unchecked_mut(), stream => AsyncRead::poll_read(Pin::new(stream), cx, buf))
        }
    }
}

impl<L, R> AsyncWrite for Either<L, R>
where
    L: AsyncWrite + Unpin,
    R: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        unsafe {
            either!(self.get_unchecked_mut(), stream => AsyncWrite::poll_write(Pin::new(stream), cx, buf))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unsafe {
            either!(self.get_unchecked_mut(), stream => AsyncWrite::poll_flush(Pin::new(stream), cx))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unsafe {
            either!(self.get_unchecked_mut(), stream => AsyncWrite::poll_shutdown(Pin::new(stream), cx))
        }
    }
}

impl<L, R, E> ToLocalAddr for Either<L, R>
where
    L: ToLocalAddr<Error = E>,
    R: ToLocalAddr<Error = E>,
{
    type Error = E;

    fn to_local_addr(&self) -> Result<DstAddr, Self::Error> {
        either!(self, stream => stream.to_local_addr())
    }
}
