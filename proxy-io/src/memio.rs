use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct Bytes {
    pub inner: Vec<u8>,
    pub pos: usize,
}

pub fn test_bytes() -> Bytes {
    return Bytes {
        inner: vec![],
        pos: 0,
    };
}

impl AsyncRead for Bytes {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pos = self.pos;
        let len = std::cmp::min(self.inner.len() - pos, buf.remaining());
        buf.put_slice(&self.inner[pos..(pos + len)]);
        self.pos = pos + len;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Bytes {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.inner.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}
