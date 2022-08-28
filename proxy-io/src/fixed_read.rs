use std::{
    future::Future,
    io::{self, ErrorKind::UnexpectedEof},
    marker::PhantomPinned,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{ready, Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A extension trait adds fixed reading methods to the [`AsyncRead`].
pub trait AsyncFixedReadExt: AsyncRead {
    fn read_to_fixed_string<'a>(&'a mut self, dst: &'a mut String) -> ReadToFixedString<'a, Self>
    where
        Self: Unpin,
    {
        read_to_fixed_string(self, dst)
    }

    fn read_to_fixed_bytes<'a>(&'a mut self, dst: &'a mut Vec<u8>) -> ReadToFixedBytes<'a, Self>
    where
        Self: Unpin,
    {
        read_to_fixed_bytes(self, dst)
    }
}

impl<R: AsyncRead + ?Sized> AsyncFixedReadExt for R {}

/// A extension trait adds fixed buf writing methods to the [`AsyncWrite`].
pub trait AsyncFixedWriteExt: AsyncWrite {
    fn write_fixed_buf<'a, B>(&'a mut self, buf: &'a mut B) -> WriteFixedBuf<'a, Self, B>
    where
        Self: Sized + Unpin,
        B: bytes::Buf,
    {
        write_fixed_buf(self, buf)
    }

    fn write_fixed<'a>(&'a mut self, src: &'a [u8]) -> WriteFixed<'a, Self>
    where
        Self: Unpin,
    {
        write_fixed(self, src)
    }
}

impl<W: AsyncWrite + ?Sized> AsyncFixedWriteExt for W {}

/// This struct wraps a `Vec<u8>` or `&mut Vec<u8>`, combining it with a
/// `num_initialized`, which keeps track of the number of initialized bytes
/// in the unused capacity.
///
/// The purpose of this struct is to remember how many bytes were initialized
/// through a `ReadBuf` from call to call.
///
/// This struct has the safety invariant that the first `num_initialized` of the
/// vector's allocation must be initialized at any time.
#[derive(Debug)]
pub struct VecReadBuf<V> {
    vec: V,
    // The number of initialized bytes in the vector.
    // Always between `vec.len()` and `vec.capacity()`.
    num_initialized: usize,
}

impl VecReadBuf<Vec<u8>> {
    pub fn take(&mut self) -> Vec<u8> {
        self.num_initialized = 0;
        std::mem::take(&mut self.vec)
    }
}

pub trait VecU8: AsMut<Vec<u8>> {}

impl VecU8 for Vec<u8> {}
impl VecU8 for &mut Vec<u8> {}

impl<V: VecU8> VecReadBuf<V> {
    pub fn new(mut vec: V) -> Self {
        // SAFETY: The safety invariants of vector guarantee that the bytes up
        // to its length are initialized.
        Self {
            num_initialized: AsMut::as_mut(&mut vec).len(),
            vec,
        }
    }

    pub fn reserve(&mut self, num_bytes: usize) {
        let vec = self.vec.as_mut();
        if vec.capacity() - vec.len() >= num_bytes {
            return;
        }
        // SAFETY: Setting num_initialized to `vec.len()` is correct as
        // `reserve` does not change the length of the vector.
        self.num_initialized = vec.len();
        vec.reserve(num_bytes);
    }

    pub fn is_empty(&mut self) -> bool {
        self.vec.as_mut().is_empty()
    }

    pub fn get_read_buf<'a>(&'a mut self) -> ReadBuf<'a> {
        let num_initialized = self.num_initialized;

        // SAFETY: Creating the slice is safe because of the safety invariants
        // on Vec<u8>. The safety invariants of `ReadBuf` will further guarantee
        // that no bytes in the slice are de-initialized.
        let vec = self.vec.as_mut();
        let len = vec.len();
        let cap = vec.capacity();
        let ptr = vec.as_mut_ptr().cast::<MaybeUninit<u8>>();
        let slice = unsafe { std::slice::from_raw_parts_mut::<'a, MaybeUninit<u8>>(ptr, cap) };

        // SAFETY: This is safe because the safety invariants of
        // VecWithInitialized say that the first num_initialized bytes must be
        // initialized.
        let mut read_buf = ReadBuf::uninit(slice);
        unsafe {
            read_buf.assume_init(num_initialized);
        }
        read_buf.set_filled(len);

        read_buf
    }

    pub fn get_exact_read_buf<'a>(&'a mut self, num_bytes: usize) -> ReadBuf<'a> {
        let num_initialized = self.num_initialized;

        // SAFETY: Creating the slice is safe because of the safety invariants
        // on Vec<u8>. The safety invariants of `ReadBuf` will further guarantee
        // that no bytes in the slice are de-initialized.
        let vec = self.vec.as_mut();
        let len = vec.len();
        let cap = vec.capacity();
        assert!(cap - len >= num_bytes);
        let ptr = vec.as_mut_ptr().cast::<MaybeUninit<u8>>();
        let slice =
            unsafe { std::slice::from_raw_parts_mut::<'a, MaybeUninit<u8>>(ptr, len + num_bytes) };
        let mut read_buf = ReadBuf::uninit(slice);
        unsafe {
            read_buf.assume_init(num_initialized);
        }
        read_buf.set_filled(len);
        read_buf
    }

    pub(crate) fn apply_read_buf(
        &mut self,
        ptr: *const u8,
        num_initialized: usize,
        filled_len: usize,
    ) {
        let vec = self.vec.as_mut();
        assert_eq!(vec.as_ptr(), ptr);
        // SAFETY:
        unsafe {
            self.num_initialized = num_initialized;
            vec.set_len(filled_len);
        }
    }
}

impl<V: VecU8> Deref for VecReadBuf<V> {
    type Target = V;
    fn deref(&self) -> &Self::Target {
        &self.vec
    }
}

impl<V: VecU8> DerefMut for VecReadBuf<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vec
    }
}

pub(crate) fn read_to_fixed_string<'a, R>(
    reader: &'a mut R,
    string: &'a mut String,
) -> ReadToFixedString<'a, R>
where
    R: AsyncRead + ?Sized + Unpin,
{
    let buf = std::mem::take(string).into_bytes();
    ReadToFixedString {
        reader,
        buf: VecReadBuf::new(buf),
        output: string,
        read: 0,
        len: None,
        _pin: PhantomPinned,
    }
}

pub(crate) fn read_to_fixed_bytes<'a, R>(
    reader: &'a mut R,
    buf: &'a mut Vec<u8>,
) -> ReadToFixedBytes<'a, R>
where
    R: AsyncRead + ?Sized + Unpin,
{
    ReadToFixedBytes {
        reader,
        buf: VecReadBuf::new(buf),
        read: 0,
        len: None,
        _pin: PhantomPinned,
    }
}

pin_project! {
    pub struct ReadToFixedString<'a, R: ?Sized> {
        reader: &'a mut R,
        // This is the buffer we were provided. It will be replaced with an empty string
        // while reading to postpone utf-8 handling until after reading.
        output: &'a mut String,
        // The actual allocation of the string is moved into this vector instead.
        buf: VecReadBuf<Vec<u8>>,
        // The number of bytes appended to buf. This can be less than buf.len() if
        // the buffer was not empty when the operation was started.
        read: usize,
        // The length of the variable field, which was stored as u8 at the first of string.
        len: Option<usize>,
        // Make this future `!Unpin` for compatibility with async trait methods.
        #[pin]
        _pin: PhantomPinned,
    }
}

impl<A> Future for ReadToFixedString<'_, A>
where
    A: AsyncRead + ?Sized + Unpin,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.project();
        poll_read_to_fixed_string(Pin::new(*me.reader), cx, me.output, me.buf, me.read, me.len)
    }
}

fn poll_read_to_fixed_string<R: AsyncRead + ?Sized>(
    mut reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    output: &mut String,
    buf: &mut VecReadBuf<Vec<u8>>,
    read: &mut usize,
    len: &mut Option<usize>,
) -> Poll<io::Result<usize>> {
    loop {
        if let Some(n) = len {
            // Read all octets.
            if *n + 1 == *read {
                return match String::from_utf8(buf.take()) {
                    Ok(s) => {
                        *output = s;
                        Poll::Ready(Ok(*read))
                    }
                    Err(e) => {
                        put_back_original_data(output, e.into_bytes(), *n);
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "stream did not contain valid UTF-8",
                        )))
                    }
                };
            }

            let ret = ready!(poll_read_num_bytes(
                buf,
                reader.as_mut(),
                cx,
                *n + 1 - *read
            ));
            match ret {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(num) => {
                    if num == 0 {
                        return Poll::Ready(Err(UnexpectedEof.into()));
                    }
                    *read += num;
                }
            }
        } else {
            let mut array = [0; 1];
            let mut read_buf = ReadBuf::new(&mut array);
            let ret = ready!(reader.as_mut().poll_read(cx, &mut read_buf));
            match ret {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(()) => {
                    if read_buf.filled().is_empty() {
                        return Poll::Ready(Err(UnexpectedEof.into()));
                    }

                    *len = Some(array[0] as usize);
                    *read += 1;
                }
            }
        }
    }
}

pin_project! {
    pub struct ReadToFixedBytes<'a, R: ?Sized> {
        reader: &'a mut R,
        // The actual allocation of the string is moved into this vector instead.
        buf: VecReadBuf<&'a mut Vec<u8>>,
        // The number of bytes appended to buf. This can be less than buf.len() if
        // the buffer was not empty when the operation was started.
        read: usize,
        // The length of the variable field, which was stored as u8 at the first of string.
        len: Option<usize>,
        // Make this future `!Unpin` for compatibility with async trait methods.
        #[pin]
        _pin: PhantomPinned,
    }
}

impl<A> Future for ReadToFixedBytes<'_, A>
where
    A: AsyncRead + ?Sized + Unpin,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.project();
        poll_read_to_fixed_bytes(Pin::new(*me.reader), cx, me.buf, me.read, me.len)
    }
}

fn poll_read_to_fixed_bytes<V: VecU8, R: AsyncRead + ?Sized>(
    mut reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    buf: &mut VecReadBuf<V>,
    read: &mut usize,
    len: &mut Option<usize>,
) -> Poll<io::Result<usize>> {
    loop {
        if let Some(n) = len {
            // Read all octets.
            if *n + 1 == *read {
                return Poll::Ready(Ok(*read));
            }

            let ret = ready!(poll_read_num_bytes(
                buf,
                reader.as_mut(),
                cx,
                *n + 1 - *read
            ));
            match ret {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(num) => {
                    if num == 0 {
                        return Poll::Ready(Err(UnexpectedEof.into()));
                    }
                    *read += num;
                }
            }
        } else {
            let mut array = [0; 1];
            let mut read_buf = ReadBuf::new(&mut array);
            let ret = ready!(reader.as_mut().poll_read(cx, &mut read_buf));
            match ret {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(()) => {
                    if read_buf.filled().is_empty() {
                        return Poll::Ready(Err(UnexpectedEof.into()));
                    }

                    *len = Some(array[0] as usize);
                    *read += 1;
                }
            }
        }
    }
}

fn poll_read_num_bytes<V: VecU8, R: AsyncRead + ?Sized>(
    buf: &mut VecReadBuf<V>,
    reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    num_bytes: usize,
) -> Poll<io::Result<usize>> {
    buf.reserve(num_bytes);
    let mut read_buf = buf.get_exact_read_buf(num_bytes);
    let filled_before = read_buf.filled().len();
    let poll_result = reader.poll_read(cx, &mut read_buf);
    let filled_after = read_buf.filled().len();
    let n = filled_after - filled_before;
    let ptr = read_buf.filled().as_ptr();
    let num_initialized = read_buf.initialized().len();
    buf.apply_read_buf(ptr, num_initialized, filled_after);

    match poll_result {
        Poll::Pending => {
            debug_assert_eq!(filled_before, filled_after);
            Poll::Pending
        }
        Poll::Ready(Err(err)) => {
            debug_assert_eq!(filled_before, filled_after);
            Poll::Ready(Err(err))
        }
        Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
    }
}

fn put_back_original_data(output: &mut String, mut vector: Vec<u8>, num_bytes_read: usize) {
    let original_len = vector.len() - num_bytes_read;
    vector.truncate(original_len);
    *output = String::from_utf8(vector).expect("The original data must be valid utf-8.");
}

pin_project! {
    #[derive(Debug)]
    pub struct WriteFixedBuf<'a, W, B> {
        writer: &'a mut W,
        buf: &'a mut B,
        len_writed: bool,
        #[pin]
        _pin: PhantomPinned,
    }
}

fn write_fixed_buf<'a, W, B>(writer: &'a mut W, buf: &'a mut B) -> WriteFixedBuf<'a, W, B>
where
    W: AsyncWrite + Unpin,
    B: bytes::Buf,
{
    WriteFixedBuf {
        writer,
        buf,
        len_writed: false,
        _pin: PhantomPinned,
    }
}

impl<W, B> Future for WriteFixedBuf<'_, W, B>
where
    W: AsyncWrite + Unpin,
    B: bytes::Buf,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.project();
        if !*me.len_writed {
            let n = ready!(Pin::new(&mut *me.writer).poll_write(cx, &[me.buf.remaining() as u8])?);
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }

            *me.len_writed = true
        }

        while me.buf.has_remaining() {
            let n = ready!(Pin::new(&mut *me.writer).poll_write(cx, me.buf.chunk())?);
            me.buf.advance(n);
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(Ok(()))
    }
}

pin_project! {
    #[derive(Debug)]
    pub struct WriteFixed<'a, W: ?Sized> {
        writer: &'a mut W,
        buf: &'a [u8],
        len_writed: bool,
        #[pin]
        _pin: PhantomPinned,
    }
}

fn write_fixed<'a, W>(writer: &'a mut W, buf: &'a [u8]) -> WriteFixed<'a, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    WriteFixed {
        writer,
        buf,
        len_writed: false,
        _pin: PhantomPinned,
    }
}

impl<W> Future for WriteFixed<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.project();
        if !*me.len_writed {
            let n = ready!(Pin::new(&mut *me.writer).poll_write(cx, &[me.buf.len() as u8])?);
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }

            *me.len_writed = true
        }

        while !me.buf.is_empty() {
            let n = ready!(Pin::new(&mut *me.writer).poll_write(cx, me.buf))?;
            {
                let (_, rest) = std::mem::take(&mut *me.buf).split_at(n);
                *me.buf = rest;
            }
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Poll::Ready(Ok(()))
    }
}
