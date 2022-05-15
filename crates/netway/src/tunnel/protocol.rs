use std::{fmt, io};

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

pub struct Header<'a> {
    /// The name portion of a header.
    ///
    /// A header name must be valid ASCII-US, so it's safe to store as a `&str`.
    pub name: &'a str,
    /// The value portion of a header.
    ///
    /// While headers **should** be ASCII-US, so it's safe to store as a `&str`.
    pub value: &'a str,
}

impl fmt::Display for Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

pub struct RequestLine<'a> {
    /// The method portion of a request line.
    ///
    /// A method must be valid ASCII-US, so it's safe to store as a `&str`.
    pub method: &'a str,
    /// The host portion of a request line.
    ///
    /// A host must be valid ASCII-US, so it's safe to store as a `&str`.
    pub host: &'a str,
    /// The protocol portion of a request line.
    ///
    /// A protocol must be valid ASCII-US, so it's safe to store as a `&str`.
    pub protocol: &'a str,
}
impl fmt::Display for RequestLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.method, self.host, self.protocol)
    }
}
pub struct StatusLine<'a> {
    /// The protocol portion of a request line.
    ///
    /// A protocol must be valid ASCII-US, so it's safe to store as a `&str`.
    pub protocol: &'a str,
    /// The status code portion of a request line.
    ///
    /// A status code must be valid ASCII-US, so it's safe to store as a `&str`.
    pub status: &'a str,
    /// The status message portion of a request line.
    ///
    /// A status message must be valid ASCII-US, so it's safe to store as a `&str`.
    pub message: &'a str,
}

impl fmt::Display for StatusLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.protocol, self.status, self.message)
    }
}

pub async fn read_request_line<'a, S>(
    socket: &mut S,
    buf: &'a mut String,
) -> Result<RequestLine<'a>, io::Error>
where
    S: AsyncBufRead + Unpin,
{
    let start = buf.len();
    let size = socket.read_line(buf).await?;
    if size > 0 {
        let splits = buf[start..(start + size - 1)]
            .split(' ')
            .collect::<Vec<_>>();
        debug_assert!(
            splits.len() == 3,
            "The number of request line splits should be 3"
        );
        Ok(RequestLine {
            method: splits[0],
            host: splits[1],
            protocol: splits[2],
        })
    } else {
        Err(io::ErrorKind::UnexpectedEof.into())
    }
}

pub async fn read_status_line<'a, S>(
    socket: &mut S,
    buf: &'a mut String,
) -> Result<StatusLine<'a>, io::Error>
where
    S: AsyncBufRead + Unpin,
{
    let start = buf.len();
    let size = socket.read_line(buf).await?;
    let splits = buf[start..(start + size - 1)]
        .split(' ')
        .collect::<Vec<_>>();
    debug_assert!(
        splits.len() == 3,
        "The number of status line splits should be 3"
    );
    Ok(StatusLine {
        protocol: splits[0],
        status: splits[1],
        message: splits[2],
    })
}

pub async fn read_headers<'a, S>(
    socket: &mut S,
    buf: &'a mut String,
) -> Result<Vec<Header<'a>>, io::Error>
where
    S: AsyncBufRead + Unpin,
{
    let mut off = buf.len();
    let mut headers = Vec::new();
    loop {
        let size = socket.read_line(buf).await?;
        if size < 3 {
            break;
        }
        headers.push((off, off + size - 1));
        off = buf.len();
    }
    // let s = buf.as_str();
    Ok(headers
        .iter()
        .map(|(start, end)| {
            let splits = buf[*start..*end].splitn(2, ':').collect::<Vec<_>>();
            Header {
                name: splits[0].trim(),
                value: splits[1].trim(),
            }
        })
        .collect())
}
