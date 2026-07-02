//! Minimal HTTP/1.1 client for `check-server`.
//!
//! `check-server` only needs a one-shot `GET /` and the status line plus a couple of
//! headers (`Location`, `Alt-Svc`). This module hand-rolls that subset over any
//! `Read + Write` stream rather than pulling in an HTTP library, since the TLS check
//! (check 5) already requires a hand-driven `BoringSSL` stream.

use std::io::{Read, Write};

use anyhow::{Context, Result, bail};

/// Cap on how many response-head bytes we buffer before giving up.
const MAX_HEAD: usize = 64 * 1024;

/// A parsed HTTP response head. The body is never read.
pub struct HttpResponse {
    /// HTTP status code (e.g. 200, 301).
    pub status: u16,
    /// Headers with lowercased names.
    headers: Vec<(String, String)>,
}

impl HttpResponse {
    /// Case-insensitive lookup of the first value for a header name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Send a minimal HTTP/1.1 `GET /` and parse the response head.
///
/// The stream is expected to already be connected (plain TCP or an established TLS
/// session). The connection is closed by the server via `Connection: close`.
///
/// # Errors
///
/// Returns an error on I/O failure, a non-UTF-8 head, a malformed status line, or a
/// response head that exceeds `MAX_HEAD` without terminating.
pub fn get<S: Read + Write>(stream: &mut S, host: &str) -> Result<HttpResponse> {
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: slt-check\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
    .context("failed to write HTTP request")?;
    stream.flush().context("failed to flush HTTP request")?;

    // Read until the header terminator, EOF, or the cap.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if find_header_end(&buf).is_some() {
            break;
        }
        if buf.len() >= MAX_HEAD {
            bail!("HTTP response head exceeded {MAX_HEAD} bytes");
        }
        let n = stream
            .read(&mut chunk)
            .context("failed to read HTTP response")?;
        if n == 0 {
            break; // EOF before terminator; parse_head will reject if incomplete.
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    parse_head(&buf)
}

/// Index of the `\r\n\r\n` header terminator, if present.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse `buf[..terminator]` into an [`HttpResponse`].
fn parse_head(buf: &[u8]) -> Result<HttpResponse> {
    let end = find_header_end(buf).context("response ended before headers were complete")?;
    let head = std::str::from_utf8(&buf[..end]).context("HTTP response head is not valid UTF-8")?;

    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("empty HTTP response")?;
    // `HTTP/1.1 200 OK`
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        bail!("invalid status line: {status_line:?}");
    }
    let code = parts.next().context("missing HTTP status code")?;
    let status = code
        .parse::<u16>()
        .with_context(|| format!("invalid HTTP status code: {code}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Ok(HttpResponse { status, headers })
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};

    use super::*;

    /// An in-memory stream: captures written bytes and serves a canned response.
    struct MockStream {
        sent: Vec<u8>,
        resp: Vec<u8>,
        pos: usize,
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.resp.len() {
                return Ok(0);
            }
            let n = (self.resp.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.resp[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parses_redirect_with_location() {
        let mut s = MockStream {
            sent: Vec::new(),
            resp: b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\n\r\nignored body"
                .to_vec(),
            pos: 0,
        };
        let resp = get(&mut s, "example.com").unwrap();
        assert_eq!(resp.status, 301);
        assert_eq!(resp.header("Location"), Some("https://example.com/"));
        // Request line + Host header were sent.
        let sent = std::str::from_utf8(&s.sent).unwrap();
        assert!(sent.starts_with("GET / HTTP/1.1\r\n"));
        assert!(sent.contains("Host: example.com\r\n"));
    }

    #[test]
    fn parses_alt_svc_header_case_insensitively() {
        let mut s = MockStream {
            sent: Vec::new(),
            resp: b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nALT-SVC: h3=\":443\"; ma=2592000\r\n\r\n"
                .to_vec(),
            pos: 0,
        };
        let resp = get(&mut s, "example.com").unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("alt-svc"), Some("h3=\":443\"; ma=2592000"));
    }

    #[test]
    fn rejects_non_http_status_line() {
        let mut s = MockStream {
            sent: Vec::new(),
            resp: b"NOTHTTP 200\r\n\r\n".to_vec(),
            pos: 0,
        };
        assert!(get(&mut s, "example.com").is_err());
    }

    #[test]
    fn rejects_incomplete_headers() {
        let mut s = MockStream {
            sent: Vec::new(),
            resp: b"HTTP/1.1 200 OK\r\nAlt-Svc: h3".to_vec(), // no terminator
            pos: 0,
        };
        assert!(get(&mut s, "example.com").is_err());
    }

    #[test]
    fn missing_header_returns_none() {
        let mut s = MockStream {
            sent: Vec::new(),
            resp: b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
            pos: 0,
        };
        let resp = get(&mut s, "example.com").unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(resp.header("alt-svc"), None);
    }
}
