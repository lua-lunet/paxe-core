//! Just enough STOMP 1.2 to drive the demo from `ncat`.
//!
//! A frame is a command line, zero or more `header:value` lines, a blank
//! line, then the body, terminated by NUL:
//!
//! ```text
//! SEND\n
//! destination:/queue/kv\n
//! \n
//! GET 67\0
//! ```
//!
//! Deliberately partial. No heart-beating, no transactions, no content-length
//! (the body runs to the NUL, so a body containing NUL cannot be sent — which
//! is fine, values here are text). Header unescaping covers the four sequences
//! STOMP 1.2 defines and nothing else. This is a toy client surface for a toy
//! protocol; see README.md.

use std::io::{self, BufRead};

/// Longest frame accepted from a client. Anything larger is a protocol
/// error rather than an allocation: an unterminated frame must not let a
/// client grow the server's memory without bound.
pub const MAX_FRAME_BYTES: usize = 8 * 1024;

pub struct Frame {
    pub command: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Frame {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Serialize for the wire. Header values are escaped per STOMP 1.2.
    pub fn encode(command: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut out = String::with_capacity(64 + body.len());
        out.push_str(command);
        out.push('\n');
        for (k, v) in headers {
            out.push_str(&escape(k));
            out.push(':');
            out.push_str(&escape(v));
            out.push('\n');
        }
        out.push('\n');
        out.push_str(body);
        let mut bytes = out.into_bytes();
        bytes.push(0);
        bytes
    }
}

/// Read one NUL-terminated frame. `Ok(None)` is a clean end of stream.
///
/// Leading newlines between frames are STOMP's heart-beat filler and are
/// skipped; a bare newline is not an empty frame.
pub fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Frame>> {
    // Bounded by hand rather than with `Read::take`, which consumes the
    // reader: this function is called in a loop on one long-lived stream.
    let mut raw = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            if raw.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream ended mid-frame: no terminating NUL",
            ));
        }
        match available.iter().position(|&b| b == 0) {
            Some(at) => {
                raw.extend_from_slice(&available[..at]);
                reader.consume(at + 1);
                break;
            }
            None => {
                let taken = available.len();
                raw.extend_from_slice(available);
                reader.consume(taken);
                if raw.len() > MAX_FRAME_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("frame exceeded {MAX_FRAME_BYTES} bytes"),
                    ));
                }
            }
        }
    }

    let text = String::from_utf8(raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let text = text.trim_start_matches(['\n', '\r']);
    if text.is_empty() {
        // Heart-beat filler only; ask the caller to read again.
        return read_frame(reader);
    }

    let (head, body) = match text.split_once("\n\n") {
        Some(pair) => pair,
        // A frame with no blank line has no body. Tolerated: ncat users
        // forget the blank line constantly.
        None => (text, ""),
    };

    let mut lines = head.split('\n');
    let command = lines
        .next()
        .unwrap_or_default()
        .trim_end_matches('\r')
        .to_string();
    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((unescape(k), unescape(v)));
        }
    }

    Ok(Some(Frame {
        command,
        headers,
        body: body.to_string(),
    }))
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            ':' => out.push_str("\\c"),
            _ => out.push(c),
        }
    }
    out
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some('c') => out.push(':'),
            Some('\\') => out.push('\\'),
            // Undefined escape: STOMP 1.2 says this is a fatal protocol
            // error. A toy server keeps the byte and carries on.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn parse(input: &str) -> Frame {
        let mut reader = BufReader::new(input.as_bytes());
        read_frame(&mut reader).unwrap().unwrap()
    }

    #[test]
    fn parses_command_headers_and_body() {
        let f = parse("SEND\ndestination:/queue/kv\nreceipt:r1\n\nGET 67\0");
        assert_eq!(f.command, "SEND");
        assert_eq!(f.header("destination"), Some("/queue/kv"));
        assert_eq!(f.header("receipt"), Some("r1"));
        assert_eq!(f.body, "GET 67");
    }

    #[test]
    fn tolerates_a_missing_blank_line_and_reports_no_body() {
        let f = parse("DISCONNECT\nreceipt:bye\0");
        assert_eq!(f.command, "DISCONNECT");
        assert_eq!(f.header("receipt"), Some("bye"));
        assert_eq!(f.body, "");
    }

    #[test]
    fn skips_heartbeat_newlines_between_frames() {
        let f = parse("\n\n\nSEND\n\nPUT 1 x\0");
        assert_eq!(f.command, "SEND");
        assert_eq!(f.body, "PUT 1 x");
    }

    #[test]
    fn end_of_stream_is_none_not_an_error() {
        let mut reader = BufReader::new(&b""[..]);
        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn an_unterminated_frame_is_an_error_not_an_unbounded_read() {
        let mut reader = BufReader::new(&b"SEND\n\nno nul here"[..]);
        assert!(read_frame(&mut reader).is_err());
    }

    #[test]
    fn header_escapes_round_trip() {
        let f = parse("SEND\nk\\cv:a\\nb\n\nbody\0");
        assert_eq!(f.header("k:v"), Some("a\nb"));
        let bytes = Frame::encode("MESSAGE", &[("k:v", "a\nb")], "body");
        assert_eq!(bytes.last(), Some(&0));
        assert!(String::from_utf8_lossy(&bytes).contains("k\\cv:a\\nb"));
    }
}
