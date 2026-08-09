//! The node-to-node payload carried inside PAXE frames.
//!
//! Text, newline-free, one line per message:
//!
//! ```text
//! REQ <corr> GET 67
//! REQ <corr> PUT 68 six seven
//! RSP <corr> VAL six seven
//! RSP <corr> OK
//! RSP <corr> NIL
//! RSP <corr> ERR some text
//! ```
//!
//! No length prefix, no framing and no version byte: PAXE already delivers
//! whole authenticated datagrams or nothing at all, so there is no partial
//! read to resynchronise against and no attacker-controlled bytes to parse
//! defensively — `open()` rejected those before this module is reached.
//!
//! `corr` is a correlation id minted by the forwarding node. It is unique
//! per in-flight request on that node and is echoed verbatim; the peer
//! never interprets it.

use crate::kv::{Op, Reply};

pub enum Peer {
    Request { corr: u64, op: Op },
    Response { corr: u64, reply: Reply },
}

fn parse_key(s: &str) -> Result<u64, String> {
    s.trim()
        .parse::<u64>()
        .map_err(|_| format!("key must be a u64, got {s:?}"))
}

impl Peer {
    pub fn encode(&self) -> String {
        match self {
            Peer::Request { corr, op } => {
                let body = match op {
                    Op::Get(k) => format!("GET {k}"),
                    Op::Rm(k) => format!("RM {k}"),
                    Op::Put(k, v) => format!("PUT {k} {v}"),
                };
                format!("REQ {corr} {body}")
            }
            Peer::Response { corr, reply } => {
                let body = match reply {
                    Reply::Value(v) => format!("VAL {v}"),
                    Reply::Ok => "OK".to_string(),
                    Reply::Nil => "NIL".to_string(),
                    Reply::Err(e) => format!("ERR {e}"),
                };
                format!("RSP {corr} {body}")
            }
        }
    }

    pub fn decode(text: &str) -> Result<Peer, String> {
        let mut parts = text.splitn(3, ' ');
        let kind = parts.next().unwrap_or_default();
        let corr = parts
            .next()
            .ok_or("missing correlation id")?
            .parse::<u64>()
            .map_err(|_| "correlation id must be a u64".to_string())?;
        let rest = parts.next().unwrap_or("");
        match kind {
            // Parsed here rather than delegated to `Op::parse`, which trims
            // its input: that is right for a human typing into `ncat`, but
            // on this hop the value is already-decided data and a trailing
            // space — or an empty value — must survive the round trip
            // byte-for-byte.
            "REQ" => {
                let (verb, tail) = rest.split_once(' ').unwrap_or((rest, ""));
                let op = match verb.to_ascii_uppercase().as_str() {
                    "GET" => Op::Get(parse_key(tail)?),
                    "RM" => Op::Rm(parse_key(tail)?),
                    "PUT" => {
                        let (key, value) = tail.split_once(' ').unwrap_or((tail, ""));
                        Op::Put(parse_key(key)?, value.to_string())
                    }
                    other => return Err(format!("unknown verb {other:?} in a peer request")),
                };
                Ok(Peer::Request { corr, op })
            }
            "RSP" => {
                let (tag, body) = match rest.split_once(' ') {
                    Some((t, b)) => (t, b),
                    None => (rest, ""),
                };
                let reply = match tag {
                    "VAL" => Reply::Value(body.to_string()),
                    "OK" => Reply::Ok,
                    "NIL" => Reply::Nil,
                    "ERR" => Reply::Err(body.to_string()),
                    other => return Err(format!("unknown response tag {other:?}")),
                };
                Ok(Peer::Response { corr, reply })
            }
            other => Err(format!("unknown peer message kind {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(p: Peer) -> Peer {
        Peer::decode(&p.encode()).expect("decode")
    }

    #[test]
    fn requests_round_trip_including_values_with_spaces() {
        let cases = [
            Op::Get(67),
            Op::Rm(68),
            Op::Put(67, "six seven".into()),
            Op::Put(68, String::new()),
        ];
        for op in cases {
            match round_trip(Peer::Request {
                corr: 9,
                op: op.clone(),
            }) {
                Peer::Request { corr, op: got } => {
                    assert_eq!(corr, 9);
                    assert_eq!(got, op);
                }
                _ => panic!("expected a request"),
            }
        }
    }

    #[test]
    fn responses_round_trip() {
        let cases = [
            Reply::Value("six seven".into()),
            Reply::Ok,
            Reply::Nil,
            Reply::Err("nope".into()),
        ];
        for reply in cases {
            match round_trip(Peer::Response {
                corr: 12,
                reply: reply.clone(),
            }) {
                Peer::Response { corr, reply: got } => {
                    assert_eq!(corr, 12);
                    assert_eq!(got, reply);
                }
                _ => panic!("expected a response"),
            }
        }
    }

    #[test]
    fn malformed_input_is_an_error_never_a_panic() {
        for bad in [
            "",
            "REQ",
            "REQ x GET 1",
            "RSP 1 WAT",
            "NOPE 1 OK",
            "REQ 1 FROB 2",
        ] {
            assert!(Peer::decode(bad).is_err(), "expected error for {bad:?}");
        }
    }

    #[test]
    fn an_empty_value_survives_the_round_trip_as_an_empty_value() {
        match round_trip(Peer::Response {
            corr: 1,
            reply: Reply::Value(String::new()),
        }) {
            Peer::Response { reply, .. } => assert_eq!(reply, Reply::Value(String::new())),
            _ => panic!("expected a response"),
        }
    }
}
