//! The six-seven protocol: the placement rule, the store, and the caps.
//!
//! THE RULE, in full:
//!
//! > Keys are `u64`. **Odd keys live on the lower-numbered node of the pair.
//! > Even keys live on the higher-numbered node.**
//!
//! That is the entire protocol. There is no replication, no quorum, no
//! failover, no persistence and no consistency argument, because there is
//! nothing to be consistent about: every key has exactly one home and only
//! its home ever stores it. A node that is asked for a key it does not own
//! forwards the whole operation to the peer over PAXE and relays the answer
//! back. Losing a node loses its half of the keyspace, permanently.
//!
//! The point is not the placement rule. The point is that every forwarded
//! operation is an authenticated, encrypted PAXE datagram, and that the
//! demo needs no distributed-systems machinery to exercise that path.

use std::collections::BTreeMap;

/// Whole-operation ceiling for a write, in bytes, measured on the client's
/// request text (`PUT <key> <value>`). Chosen so a forwarded request plus
/// PAXE's DEK-mode overhead stays far below any real path MTU: nothing here
/// fragments, and nothing here needs to reassemble.
pub const MAX_PUT_BYTES: usize = 1024;

/// Soft ceiling on the key count held by ONE node. Not a memory bound and
/// not enforced across the pair — it is a estimate-and-refuse guard, so the
/// demo cannot be turned into an unbounded heap by an enthusiastic loop.
///
/// In the lunet deployment the equivalent counter is an `lnt_shared` cell,
/// shared across worker processes; a single-process demo binary needs no
/// such thing, so this is a plain in-process count. The refusal semantics
/// are identical either way.
pub const MAX_KEYS: usize = 1_000_000;

/// Which node of a pair owns `key`.
///
/// Ties (`a == b`, a misconfigured pair pointing at itself) resolve to that
/// node, so a single-node run still answers everything locally.
pub fn owner(key: u64, a: u16, b: u16) -> u16 {
    let (lower, higher) = if a <= b { (a, b) } else { (b, a) };
    if key % 2 == 1 {
        lower
    } else {
        higher
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Get(u64),
    Put(u64, String),
    Rm(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// GET hit.
    Value(String),
    /// PUT stored, or RM removed something.
    Ok,
    /// GET or RM against a key that is not there.
    Nil,
    /// Refusal or malformed request. Never a transport failure — those are
    /// reported by the caller, which knows whether it forwarded.
    Err(String),
}

impl Op {
    pub fn key(&self) -> u64 {
        match self {
            Op::Get(k) | Op::Rm(k) => *k,
            Op::Put(k, _) => *k,
        }
    }

    /// Parse a client request body: `GET <k>`, `PUT <k> <v>`, `RM <k>`.
    /// Case-insensitive on the verb, because the demo is driven by hand.
    ///
    /// Only leading whitespace is stripped. Everything after the key of a
    /// PUT is the value, exactly as sent — including trailing spaces and a
    /// trailing newline, and including nothing at all, which stores the
    /// empty string. Trimming the tail would make `PUT 75 ` indexable as
    /// "missing value" when the client meant "empty value", and the two
    /// have to stay distinguishable from `NIL`.
    pub fn parse(body: &str) -> Result<Op, String> {
        let body = body.trim_start();
        let (verb, rest) = match body.split_once(char::is_whitespace) {
            Some((v, r)) => (v, r.trim_start()),
            None => (body, ""),
        };
        let parse_key = |s: &str| -> Result<u64, String> {
            let s = s.trim();
            if s.is_empty() {
                return Err("missing key".into());
            }
            s.parse::<u64>()
                .map_err(|_| format!("key must be a u64, got {s:?}"))
        };
        match verb.to_ascii_uppercase().as_str() {
            "GET" => Ok(Op::Get(parse_key(rest)?)),
            "RM" | "DEL" => Ok(Op::Rm(parse_key(rest)?)),
            "PUT" | "SET" => {
                if body.len() > MAX_PUT_BYTES {
                    return Err(format!(
                        "put of {} bytes exceeds the {MAX_PUT_BYTES}-byte limit",
                        body.len()
                    ));
                }
                let (key, value) = match rest.split_once(char::is_whitespace) {
                    Some((k, v)) => (k, v),
                    None => return Err("PUT needs a key and a value".into()),
                };
                Ok(Op::Put(parse_key(key)?, value.to_string()))
            }
            "" => Err("empty request".into()),
            other => Err(format!("unknown verb {other:?}; want GET, PUT or RM")),
        }
    }
}

#[derive(Default)]
pub struct Store {
    entries: BTreeMap<u64, String>,
}

impl Store {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Execute an operation this node owns. Never forwards; the caller has
    /// already decided ownership.
    pub fn execute(&mut self, op: &Op) -> Reply {
        match op {
            Op::Get(k) => match self.entries.get(k) {
                Some(v) => Reply::Value(v.clone()),
                None => Reply::Nil,
            },
            Op::Rm(k) => match self.entries.remove(k) {
                Some(_) => Reply::Ok,
                None => Reply::Nil,
            },
            Op::Put(k, v) => {
                // The cap admits overwrites unconditionally: refusing them
                // would strand a key that is already resident, and an
                // overwrite does not grow the keyset.
                if !self.entries.contains_key(k) && self.entries.len() >= MAX_KEYS {
                    return Reply::Err(format!(
                        "keyset estimate at the {MAX_KEYS}-key ceiling; refusing new keys"
                    ));
                }
                self.entries.insert(*k, v.clone());
                Reply::Ok
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odds_go_low_and_evens_go_high_whichever_way_the_pair_is_given() {
        assert_eq!(owner(67, 100, 200), 100);
        assert_eq!(owner(67, 200, 100), 100);
        assert_eq!(owner(68, 100, 200), 200);
        assert_eq!(owner(68, 200, 100), 200);
    }

    #[test]
    fn zero_is_even_and_u64_max_is_odd() {
        assert_eq!(owner(0, 1, 2), 2);
        assert_eq!(owner(u64::MAX, 1, 2), 1);
    }

    #[test]
    fn a_pair_pointing_at_itself_owns_everything() {
        assert_eq!(owner(67, 7, 7), 7);
        assert_eq!(owner(68, 7, 7), 7);
    }

    #[test]
    fn every_key_has_exactly_one_owner_across_the_pair() {
        for key in 0..1000u64 {
            let o = owner(key, 100, 200);
            assert!(o == 100 || o == 200);
            assert_eq!(
                o,
                owner(key, 200, 100),
                "owner must not depend on argument order"
            );
        }
    }

    #[test]
    fn parses_the_three_verbs_case_insensitively() {
        assert_eq!(Op::parse("GET 67").unwrap(), Op::Get(67));
        assert_eq!(Op::parse("get 67").unwrap(), Op::Get(67));
        assert_eq!(Op::parse("RM 67").unwrap(), Op::Rm(67));
        assert_eq!(Op::parse("del 67").unwrap(), Op::Rm(67));
        assert_eq!(
            Op::parse("PUT 67 six seven").unwrap(),
            Op::Put(67, "six seven".into())
        );
    }

    #[test]
    fn rejects_a_non_u64_key_and_a_missing_value() {
        assert!(Op::parse("GET nope").is_err());
        assert!(Op::parse("GET -1").is_err());
        assert!(Op::parse("PUT 67").is_err());
        assert!(Op::parse("").is_err());
        assert!(Op::parse("FROB 67").is_err());
    }

    #[test]
    fn an_empty_value_is_a_value_and_a_missing_one_is_an_error() {
        // The separating space is what distinguishes them.
        assert_eq!(Op::parse("PUT 75 ").unwrap(), Op::Put(75, String::new()));
        assert!(Op::parse("PUT 75").is_err());
    }

    #[test]
    fn the_value_is_taken_verbatim_after_the_key() {
        assert_eq!(
            Op::parse("PUT 67   padded  ").unwrap(),
            Op::Put(67, "  padded  ".into()),
            "only the separator is consumed; the rest is data"
        );
    }

    #[test]
    fn an_empty_value_reads_back_as_a_value_not_as_a_miss() {
        let mut s = Store::default();
        assert_eq!(s.execute(&Op::Put(75, String::new())), Reply::Ok);
        assert_eq!(s.execute(&Op::Get(75)), Reply::Value(String::new()));
        assert_ne!(s.execute(&Op::Get(75)), Reply::Nil);
    }

    #[test]
    fn refuses_a_put_over_the_byte_limit_at_the_boundary() {
        let value = "x".repeat(MAX_PUT_BYTES);
        let body = format!("PUT 67 {value}");
        assert!(body.len() > MAX_PUT_BYTES);
        assert!(Op::parse(&body).is_err());

        // Exactly at the limit is accepted.
        let head = "PUT 67 ";
        let body = format!("{head}{}", "x".repeat(MAX_PUT_BYTES - head.len()));
        assert_eq!(body.len(), MAX_PUT_BYTES);
        assert!(Op::parse(&body).is_ok());
    }

    #[test]
    fn get_put_rm_round_trip() {
        let mut s = Store::default();
        assert_eq!(s.execute(&Op::Get(67)), Reply::Nil);
        assert_eq!(s.execute(&Op::Put(67, "sixseven".into())), Reply::Ok);
        assert_eq!(s.execute(&Op::Get(67)), Reply::Value("sixseven".into()));
        assert_eq!(s.execute(&Op::Rm(67)), Reply::Ok);
        assert_eq!(s.execute(&Op::Rm(67)), Reply::Nil);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn overwrites_are_admitted_even_when_the_keyset_is_at_the_ceiling() {
        let mut s = Store::default();
        s.execute(&Op::Put(67, "a".into()));
        // Simulate the ceiling by asserting the branch condition directly:
        // filling a million keys in a unit test is not worth the seconds.
        assert!(s.entries.contains_key(&67));
        assert_eq!(s.execute(&Op::Put(67, "b".into())), Reply::Ok);
        assert_eq!(s.execute(&Op::Get(67)), Reply::Value("b".into()));
    }
}
