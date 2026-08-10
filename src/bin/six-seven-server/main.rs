//! six-seven-server — a two-node key-value store whose only interesting
//! property is that every node-to-node hop is a PAXE datagram.
//!
//! It exists for the same reason `vrr-core` ships a Maelstrom node: to run
//! the core over a real socket, against a real peer, doing real work, so
//! the library is exercised as a consumer would exercise it rather than
//! only by its own tests. Unlike that harness there is no Jepsen, no
//! nemesis and no verdict — PAXE is a datagram codec, not a consensus
//! protocol, and there is nothing here for a linearizability checker to
//! check. See README.md.
//!
//! ARCHITECTURE. `KeyStore` is `!Send`/`!Sync` by construction — every
//! `StoredKey` holds a `NonNull` into guarded libsodium memory — so key
//! material cannot be shared across threads even if someone wanted to.
//! That settles the design: producer threads (one per client connection,
//! one for the UDP socket, one ticker) feed a single channel, and one core
//! thread owns the keystore, the store and the pending table and is the
//! only writer to any client socket. No locks anywhere.
//!
//! WHAT THIS IS NOT. No persistence, no replication, no retries, no crash
//! recovery. A lost datagram fails one request after a timeout. A dead node
//! takes its half of the keyspace with it. That is all deliberate: the
//! placement rule is a joke, and the joke is load-bearing — it keeps the
//! demo small enough that the PAXE call sites are the only thing to read.

#![deny(unsafe_code)]

mod kv;
mod peer;
mod stomp;

use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use paxe::dek;
use paxe::keystore::{Epoch, KeyStore};
use paxe::sodium;

use crate::kv::{Op, Reply, Store};
use crate::peer::Peer;
use crate::stomp::Frame;

/// PAXE channel for peer traffic. Channels 1-99 are reserved system
/// channels, so the obvious choice of 67 is not available; 6767 is the
/// nearest thing to the joke that the protocol permits.
const PEER_CHANNEL: u16 = 6767;

/// The single key epoch this demo installs. Rotation is a PAXE feature and
/// a deliberate non-feature here: one epoch, provisioned identically on
/// both nodes from the command line.
const EPOCH: u8 = 0;

/// How long a forwarded request waits for its peer before the client is
/// told the hop failed. There are no retries — one datagram, one chance.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Core-loop wakeup, which bounds how late a timeout can fire.
const TICK: Duration = Duration::from_millis(250);

/// Largest datagram we will try to read. PAXE's own ceiling is one UDP
/// payload; anything bigger was not produced by a peer of ours.
const MAX_DATAGRAM: usize = 65_507;

enum Event {
    ClientUp(u64, TcpStream),
    ClientFrame(u64, Frame),
    ClientDown(u64),
    Datagram(Vec<u8>),
    Tick,
}

struct Pending {
    conn: u64,
    receipt: Option<String>,
    deadline: Instant,
}

struct Config {
    id: u16,
    stomp: SocketAddr,
    paxe: SocketAddr,
    peer_id: u16,
    peer_addr: SocketAddr,
    key: [u8; 32],
}

const USAGE: &str = "\
six-seven-server — the six-seven protocol, over PAXE

USAGE:
  six-seven-server --id <u16> --stomp <addr> --paxe <addr> \\
                   --peer-id <u16> --peer <addr> --key <64 hex chars>

The two nodes form a pair. Odd keys live on the lower-numbered node, even
keys on the higher; a node asked for a key it does not own forwards the
operation to its peer inside a PAXE frame and relays the answer back.

Both nodes must be given the SAME --key. It is the shared secret for the
link, 32 bytes as 64 hex characters.

EXAMPLE (two terminals):
  six-seven-server --id 100 --stomp 127.0.0.1:6167 --paxe 127.0.0.1:6100 \\
                   --peer-id 200 --peer 127.0.0.1:6200 --key $KEY
  six-seven-server --id 200 --stomp 127.0.0.1:6267 --paxe 127.0.0.1:6200 \\
                   --peer-id 100 --peer 127.0.0.1:6100 --key $KEY
";

fn main() {
    let config = match parse_args() {
        Ok(c) => c,
        Err(message) => {
            eprintln!("{message}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(message) = run(config) {
        eprintln!("six-seven-server: {message}");
        std::process::exit(1);
    }
}

fn parse_args() -> Result<Config, String> {
    let mut args = std::env::args().skip(1);
    let mut id = None;
    let mut stomp = None;
    let mut paxe = None;
    let mut peer_id = None;
    let mut peer_addr = None;
    let mut key_hex = None;

    while let Some(flag) = args.next() {
        if flag == "-h" || flag == "--help" {
            println!("{USAGE}");
            std::process::exit(0);
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--id" => id = Some(parse_u16(&value, "--id")?),
            "--peer-id" => peer_id = Some(parse_u16(&value, "--peer-id")?),
            "--stomp" => stomp = Some(parse_addr(&value, "--stomp")?),
            "--paxe" => paxe = Some(parse_addr(&value, "--paxe")?),
            "--peer" => peer_addr = Some(parse_addr(&value, "--peer")?),
            "--key" => key_hex = Some(value),
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    // A generic fn, not a closure: a closure would be monomorphised to the
    // type of its first call site and every later flag would fail to typecheck.
    fn required<T>(name: &str, v: Option<T>) -> Result<T, String> {
        v.ok_or_else(|| format!("{name} is required"))
    }
    let id = required("--id", id)?;
    let peer_id = required("--peer-id", peer_id)?;
    if id == peer_id {
        return Err("--id and --peer-id must differ: a pair needs two nodes".into());
    }
    Ok(Config {
        id,
        stomp: required("--stomp", stomp)?,
        paxe: required("--paxe", paxe)?,
        peer_id,
        peer_addr: required("--peer", peer_addr)?,
        key: parse_key(&required("--key", key_hex)?)?,
    })
}

fn parse_u16(value: &str, flag: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("{flag} must be 0-65535, got {value:?}"))
}

fn parse_addr(value: &str, flag: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| format!("{flag} must be host:port, got {value:?}"))
}

fn parse_key(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!(
            "--key must be exactly 64 hex characters (32 bytes), got {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &hex[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("--key is not hexadecimal at offset {}", i * 2))?;
    }
    Ok(out)
}

fn run(config: Config) -> Result<(), String> {
    // Fail before binding anything if this host cannot do hardware
    // AES-256-GCM: PAXE reports that as an error rather than dropping to a
    // software path, and a demo that silently could not encrypt would be
    // worse than one that refuses to start.
    sodium::init().map_err(|e| format!("libsodium init failed: {e}"))?;
    sodium::require_aes_gcm().map_err(|e| format!("AES-256-GCM hardware path unavailable: {e}"))?;

    let epoch = Epoch::new(EPOCH).map_err(|e| e.to_string())?;
    let mut store = KeyStore::new(config.id).map_err(|e| e.to_string())?;
    store
        .install(config.peer_id, epoch, &config.key)
        .map_err(|e| format!("installing the link key failed: {e}"))?;

    let socket =
        UdpSocket::bind(config.paxe).map_err(|e| format!("binding --paxe {}: {e}", config.paxe))?;
    let listener = TcpListener::bind(config.stomp)
        .map_err(|e| format!("binding --stomp {}: {e}", config.stomp))?;

    let (tx, rx) = mpsc::channel();

    // UDP reader.
    {
        let socket = socket
            .try_clone()
            .map_err(|e| format!("cloning the UDP socket: {e}"))?;
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((n, _from)) => {
                        // The sender address is deliberately ignored. PAXE
                        // authenticates the frame's fromId; an IP is not
                        // evidence of anything and checking it would imply
                        // it was.
                        if tx.send(Event::Datagram(buf[..n].to_vec())).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        eprintln!("udp recv: {e}");
                        return;
                    }
                }
            }
        });
    }

    // TCP acceptor, one reader thread per connection.
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut next_id = 0u64;
            for stream in listener.incoming() {
                let stream = match stream {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("accept: {e}");
                        continue;
                    }
                };
                next_id += 1;
                let conn = next_id;
                let writer = match stream.try_clone() {
                    Ok(w) => w,
                    Err(e) => {
                        eprintln!("clone client socket: {e}");
                        continue;
                    }
                };
                if tx.send(Event::ClientUp(conn, writer)).is_err() {
                    return;
                }
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream);
                    loop {
                        match stomp::read_frame(&mut reader) {
                            Ok(Some(frame)) => {
                                if tx.send(Event::ClientFrame(conn, frame)).is_err() {
                                    return;
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                eprintln!("client {conn}: {e}");
                                break;
                            }
                        }
                    }
                    let _ = tx.send(Event::ClientDown(conn));
                });
            }
        });
    }

    // Ticker: bounds how late a forward timeout can fire.
    {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(TICK);
            if tx.send(Event::Tick).is_err() {
                return;
            }
        });
    }

    eprintln!(
        "six-seven-server node {} — STOMP on {}, PAXE on {} (channel {}), peer {} at {}",
        config.id, config.stomp, config.paxe, PEER_CHANNEL, config.peer_id, config.peer_addr
    );
    eprintln!(
        "  odd keys -> node {}, even keys -> node {}",
        config.id.min(config.peer_id),
        config.id.max(config.peer_id)
    );

    core_loop(config, store, epoch, socket, rx);
    Ok(())
}

fn core_loop(
    config: Config,
    store: KeyStore,
    epoch: Epoch,
    socket: UdpSocket,
    rx: mpsc::Receiver<Event>,
) {
    let mut kv = Store::default();
    let mut clients: HashMap<u64, TcpStream> = HashMap::new();
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut next_corr = 0u64;

    while let Ok(event) = rx.recv() {
        match event {
            Event::ClientUp(conn, stream) => {
                clients.insert(conn, stream);
            }
            Event::ClientDown(conn) => {
                clients.remove(&conn);
                // Answers for a departed client have nowhere to go; drop
                // the entries rather than leaking them until timeout.
                pending.retain(|_, p| p.conn != conn);
            }
            Event::ClientFrame(conn, frame) => handle_client_frame(
                &config,
                &store,
                epoch,
                &socket,
                &mut kv,
                &mut clients,
                &mut pending,
                &mut next_corr,
                conn,
                frame,
            ),
            Event::Datagram(bytes) => handle_datagram(
                &config,
                &store,
                epoch,
                &socket,
                &mut kv,
                &mut clients,
                &mut pending,
                &bytes,
            ),
            Event::Tick => {
                let now = Instant::now();
                let expired: Vec<u64> = pending
                    .iter()
                    .filter(|(_, p)| p.deadline <= now)
                    .map(|(corr, _)| *corr)
                    .collect();
                for corr in expired {
                    if let Some(p) = pending.remove(&corr) {
                        reply_to_client(
                            &mut clients,
                            p.conn,
                            p.receipt.as_deref(),
                            &Reply::Err(format!(
                                "peer {} did not answer within {:?}",
                                config.peer_id, FORWARD_TIMEOUT
                            )),
                        );
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_client_frame(
    config: &Config,
    store: &KeyStore,
    epoch: Epoch,
    socket: &UdpSocket,
    kv: &mut Store,
    clients: &mut HashMap<u64, TcpStream>,
    pending: &mut HashMap<u64, Pending>,
    next_corr: &mut u64,
    conn: u64,
    frame: Frame,
) {
    let receipt = frame.header("receipt").map(str::to_string);
    match frame.command.to_ascii_uppercase().as_str() {
        "CONNECT" | "STOMP" => {
            write_frame(
                clients,
                conn,
                &Frame::encode(
                    "CONNECTED",
                    &[("version", "1.2"), ("server", "six-seven-server/0.1")],
                    "",
                ),
            );
        }
        // Accepted and ignored: replies go back on the same connection
        // regardless, so a subscription changes nothing. Answering ERROR
        // instead would break every stock STOMP client for no gain.
        "SUBSCRIBE" | "UNSUBSCRIBE" => {
            if let Some(r) = receipt {
                write_frame(
                    clients,
                    conn,
                    &Frame::encode("RECEIPT", &[("receipt-id", &r)], ""),
                );
            }
        }
        "DISCONNECT" => {
            if let Some(r) = receipt {
                write_frame(
                    clients,
                    conn,
                    &Frame::encode("RECEIPT", &[("receipt-id", &r)], ""),
                );
            }
            clients.remove(&conn);
        }
        "SEND" => {
            // Server introspection, deliberately not a KV operation: it
            // reports THIS node's half of the keyset against the ceiling
            // that PUT enforces, and is never forwarded. Asking the pair
            // for a global count would need a round trip to answer with a
            // number that is stale by the time it arrives.
            if frame.body.trim().eq_ignore_ascii_case("SIZE") {
                let reply = Reply::Value(format!(
                    "{} of {} keys on node {}",
                    kv.len(),
                    kv::MAX_KEYS,
                    config.id
                ));
                reply_to_client(clients, conn, receipt.as_deref(), &reply);
                return;
            }
            let op = match Op::parse(&frame.body) {
                Ok(op) => op,
                Err(e) => {
                    reply_to_client(clients, conn, receipt.as_deref(), &Reply::Err(e));
                    return;
                }
            };
            if kv::owner(op.key(), config.id, config.peer_id) == config.id {
                let reply = kv.execute(&op);
                reply_to_client(clients, conn, receipt.as_deref(), &reply);
                return;
            }
            // Not ours: forward the whole operation to the peer inside a
            // PAXE frame and answer the client when the peer answers us.
            *next_corr += 1;
            let corr = *next_corr;
            let message = Peer::Request { corr, op }.encode();
            if let Err(e) = send_to_peer(config, store, epoch, socket, &message) {
                reply_to_client(clients, conn, receipt.as_deref(), &Reply::Err(e));
                return;
            }
            pending.insert(
                corr,
                Pending {
                    conn,
                    receipt,
                    deadline: Instant::now() + FORWARD_TIMEOUT,
                },
            );
        }
        other => {
            write_frame(
                clients,
                conn,
                &Frame::encode(
                    "ERROR",
                    &[("message", "unsupported command")],
                    &format!("six-seven-server does not implement {other}\n"),
                ),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_datagram(
    config: &Config,
    store: &KeyStore,
    epoch: Epoch,
    socket: &UdpSocket,
    kv: &mut Store,
    clients: &mut HashMap<u64, TcpStream>,
    pending: &mut HashMap<u64, Pending>,
    bytes: &[u8],
) {
    // Every rejection — malformed, wrong key, failed authentication — is
    // one opaque error by design: PAXE will not tell us which, so that a
    // caller cannot be turned into a decryption oracle. Counters are the
    // diagnostic channel.
    let (header, _flags, payload) = match dek::open(store, bytes) {
        Ok(opened) => opened,
        Err(_) => return,
    };
    if header.from_id != config.peer_id || header.channel != PEER_CHANNEL {
        // Authenticated, but not from our peer or not on our channel.
        return;
    }
    let text = match String::from_utf8(payload) {
        Ok(t) => t,
        Err(_) => return,
    };
    let message = match Peer::decode(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("peer sent an undecodable message: {e}");
            return;
        }
    };
    match message {
        Peer::Request { corr, op } => {
            // The peer only forwards what we own, but do not take its word
            // for it: a node that answered for a key it does not own would
            // silently split the keyspace in two.
            let reply = if kv::owner(op.key(), config.id, config.peer_id) == config.id {
                kv.execute(&op)
            } else {
                Reply::Err(format!(
                    "key {} does not belong to node {}",
                    op.key(),
                    config.id
                ))
            };
            let response = Peer::Response { corr, reply }.encode();
            if let Err(e) = send_to_peer(config, store, epoch, socket, &response) {
                eprintln!("answering peer request {corr}: {e}");
            }
        }
        Peer::Response { corr, reply } => {
            // A miss here is a late answer to a request we already timed
            // out, or a replay. Either way there is no client left to
            // tell, so it is dropped without ceremony.
            if let Some(p) = pending.remove(&corr) {
                reply_to_client(clients, p.conn, p.receipt.as_deref(), &reply);
            }
        }
    }
}

fn send_to_peer(
    config: &Config,
    store: &KeyStore,
    epoch: Epoch,
    socket: &UdpSocket,
    message: &str,
) -> Result<(), String> {
    // The one-recipient API always emits a standard frame.
    let frame = dek::seal(
        store,
        config.peer_id,
        PEER_CHANNEL,
        epoch,
        message.as_bytes(),
    )
    .map_err(|e| format!("sealing for peer {}: {e}", config.peer_id))?;
    socket
        .send_to(&frame, config.peer_addr)
        .map_err(|e| format!("sending to peer {}: {e}", config.peer_addr))?;
    Ok(())
}

/// Render a reply as the client-facing body and post it as a MESSAGE.
///
/// Deviation from STOMP, stated plainly: a `receipt` header on the request
/// comes back as `receipt-id` on this MESSAGE rather than as a separate
/// RECEIPT frame. One frame per request is far easier to read in `ncat`,
/// which is the only client this demo expects.
fn reply_to_client(
    clients: &mut HashMap<u64, TcpStream>,
    conn: u64,
    receipt: Option<&str>,
    reply: &Reply,
) {
    let body = match reply {
        Reply::Value(v) => v.clone(),
        Reply::Ok => "OK".to_string(),
        Reply::Nil => "NIL".to_string(),
        Reply::Err(e) => format!("ERR {e}"),
    };
    let mut headers: Vec<(&str, &str)> = vec![
        ("destination", "/queue/kv"),
        ("content-type", "text/plain"),
        ("subscription", "0"),
    ];
    if let Some(r) = receipt {
        headers.push(("receipt-id", r));
    }
    write_frame(clients, conn, &Frame::encode("MESSAGE", &headers, &body));
}

fn write_frame(clients: &mut HashMap<u64, TcpStream>, conn: u64, bytes: &[u8]) {
    let Some(stream) = clients.get_mut(&conn) else {
        return;
    };
    if stream
        .write_all(bytes)
        .and_then(|_| stream.flush())
        .is_err()
    {
        // The client vanished mid-write. Its reader thread will post
        // ClientDown; nothing else to do here.
        clients.remove(&conn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hex_must_be_64_characters_of_hex() {
        assert!(parse_key(&"a".repeat(64)).is_ok());
        assert!(parse_key(&"a".repeat(63)).is_err());
        assert!(parse_key(&"a".repeat(65)).is_err());
        assert!(parse_key(&"z".repeat(64)).is_err());
    }

    #[test]
    fn key_hex_decodes_big_endian_per_byte() {
        let mut hex = String::new();
        for i in 0..32u8 {
            hex.push_str(&format!("{i:02x}"));
        }
        let key = parse_key(&hex).unwrap();
        assert_eq!(key[0], 0);
        assert_eq!(key[31], 31);
    }

    #[test]
    fn the_reserved_channel_range_is_avoided() {
        assert!(
            !(1..=99).contains(&PEER_CHANNEL),
            "channels 1-99 are reserved system channels"
        );
    }
}
