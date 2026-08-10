# paxe-core

A **sans-io** PAXE datagram-encryption core library in Rust, with a C ABI for
LuaJIT FFI and a deliberately silly demo server for exercising it over real
sockets.

The wire and security contract is defined in [PAXE.md](PAXE.md).

Sans-io means the whole protocol is a function of its inputs: you hand it a
payload and a keystore and get a sealed frame back. No sockets, no threads, no
async runtime, no callbacks. The host owns transport and timers.

```rust
let mut store = KeyStore::new(/* local id */ 100)?;
store.install(/* peer */ 200, Epoch::new(0)?, &key)?;

let frame = dek::seal(&store, 200, 6767, Epoch::new(0)?, b"six seven")?;
let (header, _flags, payload) = dek::open(&store, &frame)?;
```

To build and test:

```
cargo test
```

## Why this exists

PAXE is AES-256-GCM authenticated encryption for **datagrams** — a wire format
with out-of-band pre-shared keys (PSKs), key epochs, standard one-recipient
frames, and explicit reusable-DEK fanout. It protects one UDP payload at a time,
with no handshake, session, ordering, or replay guarantees.

PSKs are installed by the host from configuration, a secret manager, or another
operator-controlled mechanism. PAXE only looks up an already installed key. It
does not implement TLS, ECDHE, SRP, certificates, or network key negotiation.

| | |
|---|---|
| Wire format | `fromId`/`toId`/`channel`/`length` header, separate flags byte, 9-byte AAD |
| Standard mode | one AES-256-GCM seal under the recipient PSK; 37-byte overhead |
| Reusable-DEK mode | body encrypted once, separately authenticated DEK envelope per recipient; 97-byte overhead |
| Mode selection | one-recipient seal is always standard; reusable-DEK requires explicit fanout |
| Keys | addressed by `(peer, epoch)`, 0-31 epochs, guarded/locked/zero-on-drop memory |
| C ABI | `cdylib` + `staticlib` + [`include/paxe.h`](include/paxe.h); standard one-recipient sealing only |

### Two properties worth knowing before you use it

**`open()` never tells you why.** Malformed, unknown peer, unknown epoch, failed
authentication — every rejection collapses to one opaque error. That is
deliberate: a caller that could distinguish them is a decryption oracle. The
reason survives only as a counter, so diagnose with `stats()` **deltas**, never
with an absolute value; the counters are cumulative for the process lifetime.

**No hardware AES-256-GCM means no PAXE.** `init()` reports that as an error
rather than falling back to a software path. A build of libsodium without the
hardware path, or a CPU without the instructions, cannot run this crate — by
design, not by omission.

## Dependencies

Zero crate dependencies. Not `libc`, not `zeroize`, not a crypto crate. All cryptography and
all secure-memory handling come from libsodium via `extern "C"` declarations,
statically linked by `build.rs`. The demo binary holds the same line: its STOMP
and UDP transports are `std::net` and `std::thread` only.

`build.rs` needs a **static** libsodium archive. On Unix it reads
`pkg-config --libs --static libsodium`; set `PAXE_SODIUM_LIB_DIR` to override.
On Windows it probes a vcpkg static triplet. There is no bundled fallback — a
missing archive fails the build rather than silently linking something else.

## Evidence

`cargo test` runs unit and matrix tests per protocol path, targeted regressions,
seeded property tests, and **known-answer vectors pinned byte-for-byte** —
derived from the specification with crypto bytes produced by an independent
OpenSSL EVP helper that is first checked against a published AES-256-GCM vector,
so a change to this crate cannot quietly redefine the wire format to agree with
itself.

The C ABI intentionally offers standard one-recipient sealing only. Rust hosts
that use reusable-DEK fanout record each returned frame actually accepted for
transmission with `stats::record_tx_sealed(Mode::Dek)`; this is when `tx_dek`
advances.

`tests/six_seven_e2e.sh` starts two real nodes on real sockets and asserts that
keys land on the right one, that the wrong one forwards over PAXE and relays the
answer, and that refusals are errors rather than crashes.

Passing tests are not evidence of zero bugs. They are evidence of an absence of
shallow bugs and of a wire format that cannot drift unnoticed.

## The demo: `six-seven-server`

A two-node key-value store whose only interesting property is that every
node-to-node hop is a PAXE datagram. Clients speak [STOMP](https://stomp.github.io/)
over TCP; nodes speak PAXE over UDP.

**The six-seven protocol, in full:** keys are `u64`. Odd keys live on the
lower-numbered node of the pair. Even keys live on the higher-numbered node.

That is the entire protocol. It is named after a [playground meme whose whole
joke is that it means nothing](https://en.wikipedia.org/wiki/Brainrot), which is
the correct amount of meaning for a placement rule chosen by parity. There is no
replication, no quorum, no failover and no persistence, because there is nothing
to be consistent about: every key has exactly one home. Lose a node and you lose
its half of the keyspace, permanently.

The point is not the placement rule. The point is that a node asked for a key it
does not own forwards the whole operation to its peer inside a sealed frame and
relays the answer back — so the demo exercises seal, transmit, open and reply
without needing any distributed-systems machinery to justify itself.

Unlike vrr-core's Maelstrom node there is no Jepsen and no verdict here. PAXE is
a datagram codec, not a consensus protocol; there is nothing for a
linearizability checker to check.

```bash
make build
KEY=$(printf '6767%.0s' {1..16})

# terminal 1 — node 100
./target/debug/six-seven-server --id 100 --stomp 127.0.0.1:6167 \
    --paxe 127.0.0.1:6100 --peer-id 200 --peer 127.0.0.1:6200 --key $KEY

# terminal 2 — node 200
./target/debug/six-seven-server --id 200 --stomp 127.0.0.1:6267 \
    --paxe 127.0.0.1:6200 --peer-id 100 --peer 127.0.0.1:6100 --key $KEY
```

Drive it with anything that can write bytes to a socket. Frames are
NUL-terminated, shown here as `^@`:

```
$ ncat 127.0.0.1 6167
CONNECT
accept-version:1.2

^@
SEND
destination:/queue/kv

PUT 68 six eight^@
```

68 is even, so node 100 forwards it to node 200 over PAXE and relays the `OK`.
`GET 68` from either node returns `six eight`.

| Request body | Meaning |
|---|---|
| `GET <k>` | value, or `NIL` |
| `PUT <k> <v>` | `OK`; the whole request is capped at 1024 bytes |
| `RM <k>` | `OK` if something was removed, else `NIL` |
| `SIZE` | this node's key count against the ceiling; never forwarded |

Errors come back as `ERR <text>`. A key the pair cannot reach — peer down,
datagram lost — fails after a five-second timeout with no retry.

The STOMP surface is partial on purpose: no heart-beating, no transactions, no
`content-length`, and a `receipt` header comes back as `receipt-id` on the
answering `MESSAGE` rather than as a separate `RECEIPT` frame. One frame per
request is much easier to read in `ncat`, which is the only client this expects.

### Caps

`MAX_PUT_BYTES` is 1024, measured on the client's request text, so a forwarded
request plus DEK-mode overhead stays far below any real path MTU — nothing here
fragments and nothing reassembles. `MAX_KEYS` is 1,000,000 per node: an
estimate-and-refuse guard so a loop cannot turn the demo into an unbounded heap.
Overwrites are always admitted, since they do not grow the keyset.

In the lunet deployment that counter is an `lnt_shared` cell shared across
worker processes. A single-process demo needs no such thing, so here it is a
plain in-process count; the refusal semantics are identical.

## Status

Pre-alpha. The protocol is covered by the tests above; the API is not stable and
there has been no production use.

## Licence

MIT.
