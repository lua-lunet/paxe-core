//! The C ABI for LuaJIT FFI.
//!
//! Sans-io, like the rest of the crate: this layer owns no sockets and no
//! threads. It owns the process-global session state — the keystore, the
//! local node identity, the failure policy and the last-error buffer —
//! because key material must never cross into Lua, and because the Lua
//! loader is a single VM thread by construction.
//!
//! Rust consumers should use `codec`, `keystore`, `standard`, `dek` and
//! `stats` directly and keep their own `KeyStore`; nothing here is needed
//! from Rust. See `src/bin/six-seven-server` for a worked example.

use crate::{codec, dek, keystore, sodium, standard, stats};

use std::cell::RefCell;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Module state. ALL crypto state (the keystore = all key material) lives
// here behind the FFI, never in Lua. Single-threaded by construction
// (keystore.rs: every caller runs on the one LuaJIT VM thread), so
// thread-local RefCells are the honest structure — and fully safe code.
// ---------------------------------------------------------------------------

thread_local! {
    /// THE keystore. `None` until `set_local_id` configures the node
    /// identity, and again after `shutdown`. `KeyStore` is `!Send`/
    /// `!Sync`, matching the single-VM-thread call model.
    static STORE: RefCell<Option<keystore::KeyStore>> = const { RefCell::new(None) };

    /// The last RC_ERR / RC_INVAL message. Read via
    /// [`lunet_paxe_last_error`]; copied out by paxe.lua immediately.
    /// RC_DROP never writes here (oracle avoidance, see its doc below).
    static LAST_ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Success.
const RC_OK: c_int = 0;
/// Success with information: the addressed slot did not exist
/// (keystore_retire of an absent `(peer, epoch)` — paxe.lua returns
/// `false`, not an error).
const RC_OK_ABSENT: c_int = 1;
/// OPERATIONAL failure — a condition the script handles. Message in the
/// last-error buffer; paxe.lua returns `nil, message`.
const RC_ERR: c_int = -1;
/// MALFORMED ARGUMENT — a bug in the calling script. Message (naming the
/// constraint) in the last-error buffer; paxe.lua RAISES a Lua error.
const RC_INVAL: c_int = -2;
/// `open` rejected the frame. THE single opaque outcome for EVERY
/// frame-level failure (parse, unknown key, authentication, unconfigured
/// keystore): the typed in-crate [`dek::OpenError`] reason is dropped
/// right here and NEVER written to the last-error buffer, because a
/// receiver that explains why a forgery failed is a decryption oracle
/// (PAXE.md "Failure Handling"). The reason is recorded into the
/// counters at the reject point inside dek/standard, BEFORE this collapse
/// — the counters are the one place reasons survive.
const RC_DROP: c_int = -3;

/// Record an OPERATIONAL failure message and return its code.
fn fail(msg: &str) -> c_int {
    set_last_error(msg.as_bytes());
    RC_ERR
}

/// Record a MALFORMED ARGUMENT message and return its code.
fn invalid(msg: String) -> c_int {
    set_last_error(msg.as_bytes());
    RC_INVAL
}

/// Write the last-error buffer. A RefCell borrow conflict is impossible
/// by construction (no export holds the borrow across a call into
/// anything that writes it) and handled defensively anyway: the code is
/// still returned, so no path can panic.
fn set_last_error(msg: &[u8]) {
    LAST_ERROR.with(|e| {
        if let Ok(mut e) = e.try_borrow_mut() {
            e.clear();
            e.extend_from_slice(msg);
        }
    });
}

// ---------------------------------------------------------------------------
// Argument validation — EVERY value crossing the boundary is untrusted.
// Each check names its constraint; each returns, never panics. Ids and
// epochs arrive as u32 precisely so out-of-range values are representable
// here and rejected with a message instead of being silently truncated
// by the FFI conversion (paxe.lua separately guarantees the value is an
// integer within u32 so the conversion itself is exact).
// ---------------------------------------------------------------------------

/// u32 → u16 with a named-constraint message (node ids, channels).
fn check_u16(v: u32, what: &str) -> Result<u16, String> {
    u16::try_from(v).map_err(|_| format!("{what} {v} out of range: must be 0-65535"))
}

/// u32 → bounded [`keystore::Epoch`] (0-31, the 5-bit wire field).
fn check_epoch(v: u32) -> Result<keystore::Epoch, String> {
    keystore::Epoch::new(u8::try_from(v).map_err(|_| epoch_message(v))?)
        .map_err(|_| epoch_message(v))
}

fn epoch_message(v: u32) -> String {
    format!("epoch {v} out of range: must be 0-{}", keystore::MAX_EPOCH)
}

/// Seal-side channel validation: channels 1-99 are RESERVED for system
/// traffic (PAXE.md "Channels"); the application API seals on channel 0
/// and 100-65535 only. (Receive-side there is no such gate: `open`
/// reports whatever channel the authenticated header carries.)
fn check_channel(v: u32) -> Result<u16, String> {
    let c = check_u16(v, "channel")?;
    if (1..=99).contains(&c) {
        return Err(format!(
            "channel {c} is reserved: 1-99 are system channels, application channels start at 100"
        ));
    }
    Ok(c)
}

/// Borrow a Lua buffer as a slice for the duration of one call.
///
/// Null with length 0 is an empty slice (LuaJIT may hand NULL for an
/// empty string); null with a non-zero length is a malformed argument.
/// The returned slice borrows the CALLER's memory and is never stored —
/// the soundness contract of this FFI is that the pointer is valid for
/// `len` bytes for the duration of the call, which paxe.lua guarantees
/// by passing live Lua strings / ffi buffers straight through.
#[allow(unsafe_code)]
fn buf_in<'a>(ptr: *const u8, len: usize, what: &str) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(format!("{what}: null pointer with non-zero length {len}"));
    }
    // SAFETY: non-null checked above; the caller contract (above) keeps
    // the pointee alive and unaliased for this call; read-only use.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Borrow a Lua output buffer as a mutable slice for one call. Same
/// contract as [`buf_in`]; null with capacity 0 is an empty slice.
#[allow(unsafe_code)]
fn buf_out<'a>(ptr: *mut u8, cap: usize, what: &str) -> Result<&'a mut [u8], String> {
    if cap == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() {
        return Err(format!("{what}: null output pointer with capacity {cap}"));
    }
    // SAFETY: non-null checked above; caller contract per buf_in.
    Ok(unsafe { std::slice::from_raw_parts_mut(ptr, cap) })
}

// ---------------------------------------------------------------------------
// Constants — exported from the SAME values the codec/standard/dek layers
// compute with, never restated as literals in paxe.lua.
// ---------------------------------------------------------------------------

/// Standard-mode per-frame overhead in bytes (37), from `standard.rs`.
// Per-symbol unsafe allowance: see lunet_paxe_version.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_overhead_standard() -> u32 {
    standard::OVERHEAD as u32
}

/// Reusable-DEK per-frame overhead in bytes (97), from `dek.rs`.
///
/// The C ABI exposes no reusable-DEK fanout sealer; this constant describes
/// frames a C host may receive from a Rust fanout host.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_overhead_dek() -> u32 {
    dek::DEK_OVERHEAD as u32
}

/// Maximum standard-mode plaintext payload (65470), from `standard.rs`.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_max_payload_standard() -> u32 {
    standard::MAX_PAYLOAD as u32
}

/// Maximum reusable-DEK plaintext payload (65410), from `dek.rs`.
///
/// The C ABI exposes no reusable-DEK fanout sealer; this is the limit for
/// reusable-DEK frames it may receive.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_max_payload_dek() -> u32 {
    dek::DEK_MAX_PAYLOAD as u32
}

// ---------------------------------------------------------------------------
// Lifecycle.
// ---------------------------------------------------------------------------

/// Initialise the module: core-dump suppression, libsodium init, the
/// startup ABI size check, and the AES-256-GCM hardware-availability
/// requirement. Idempotent. Unavailability is an OPERATIONAL failure
/// (environment property) — never a panic, never a silent fallback to
/// another cipher.
///
/// The first act disables core dumps for the process
/// (`RLIMIT_CORE` soft limit 0), before any key material can exist. On
/// Linux the keystore's mlocked pages were already excluded from cores
/// via `MADV_DONTDUMP` (verified against a real post-abort core);
/// on macOS they were NOT — Darwin has no `MADV_DONTDUMP`, `mlock`
/// excludes nothing, and recovered a full key from dumpable
/// post-abort memory. `RLIMIT_CORE` 0 is the only mechanism that covers
/// Darwin and it is uniform across platforms: after it, the kernel
/// writes no core at all. The suppression is process-wide, which is
/// sound here because loading PAXE IS the opt-in: a process reaches this
/// function only through an explicit `require("lunet.paxe")` — exactly
/// when it starts holding cluster key material — and a host that never
/// loads PAXE is untouched. DEBUGGING OPT-OUT:
/// `LUNET_PAXE_ALLOW_CORE_DUMPS=1` in the environment keeps the inherited
/// limit (see below). Best-effort like the `atexit` registration: a
/// failure warns loudly once on stderr instead of failing init.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_init() -> c_int {
    if !core_dumps_allowed_by_env() {
        if let Err(e) = sodium::disable_core_dumps() {
            warn_core_disable_failed(&e);
        }
    }
    if let Err(e) = sodium::init() {
        return fail(&format!("libsodium initialisation failed: {e}"));
    }
    if let Err(e) = sodium::check_sizes() {
        return fail(&format!("libsodium ABI check failed: {e}"));
    }
    if let Err(e) = sodium::require_aes_gcm() {
        return fail(&format!(
            "AES-256-GCM hardware path unavailable (libsodium {}); \
             PAXE cannot operate on this host: {e}",
            sodium::version_string()
        ));
    }
    // Key erasure at process exit is owned by the runtime, not by
    // a script remembering to call shutdown(). Register the exit hook
    // exactly once; the hook runs shutdown_state() at normal termination
    // (see its contract in sodium.rs — best-effort, never fatal).
    if !EXIT_HOOK_REGISTERED.swap(true, Ordering::SeqCst) {
        sodium::register_exit_hook(shutdown_at_exit);
    }
    RC_OK
}

/// Guards the one-time `atexit` registration. An atomic, not a lock: no
/// poisoning, no panic path.
static EXIT_HOOK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// The documented debugging opt-out: when
/// `LUNET_PAXE_ALLOW_CORE_DUMPS` is exactly `"1"`, `lunet_paxe_init`
/// leaves the process's inherited `RLIMIT_CORE` alone so core-dump
/// debugging sessions (AGENTS.md: `ulimit -c unlimited`, `lldb -c
/// /cores/core.*`) keep working for a PAXE-loaded host. Any other value —
/// including `0`, empty or a misspelling — is treated as UNSET, so a
/// misconfiguration fails safe (cores stay off). Never set this on a
/// production node: on macOS a crash can write live key material into a
/// core file.
fn core_dumps_allowed_by_env() -> bool {
    std::env::var_os("LUNET_PAXE_ALLOW_CORE_DUMPS").is_some_and(|v| v == "1")
}

/// Guards the one-time stderr warning when core-dump suppression fails.
static CORE_WARN_EMITTED: AtomicBool = AtomicBool::new(false);

/// Loud, one-time, panic-free warning for a `disable_core_dumps` failure.
/// `eprintln!` is NOT used: it panics on a broken stderr, and under
/// `panic = "abort"` that would kill the LuaJIT host — the error from
/// `write_all` is deliberately discarded instead.
fn warn_core_disable_failed(err: &std::io::Error) {
    if CORE_WARN_EMITTED.swap(true, Ordering::SeqCst) {
        return;
    }
    use std::io::Write as _;
    let msg = format!(
        "[PAXE] WARNING: setrlimit(RLIMIT_CORE, 0) failed ({err}); core dumps are NOT \
         disabled and on macOS a crash can write key material into a core file \
         (see PAXE.md \"Security Considerations\")\n"
    );
    let _ = std::io::stderr().write_all(msg.as_bytes());
}

/// The `atexit` callback: normal process termination erases the keystore
/// even when the script never called shutdown(). Must be panic-free after
/// arbitrary thread-local destruction — everything it touches goes
/// through `try_with` (see shutdown_state).
extern "C" fn shutdown_at_exit() {
    shutdown_state();
}

/// Configure this node's identity — ONCE. Creates the keystore. Calling
/// again without an intervening `shutdown` is a malformed use (a bug in
/// the script): silently re-creating the store would erase installed
/// keys, so the second call is RC_INVAL, never a silent wipe.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_set_local_id(node_id: u32) -> c_int {
    let id = match check_u16(node_id, "node id") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    STORE.with(|s| {
        let mut s = match s.try_borrow_mut() {
            Ok(s) => s,
            Err(_) => return fail("internal: keystore borrow conflict"),
        };
        if s.is_some() {
            return invalid(
                "local node id already configured; call shutdown() before reconfiguring"
                    .to_string(),
            );
        }
        match keystore::KeyStore::new(id) {
            Ok(store) => {
                *s = Some(store);
                RC_OK
            }
            Err(e) => fail(&format!("could not create keystore: {e}")),
        }
    })
}

/// Shut the module down: drop the keystore — every StoredKey is
/// `sodium_memzero`'d and `sodium_free`d on drop — and clear
/// the last-error buffer. Afterwards `set_local_id` may configure afresh.
/// Safe to call when unconfigured (a no-op).
///
/// Normal process exit needs no script-side call: `lunet_paxe_init`
/// registers this same state drop as an `atexit` hook, so the
/// runtime erases keys at exit even when a script forgets.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_shutdown() {
    shutdown_state();
}

/// The shared shutdown body, used by the exported shutdown AND by the
/// `atexit` exit hook. Every thread-local access is `try_with`:
/// at process exit the hook can run AFTER a thread-local's destructor
/// (destructors run in reverse registration order, and a thread-local
/// first touched after `init` registered the hook is destroyed before
/// it). A destroyed thread-local means its contents — including the key
/// material, whose own destructor IS the zeroisation — are already gone,
/// so skipping is correct; `with` would panic, and under
/// `panic = "abort"` a panic in an exit hook turns a clean exit into an
/// abort.
fn shutdown_state() {
    let _ = STORE.try_with(|s| {
        if let Ok(mut s) = s.try_borrow_mut() {
            // The drop of the KeyStore IS the zeroisation.
            *s = None;
        }
    });
    let _ = LAST_ERROR.try_with(|e| {
        if let Ok(mut e) = e.try_borrow_mut() {
            e.clear();
        }
    });
    // A re-initialised module starts a fresh log-once window. The counters
    // themselves are NOT reset —
    // they are cumulative for the process lifetime so monitoring deltas
    // never go negative across a restart. (try_with inside, same reason.)
    stats::reset_log_once_memo();
}

// ---------------------------------------------------------------------------
// Keystore operations. Keys are addressed by (peer node id, epoch) — no
// key_id anywhere; the old addressing model did not survive.
// ---------------------------------------------------------------------------

/// Install a 32-byte per-link key shared with `peer` under `epoch`.
/// `key` must point at EXACTLY 32 bytes; the material is copied into a
/// guarded, mlocked allocation inside Rust and the caller's buffer is
/// never retained. Overwriting an occupied slot erases the old key.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_keystore_set(
    peer: u32,
    epoch: u32,
    key: *const u8,
    key_len: usize,
) -> c_int {
    let peer = match check_u16(peer, "peer node id") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    let epoch = match check_epoch(epoch) {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    let key = match buf_in(key, key_len, "key") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    if key.len() != sodium::KEYBYTES {
        return invalid(format!(
            "key must be exactly {} bytes, got {}",
            sodium::KEYBYTES,
            key.len()
        ));
    }
    // Cannot fail after the length check; mapped anyway, never unwrapped.
    let material: &[u8; sodium::KEYBYTES] = match key.try_into() {
        Ok(a) => a,
        Err(_) => return invalid(format!("key must be exactly {} bytes", sodium::KEYBYTES)),
    };
    STORE.with(|s| {
        let mut s = match s.try_borrow_mut() {
            Ok(s) => s,
            Err(_) => return fail("internal: keystore borrow conflict"),
        };
        let store = match s.as_mut() {
            Some(st) => st,
            None => return fail("local node id not configured: call set_local_id() first"),
        };
        match store.install(peer, epoch, material) {
            Ok(()) => RC_OK,
            Err(e) => fail(&format!("could not install key: {e}")),
        }
    })
}

/// Retire one `(peer, epoch)` slot, erasing its key. RC_OK if a key was
/// retired, RC_OK_ABSENT if the slot was empty (informational, not an
/// error), RC_ERR if the store is unconfigured.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_keystore_retire(peer: u32, epoch: u32) -> c_int {
    let peer = match check_u16(peer, "peer node id") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    let epoch = match check_epoch(epoch) {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    STORE.with(|s| {
        let mut s = match s.try_borrow_mut() {
            Ok(s) => s,
            Err(_) => return fail("internal: keystore borrow conflict"),
        };
        let store = match s.as_mut() {
            Some(st) => st,
            None => return fail("local node id not configured: call set_local_id() first"),
        };
        if store.retire(peer, epoch) {
            RC_OK
        } else {
            RC_OK_ABSENT
        }
    })
}

/// Erase every installed key. Tolerant by design: clearing an
/// unconfigured store is a successful no-op (cleanup must never fail).
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_keystore_clear() -> c_int {
    STORE.with(|s| {
        if let Ok(mut s) = s.try_borrow_mut() {
            if let Some(store) = s.as_mut() {
                store.clear();
            }
        }
        RC_OK
    })
}

// ---------------------------------------------------------------------------
// Seal / open.
// ---------------------------------------------------------------------------

/// Seal `payload` for `to_id` on `channel` as a standard frame. This is the
/// C ABI's only sealing operation; reusable-DEK fanout is Rust API-only. The
/// frame's `fromId` is the configured local id — never a
/// parameter, so no caller can spoof a source. The send epoch is the
/// NEWEST epoch installed for `to_id` (PAXE.md "Rotation": installing a
/// new epoch switches senders to it); sealing under a retired/absent key
/// is therefore impossible by construction.
///
/// `out` must hold at least `payload_len + 37` bytes; the frame size is written
/// to `out_len`. An oversized payload is an operational failure naming the
/// standard-mode maximum
/// — never a truncated length field (PAXE.md "Limits").
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_seal(
    payload: *const u8,
    payload_len: usize,
    to_id: u32,
    channel: u32,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    let to_id = match check_u16(to_id, "destination node id") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    let channel = match check_channel(channel) {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    let payload = match buf_in(payload, payload_len, "payload") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    if out_len.is_null() {
        return invalid("frame length output pointer must not be null".to_string());
    }
    let out = match buf_out(out, out_cap, "frame output") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    if payload.len() > standard::MAX_PAYLOAD {
        stats::record_tx_oversize();
        return fail(&format!(
            "payload too large: {} bytes exceeds the standard-mode maximum of {}",
            payload.len(),
            standard::MAX_PAYLOAD
        ));
    }
    STORE.with(|s| {
        let s = match s.try_borrow() {
            Ok(s) => s,
            Err(_) => return fail("internal: keystore borrow conflict"),
        };
        let store = match s.as_ref() {
            Some(st) => st,
            None => return fail("local node id not configured: call set_local_id() first"),
        };
        // The send epoch: the NEWEST epoch installed for this peer.
        let (epoch, _) = match store.key_for_send_current(to_id) {
            Some(e) => e,
            None => {
                return fail(&format!(
                    "no key installed for peer {to_id} under any epoch"
                ))
            }
        };
        match dek::seal(store, to_id, channel, epoch, payload) {
            Ok(frame) => {
                if frame.len() > out.len() {
                    // paxe.lua supplies payload_len + 37, so a
                    // short buffer here is a loader bug — malformed use.
                    return invalid(format!(
                        "frame output buffer too small: need {}, have {}",
                        frame.len(),
                        out.len()
                    ));
                }
                // Bounds checked above; the copy cannot panic.
                out[..frame.len()].copy_from_slice(&frame);
                // SAFETY: non-null checked at entry; single u32 write.
                unsafe { *out_len = frame.len() };
                stats::record_tx_sealed(codec::Mode::Standard);
                RC_OK
            }
            Err(e) => fail(&format!("seal failed: {e}")),
        }
    })
}

/// Open one received frame. Success: the payload in `out` (length in
/// `out_len`), plus `from_id`, `channel` and `mode` (0 = standard,
/// 1 = DEK) through the out-pointers. `fromId` is authenticated (it sits
/// inside the AAD), so it is trustworthy information and is surfaced —
/// that is the point of the header design.
///
/// ANY frame-level failure returns RC_DROP with NO message: the opaque
/// collapse documented at RC_DROP. Only malformed C-level arguments
/// (null out-pointers — a loader bug, unreachable from paxe.lua) return
/// RC_INVAL.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_open(
    frame: *const u8,
    frame_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    from_id: *mut u32,
    channel: *mut u32,
    mode: *mut u32,
) -> c_int {
    let frame = match buf_in(frame, frame_len, "frame") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    if out_len.is_null() || from_id.is_null() || channel.is_null() || mode.is_null() {
        return invalid("open: output pointers must not be null".to_string());
    }
    let out = match buf_out(out, out_cap, "payload output") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    STORE.with(|s| {
        let s = match s.try_borrow() {
            Ok(s) => s,
            // Unreachable by construction; still just a drop.
            Err(_) => return RC_DROP,
        };
        let store = match s.as_ref() {
            Some(st) => st,
            // An unconfigured receiver drops like any other failure:
            // "not configured" reveals nothing about the frame, and one
            // outcome keeps the surface uniform. NOT counted in the
            // counters: the module is not running PAXE at all, and
            // the rx invariant is defined over frames presented to a
            // configured receiver (stats.rs module docs).
            None => return RC_DROP,
        };
        match dek::open(store, frame) {
            Ok((h, f, plain)) => {
                if plain.len() > out.len() {
                    // paxe.lua supplies frame_len bytes, always enough —
                    // a short buffer here is a loader bug. Uncounted: a
                    // loader bug is not wire accounting.
                    return invalid(format!(
                        "payload output buffer too small: need {}, have {}",
                        plain.len(),
                        out.len()
                    ));
                }
                out[..plain.len()].copy_from_slice(&plain);
                // SAFETY: all four pointers checked non-null at entry.
                unsafe {
                    *out_len = plain.len();
                    *from_id = u32::from(h.from_id);
                    *channel = u32::from(h.channel);
                    *mode = match f.mode() {
                        codec::Mode::Standard => 0,
                        codec::Mode::Dek => 1,
                    };
                }
                stats::record_rx_ok();
                RC_OK
            }
            // Impossible internal result (a libsodium contract violation,
            // not a wire condition): dropped like any other failure but
            // deliberately NOT counted — no honest reason counter fits,
            // and inventing one would falsify the invariant.
            Err(dek::OpenError::Sodium(_)) => RC_DROP,
            // The typed reason was recorded into the counters at the
            // reject point inside dek/standard; here the frame joins
            // rx_total and the reason dies: no last-error write, one code.
            Err(_) => {
                stats::record_rx_drop();
                RC_DROP
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Protected-socket plaintext gate. Consumed by the Lua-side
// UDP wrapper (ext/paxe/paxe.lua `protect`) BEFORE `lunet_paxe_open`.
// ---------------------------------------------------------------------------

/// The explicit "is this a PAXE frame addressed to this node" check for a
/// protected UDP socket. Returns 1 when `frame` is at least the 9-byte
/// prefix AND its header `toId` (bytes 2-3, big-endian) equals the
/// configured local id — the caller then proceeds to `lunet_paxe_open`.
/// Returns 0 otherwise: plaintext, foreign-protocol or misaddressed
/// traffic, to be dropped without delivery.
///
/// This gate exists so the plaintext drop is EXPLICIT, with its own
/// counter ([`stats::RejectReason::Plaintext`]): it must not rest on the
/// flags constant-bit check, because crafted plaintext could have a byte
/// 8 that passes it. The addressing check is the honest
/// transport-level discriminator — a datagram that is not even addressed
/// to this node in PAXE framing is not a frame for this node, whatever
/// its flags byte says — and it runs BEFORE the codec, so when the
/// plaintext case and the flags case coincide (ordinary garbage), the
/// plaintext counter, not `rx_bad_flags`, is the one that moves. Only a
/// datagram presenting a PAXE prefix addressed to this node reaches
/// `open`, where failure is attributed to the precise reason counter.
///
/// Counting (a configured receiver only, mirroring open's rule that an
/// unconfigured receiver drops untallied): a 0-verdict records rx_total
/// AND rx_plaintext HERE; a 1-verdict records nothing — `open` counts
/// the frame exactly once. The rx invariant is preserved on both arms.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_frame_for_us(frame: *const u8, frame_len: usize) -> c_int {
    let frame = match buf_in(frame, frame_len, "frame") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    STORE.with(|s| {
        let s = match s.try_borrow() {
            Ok(s) => s,
            // Unreachable by construction (no export holds the borrow
            // across calls into this one); treated as an impossible
            // internal result and deliberately NOT counted — no honest
            // reason counter fits (same rule as OpenError::Sodium).
            Err(_) => return 0,
        };
        let store = match s.as_ref() {
            Some(st) => st,
            // Unconfigured receiver: drop, uncounted — the module is not
            // running PAXE at all (the same rule open() applies).
            None => return 0,
        };
        // bytes 2-3 are the header toId, big-endian (codec.rs wire
        // layout). `get` + fixed-size conversion: no indexing, no panic.
        let to_id = match frame.get(2..4).and_then(|t| <[u8; 2]>::try_from(t).ok()) {
            Some(t) => u16::from_be_bytes(t),
            None => 0,
        };
        if frame.len() >= codec::PREFIX_LEN && to_id == store.local_id() {
            return 1;
        }
        // The explicit plaintext drop: counted HERE, at the gate, never
        // by coincidence of a later parse failure.
        stats::record_rx_drop();
        stats::record_reject(stats::RejectReason::Plaintext);
        0
    })
}

// ---------------------------------------------------------------------------
// Statistics snapshot and failure policy. The counters are the
// operator's ONLY diagnostic channel for dropped frames (open collapses
// every reason to RC_DROP); they are process-global, cumulative, and
// never reset by any API — consumers measure deltas between snapshots.
// ---------------------------------------------------------------------------

/// Copy the counter snapshot into `out` in the PINNED field order
/// ([`stats::Stats::fields`]; paxe.lua maps the indices to names and
/// asserts the count, so a drift fails loudly). Always returns the total
/// field count, so a caller can probe with `(NULL, 0)` to size a buffer;
/// with a buffer it fills `min(out_cap, count)` entries. Cannot fail and
/// cannot panic.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_stats(out: *mut u64, out_cap: usize) -> u32 {
    let fields = stats::snapshot().fields();
    let n = fields.len();
    if !out.is_null() && out_cap > 0 {
        let count = n.min(out_cap);
        // SAFETY: out is non-null; the caller contract (same as buf_out)
        // guarantees out_cap writable u64s, and count <= out_cap.
        unsafe { std::ptr::copy_nonoverlapping(fields.as_ptr(), out, count) };
    }
    n as u32
}

/// Select the failure policy: "silent" (drop and count only; the
/// default), "log_once" (first drop of each reason per window logs one
/// `[PAXE]` stderr line), "verbose" (every drop logs). Entering log_once
/// starts a fresh window (the memo resets;
/// stats.rs). Unknown spellings are RC_INVAL; paxe.lua pre-validates and
/// returns `false` instead, so that arm is defence in depth.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_fail_policy_set(name: *const u8, name_len: usize) -> c_int {
    let name = match buf_in(name, name_len, "policy name") {
        Ok(v) => v,
        Err(m) => return invalid(m),
    };
    let name = match std::str::from_utf8(name) {
        Ok(s) => s,
        Err(_) => return invalid("policy name must be UTF-8".to_string()),
    };
    match stats::FailPolicy::from_name(name) {
        Some(p) => {
            stats::set_policy(p);
            RC_OK
        }
        None => invalid(format!(
            "unknown failure policy '{name}': must be silent, log_once or verbose"
        )),
    }
}

/// The last RC_ERR / RC_INVAL message for this thread: a borrowed
/// pointer plus length (NOT NUL-terminated; use the length). Valid until
/// the next fallible call on this thread — paxe.lua copies it out with
/// `ffi.string` immediately. Never carries an open() rejection reason.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_last_error(len: *mut usize) -> *const u8 {
    LAST_ERROR.with(|e| {
        let e = match e.try_borrow() {
            Ok(e) => e,
            Err(_) => return std::ptr::null(),
        };
        if !len.is_null() {
            // SAFETY: non-null checked; single usize write.
            unsafe { *len = e.len() };
        }
        // The Vec lives in the thread-local; its buffer stays valid until
        // the next set_last_error on this thread (documented contract).
        e.as_ptr()
    })
}

/// Crate version as a NUL-terminated static string, baked into the cdylib's
/// read-only data. Built from `CARGO_PKG_VERSION` at compile time so this
/// string and the manifest can never disagree.
static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

/// Return the crate version as a pointer to a NUL-terminated UTF-8 string.
///
/// The pointer borrows a `'static` allocation; the caller must NOT free it.
/// Cannot fail and cannot panic: no input, no allocation, no indexing. This
/// is the scaffold symbol proving the build → `require` → call path.
// `#[no_mangle]` is an unsafe attribute (RFC 3325) and so falls under the
// crate's deny(unsafe_code); exporting C ABI symbols is the one legitimate
// use beside sodium.rs, allowed here per-symbol.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn lunet_paxe_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    // Reading back the exported C string inherently dereferences a raw
    // pointer; test-only, and it never ships in the cdylib.
    #![allow(unsafe_code)]

    use super::*;
    use std::ffi::CStr;

    #[test]
    fn version_is_nul_terminated_and_matches_manifest() {
        let ptr = lunet_paxe_version();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(s, env!("CARGO_PKG_VERSION"));
    }
}

// ---------------------------------------------------------------------------
// FFI boundary tests. These drive the EXPORTED symbols exactly as
// paxe.lua does — pointer/length buffers, u32 ids, out-pointers — and pin
// the two integration properties: the standard/DEK dispatch is
// exercised in both directions, and every open failure collapses to RC_DROP
// with nothing written to the last-error buffer.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ffi_tests {
    #![allow(unsafe_code)]

    use super::*;

    const NODE_A: u32 = 100;
    const NODE_B: u32 = 200;
    const CHAN: u32 = 137;
    const KEY: [u8; 32] = [0x42; 32];

    fn gcm() -> bool {
        sodium::init().is_ok() && sodium::aes_gcm_available()
    }

    fn last_error_string() -> String {
        let mut len: usize = 0;
        let ptr = lunet_paxe_last_error(&mut len);
        if ptr.is_null() || len == 0 {
            return String::new();
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// Configure node A with a link key for peer B under `epoch`.
    fn setup_node_a(epoch: u32) {
        assert_eq!(
            lunet_paxe_init(),
            RC_OK,
            "init failed (libsodium {}): {}",
            crate::sodium::version_string(),
            last_error_string()
        );
        assert_eq!(lunet_paxe_set_local_id(NODE_A), RC_OK);
        assert_eq!(
            lunet_paxe_keystore_set(NODE_B, epoch, KEY.as_ptr(), KEY.len()),
            RC_OK
        );
    }

    /// Become the OTHER end of the link. The FFI holds ONE store per
    /// process (one Lua VM = one node), and the send/receive addressing
    /// asymmetry (: seal looks up by toId, open by fromId) means a
    /// frame A sealed for B can only be opened by B's store — keyed under
    /// peer A. Two genuinely different node ids: shutdown, reconfigure.
    fn become_node_b(epoch: u32) {
        lunet_paxe_shutdown();
        assert_eq!(lunet_paxe_set_local_id(NODE_B), RC_OK);
        assert_eq!(
            lunet_paxe_keystore_set(NODE_A, epoch, KEY.as_ptr(), KEY.len()),
            RC_OK
        );
    }

    fn seal(payload: &[u8], to_id: u32, channel: u32) -> (c_int, Vec<u8>) {
        let mut out = vec![0u8; payload.len() + standard::OVERHEAD];
        let mut out_len: usize = 0;
        let rc = lunet_paxe_seal(
            payload.as_ptr(),
            payload.len(),
            to_id,
            channel,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        out.truncate(out_len);
        (rc, out)
    }

    fn open(frame: &[u8]) -> (c_int, Vec<u8>, u32, u32, u32) {
        let mut out = vec![0u8; frame.len().max(1)];
        let mut out_len: usize = 0;
        let mut from_id: u32 = 0;
        let mut channel: u32 = 0;
        let mut mode: u32 = u32::MAX;
        let rc = lunet_paxe_open(
            frame.as_ptr(),
            frame.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut from_id,
            &mut channel,
            &mut mode,
        );
        out.truncate(out_len);
        (rc, out, from_id, channel, mode)
    }

    #[test]
    fn constants_are_the_codec_side_values_not_literals() {
        assert_eq!(lunet_paxe_overhead_standard(), standard::OVERHEAD as u32);
        assert_eq!(lunet_paxe_overhead_dek(), dek::DEK_OVERHEAD as u32);
        assert_eq!(
            lunet_paxe_max_payload_standard(),
            standard::MAX_PAYLOAD as u32
        );
        assert_eq!(lunet_paxe_max_payload_dek(), dek::DEK_MAX_PAYLOAD as u32);
        // ...and those values are the documented protocol numbers.
        assert_eq!(lunet_paxe_overhead_standard(), 37);
        assert_eq!(lunet_paxe_overhead_dek(), 97);
        assert_eq!(lunet_paxe_max_payload_standard(), 65470);
        assert_eq!(lunet_paxe_max_payload_dek(), 65410);
    }

    #[test]
    fn malformed_arguments_are_rc_inval_with_named_constraints() {
        assert_eq!(lunet_paxe_set_local_id(65536), RC_INVAL);
        assert!(last_error_string().contains("0-65535"));
        assert_eq!(lunet_paxe_set_local_id(u32::MAX), RC_INVAL);

        assert_eq!(
            lunet_paxe_init(),
            RC_OK,
            "init failed (libsodium {}): {} — see PAXE.md \"Requirements\" \
             (AES-256-GCM hardware crypto; libsodium >= 1.0.20 on ARM64 Linux)",
            crate::sodium::version_string(),
            last_error_string()
        );
        assert_eq!(lunet_paxe_set_local_id(NODE_A), RC_OK);
        // Second configuration without shutdown: malformed use, no wipe.
        assert_eq!(lunet_paxe_set_local_id(NODE_A), RC_INVAL);

        // Epoch range.
        assert_eq!(
            lunet_paxe_keystore_set(NODE_B, 32, KEY.as_ptr(), KEY.len()),
            RC_INVAL
        );
        assert!(last_error_string().contains("0-31"));
        // Key length.
        assert_eq!(
            lunet_paxe_keystore_set(NODE_B, 3, KEY.as_ptr(), 31),
            RC_INVAL
        );
        assert!(last_error_string().contains("exactly 32 bytes"));
        // Peer id range.
        assert_eq!(
            lunet_paxe_keystore_set(70000, 3, KEY.as_ptr(), KEY.len()),
            RC_INVAL
        );
        // Channels 1-99 are reserved; 0 and 100+ are fine.
        let (rc, _) = seal(b"x", NODE_B, 99);
        assert_eq!(rc, RC_INVAL);
        assert!(last_error_string().contains("reserved"));
        let (rc, _) = seal(b"x", NODE_B, 65536);
        assert_eq!(rc, RC_INVAL);
        // Null payload pointer with a non-zero length: malformed, no panic.
        let mut out_len: usize = 0;
        let mut buf = [0u8; 128];
        let rc = lunet_paxe_seal(
            std::ptr::null(),
            5,
            NODE_B,
            CHAN,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out_len,
        );
        assert_eq!(rc, RC_INVAL);
        // Retire validates too.
        assert_eq!(lunet_paxe_keystore_retire(NODE_B, 200), RC_INVAL);
    }

    #[test]
    fn ffi_seal_is_standard_at_every_payload_size() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        setup_node_a(3);

        // A seals both payload sizes for B as standard frames.
        let payload63: Vec<u8> = (0..63u8).collect();
        let (rc, frame63) = seal(&payload63, NODE_B, CHAN);
        assert_eq!(rc, RC_OK, "seal 63: {}", last_error_string());
        assert_eq!(frame63.len(), 63 + 37);
        assert_eq!(frame63[8] & 0x01, 0, "63-byte payload must seal standard");
        let payload64: Vec<u8> = (0..64u8).collect();
        let (rc, frame64) = seal(&payload64, NODE_B, CHAN);
        assert_eq!(rc, RC_OK, "seal 64: {}", last_error_string());
        assert_eq!(frame64.len(), 64 + 37);
        assert_eq!(frame64[8] & 0x01, 0, "64-byte payload must seal standard");
        // The wire epoch is the installed one (flags bits 3-7).
        assert_eq!(frame64[8] >> 3, 3);

        // B opens both frames with standard mode.
        become_node_b(3);
        let (rc, plain, from_id, channel, mode) = open(&frame63);
        assert_eq!(rc, RC_OK);
        assert_eq!(plain, payload63);
        assert_eq!(from_id, NODE_A);
        assert_eq!(channel, CHAN);
        assert_eq!(mode, 0, "standard mode reported as 0");
        let (rc, plain, from_id, _, mode) = open(&frame64);
        assert_eq!(rc, RC_OK);
        assert_eq!(plain, payload64);
        assert_eq!(from_id, NODE_A);
        assert_eq!(mode, 0, "standard mode reported as 0");
    }

    #[test]
    fn seal_uses_the_newest_installed_epoch() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        setup_node_a(1);
        let wire_epoch = |frame: &[u8]| frame[8] >> 3;

        let payload = [0u8; 10];
        let (rc, frame) = seal(&payload, NODE_B, CHAN);
        assert_eq!(rc, RC_OK);
        assert_eq!(wire_epoch(&frame), 1);

        // Rotation: install a newer epoch and the sender switches at once.
        let key2 = [0x77u8; 32];
        assert_eq!(
            lunet_paxe_keystore_set(NODE_B, 6, key2.as_ptr(), key2.len()),
            RC_OK
        );
        let (rc, frame) = seal(&payload, NODE_B, CHAN);
        assert_eq!(rc, RC_OK);
        assert_eq!(wire_epoch(&frame), 6);

        // Retire the newest: the sender falls back to the next-highest.
        assert_eq!(lunet_paxe_keystore_retire(NODE_B, 6), RC_OK);
        let (rc, frame) = seal(&payload, NODE_B, CHAN);
        assert_eq!(rc, RC_OK);
        assert_eq!(wire_epoch(&frame), 1);

        // Retire of an absent slot: informational, not an error.
        assert_eq!(lunet_paxe_keystore_retire(NODE_B, 6), RC_OK_ABSENT);

        // Retire the last: no key under any epoch -> operational failure.
        assert_eq!(lunet_paxe_keystore_retire(NODE_B, 1), RC_OK);
        let (rc, _) = seal(&payload, NODE_B, CHAN);
        assert_eq!(rc, RC_ERR);
        assert!(last_error_string().contains("no key installed"));
    }

    #[test]
    fn every_open_failure_collapses_to_one_opaque_drop() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        // Unconfigured receiver: even THIS is the same opaque drop.
        let (rc, _, _, _, _) = open(b"whatever");
        assert_eq!(rc, RC_DROP);

        setup_node_a(3);
        let payload = [0x55u8; 40];
        let (rc, frame) = seal(&payload, NODE_B, CHAN);
        assert_eq!(rc, RC_OK);
        become_node_b(3);

        let mut cases: Vec<Vec<u8>> = Vec::new();
        // Corrupted ciphertext byte (tag failure).
        let mut c1 = frame.clone();
        c1[30] ^= 0x01;
        cases.push(c1);
        // Corrupted AAD (header byte).
        let mut c2 = frame.clone();
        c2[1] ^= 0x01;
        cases.push(c2);
        // Garbage flags byte.
        let mut c3 = frame.clone();
        c3[8] = 0x00;
        cases.push(c3);
        // Truncated.
        cases.push(frame[..frame.len() - 1].to_vec());
        // Too short to parse at all.
        cases.push(vec![0u8; 4]);
        // Empty.
        cases.push(Vec::new());
        for (i, bad) in cases.iter().enumerate() {
            // Prime the last-error buffer with a REAL message; the drop
            // must not overwrite it with a reason.
            assert_eq!(lunet_paxe_set_local_id(NODE_A), RC_INVAL);
            let before = last_error_string();
            let (rc, _, _, _, _) = open(bad);
            assert_eq!(rc, RC_DROP, "case {i} must be the opaque drop");
            assert_eq!(
                last_error_string(),
                before,
                "case {i}: the typed reason must never reach the error buffer"
            );
        }
        // Control: the good frame still opens.
        let (rc, plain, _, _, _) = open(&frame);
        assert_eq!(rc, RC_OK);
        assert_eq!(plain, payload);
    }

    #[test]
    fn seal_operational_failures_are_rc_err_and_oversize_is_named() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        assert_eq!(
            lunet_paxe_init(),
            RC_OK,
            "init failed (libsodium {}): {}",
            crate::sodium::version_string(),
            last_error_string()
        );
        // Seal before set_local_id: operational, clear message.
        let (rc, _) = seal(b"x", NODE_B, CHAN);
        assert_eq!(rc, RC_ERR);
        assert!(last_error_string().contains("set_local_id"));

        assert_eq!(lunet_paxe_set_local_id(NODE_A), RC_OK);
        // No key for the peer.
        let (rc, _) = seal(b"x", NODE_B, CHAN);
        assert_eq!(rc, RC_ERR);
        assert!(last_error_string().contains("no key installed"));

        // Oversize: above the standard maximum.
        assert_eq!(
            lunet_paxe_keystore_set(NODE_B, 3, KEY.as_ptr(), KEY.len()),
            RC_OK
        );
        let big = vec![0u8; standard::MAX_PAYLOAD + 1];
        let (rc, _) = seal(&big, NODE_B, CHAN);
        assert_eq!(rc, RC_ERR);
        let msg = last_error_string();
        assert!(
            msg.contains("standard-mode maximum of 65470"),
            "message was: {msg}"
        );
        // Exactly the maximum seals.
        let max = vec![0u8; standard::MAX_PAYLOAD];
        let (rc, frame) = seal(&max, NODE_B, CHAN);
        assert_eq!(rc, RC_OK, "seal max: {}", last_error_string());
        assert_eq!(frame.len(), 65507);
    }

    #[test]
    fn keystore_clear_and_shutdown_drop_all_state() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        setup_node_a(3);
        assert_eq!(lunet_paxe_keystore_clear(), RC_OK);
        let (rc, _) = seal(b"x", NODE_B, CHAN);
        assert_eq!(rc, RC_ERR, "cleared store has no keys");

        assert_eq!(
            lunet_paxe_keystore_set(NODE_B, 3, KEY.as_ptr(), KEY.len()),
            RC_OK
        );
        lunet_paxe_shutdown();
        // After shutdown the identity is gone: seal is operational
        // failure, open is the opaque drop, and reconfiguration works.
        let (rc, _) = seal(b"x", NODE_B, CHAN);
        assert_eq!(rc, RC_ERR);
        let (rc, _, _, _, _) = open(b"x");
        assert_eq!(rc, RC_DROP);
        assert_eq!(lunet_paxe_set_local_id(NODE_B), RC_OK);
        // And the erased key no longer resolves.
        let (rc, _) = seal(b"x", NODE_A, CHAN);
        assert_eq!(rc, RC_ERR);
        assert!(last_error_string().contains("no key installed"));
        // Shutdown is idempotent.
        lunet_paxe_shutdown();
    }

    // -------------------------------------------------------------------
    // Counters at the FFI boundary. Delta-measured throughout —
    // no absolute values (the counters are cumulative process state).
    // -------------------------------------------------------------------

    fn assert_invariant(s: &stats::Stats, what: &str) {
        assert_eq!(
            s.rx_total,
            s.rx_ok + s.reject_sum(),
            "invariant rx_total == rx_ok + sum(reject reasons) violated {what}"
        );
    }

    /// One drop through the exported open: rx_total advances by one,
    /// EXACTLY the expected reason counter advances by one, every other
    /// counter is untouched, and the invariant holds afterwards.
    fn assert_one_drop(frame: &[u8], reason: stats::RejectReason) {
        let before = stats::snapshot();
        let (rc, _, _, _, _) = open(frame);
        assert_eq!(rc, RC_DROP, "{reason:?}: the opaque drop");
        let after = stats::snapshot();
        assert_eq!(
            after.rx_total - before.rx_total,
            1,
            "{reason:?}: rx_total +1"
        );
        assert_eq!(after.rx_ok - before.rx_ok, 0, "{reason:?}: rx_ok untouched");
        for r in stats::RejectReason::ALL {
            let moved = after.reject(r) - before.reject(r);
            if r == reason {
                assert_eq!(moved, 1, "{reason:?}: its counter +1");
            } else {
                assert_eq!(moved, 0, "{reason:?}: {r:?} must not move");
            }
        }
        assert_invariant(&after, "after a drop");
    }

    #[test]
    fn every_reject_reason_counts_exactly_once_and_the_invariant_holds() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        use stats::RejectReason as R;

        // An UNCONFIGURED receiver drops but does NOT count: the module
        // is not running PAXE at all (see stats.rs).
        let before = stats::snapshot();
        let (rc, _, _, _, _) = open(b"whatever");
        assert_eq!(rc, RC_DROP);
        let after = stats::snapshot();
        assert_eq!(
            after.rx_total - before.rx_total,
            0,
            "unconfigured: uncounted"
        );
        assert_eq!(
            after.reject_sum() - before.reject_sum(),
            0,
            "unconfigured: uncounted"
        );

        setup_node_a(3);
        let payload40 = [0x55u8; 40];
        let (rc, frame63) = seal(&payload40, NODE_B, CHAN);
        assert_eq!(rc, RC_OK);
        // A also installs epoch 4, so a frame can carry an epoch B lacks.
        assert_eq!(
            lunet_paxe_keystore_set(NODE_B, 4, KEY.as_ptr(), KEY.len()),
            RC_OK
        );
        let (rc, frame63_e4) = seal(&payload40, NODE_B, CHAN);
        assert_eq!(rc, RC_OK);
        assert_eq!(frame63_e4[8] >> 3, 4, "newest epoch seals");

        // THE reason -> trigger mapping, EXHAUSTIVE BY CONSTRUCTION: the
        // match below iterates RejectReason::ALL and has no wildcard arm,
        // so adding a RejectReason variant without adding its triggering
        // case here is a COMPILE ERROR (non-exhaustive pattern), not a
        // forgotten list entry. The enum's own tripwires (the ALL array
        // literal, the exhaustive line() match, the COUNT assertion in
        // stats.rs) guard the reason-to-COUNTER mapping; this match
        // guards the reason-to-TEST mapping — one arm per enumerated
        // reason, each asserting the rejection AND that exactly its own
        // counter moved. B holds the A-key under epoch 3 ONLY; each arm
        // (re)establishes the receiver configuration it needs.
        for reason in stats::RejectReason::ALL {
            match reason {
                // rx_plaintext: the protected-socket gate (not
                // open()): a datagram whose toId is not this node, with
                // a flags byte that deliberately PASSES the constant-bit
                // filter — only the explicit addressing check rejects it.
                R::Plaintext => {
                    become_node_b(3);
                    let d = datagram_to(0x270F, 40, 0x04);
                    let before = stats::snapshot();
                    assert_eq!(lunet_paxe_frame_for_us(d.as_ptr(), d.len()), 0);
                    let after = stats::snapshot();
                    assert_eq!(
                        after.rx_total - before.rx_total,
                        1,
                        "{reason:?}: rx_total +1"
                    );
                    assert_eq!(after.rx_ok - before.rx_ok, 0, "{reason:?}: rx_ok untouched");
                    for r in stats::RejectReason::ALL {
                        let moved = after.reject(r) - before.reject(r);
                        if r == reason {
                            assert_eq!(moved, 1, "{reason:?}: its counter +1");
                        } else {
                            assert_eq!(moved, 0, "{reason:?}: {r:?} must not move");
                        }
                    }
                    assert_invariant(&after, "after a plaintext drop");
                }
                // rx_short, both forms: fewer bytes than the 9-byte
                // prefix, and a 37-byte frame carrying the DEK bit
                // (flags 0x1D = DEK | pattern | epoch 3) rejected at the
                // DEK minimum-size gate.
                R::TooShort => {
                    become_node_b(3);
                    assert_one_drop(b"1234", reason);
                    let mut short_dek = vec![0u8; 37];
                    short_dek[8] = 0x1D;
                    assert_one_drop(&short_dek, reason);
                }
                // rx_bad_flags: the constant-bit gate (bit 2 clear here).
                R::BadFlags => {
                    become_node_b(3);
                    let mut bad_flags = vec![0u8; 37];
                    bad_flags[8] = 0x00;
                    assert_one_drop(&bad_flags, reason);
                }
                // rx_len_mismatch: a real standard frame truncated by
                // one byte.
                R::LenMismatch => {
                    become_node_b(3);
                    assert_one_drop(&frame63[..frame63.len() - 1], reason);
                }
                // rx_no_peer: a node with NO key for A under any epoch —
                // a TOPOLOGY problem, counted separately from NoEpoch.
                R::NoPeer => {
                    lunet_paxe_shutdown();
                    assert_eq!(lunet_paxe_set_local_id(300), RC_OK);
                    // The receive path now rejects a foreign destination
                    // before looking up its source key. Retarget this
                    // otherwise-valid frame so this arm continues to reach
                    // the intended missing-peer gate.
                    let mut no_peer = frame63.clone();
                    no_peer[2..4].copy_from_slice(&300u16.to_be_bytes());
                    assert_one_drop(&no_peer, reason);
                }
                // rx_no_epoch: B knows peer A but not epoch 4 — a
                // ROTATION problem.
                R::NoEpoch => {
                    become_node_b(3);
                    assert_one_drop(&frame63_e4, reason);
                }
                // rx_auth_fail: one flipped ciphertext byte.
                R::AuthFailed => {
                    become_node_b(3);
                    let mut forged_ct = frame63.clone();
                    forged_ct[30] ^= 0x01;
                    assert_one_drop(&forged_ct, reason);
                }
            }
        }
        // The final arm (AuthFailed, last in ALL) left node B configured.

        // Success: rx_total AND rx_ok advance; the invariant holds.
        let before = stats::snapshot();
        let (rc, plain, _, _, _) = open(&frame63);
        assert_eq!(rc, RC_OK);
        assert_eq!(plain, payload40);
        let after = stats::snapshot();
        assert_eq!(after.rx_total - before.rx_total, 1);
        assert_eq!(after.rx_ok - before.rx_ok, 1);
        assert_invariant(&after, "after a success");
    }

    #[test]
    fn tx_counters_split_by_mode_and_count_oversize() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        setup_node_a(3);
        let before = stats::snapshot();
        // Both payloads use standard mode through the C ABI.
        let (rc, _) = seal(&[0u8; 63], NODE_B, CHAN);
        assert_eq!(rc, RC_OK);
        let (rc, _) = seal(&[0u8; 64], NODE_B, CHAN);
        assert_eq!(rc, RC_OK);
        // Oversize: RC_ERR, counted, and NOT a sealed frame.
        let big = vec![0u8; standard::MAX_PAYLOAD + 1];
        let (rc, _) = seal(&big, NODE_B, CHAN);
        assert_eq!(rc, RC_ERR);
        let after = stats::snapshot();
        assert_eq!(after.tx_total - before.tx_total, 2, "two seals");
        assert_eq!(after.tx_standard - before.tx_standard, 2, "standard seals");
        assert_eq!(after.tx_dek - before.tx_dek, 0, "no fanout C ABI");
        assert_eq!(after.tx_oversize - before.tx_oversize, 1, "oversize offer");
        assert_eq!(
            after.rx_total - before.rx_total,
            0,
            "sealing is not receiving"
        );
        // Failed seals for OTHER reasons (no key for the peer) are
        // operational errors reported to the caller, not drop accounting.
        let before = stats::snapshot();
        let (rc, _) = seal(b"x", 300, CHAN);
        assert_eq!(rc, RC_ERR);
        let after = stats::snapshot();
        assert_eq!(after.tx_total - before.tx_total, 0);
        assert_eq!(after.tx_oversize - before.tx_oversize, 0);
    }

    #[test]
    fn stats_ffi_probe_sizes_and_writes_the_pinned_order() {
        // Probing with (NULL, 0) returns the field count and writes
        // nothing; a real buffer receives the snapshot in the pinned
        // order, identical to the in-crate snapshot.
        let n = lunet_paxe_stats(std::ptr::null_mut(), 0);
        assert_eq!(n as usize, stats::SNAPSHOT_FIELD_COUNT);
        assert_eq!(n, 13);

        stats::record_rx_ok();
        stats::record_rx_drop();
        stats::record_reject(stats::RejectReason::NoPeer);
        stats::record_tx_sealed(codec::Mode::Dek);

        let mut buf = [0u64; 16];
        let n2 = lunet_paxe_stats(buf.as_mut_ptr(), buf.len());
        assert_eq!(n2, n);
        let expect = stats::snapshot().fields();
        assert_eq!(&buf[..expect.len()], &expect[..]);
        // The pinned positions, spot-checked against the struct.
        let s = stats::snapshot();
        assert_eq!(buf[0], s.rx_total);
        assert_eq!(buf[1], s.rx_ok);
        assert_eq!(buf[6], s.reject(stats::RejectReason::NoPeer));
        assert_eq!(buf[9], s.tx_total);
        assert_eq!(buf[11], s.tx_dek);
        assert_invariant(&s, "over direct recordings");
    }

    #[test]
    fn fail_policy_set_validates_spellings_and_leaves_state_on_error() {
        for good in ["silent", "log_once", "verbose"] {
            assert_eq!(lunet_paxe_fail_policy_set(good.as_ptr(), good.len()), RC_OK);
            assert_eq!(
                stats::policy(),
                stats::FailPolicy::from_name(good).expect("spelling parses")
            );
        }
        let bad = "loud";
        assert_eq!(
            lunet_paxe_fail_policy_set(bad.as_ptr(), bad.len()),
            RC_INVAL
        );
        assert!(last_error_string().contains("silent"));
        // A failed set changes nothing.
        assert_eq!(stats::policy(), stats::FailPolicy::Verbose);
        let bad_utf8 = [0xFFu8, 0xFE];
        assert_eq!(
            lunet_paxe_fail_policy_set(bad_utf8.as_ptr(), bad_utf8.len()),
            RC_INVAL
        );
        // Leave the policy silent for other tests on this thread.
        let silent = "silent";
        assert_eq!(
            lunet_paxe_fail_policy_set(silent.as_ptr(), silent.len()),
            RC_OK
        );
    }

    // -------------------------------------------------------------------
    // The protected-socket plaintext gate. A datagram is "for us"
    // iff it carries at least the 9-byte prefix AND a header toId equal
    // to the configured local id — the explicit check, never the flags
    // byte. Counting: a rejection moves rx_total AND rx_plaintext, each
    // by one, nothing else; an unconfigured receiver drops untallied.
    // -------------------------------------------------------------------

    /// Build a raw datagram with the given toId at header bytes 2-3.
    fn datagram_to(to_id: u16, len: usize, flags: u8) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[2..4].copy_from_slice(&to_id.to_be_bytes());
        if len > 8 {
            d[8] = flags;
        }
        d
    }

    #[test]
    fn frame_for_us_is_an_explicit_addressing_check_with_its_own_counter() {
        // Unconfigured: every verdict is 0 and NOTHING is counted (the
        // same rule open applies — the module is not running PAXE).
        let before = stats::snapshot();
        let d = datagram_to(NODE_A as u16, 40, 0x04);
        assert_eq!(lunet_paxe_frame_for_us(d.as_ptr(), d.len()), 0);
        let after = stats::snapshot();
        assert_eq!(
            after.rx_total - before.rx_total,
            0,
            "unconfigured: uncounted"
        );
        assert_eq!(
            after.reject(stats::RejectReason::Plaintext)
                - before.reject(stats::RejectReason::Plaintext),
            0,
            "unconfigured: uncounted"
        );

        // Configure WITHOUT lunet_paxe_init: the gate does no crypto, so
        // this test must also run on hosts without the AES-GCM hardware
        // path (set_local_id needs only the keystore, which self-inits).
        assert_eq!(lunet_paxe_set_local_id(NODE_A), RC_OK);

        // Addressed to us (toId == local id), flags byte PASSING the
        // constant-bit gate: classified as a frame, counted nowhere —
        // open() will count it exactly once.
        let d = datagram_to(NODE_A as u16, 40, 0x04);
        let before = stats::snapshot();
        assert_eq!(lunet_paxe_frame_for_us(d.as_ptr(), d.len()), 1);
        let after = stats::snapshot();
        assert_eq!(
            after.rx_total - before.rx_total,
            0,
            "a frame is open's to count"
        );

        // THE attack case: plaintext crafted so byte 8 PASSES the
        // flags constant-bit gate (0x04: pattern bits set), with a toId
        // that is not this node. The explicit addressing check rejects it
        // and the PLAINTEXT counter moves — rx_bad_flags must not.
        let crafted = datagram_to(0x270F, 40, 0x04);
        let before = stats::snapshot();
        assert_eq!(lunet_paxe_frame_for_us(crafted.as_ptr(), crafted.len()), 0);
        let after = stats::snapshot();
        assert_eq!(after.rx_total - before.rx_total, 1, "rx_total +1");
        assert_eq!(
            after.reject(stats::RejectReason::Plaintext)
                - before.reject(stats::RejectReason::Plaintext),
            1,
            "rx_plaintext +1"
        );
        assert_eq!(
            after.reject(stats::RejectReason::BadFlags)
                - before.reject(stats::RejectReason::BadFlags),
            0,
            "rx_bad_flags must not move: the flags byte was never consulted"
        );
        assert_invariant(&after, "after a crafted-plaintext drop");

        // Under the 9-byte prefix: cannot even present as a frame —
        // plaintext, not TooShort (the gate precedes the codec).
        let short = datagram_to(NODE_A as u16, 8, 0x04);
        let before = stats::snapshot();
        assert_eq!(lunet_paxe_frame_for_us(short.as_ptr(), short.len()), 0);
        let after = stats::snapshot();
        assert_eq!(
            after.reject(stats::RejectReason::Plaintext)
                - before.reject(stats::RejectReason::Plaintext),
            1,
            "sub-prefix datagram counts as plaintext"
        );
        assert_eq!(
            after.reject(stats::RejectReason::TooShort)
                - before.reject(stats::RejectReason::TooShort),
            0,
            "rx_short must not move"
        );

        // Malformed C-level argument: null with non-zero length raises
        // (RC_INVAL), counts nothing, and cannot panic.
        let before = stats::snapshot();
        assert_eq!(lunet_paxe_frame_for_us(std::ptr::null(), 9), RC_INVAL);
        let after = stats::snapshot();
        assert_eq!(after.rx_total - before.rx_total, 0);
    }
}
