//! DEK-mode seal and open (item06), plus the automatic mode-selection
//! layer that picks standard versus DEK on the send path.
//!
//! DEK mode is the 83-byte-overhead frame (PAXE.md "DEK Frame"):
//!
//! ```text
//! Header(8) ‖ Flags(1) ‖ KEK Nonce(12) ‖ Wrapped DEK(32) ‖ DEK Nonce(12)
//!         ‖ Length(2) ‖ Ciphertext(N) ‖ Tag(16)
//! ```
//!
//! The payload is sealed under a freshly generated per-message DEK (32
//! bytes from the CSPRNG); that DEK is wrapped under the link key acting as
//! KEK with a ChaCha20-IETF stream XOR and carried in the frame.
//!
//! This module replaces the DEK branch of the deleted `src/paxe.c` — code
//! that had **never executed** (the C encoder hard-coded flags to zero, so
//! no caller could set the DEK bit) and was wrong in ways nothing could
//! have caught: a four-link chain of pointer arithmetic located the KEK
//! nonce, wrapped DEK, DEK nonce and ciphertext, and a spurious error check
//! on the un-failable stream XOR attributed its "failure" to
//! `rx_auth_fail`. Both anti-patterns are designed out below, not patched.
//!
//! ## Declarative layout, not chained pointer arithmetic
//!
//! Every field offset is derived ONCE, in [`layout`], from the field sizes
//! (`PREFIX_LEN`, `NPUBBYTES`, `KEYBYTES`, the 2-byte inner length,
//! `ABYTES`) with compile-time assertions pinning each offset to the value
//! PAXE.md documents. Seal and open consume exactly the same constants, so
//! the two directions cannot drift apart, and no offset is ever computed by
//! adding a runtime length to a previous field's end. Field extraction on
//! the receive side is fixed-size destructuring: the 67-byte head is
//! converted to a `[u8; HEAD]` array (after the length gates) and each
//! field is taken as a fixed-size array whose size the compiler checks
//! against the turbofish at the call site.
//!
//! ## The DEK is key material: zeroed on EVERY exit path, by construction
//!
//! The DEK is held in a [`KeyGuard`]: a stack `sodium::Key` whose `Drop`
//! runs `sodium_memzero`. Erasure is therefore a Rust drop guarantee that
//! fires on success, on every early return, and on every rejection — NOT a
//! `sodium_memzero` remembered only on the success path, which is exactly
//! the deleted C's bug (its early returns left a plaintext DEK on the
//! stack). There is no test that "verifies" this by reading freed stack
//! memory (there is nothing sound to read); the guarantee is structural
//! and stated, the same standard item03 set for its erasure paths.
//!
//! The link key (KEK) needs no guard at all: it is never copied out of
//! the keystore's guarded allocation. item05's minimal sodium.rs exposure,
//! `Key::from_borrowed`, reinterprets the `StoredKey`'s borrowed guarded
//! bytes as a `&Key` (`repr(transparent)`, no copy), so the KEK feeds the
//! AEAD and stream-XOR wrappers directly from guarded, mlocked memory —
//! the same key-handling path item05's standard mode uses, so the two
//! modes cannot diverge on the parts they share.
//!
//! Why not a `GuardedAllocation` (the item03 heap discipline) for the DEK?
//! A guarded page per datagram is disproportionate: the DEK is ephemeral
//! (its lifetime is one seal or one open, microseconds), unlike the
//! long-term link keys the guarded heap exists for. The mlock argument —
//! the protection that survives `panic = "abort"` — also does not transfer:
//! an aborted process loses its stack with it, and a DEK recovered from a
//! crash image could only touch frames already sent. Stack array plus a
//! zeroing Drop guard is the item03 discipline applied at frame scope.
//!
//! ## The wrap is unauthenticated by construction
//!
//! ChaCha20 stream XOR has no tag and **cannot meaningfully fail**: any 32
//! bytes XOR to some 32 bytes, so a corrupted wrapped DEK yields a WRONG
//! DEK, not an error — the failure surfaces later, at the payload's AES-GCM
//! tag check. This is correct by design (PAXE.md "Cryptography").
//! `sodium::stream_xor` returns `()` precisely so there is nothing to
//! check; the deleted C checked it and mis-attributed the impossible
//! failure to `rx_auth_fail`. Do not reintroduce that check. The
//! corresponding test flips a bit in the wrapped-DEK field and asserts the
//! rejection is `AuthFailed` — there is no wrap-error variant to return.
//!
//! ## Two independent nonces
//!
//! The KEK nonce and the DEK nonce are drawn by two separate
//! `sodium::random_nonce()` CSPRNG calls. Neither is derived from the
//! other, and neither reuses the other field's value. Twelve random bytes
//! per nonce is what the protocol specifies; a counter or timestamp is not
//! acceptable (GCM nonce reuse under one key is catastrophic, and stream
//! nonce reuse leaks the XOR of the wrapped DEKs). A self-round-trip cannot
//! detect transposed or shared nonces — encoder and decoder would make the
//! same mistake — so the deterministic-seam test pins which nonce feeds the
//! wrap and which the AEAD, and item12's known-answer vectors pin it on the
//! wire.
//!
//! ## The inner Length field is redundant — and checked anyway
//!
//! Bytes 65–66 duplicate the header's `length` (reference compatibility,
//! honestly documented in PAXE.md). The receiver's only use for it is
//! rejection: if inner and header disagree — in EITHER direction — the
//! frame is dropped with [`OpenError::InnerLengthMismatch`]. The check runs
//! before the AEAD, so it does not depend on the tag.
//!
//! ## Receive-side gate ordering is a memory-safety requirement
//!
//! [`open_dek`] validates in this exact order:
//!
//! 1. **Minimum size** — `datagram.len() >= 83`, using ONLY the length. A
//!    short frame carrying the DEK bit (e.g. a 37-byte standard-geometry
//!    frame with bit 0 flipped) is rejected HERE, before any field beyond
//!    the 9-byte prefix is read. With `panic = "abort"`, indexing past a
//!    small datagram would be a remotely triggerable kill of the LuaJIT
//!    host process, so this ordering is not a nicety. The test truncates a
//!    real DEK frame at every length below 83 and asserts rejection with no
//!    panic, and pins the 37-byte case to the `TooShort` gate specifically
//!    (which proves the ordering: no later check ran first).
//! 2. **Declared length vs frame size** — `datagram.len()` must equal
//!    `header.length + 83` exactly (checked arithmetic on the untrusted
//!    declared value). This is the length-vs-datagram validation item04
//!    deliberately deferred to the mode implementations.
//! 3. **Inner length equality** — bytes 65–66 must equal `header.length`.
//! 4. **Key lookup** — by `fromId` and epoch (receive-side keystore
//!    asymmetry, item03). Cheap structural rejection always precedes
//!    keystore access, matching the codec's ordering philosophy.
//! 5. **Unwrap, then AEAD open** — the tag is the last word.
//!
//! ## AAD: one construction point, both directions
//!
//! The authenticated span is the 9-byte prefix (header + flags). Seal
//! authenticates the exact prefix array it places at the head of the frame;
//! open authenticates a BORROW of the frame's first 9 bytes. "The AAD is
//! the frame prefix" is true by construction in both directions — there is
//! no second, independently-built AAD that could diverge (the tamper tests
//! flip header and flags bytes and assert `AuthFailed`, proving the span
//! genuinely covers all 9 bytes).
//!
//! ## Out-of-place decryption (recorded decision)
//!
//! Open writes the plaintext to a fresh `Vec`, NOT in place over the
//! datagram. In-place operation is what forced the deleted C's overlapping
//! `memmove` with its 36-byte boundary hazard; out-of-place cannot corrupt
//! the input on failure (the sodium wrapper wipes the output on tag
//! mismatch before it is dropped), and at datagram sizes the copy is not
//! the bottleneck.
//!
//! ## Mode selection: one place, one constant, observable
//!
//! [`select_mode`] is the ONLY decision point on the send path: payloads
//! below [`DEK_THRESHOLD`] (64 bytes) seal standard, 64 and above seal DEK.
//! 64 bytes is one CPU cache line; the threshold is fixed by the protocol
//! (PAXE.md "Mode Selection"), NOT a tuning knob — sender and receiver must
//! always agree on the layout. The function is public so item13 can assert
//! the split, and the boundary is pinned by tests at 63, 64 and 65 bytes.
//! The RECEIVER never applies the threshold: it parses strictly by the
//! flags bit, so a sub-threshold DEK frame (only producible by forcing)
//! opens correctly — the threshold binds senders, not the wire.
//!
//! ## Forcing: automatic-only in production (recorded decision)
//!
//! The public send API takes no mode parameter — callers cannot force a
//! mode. Wire behaviour stays predictable and there is one selection rule
//! to audit. Forcing exists ONLY as `#[cfg(test)]` seams
//! ([`seal_forced`], [`seal_dek_deterministic`]), compiled out of every
//! non-test build: item12's known-answer vectors need supplied nonces and a
//! supplied DEK, and deterministic nonces must never be reachable in
//! production (GCM nonce reuse is catastrophic — this is the reasoning
//! item12 asks to have written down). The seams are `pub(crate)` so
//! item12's in-crate tests can reach them; nothing else can.
//!
//! ## Failure uniformity
//!
//! [`OpenError`] is a typed enum IN-CRATE so the tests below can pin each
//! rejection cause and item08 can derive one counter per reason — but every
//! variant means "drop the datagram", no variant carries unverified
//! plaintext, and the item07 FFI boundary MUST collapse all of them to a
//! single opaque failure. Returning the reason to a caller (or worse, to
//! the sender) would make the receiver a decryption oracle (PAXE.md
//! "Failure Handling"). There is deliberately no wrap-failure variant: the
//! condition cannot occur (see above), and item08 gets no counter for it.
//!
//! ## item05 integration point (WIRED in item07)
//!
//! Standard-mode seal/open are owned by item05 (`standard.rs`), built in
//! parallel. The dispatch below routes sub-threshold payloads and
//! non-DEK-flag frames to `standard_seal` / `standard_open` at the bottom
//! of this file — thin shims over `crate::standard::seal/open` (wired in
//! item07; before that they returned a typed unavailability). Standard
//! mode is deliberately NOT implemented here: duplicating item05's seal
//! is out of bounds for item06, and the shims keep it that way.

// Callers landed in item07 (Lua API); item09 (receive path) and item13
// (the select_mode assertion surface) have not. Parts of the public
// surface are still exercised only by unit tests, so dead_code is allowed
// here on the same terms as keystore.rs and codec.rs: remove the
// allowance as those items land.
#![allow(dead_code)]

use crate::codec::{self, CodecError, Flags, Header, Mode, PREFIX_LEN};
use crate::keystore::{Epoch, KeyStore, StoredKey};
use crate::sodium::{self, Key, Nonce, SodiumError, ABYTES, KEYBYTES, NPUBBYTES};
use crate::standard;
use crate::stats::{self, RejectReason};
use std::error::Error;
use std::fmt;

// ---------------------------------------------------------------------------
// Mode selection — the ONE place on the send path where the frame mode is
// decided.
// ---------------------------------------------------------------------------

/// Payload size at which the sender switches from standard to DEK framing:
/// **64 bytes — one CPU cache line.** Fixed by the protocol (PAXE.md "Mode
/// Selection"), not a tuning knob: sender and receiver must always agree on
/// the layout, so the threshold is a named constant with the rationale
/// attached, never a configuration value.
pub const DEK_THRESHOLD: usize = 64;

/// The only mode-selection decision point on the send path. Payloads below
/// [`DEK_THRESHOLD`] seal standard; 64 and above seal DEK. Public so the
/// split is observable — item13 asserts it — and pure so it can be tested
/// without any key material.
pub fn select_mode(payload_len: usize) -> Mode {
    if payload_len < DEK_THRESHOLD {
        Mode::Standard
    } else {
        Mode::Dek
    }
}

// ---------------------------------------------------------------------------
// DEK frame geometry — the SINGLE declarative layout both directions
// consume. Offsets derive from field sizes, never from chained runtime
// addition; the const block pins each one to the value PAXE.md documents
// and proves every field span equals its field size (so the fixed-size
// destructuring in open_dek cannot fail — its None arms are unreachable
// and mapped, never unwrapped).
// ---------------------------------------------------------------------------

mod layout {
    use crate::codec::PREFIX_LEN;
    use crate::sodium::{ABYTES, KEYBYTES, NPUBBYTES};

    /// KEK nonce: bytes 9..21 (12 bytes).
    pub const KEK_NONCE: usize = PREFIX_LEN;
    /// Wrapped DEK: bytes 21..53 (32 bytes).
    pub const WRAPPED_DEK: usize = KEK_NONCE + NPUBBYTES;
    /// DEK nonce: bytes 53..65 (12 bytes).
    pub const DEK_NONCE: usize = WRAPPED_DEK + KEYBYTES;
    /// Inner length: bytes 65..67 (2 bytes, big-endian).
    pub const INNER_LEN: usize = DEK_NONCE + NPUBBYTES;
    /// End of the fixed head; ciphertext runs from here to 16 bytes before
    /// the end of the frame. Byte 67.
    pub const HEAD: usize = INNER_LEN + 2;
    /// Per-frame overhead: fixed head plus the 16-byte tag = 83 bytes.
    pub const OVERHEAD: usize = HEAD + ABYTES;

    // Compile-time proof that the derived offsets are exactly the
    // documented wire offsets, and that every field span equals its field
    // size. A failed assert here is a build failure, not a runtime one.
    const _: () = {
        assert!(KEK_NONCE == 9);
        assert!(WRAPPED_DEK == 21);
        assert!(DEK_NONCE == 53);
        assert!(INNER_LEN == 65);
        assert!(HEAD == 67);
        assert!(OVERHEAD == 83);
        assert!(WRAPPED_DEK - KEK_NONCE == NPUBBYTES);
        assert!(DEK_NONCE - WRAPPED_DEK == KEYBYTES);
        assert!(INNER_LEN - DEK_NONCE == NPUBBYTES);
        assert!(HEAD - INNER_LEN == 2);
    };
}

/// Per-frame DEK overhead in bytes: 83 (PAXE.md "DEK Frame"). Frame size
/// is always exactly `payload + DEK_OVERHEAD`.
pub const DEK_OVERHEAD: usize = layout::OVERHEAD;

/// The largest possible UDP datagram payload (PAXE.md "Limits").
const UDP_DATAGRAM_MAX: usize = 65507;

/// Maximum plaintext payload for DEK mode: 65507 − 83 = **65424**
/// (PAXE.md "Limits"). Seal rejects anything larger with a reportable
/// error — never a truncated length field.
pub const DEK_MAX_PAYLOAD: usize = UDP_DATAGRAM_MAX - DEK_OVERHEAD;

// ---------------------------------------------------------------------------
// KeyGuard: key material on the stack, erased by Drop on every exit path.
// ---------------------------------------------------------------------------

/// A 32-byte key held on the stack under a zeroing Drop guard. Used for
/// the per-message DEK: it is generated on the stack (or recovered there
/// by the unwrap XOR), so it needs stack-resident erasure. The link key
/// does NOT come through here — it is borrowed in place from the
/// keystore's guarded allocation via `Key::from_borrowed`, never copied.
///
/// `Drop` runs `sodium_memzero` on EVERY exit path: success, early return,
/// every rejection. Erasure is by construction, not by a remembered call —
/// this is the direct answer to the deleted C, which kept the DEK in a
/// plain stack array and memzero'd it on the success path only. Not
/// `Clone`, so the guarded copy can never be duplicated silently.
struct KeyGuard(Key);

impl KeyGuard {
    /// A fresh 32-byte key from the CSPRNG (the per-message DEK). The only
    /// randomness source for key material anywhere in the crate.
    fn generate() -> Self {
        KeyGuard(sodium::random_key())
    }

    /// Guard an existing key array (e.g. the DEK supplied by the test
    /// seam, or the still-wrapped DEK copied out of a received frame).
    fn from_bytes(bytes: &[u8; KEYBYTES]) -> Self {
        KeyGuard(Key::from_bytes(*bytes))
    }

    /// Borrow the key for an FFI wrapper call.
    fn key(&self) -> &Key {
        &self.0
    }

    /// Mutable access for the in-place unwrap XOR.
    fn as_mut_bytes(&mut self) -> &mut [u8; KEYBYTES] {
        self.0.as_mut_bytes()
    }
}

/// Borrow the link key out of a `StoredKey`'s guarded allocation as a
/// `&Key` — NO copy. The keystore invariant makes the slice exactly
/// KEYBYTES long, so the `Err` arm is unreachable; callers map it, never
/// unwrap it. (item05's minimal sodium.rs exposure, shared by both modes.)
fn borrow_link_key(stored: &StoredKey) -> Result<&Key, SodiumError> {
    match <&[u8; KEYBYTES]>::try_from(stored.expose()) {
        Ok(a) => Ok(Key::from_borrowed(a)),
        Err(_) => Err(SodiumError::Internal),
    }
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        // The one erasure point for every path: sodium_memzero cannot be
        // elided by the optimiser, and Drop ordering runs it before the
        // stack frame is reused.
        sodium::memzero(self.0.as_mut_bytes());
    }
}

// ---------------------------------------------------------------------------
// Errors. Typed in-crate (tests pin each cause; item08 derives one counter
// per reason); the item07 FFI boundary collapses every OpenError to a
// single opaque drop — see the module docs.
// ---------------------------------------------------------------------------

/// Every failure the seal path can report. No operation in this module
/// panics — `panic = "abort"` would kill the LuaJIT host process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// Payload exceeds [`DEK_MAX_PAYLOAD`]; carries the offered size.
    /// Reportable, never a truncated length field (PAXE.md "Limits").
    Oversize(usize),
    /// No key installed for this `(peer, epoch)` — a drop reason on the
    /// wire, reported here so the caller can surface misconfiguration.
    NoKey,
    /// Wrapped from the sodium boundary (allocation or an impossible
    /// internal result).
    Sodium(SodiumError),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Oversize(n) => write!(
                f,
                "payload too large for DEK frame: {n} bytes (max {DEK_MAX_PAYLOAD})"
            ),
            SealError::NoKey => write!(f, "no key installed for (peer, epoch)"),
            SealError::Sodium(e) => write!(f, "crypto failure: {e}"),
        }
    }
}

impl Error for SealError {}

impl From<SodiumError> for SealError {
    fn from(e: SodiumError) -> Self {
        SealError::Sodium(e)
    }
}

/// Every rejection the open path can report. In-crate these stay specific
/// (item08 counts each cause; the tests pin each one); at the item07 FFI
/// boundary they MUST collapse to a single opaque drop — a receiver that
/// explains why a forgery failed is a decryption oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The codec rejected the 9-byte prefix: fewer than 9 bytes, or the
    /// flags constant-bit gate fired (the protocol's cheap garbage filter,
    /// applied before anything else runs).
    Prefix(CodecError),
    /// The frame carries the DEK bit but is shorter than the 83-byte
    /// minimum DEK frame; carries the actual size. This is gate 1 — it
    /// fires before ANY field beyond the 9-byte prefix is read (the
    /// memory-safety ordering, see the module docs).
    TooShort(usize),
    /// `header.length + 83` does not equal the actual frame size: the
    /// declared plaintext length disagrees with the datagram.
    LengthMismatch,
    /// The redundant inner Length field (bytes 65–66) disagrees with the
    /// header's `length` — rejected in both directions of mismatch.
    InnerLengthMismatch,
    /// No key installed for the frame's `(fromId, epoch)`.
    NoKey,
    /// The AES-GCM tag did not verify: wrong key, tampered ciphertext,
    /// tampered AAD (header or flags), or a wrong DEK from a corrupted
    /// wrapped DEK. This is where wrap corruption surfaces — there is no
    /// wrap-failure variant, by design.
    AuthFailed,
    /// A standard-mode frame was rejected by `standard::open`. item05's
    /// open is deliberately single-variant (opaque `Rejected`: oracle
    /// avoidance at its own layer), so the cause is already erased before
    /// it reaches this dispatch — mapping it onto any of the typed
    /// variants above would INVENT a reason. One honest variant, one
    /// item08 counter: that is the most the counters can know about a
    /// standard-mode rejection.
    StandardRejected,
    /// Wrapped from the sodium boundary (an impossible internal result).
    Sodium(SodiumError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Prefix(e) => write!(f, "{e}"),
            OpenError::TooShort(n) => write!(
                f,
                "DEK frame too short: {n} bytes, need at least {DEK_OVERHEAD}"
            ),
            OpenError::LengthMismatch => {
                write!(f, "declared length disagrees with frame size")
            }
            OpenError::InnerLengthMismatch => {
                write!(f, "DEK inner length disagrees with header length")
            }
            OpenError::NoKey => write!(f, "no key installed for (fromId, epoch)"),
            OpenError::AuthFailed => write!(f, "authentication failed"),
            OpenError::StandardRejected => write!(f, "standard-mode frame rejected"),
            OpenError::Sodium(e) => write!(f, "crypto failure: {e}"),
        }
    }
}

impl Error for OpenError {}

// ---------------------------------------------------------------------------
// Seal.
// ---------------------------------------------------------------------------

/// The send path: seal `payload` for `to_id` on `channel` under `epoch`,
/// choosing the frame mode by [`select_mode`] — the ONE place the choice
/// happens. Returns the complete frame, exactly `payload.len() + 37` or
/// `payload.len() + 83` bytes depending on the chosen mode.
pub fn seal(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
) -> Result<Vec<u8>, SealError> {
    match select_mode(payload.len()) {
        Mode::Dek => seal_dek(store, to_id, channel, epoch, payload),
        Mode::Standard => standard_seal(store, to_id, channel, epoch, payload),
    }
}

/// DEK-mode seal with production randomness: the DEK and BOTH nonces are
/// independent CSPRNG draws, made here and nowhere else. There is no code
/// path that derives one nonce from the other, from a counter, from a
/// timestamp, or from the payload.
fn seal_dek(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
) -> Result<Vec<u8>, SealError> {
    let dek = KeyGuard::generate();
    let kek_nonce = sodium::random_nonce();
    let dek_nonce = sodium::random_nonce();
    seal_dek_core(
        store, to_id, channel, epoch, payload, kek_nonce, dek, dek_nonce,
    )
}

/// The deterministic core of DEK seal. Production reaches it only via
/// [`seal_dek`] (CSPRNG draws above); the `#[cfg(test)]` seam below reaches
/// it with supplied values for item12's known-answer vectors. Randomness
/// is a parameter precisely so the production path has exactly one
/// randomness source and the test path is compiled out of release builds.
///
/// The argument count is the point: every value the frame depends on is
/// passed in, including both nonces and the DEK, so nothing is drawn
/// inside. Bundling them into a struct would hide exactly what this
/// signature is here to expose.
#[allow(clippy::too_many_arguments)]
fn seal_dek_core(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
    kek_nonce: Nonce,
    dek: KeyGuard,
    dek_nonce: Nonce,
) -> Result<Vec<u8>, SealError> {
    // Bound BEFORE a Header is constructed (the codec's rule: the u16
    // length field can never be made to truncate what it cannot hold).
    if payload.len() > DEK_MAX_PAYLOAD {
        return Err(SealError::Oversize(payload.len()));
    }
    // Send-side key lookup: the peer is the frame's toId — we seal with
    // the key we share with the destination (item03 asymmetry).
    let stored = match store.key_for_send(to_id, epoch) {
        Some(k) => k,
        None => return Err(SealError::NoKey),
    };
    // payload.len() <= DEK_MAX_PAYLOAD < 65536, so this conversion cannot
    // fail; matched anyway — nothing in this module unwraps.
    let length = match u16::try_from(payload.len()) {
        Ok(l) => l,
        Err(_) => return Err(SealError::Oversize(payload.len())),
    };
    let header = Header {
        from_id: store.local_id(),
        to_id,
        channel,
        length,
    };
    let flags = Flags::new(Mode::Dek, epoch);
    // THE AAD, constructed once: the 9-byte prefix that leads the frame.
    // Seal authenticates this exact array; open authenticates a borrow of
    // the frame's first 9 bytes — the same span by construction.
    let prefix = codec::serialize_prefix(&header, &flags);

    // The link key (KEK) is borrowed IN PLACE from the keystore's guarded,
    // mlocked allocation — never copied to the stack (item05's
    // Key::from_borrowed exposure; see the module docs).
    let kek = match borrow_link_key(stored) {
        Ok(k) => k,
        Err(e) => return Err(SealError::Sodium(e)),
    };

    // Assemble the fixed 67-byte head at the declarative offsets. Every
    // range is a layout constant against a fixed-size array, so every copy
    // is in bounds by construction (the const asserts in `layout` prove
    // the spans); no attacker-controlled value influences an index here —
    // the payload only appends AFTER the head.
    let mut head = [0u8; layout::HEAD];
    head[..PREFIX_LEN].copy_from_slice(&prefix);
    head[layout::KEK_NONCE..layout::WRAPPED_DEK].copy_from_slice(kek_nonce.as_bytes());
    head[layout::WRAPPED_DEK..layout::DEK_NONCE].copy_from_slice(dek.key().as_bytes());
    head[layout::DEK_NONCE..layout::INNER_LEN].copy_from_slice(dek_nonce.as_bytes());
    head[layout::INNER_LEN..layout::HEAD].copy_from_slice(&length.to_be_bytes());

    // WRAP the DEK: ChaCha20-IETF stream XOR under the KEK, IN PLACE in
    // the frame head (no second plaintext copy is ever made).
    //
    // UNAUTHENTICATED, AND CANNOT MEANINGFULLY FAIL. A stream XOR has no
    // tag and no error channel: any 32 bytes XOR to some 32 bytes, so a
    // corrupted wrapped DEK yields a WRONG DEK, and the failure surfaces
    // later at the payload's AES-GCM tag check in open_dek. This is
    // correct by design (PAXE.md "Cryptography"); sodium::stream_xor
    // returns () precisely so there is nothing to check. The deleted C
    // error-checked this call and attributed the impossible failure to
    // rx_auth_fail — do NOT reintroduce that check. Between the copy
    // above and this XOR the head holds the PLAINTEXT DEK: no fallible
    // operation separates them, and the XOR overwrites it with ciphertext.
    sodium::stream_xor(
        kek,
        &kek_nonce,
        &mut head[layout::WRAPPED_DEK..layout::DEK_NONCE],
    );

    // Frame = head (67) ‖ ciphertext (N) ‖ tag (16) = N + 83 exactly.
    // N <= DEK_MAX_PAYLOAD, so the additions cannot overflow usize.
    let mut frame = Vec::with_capacity(payload.len() + DEK_OVERHEAD);
    frame.extend_from_slice(&head);
    frame.resize(layout::HEAD + payload.len() + ABYTES, 0);
    let out = match frame.get_mut(layout::HEAD..) {
        Some(o) => o,
        // Unreachable: the buffer was just sized to exactly this.
        None => return Err(SealError::Sodium(SodiumError::Internal)),
    };
    // Seal the payload under the DEK with the 9-byte prefix as AAD. The
    // wrapper contract writes exactly payload.len() + ABYTES bytes — the
    // space reserved above — so the frame is N + 83 by construction.
    sodium::aead_encrypt(dek.key(), &dek_nonce, &prefix, payload, out)?;
    Ok(frame)
}

// ---------------------------------------------------------------------------
// Open.
// ---------------------------------------------------------------------------

/// The receive path: parse and open one datagram. On success returns the
/// parsed header, the validated flags (reporting the frame's mode), and
/// the recovered plaintext. On ANY failure returns a typed
/// [`OpenError`] — a drop reason, never partial plaintext.
pub fn open(store: &KeyStore, datagram: &[u8]) -> Result<(Header, Flags, Vec<u8>), OpenError> {
    // Codec gates first: at least 9 bytes, flags constant-bit garbage
    // filter — both before any mode-specific work and before any keystore
    // access (the Epoch type enforces the latter, item04). The item08
    // reason is recorded HERE, at the reject point — the only place the
    // typed cause still exists.
    let (header, flags) = match codec::parse_prefix(datagram) {
        Ok(hf) => hf,
        Err(e) => {
            stats::record_reject(RejectReason::from_codec(e));
            return Err(OpenError::Prefix(e));
        }
    };
    // The flags byte selects the parse geometry. The threshold plays no
    // part here: the receiver parses by the bit, not by size.
    match flags.mode() {
        Mode::Dek => open_dek(store, datagram, header, flags),
        Mode::Standard => standard_open(store, datagram, header, flags),
    }
}

/// Take one fixed-size field out of the DEK head at a declarative span.
/// Returns `None` if the span is out of bounds or its length differs from
/// `N` — both impossible after the length gates given the const asserts in
/// `layout`, and the caller maps that to an internal error rather than
/// ever unwrapping.
fn field<const N: usize>(head: &[u8; layout::HEAD], start: usize, end: usize) -> Option<[u8; N]> {
    head.get(start..end).and_then(|s| s.try_into().ok())
}

/// DEK-mode open. Gate order is the memory-safety contract documented at
/// the top of this module: minimum size, declared-vs-actual size, inner
/// length equality, key lookup, unwrap, AEAD — in that order, always.
fn open_dek(
    store: &KeyStore,
    datagram: &[u8],
    header: Header,
    flags: Flags,
) -> Result<(Header, Flags, Vec<u8>), OpenError> {
    // GATE 1 — minimum DEK frame size, using ONLY the datagram length.
    // Fires before any field beyond the 9-byte prefix is read, so a short
    // frame with the DEK bit set (e.g. 37 bytes) can never cause an
    // out-of-bounds read of the KEK nonce, wrapped DEK, DEK nonce or inner
    // length. Memory-safety ordering, tested at every truncation < 83.
    if datagram.len() < DEK_OVERHEAD {
        stats::record_reject(RejectReason::TooShort);
        return Err(OpenError::TooShort(datagram.len()));
    }
    // GATE 2 — declared length vs actual frame size, exactly:
    // frame == header.length + 83. Checked arithmetic on the untrusted
    // declared value (a u16, so the add cannot in fact overflow usize;
    // checked anyway so no path can panic if that ever changes).
    let expected = match (header.length as usize).checked_add(DEK_OVERHEAD) {
        Some(e) => e,
        None => {
            stats::record_reject(RejectReason::LenMismatch);
            return Err(OpenError::LengthMismatch);
        }
    };
    if datagram.len() != expected {
        stats::record_reject(RejectReason::LenMismatch);
        return Err(OpenError::LengthMismatch);
    }

    // From here on every fixed field of the 67-byte head is known to be in
    // bounds. Fixed-size destructuring: convert the head once, then take
    // each field as a fixed-size array — the compiler checks every field
    // size, and the layout const asserts prove the spans match them.
    let head: [u8; layout::HEAD] =
        match datagram.get(..layout::HEAD).and_then(|s| s.try_into().ok()) {
            Some(h) => h,
            // Unreachable after gate 1 (OVERHEAD > HEAD); mapped, never unwrapped.
            None => return Err(OpenError::TooShort(datagram.len())),
        };
    let fields = (
        field::<NPUBBYTES>(&head, layout::KEK_NONCE, layout::WRAPPED_DEK),
        field::<KEYBYTES>(&head, layout::WRAPPED_DEK, layout::DEK_NONCE),
        field::<NPUBBYTES>(&head, layout::DEK_NONCE, layout::INNER_LEN),
        field::<2>(&head, layout::INNER_LEN, layout::HEAD),
    );
    let (kek_nonce_bytes, wrapped_dek_bytes, dek_nonce_bytes, inner_len_bytes) = match fields {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        // Unreachable: each span equals its field size by const assert.
        _ => return Err(OpenError::Sodium(SodiumError::Internal)),
    };

    // GATE 3 — the redundant inner Length must EQUAL the header's declared
    // length, rejecting on disagreement in BOTH directions. It is outside
    // the AAD and redundant with gate 2 (reference compatibility, PAXE.md),
    // so this explicit equality check is its only enforcement.
    if u16::from_be_bytes(inner_len_bytes) != header.length {
        stats::record_reject(RejectReason::DekLenMismatch);
        return Err(OpenError::InnerLengthMismatch);
    }

    // GATE 4 — receive-side key lookup: the peer is the frame's fromId —
    // we open with the key we share with the source (item03 asymmetry).
    // A miss is classified for item08 AT THIS POINT, where the store is
    // in scope: a peer with no entries at all is a topology problem
    // (NoPeer), a peer holding other epochs is a rotation problem
    // (NoEpoch). The typed error stays the single honest NoKey — the
    // split lives only in the counters.
    let stored = match store.key_for_receive(header.from_id, flags.epoch()) {
        Some(k) => k,
        None => {
            stats::record_reject(if store.peer_known(header.from_id) {
                RejectReason::NoEpoch
            } else {
                RejectReason::NoPeer
            });
            return Err(OpenError::NoKey);
        }
    };
    let kek = match borrow_link_key(stored) {
        Ok(k) => k,
        Err(e) => return Err(OpenError::Sodium(e)),
    };

    // UNWRAP the DEK: the same ChaCha20-IETF stream XOR as the wrap, keyed
    // by the KEK with the KEK nonce — UNAUTHENTICATED and incapable of
    // failure, so a corrupted wrapped DEK silently yields a WRONG DEK here
    // and the rejection comes from the payload tag check below. By design;
    // see the wrap call site in seal_dek_core and the module docs. The
    // recovered DEK lives only inside this KeyGuard: zeroed on every exit
    // path from here, including the AuthFailed return.
    let mut dek = KeyGuard::from_bytes(&wrapped_dek_bytes);
    sodium::stream_xor(kek, &Nonce::from_bytes(kek_nonce_bytes), dek.as_mut_bytes());

    // THE AAD: a borrow of the frame's first 9 bytes — "the AAD is the
    // frame prefix" by construction, the same span seal authenticated.
    let aad = match datagram.get(..PREFIX_LEN) {
        Some(a) => a,
        // Unreachable: the codec already parsed a full prefix.
        None => return Err(OpenError::Prefix(CodecError::TooShort(datagram.len()))),
    };
    let ct_tag = match datagram.get(layout::HEAD..) {
        Some(c) => c,
        // Unreachable after gates 1–2; mapped, never unwrapped.
        None => return Err(OpenError::TooShort(datagram.len())),
    };

    // GATE 5 — the tag is the last word. Out-of-place into a fresh buffer
    // (recorded decision, module docs): on tag mismatch the sodium wrapper
    // wipes the output region before we return, so unverified plaintext
    // never escapes — and the caller's datagram is never mutated.
    let declared = header.length as usize;
    let mut plain = vec![0u8; declared];
    match sodium::aead_decrypt(
        dek.key(),
        &Nonce::from_bytes(dek_nonce_bytes),
        aad,
        ct_tag,
        &mut plain,
    ) {
        Ok(_) => Ok((header, flags, plain)),
        Err(SodiumError::AuthFailed) => {
            stats::record_reject(RejectReason::AuthFailed);
            Err(OpenError::AuthFailed)
        }
        // Impossible internal result: not a wire condition, so no reason
        // counter fits — deliberately uncounted (stats.rs module docs).
        Err(e) => Err(OpenError::Sodium(e)),
    }
}

// ---------------------------------------------------------------------------
// Test-only seams: forcing and deterministic randomness. `#[cfg(test)]` —
// COMPILED OUT of every non-test build. Deterministic nonces must never be
// reachable in production: GCM nonce reuse under one key destroys both
// confidentiality and authenticity, and a fixed DEK destroys per-message
// key separation. These exist for item12's known-answer vectors and for
// the boundary/geometry tests below; they are pub(crate) so item12's
// in-crate tests can reach them, and nothing else can.
// ---------------------------------------------------------------------------

/// Force a frame mode, bypassing [`select_mode`]. TEST-ONLY: the public
/// send API is automatic-only (recorded decision, module docs). The
/// receiver parses by the flags bit, so a forced frame is ordinary wire
/// traffic — used below to prove sub-threshold DEK frames round-trip.
#[cfg(test)]
pub(crate) fn seal_forced(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    mode: Mode,
    payload: &[u8],
) -> Result<Vec<u8>, SealError> {
    match mode {
        Mode::Dek => seal_dek(store, to_id, channel, epoch, payload),
        Mode::Standard => standard_seal(store, to_id, channel, epoch, payload),
    }
}

/// DEK seal with supplied nonces and a supplied DEK. TEST-ONLY known-
/// answer seam for item12: pins every field offset, the wrap primitive,
/// and which nonce feeds the wrap versus the AEAD, byte-for-byte.
///
/// Every randomness input is a parameter by design — that is what makes
/// the vectors reproducible — so the argument count is the feature.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn seal_dek_deterministic(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
    kek_nonce: [u8; NPUBBYTES],
    dek: [u8; KEYBYTES],
    dek_nonce: [u8; NPUBBYTES],
) -> Result<Vec<u8>, SealError> {
    seal_dek_core(
        store,
        to_id,
        channel,
        epoch,
        payload,
        Nonce::from_bytes(kek_nonce),
        KeyGuard::from_bytes(&dek),
        Nonce::from_bytes(dek_nonce),
    )
}

// ===========================================================================
// item05 INTEGRATION POINT — standard mode (WIRED in item07).
//
// Standard-mode seal/open are owned by item05 (`standard.rs`). The
// dispatch above routes sub-threshold payloads (seal) and non-DEK-flag
// frames (open) to these two shims, which adapt item05's caller-buffer
// seal and its deliberately single-variant open error to this module's
// Vec-returning, typed-error shapes. Standard mode is NOT implemented
// here: the shims call `crate::standard::seal/open` and nothing else.
//
// Error mapping (settled in item07, recorded for item08): item05's
// `standard::OpenError` is a single opaque variant by design, so a
// standard-mode rejection maps to the ONE honest variant
// `OpenError::StandardRejected` — never to a typed cause this layer
// cannot know. Both surfaces collapse to one opaque drop at the item07
// FFI boundary.
// ===========================================================================

fn standard_seal(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
) -> Result<Vec<u8>, SealError> {
    // Bound BEFORE allocating the frame buffer (standard::seal enforces
    // the same bound against the caller buffer, but by then the Vec
    // would already exist). Oversize is reportable, never a truncated
    // length field. Reachable here only via the cfg(test) forcing seam —
    // the dispatch routes sub-threshold payloads, which are always in
    // range — but totality does not depend on the caller.
    if payload.len() > standard::MAX_PAYLOAD {
        return Err(SealError::Oversize(payload.len()));
    }
    // payload.len() <= 65470, so the addition cannot overflow.
    let mut frame = vec![0u8; payload.len() + standard::OVERHEAD];
    match standard::seal(store, to_id, channel, epoch, payload, &mut frame) {
        Ok(_) => Ok(frame),
        Err(standard::SealError::PayloadTooLarge(n)) => Err(SealError::Oversize(n)),
        Err(standard::SealError::OutputTooSmall { .. }) => {
            // Unreachable: the buffer was sized to exactly the frame.
            Err(SealError::Sodium(SodiumError::Internal))
        }
        Err(standard::SealError::NoKey) => Err(SealError::NoKey),
        Err(standard::SealError::Sodium(e)) => Err(SealError::Sodium(e)),
    }
}

fn standard_open(
    store: &KeyStore,
    datagram: &[u8],
    header: Header,
    _flags: Flags,
) -> Result<(Header, Flags, Vec<u8>), OpenError> {
    // Output sized by the DECLARED length (a u16, so at most 65535) —
    // never by the datagram size, which is attacker-controlled and
    // unbounded. If the declaration disagrees with the frame size,
    // standard::open rejects before any decryption runs.
    let mut plain = vec![0u8; header.length as usize];
    match standard::open(store, datagram, &mut plain) {
        Ok((h, f, n)) => {
            plain.truncate(n);
            Ok((h, f, plain))
        }
        // item05 erased the cause by design; do not invent one.
        Err(_) => Err(OpenError::StandardRejected),
    }
}

// ---------------------------------------------------------------------------
// Tests. Panicking asserts are fine here: test code never ships in the
// cdylib.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // A genuine TWO-NODE link: node A (id 100) and node B (id 200) share
    // one per-link key. Sealing A->B looks the key up by toId (200) in A's
    // store; opening looks it up by fromId (100) in B's store. Distinct
    // ids are essential — with fromId == toId a transposed send/receive
    // lookup resolves to the same slot and proves nothing (item03).
    const NODE_A: u16 = 100;
    const NODE_B: u16 = 200;
    const CHAN: u16 = 137; // application channel, deliberately non-round
    const LINK_KEY: [u8; KEYBYTES] = [0x42; KEYBYTES];
    const EPOCH: u8 = 3;

    struct Link {
        a: KeyStore,
        b: KeyStore,
    }

    fn ep(bits: u8) -> Epoch {
        Epoch::new(bits).expect("test epochs are in range")
    }

    fn link() -> Link {
        let mut a = KeyStore::new(NODE_A).expect("store A");
        a.install(NODE_B, ep(EPOCH), &LINK_KEY).expect("install A");
        let mut b = KeyStore::new(NODE_B).expect("store B");
        b.install(NODE_A, ep(EPOCH), &LINK_KEY).expect("install B");
        Link { a, b }
    }

    /// AES-GCM needs the hardware path (Debian trixie arm64 ships a
    /// libsodium without it; see sodium.rs). Skip pattern matches the
    /// sodium.rs tests: unavailability is an environment property, never
    /// a test failure.
    fn gcm() -> bool {
        sodium::init().is_ok() && sodium::aes_gcm_available()
    }

    /// Payload containing NUL bytes, high bytes and a position-dependent
    /// fill, so byte-exactness is checked across the whole value range.
    fn payload(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| match i % 3 {
                0 => 0x00,
                1 => 0xFF,
                _ => (i % 256) as u8,
            })
            .collect()
    }

    #[test]
    fn dek_round_trip_byte_exact_across_lengths() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        // Span the fixed 67-byte head length (66/67/68 — the payload
        // sizes around which the deleted C's in-place decrypt+memmove
        // began to overlap; out-of-place decryption removes that boundary
        // by construction, and the straddle pins it), the 83-byte
        // overhead region (64..128), typical datagram sizes, and the
        // documented DEK maximum 65507 - 83 = 65424.
        for n in [
            64usize,
            65,
            66,
            67,
            68,
            82,
            83,
            84,
            100,
            128,
            1400,
            8192,
            DEK_MAX_PAYLOAD,
        ] {
            let pt = payload(n);
            let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &pt).expect("seal");
            assert_eq!(
                frame.len(),
                n + DEK_OVERHEAD,
                "frame must be N + 83 exactly (n={n})"
            );
            // The flags on the wire report DEK mode.
            let (wh, wf) = codec::parse_prefix(&frame).expect("wire prefix");
            assert_eq!(wf.mode(), Mode::Dek, "wire flags must report DEK (n={n})");
            assert_eq!(wh.length as usize, n);
            let (h, f, plain) = open(&l.b, &frame).expect("open");
            // The RETURNED flags report DEK mode; header round-trips.
            assert_eq!(
                f.mode(),
                Mode::Dek,
                "returned flags must report DEK (n={n})"
            );
            assert_eq!(f.epoch(), ep(EPOCH));
            assert_eq!(h, wh);
            assert_eq!(h.from_id, NODE_A);
            assert_eq!(h.to_id, NODE_B);
            assert_eq!(h.channel, CHAN);
            assert_eq!(plain, pt, "byte-exact round trip (n={n})");
        }
    }

    #[test]
    fn mode_selection_boundary_63_64_65() {
        // The ONE decision point, asserted at and around the boundary.
        assert_eq!(select_mode(0), Mode::Standard);
        assert_eq!(select_mode(1), Mode::Standard);
        assert_eq!(select_mode(63), Mode::Standard);
        assert_eq!(select_mode(64), Mode::Dek);
        assert_eq!(select_mode(65), Mode::Dek);
        assert_eq!(select_mode(DEK_MAX_PAYLOAD), Mode::Dek);
        assert_eq!(DEK_THRESHOLD, 64, "one cache line, fixed by the protocol");

        if !gcm() {
            eprintln!("skipping wire half of boundary test: AES-GCM unavailable");
            return;
        }
        let l = link();
        // On the wire, 64 and 65 carry the DEK bit through the dispatch.
        for n in [64usize, 65] {
            let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &payload(n)).expect("seal");
            let (_, f) = codec::parse_prefix(&frame).expect("prefix");
            assert_eq!(f.mode(), Mode::Dek, "n={n} must select DEK on the wire");
            assert_eq!(frame.len(), n + DEK_OVERHEAD);
        }
        // 63 routes to standard (the wired item05 path): a real
        // 37-byte-overhead standard frame carrying the standard-mode bit.
        let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &payload(63)).expect("seal 63");
        let (_, f) = codec::parse_prefix(&frame).expect("prefix");
        assert_eq!(
            f.mode(),
            Mode::Standard,
            "n=63 must select standard on the wire"
        );
        assert_eq!(frame.len(), 63 + 37, "standard overhead is 37 bytes");
    }

    #[test]
    fn inner_length_disagreement_rejected_in_both_directions() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        let pt = payload(100);
        let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &pt).expect("seal");

        // The inner Length field (bytes 65-66) sits OUTSIDE the AAD, so
        // patching it leaves a valid tag: only the explicit equality check
        // can catch the forgery. One direction below, one above.
        for wrong in [99u16, 101] {
            let mut forged = frame.clone();
            let [b0, b1] = wrong.to_be_bytes();
            forged[layout::INNER_LEN] = b0;
            forged[layout::INNER_LEN + 1] = b1;
            assert_eq!(
                open(&l.b, &forged),
                Err(OpenError::InnerLengthMismatch),
                "inner {wrong} vs declared 100 must be rejected"
            );
        }
        // Control: the unmodified frame opens.
        assert!(open(&l.b, &frame).is_ok());

        // Declared length vs actual frame size: truncate and extend.
        let truncated = &frame[..frame.len() - 1];
        assert_eq!(open(&l.b, truncated), Err(OpenError::LengthMismatch));
        let mut extended = frame.clone();
        extended.push(0);
        assert_eq!(open(&l.b, &extended), Err(OpenError::LengthMismatch));
    }

    #[test]
    fn corrupted_wrapped_dek_surfaces_as_payload_tag_failure() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        let pt = payload(100);
        let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &pt).expect("seal");

        // Flip a bit at the start, middle and end of the wrapped-DEK field
        // (bytes 21-52). The wrap is unauthenticated by construction, so
        // this yields a WRONG DEK and the rejection MUST be the payload
        // tag check — there is no wrap-error variant to return instead.
        for offset in [layout::WRAPPED_DEK, 37, layout::DEK_NONCE - 1] {
            let mut forged = frame.clone();
            forged[offset] ^= 0x01;
            assert_eq!(
                open(&l.b, &forged),
                Err(OpenError::AuthFailed),
                "corruption at offset {offset} must surface at the payload tag"
            );
        }
        // A corrupted DEK nonce fails at the tag for the same reason.
        let mut forged = frame.clone();
        forged[layout::DEK_NONCE] ^= 0x01;
        assert_eq!(open(&l.b, &forged), Err(OpenError::AuthFailed));
        // Control.
        assert!(open(&l.b, &frame).is_ok());
    }

    #[test]
    fn short_frame_with_dek_flag_rejects_before_any_field_read() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &payload(64)).expect("seal");

        // THE spec case: a 37-byte frame (standard-mode geometry) carrying
        // the DEK flag. The truncated real frame has a valid prefix
        // (declared length 64, DEK bit set), so ONLY the gate ordering
        // protects the out-of-bounds fields. Asserting TooShort — not
        // LengthMismatch, not InnerLengthMismatch, not AuthFailed — proves
        // gate 1 fired before any field beyond the 9-byte prefix was read
        // (gate 2 would also reject this frame, so only the variant tells
        // which check ran first). And no panic: with panic = "abort" a
        // panic here would kill the host process.
        let short = &frame[..37];
        assert_eq!(open(&l.b, short), Err(OpenError::TooShort(37)));

        // Every truncation below the 83-byte minimum rejects, never panics.
        for cut in 0..DEK_OVERHEAD {
            assert!(
                open(&l.b, &frame[..cut]).is_err(),
                "truncation to {cut} bytes must be rejected"
            );
        }
        // And the codec's own gates still lead: flags garbage at byte 8 is
        // the protocol's cheap filter, before any DEK-specific work.
        let mut bad_flags = frame.clone();
        bad_flags[8] = 0x00;
        assert_eq!(
            open(&l.b, &bad_flags),
            Err(OpenError::Prefix(CodecError::InvalidFlags(0x00)))
        );
    }

    #[test]
    fn dispatch_round_trips_dek_and_forced_small_dek_frames() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        // DEK through the public dispatch.
        for n in [64usize, 65, 1400] {
            let pt = payload(n);
            let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &pt).expect("seal");
            let (_, f, plain) = open(&l.b, &frame).expect("open");
            assert_eq!(f.mode(), Mode::Dek);
            assert_eq!(plain, pt);
        }
        // Sub-threshold payloads route standard through the wired item05
        // path: real standard frames that round-trip byte-exactly through
        // the same public dispatch (open parses by the flags bit).
        for n in [0usize, 1, 63] {
            let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &payload(n)).expect("seal standard");
            assert_eq!(frame.len(), n + 37, "standard overhead is 37 bytes (n={n})");
            let (_, f, plain) = open(&l.b, &frame).expect("open standard");
            assert_eq!(f.mode(), Mode::Standard);
            assert_eq!(plain, payload(n));
        }
        // FORCED DEK below the threshold: the receiver parses by the flags
        // bit, never by size — the 64-byte threshold binds senders only.
        let pt = payload(10);
        let frame =
            seal_forced(&l.a, NODE_B, CHAN, ep(EPOCH), Mode::Dek, &pt).expect("forced DEK seal");
        assert_eq!(frame.len(), 10 + DEK_OVERHEAD);
        let (_, f, plain) = open(&l.b, &frame).expect("open forced small DEK frame");
        assert_eq!(f.mode(), Mode::Dek);
        assert_eq!(plain, pt);
        // Forced empty payload exercises the N=0 DEK geometry (83-byte
        // frame: head + tag, no ciphertext).
        let frame =
            seal_forced(&l.a, NODE_B, CHAN, ep(EPOCH), Mode::Dek, &[]).expect("forced empty");
        assert_eq!(frame.len(), DEK_OVERHEAD);
        let (_, _, plain) = open(&l.b, &frame).expect("open empty DEK frame");
        assert!(plain.is_empty());
    }

    #[test]
    fn wired_standard_dispatch_rejects_tampered_frames_as_standard_rejected() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        let pt = payload(40); // sub-threshold: standard mode via the shim
        let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &pt).expect("seal");

        // A tampered standard frame rejected inside standard::open maps
        // to the ONE honest variant — the cause was erased by item05's
        // opaque open and must not be invented here.
        let mut forged = frame.clone();
        forged[30] ^= 0x01; // inside the ciphertext region
        assert_eq!(open(&l.b, &forged), Err(OpenError::StandardRejected));
        // Unknown key on a standard frame: same single variant (item05
        // collapses unknown-key and tag failure; so does this mapping).
        let c = KeyStore::new(300).expect("store C");
        assert_eq!(open(&c, &frame), Err(OpenError::StandardRejected));
        // Declared-vs-actual size disagreement: same.
        let truncated = &frame[..frame.len() - 1];
        assert_eq!(open(&l.b, truncated), Err(OpenError::StandardRejected));
        // Control: the untampered frame still opens through the dispatch.
        let (_, f, plain) = open(&l.b, &frame).expect("open");
        assert_eq!(f.mode(), Mode::Standard);
        assert_eq!(plain, pt);
    }

    #[test]
    fn nonces_and_dek_are_independent_csprng_draws() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        let pt = payload(128);
        let f1 = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &pt).expect("seal 1");
        let f2 = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &pt).expect("seal 2");

        // Fresh randomness per frame: identical inputs, different frames.
        assert!(f1 != f2, "frames must differ under fresh randomness");
        // Within one frame the two nonce FIELDS are independent draws (a
        // collision is a 2^-96 event, same standard as the sodium tests).
        assert!(
            f1[layout::KEK_NONCE..layout::WRAPPED_DEK] != f1[layout::DEK_NONCE..layout::INNER_LEN],
            "KEK and DEK nonces must be independent draws"
        );
        // Across frames, both fields change.
        assert!(
            f1[layout::KEK_NONCE..layout::WRAPPED_DEK]
                != f2[layout::KEK_NONCE..layout::WRAPPED_DEK]
        );
        assert!(
            f1[layout::DEK_NONCE..layout::INNER_LEN] != f2[layout::DEK_NONCE..layout::INNER_LEN]
        );
        // The wrapped DEK field differs per frame (fresh DEK each time),
        // and both frames still open — independence did not break the wrap.
        assert!(
            f1[layout::WRAPPED_DEK..layout::DEK_NONCE]
                != f2[layout::WRAPPED_DEK..layout::DEK_NONCE]
        );
        assert!(open(&l.b, &f1).is_ok());
        assert!(open(&l.b, &f2).is_ok());
    }

    #[test]
    fn oversize_rejected_never_truncated_and_maximum_seals() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        // One byte over the documented DEK maximum: reportable error, and
        // NEVER a truncated length field (PAXE.md "Limits").
        let big = payload(DEK_MAX_PAYLOAD + 1);
        assert_eq!(
            seal(&l.a, NODE_B, CHAN, ep(EPOCH), &big),
            Err(SealError::Oversize(DEK_MAX_PAYLOAD + 1))
        );
        // Exactly the maximum seals to the largest possible UDP datagram
        // and opens byte-exactly.
        let max = payload(DEK_MAX_PAYLOAD);
        let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &max).expect("seal max");
        assert_eq!(frame.len(), UDP_DATAGRAM_MAX);
        let (_, _, plain) = open(&l.b, &frame).expect("open max");
        assert_eq!(plain, max);
    }

    #[test]
    fn unknown_key_or_epoch_is_a_typed_drop_reason() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        // Seal to an unknown peer, or under an epoch with no key.
        assert_eq!(
            seal(&l.a, 999, CHAN, ep(EPOCH), &payload(64)),
            Err(SealError::NoKey)
        );
        assert_eq!(
            seal(&l.a, NODE_B, CHAN, ep(4), &payload(64)),
            Err(SealError::NoKey)
        );
        // Open with no key for the frame's fromId (a third node that never
        // provisioned the link key).
        let c = KeyStore::new(300).expect("store C");
        let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &payload(64)).expect("seal");
        assert_eq!(open(&c, &frame), Err(OpenError::NoKey));
        // Open under an epoch B never installed.
        let mut b2 = KeyStore::new(NODE_B).expect("store B2");
        b2.install(NODE_A, ep(4), &LINK_KEY).expect("install ep 4");
        assert_eq!(open(&b2, &frame), Err(OpenError::NoKey));
    }

    #[test]
    fn aad_covers_all_nine_prefix_bytes() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        // B holds the same link key under a second node id and a second
        // epoch, so tampered frames still FIND a key and reach the AEAD:
        // only genuine AAD coverage can reject them. (Without the extra
        // installs the tampered fromId/epoch would fail earlier at NoKey
        // and prove nothing about the AAD span.)
        let mut b = KeyStore::new(NODE_B).expect("store B");
        b.install(NODE_A, ep(EPOCH), &LINK_KEY).expect("install");
        b.install(150, ep(EPOCH), &LINK_KEY)
            .expect("install alt id");
        b.install(NODE_A, ep(7), &LINK_KEY)
            .expect("install alt epoch");

        let l = link();
        let pt = payload(96);
        let frame = seal(&l.a, NODE_B, CHAN, ep(EPOCH), &pt).expect("seal");

        // fromId 100 -> 150 (byte 1: 0x0064 -> 0x0096).
        let mut forged = frame.clone();
        forged[1] = 0x96;
        assert_eq!(
            open(&b, &forged),
            Err(OpenError::AuthFailed),
            "fromId must be AAD-covered"
        );
        // toId 200 -> 201 (byte 3: 0xC8 -> 0xC9).
        let mut forged = frame.clone();
        forged[3] = 0xC9;
        assert_eq!(
            open(&b, &forged),
            Err(OpenError::AuthFailed),
            "toId must be AAD-covered"
        );
        // channel 137 -> 1 (byte 5: 0x89 -> 0x01).
        let mut forged = frame.clone();
        forged[5] = 0x01;
        assert_eq!(
            open(&b, &forged),
            Err(OpenError::AuthFailed),
            "channel must be AAD-covered"
        );
        // length 96 -> 95 (byte 7): the header's length is protected by
        // the declared-vs-actual size gate (gate 2), which fires before
        // the AEAD — coverage via the size check rather than the tag.
        let mut forged = frame.clone();
        forged[7] = 0x5F;
        assert_eq!(
            open(&b, &forged),
            Err(OpenError::LengthMismatch),
            "length must be covered by the size gate"
        );
        // flags epoch 3 -> 7 (0x1D -> 0x3D), constant bits preserved.
        let mut forged = frame.clone();
        forged[8] = 0x3D;
        assert_eq!(
            open(&b, &forged),
            Err(OpenError::AuthFailed),
            "flags byte must be AAD-covered"
        );
        // Control.
        assert!(open(&b, &frame).is_ok());
    }

    #[test]
    fn deterministic_seam_pins_offsets_wrap_and_nonce_roles() {
        if !gcm() {
            eprintln!("skipping: AES-GCM hardware path unavailable");
            return;
        }
        let l = link();
        let pt = payload(100);
        let kek_nonce = [0x11u8; NPUBBYTES];
        let dek = [0x77u8; KEYBYTES];
        let dek_nonce = [0x99u8; NPUBBYTES];

        let frame = seal_dek_deterministic(
            &l.a,
            NODE_B,
            CHAN,
            ep(EPOCH),
            &pt,
            kek_nonce,
            dek,
            dek_nonce,
        )
        .expect("deterministic seal");
        assert_eq!(frame.len(), 100 + DEK_OVERHEAD);

        // Prefix (bytes 0-8): header fields big-endian, flags DEK+epoch 3.
        let (h, f) = codec::parse_prefix(&frame).expect("prefix");
        assert_eq!(
            h,
            Header {
                from_id: NODE_A,
                to_id: NODE_B,
                channel: CHAN,
                length: 100
            }
        );
        assert_eq!(f, Flags::new(Mode::Dek, ep(EPOCH)));
        // KEK nonce at bytes 9-20, exactly as supplied.
        assert_eq!(&frame[layout::KEK_NONCE..layout::WRAPPED_DEK], &kek_nonce);
        // Wrapped DEK at bytes 21-52: independently computed as the
        // supplied DEK XORed with the ChaCha20 stream keyed by the LINK
        // KEY under the KEK NONCE. This pins the wrap primitive, its key,
        // and WHICH nonce feeds it — a transposed-nonce implementation
        // produces different bytes here. (It pins geometry and nonce
        // roles, not the cipher; the cipher is pinned by sodium's own
        // known-answer tests.)
        let mut expected_wrapped = dek;
        sodium::stream_xor(
            &Key::from_bytes(LINK_KEY),
            &Nonce::from_bytes(kek_nonce),
            &mut expected_wrapped,
        );
        assert_eq!(
            &frame[layout::WRAPPED_DEK..layout::DEK_NONCE],
            &expected_wrapped
        );
        assert_ne!(expected_wrapped, dek, "the wrap must change the DEK bytes");
        // DEK nonce at bytes 53-64, exactly as supplied.
        assert_eq!(&frame[layout::DEK_NONCE..layout::INNER_LEN], &dek_nonce);
        // Inner length at bytes 65-66, big-endian, equal to the payload len.
        assert_eq!(
            &frame[layout::INNER_LEN..layout::HEAD],
            &100u16.to_be_bytes()
        );
        // The frame opens byte-exactly through the production receive path.
        let (_, _, plain) = open(&l.b, &frame).expect("open");
        assert_eq!(plain, pt);
        // The seam is deterministic: same inputs, identical frame.
        let frame2 = seal_dek_deterministic(
            &l.a,
            NODE_B,
            CHAN,
            ep(EPOCH),
            &pt,
            kek_nonce,
            dek,
            dek_nonce,
        )
        .expect("deterministic seal 2");
        assert_eq!(frame, frame2);
    }
}
