//! Standard-mode seal and open: the 37-byte-overhead frame
//!
//! ```text
//! Header(8) ‖ Flags(1) ‖ Nonce(12) ‖ Ciphertext(N) ‖ Tag(16)
//! ```
//!
//! Total frame size is exactly `N + 37`; the AAD is the 9-byte prefix
//! (header followed by the flags byte). The implementation uses the typed
//! prefix codec, guarded keystore, and safe AEAD wrappers. Tests emphasize
//! properties a
//! self-round-trip CANNOT establish: that the AAD really covers all 9
//! bytes (tamper tests under identical key material), that the length
//! field is validated against the actual datagram size on both sides, and
//! that the key is selected by the right peer field (two DISTINCT node
//! ids — a transposed lookup is invisible in a same-id loopback).
//!
//! ## The AAD is constructed in EXACTLY ONE place
//!
//! [`frame_aad`] is the only code in the crate that produces the
//! authenticated span, and it produces it as a BORROW of the frame's first
//! 9 bytes — never a copy assembled from parts. "The AAD is the frame
//! prefix" is therefore true by construction, not by convention: seal
//! passes the prefix region of the frame it is building, open passes the
//! received frame, and both go through the same function. If each
//! direction built its own AAD slice, a divergence (e.g. an 8-byte AAD
//! that drops the flags byte — and with it the epoch and the DEK/mode bit)
//! would be possible and every round-trip test would still pass; with one
//! shared borrow it is not. DEK mode reuses this same function.
//!
//! ## Length validation is two-sided, and both sides are here
//!
//! The prefix codec deliberately does not check `length` against the datagram size,
//! because the expected size depends on the mode's overhead. That check
//! lives here for standard mode:
//!
//! - **Seal**: the payload must fit [`MAX_PAYLOAD`] (65507 − 37 = 65470,
//!   PAXE.md "Limits"). An oversized payload is a REPORTABLE error —
//!   never a truncated length field.
//! - **Open**: the frame's actual size must equal the declared length +
//!   37 EXACTLY, checked BEFORE the AEAD call, because the declared length
//!   determines the ciphertext slice bounds.
//!
//! ## Key selection: `toId` on seal, `fromId` on open
//!
//! Under the keystore addressing model, send seals with the key shared with the
//! DESTINATION and receive opens with the key shared with the SOURCE —
//! `key_for_send(to_id)` / `key_for_receive(from_id)`. The epoch is the
//! caller's configured send epoch on seal and the wire epoch (flags bits
//! 3-7) on open. The `fromId` written into the frame is always THIS node,
//! taken from the store (configured once at `KeyStore::new`, per PAXE.md
//! "Key Management") rather than from a parameter, so no caller can seal
//! a frame claiming a spoofed source. Transposition still decrypts
//! loopback traffic, so the test uses two distinct node ids with decoy
//! keys under each node's own id.
//!
//! ## Nonces: CSPRNG only
//!
//! AES-GCM nonce reuse under the same key is CATASTROPHIC: the XOR of the
//! two plaintexts leaks and the GCM authentication key becomes
//! recoverable, losing confidentiality and authenticity for those
//! messages. Per-link keys make this matter MORE, not less: one link
//! carries many frames under one key, so a repeated nonce on that link is
//! a real exposure. Every nonce here comes from [`sodium::random_nonce`]
//! (the CSPRNG wrapper) and from nowhere else — there is no code
//! path that derives a nonce from a counter, a timestamp, or the payload.
//! Twelve fresh random bytes per frame is what the protocol specifies; the
//! birthday bound on a 96-bit random nonce (collision probability reaches
//! ~2^-32 only after ~2^48 frames under one key) is acceptable for the
//! volumes a link carries, and epoch rotation shrinks it further. A
//! counter would only be safe if its state could never be reset by a
//! restart, a reinstall or a second sender — guarantees this design does
//! not have.
//!
//! ## Separate-output decryption
//!
//! This module decrypts into a separate caller-supplied output buffer:
//!
//! - **Failure cannot destroy the input.** The frame is borrowed
//!   immutably: after a tag failure the received datagram is byte-for-byte
//!   intact, and the sodium wrapper wipes the would-be plaintext region of
//!   the output buffer, so unverified plaintext can never escape and no
//!   live buffer is clobbered by a forgery.
//! - **No overlap boundary exists.** There is no relocation and therefore
//!   no payload size at which source and destination begin to overlap.
//! - **The copy is not the bottleneck.** Frames are datagram-sized (at
//!   most 65507 bytes, usually far less); the AES-GCM pass dominates the
//!   memmove an in-place scheme would save.
//!
//! ## Uniform opaque failure (oracle avoidance)
//!
//! PAXE.md "Failure Handling": a receiver that explains WHY a forgery
//! failed is a decryption oracle. Every rejection in [`open`] — too
//! short, bad flags, wrong mode, size mismatch, unknown key, tag failure,
//! short output buffer — returns the SAME opaque
//! [`OpenError::Rejected`]; the reason is deliberately unrepresentable to
//! the caller and will be visible only in the statistics counters.
//! [`seal`] is different BY DESIGN: its failures are local (oversized
//! payload, short output buffer, no key installed for the destination) —
//! reportable configuration/usage errors, not wire rejections, so they
//! keep distinct typed variants.
//!
//! ## Boundary with DEK mode
//!
//! This module is standard mode ONLY. Seal always emits flags with the
//! DEK bit 0; open rejects any frame whose DEK bit is set. Choosing the
//! frames to the right open is the reusable-DEK dispatch layer — deliberately
//! not here.

use crate::codec::{self, Flags, Header, Mode, PREFIX_LEN};
use crate::keystore::{Epoch, KeyStore};
use crate::sodium::{self, Key, Nonce, SodiumError, ABYTES, KEYBYTES, NPUBBYTES};
use crate::stats::{self, RejectReason};
use std::error::Error;
use std::fmt;

/// Per-frame overhead of a standard frame: 9-byte prefix + 12-byte nonce +
/// 16-byte tag = 37 (PAXE.md "Standard Frame").
pub const OVERHEAD: usize = PREFIX_LEN + NPUBBYTES + ABYTES;

/// The largest possible UDP datagram (PAXE.md "Limits").
pub const MAX_UDP_DATAGRAM: usize = 65507;

/// Maximum standard-mode plaintext payload: 65507 − 37 = 65470 (PAXE.md
/// "Limits"). Seal rejects anything larger with a reportable error, never
/// a truncated length field.
pub const MAX_PAYLOAD: usize = MAX_UDP_DATAGRAM - OVERHEAD;

/// THE single AAD construction point for both directions — and, via
/// `pub(crate)`, for DEK mode. The AAD is a borrow of the frame's
/// first [`PREFIX_LEN`] bytes: the 8-byte header followed by the flags
/// byte. Returns `None` for a frame shorter than the prefix; both callers
/// have excluded that case before calling (seal builds at least the
/// prefix; open has passed [`codec::parse_prefix`]) and map it rather than
/// panic, so every code path stays total.
#[inline]
pub(crate) fn frame_aad(frame: &[u8]) -> Option<&[u8]> {
    frame.get(..PREFIX_LEN)
}

/// Every failure seal can report. Seal errors are LOCAL and reportable
/// (module docs: they are usage/configuration errors, not wire rejections,
/// so — unlike open — they keep distinct typed variants). No operation in
/// this module panics: `panic = "abort"` would kill the LuaJIT host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// Payload exceeds [`MAX_PAYLOAD`] (65507 − 37 = 65470). Carries the
    /// offending size. Reported — NEVER silently truncated into the u16
    /// length field.
    PayloadTooLarge(usize),
    /// The caller's output buffer cannot hold the frame. Carries the
    /// required and actual sizes. Checked before anything is written.
    OutputTooSmall { needed: usize, actual: usize },
    /// No key installed for `(to_id, epoch)`. An absent key is a local
    /// configuration error on SEND (unlike receive, where it is a drop
    /// reason), so it is reportable and distinguishable.
    NoKey,
    /// libsodium reported a condition its documentation says cannot
    /// happen. Kept so no path ever has to panic on the impossible.
    Sodium(SodiumError),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::PayloadTooLarge(n) => write!(
                f,
                "payload too large: {n} bytes exceeds the standard-mode maximum of {MAX_PAYLOAD}"
            ),
            SealError::OutputTooSmall { needed, actual } => write!(
                f,
                "output buffer too small: the frame needs {needed} bytes, have {actual}"
            ),
            SealError::NoKey => {
                write!(f, "no key installed for the destination peer and epoch")
            }
            SealError::Sodium(e) => write!(f, "libsodium failure: {e}"),
        }
    }
}

impl Error for SealError {}

impl From<SodiumError> for SealError {
    fn from(e: SodiumError) -> Self {
        SealError::Sodium(e)
    }
}

/// The ONLY outcome a rejected frame can produce (module docs: oracle
/// avoidance). Deliberately a single variant — bad flags, length mismatch,
/// unknown key and tag failure are indistinguishable to the caller. The
/// typed reasons are not lost, though: each is recorded into the
/// statistics counters AT the reject point below, before this opaque
/// variant is returned — exactly the consumption the single-variant
/// design anticipated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The frame was rejected. Why is deliberately not represented.
    Rejected,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Rejected => write!(f, "frame rejected"),
        }
    }
}

impl Error for OpenError {}

/// Seal `payload` into a standard-mode frame in `out`, returning the frame
/// size — exactly `payload.len() + 37`.
///
/// The frame is addressed `local_id → to_id` on `channel`, sealed with the
/// key installed for `(to_id, epoch)` (send selection). The nonce
/// is fresh from the CSPRNG (module docs: never a counter, timestamp or
/// payload derivative). The AAD is a borrow of the frame's own 9-byte
/// prefix via [`frame_aad`], the single construction point shared with
/// [`open`].
///
/// Errors are reportable and typed: oversized payload (never truncated),
/// output buffer too small, no key for the destination, or an impossible
/// libsodium condition. On every error path `out` is untouched.
pub fn seal(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, SealError> {
    // CSPRNG ONLY — see the module-docs nonce policy for why a counter or
    // timestamp is never acceptable (GCM nonce reuse under one key is
    // catastrophic, and per-link keys make it matter more, not less). This
    // is the ONE randomness draw of the standard-mode send path; the rest
    // of the work lives in [`seal_core`], parameterised on the nonce, so
    // that the `#[cfg(test)]` seam below can reach the identical code path
    // with a supplied nonce while non-test builds contain no such entry.
    let nonce = sodium::random_nonce();
    seal_core(store, to_id, channel, epoch, payload, &nonce, out)
}

/// The deterministic core of standard seal. Production reaches it only
/// via [`seal`] (the CSPRNG draw above); the `#[cfg(test)]` seam below
/// reaches it with a supplied nonce for known-answer vectors.
/// Randomness is a parameter precisely so the production path has exactly
/// one randomness source and the test path is compiled out of every
/// non-test build — the same discipline `seal_dek_core`
/// established for DEK mode.
fn seal_core(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
    nonce: &Nonce,
    out: &mut [u8],
) -> Result<usize, SealError> {
    // Length gate FIRST (module docs, PAXE.md "Limits"): oversized is a
    // reportable error, never a truncated length field. Because of this
    // check the u16 cast below cannot truncate: MAX_PAYLOAD = 65470 < 65536.
    if payload.len() > MAX_PAYLOAD {
        return Err(SealError::PayloadTooLarge(payload.len()));
    }
    // payload.len() <= 65470, so this addition cannot overflow.
    let frame_len = payload.len() + OVERHEAD;
    // Buffer gate BEFORE anything is written, so error paths leave `out`
    // untouched.
    if out.len() < frame_len {
        return Err(SealError::OutputTooSmall {
            needed: frame_len,
            actual: out.len(),
        });
    }
    // SEND key selection is by toId (module docs). fromId is always this
    // node, taken from the store so no caller can spoof a source.
    let stored = store.key_for_send(to_id, epoch).ok_or(SealError::NoKey)?;
    // expose() is exactly KEYBYTES by StoredKey's construction, so this
    // conversion cannot fail; it is mapped (not unwrapped) to keep the
    // path total. from_borrowed avoids a stack copy of the material.
    let key_bytes: &[u8; KEYBYTES] = stored
        .expose()
        .try_into()
        .map_err(|_| SealError::Sodium(SodiumError::Internal))?;
    let key = Key::from_borrowed(key_bytes);
    let header = Header {
        from_id: store.local_id(),
        to_id,
        channel,
        length: payload.len() as u16,
    };
    // Standard mode only: the DEK bit is always 0.
    let flags = Flags::new(Mode::Standard, epoch);

    // Split `out` into the frame's three regions. Both split points are
    // below the buffer gate above (PREFIX_LEN = 9 and PREFIX_LEN +
    // NPUBBYTES = 21 are both < 37 <= frame_len <= out.len()), so neither
    // split can panic. copy_from_slice pairs are compile-time equal in
    // size (9 == 9, 12 == 12), so they cannot panic either.
    let (prefix, rest) = out.split_at_mut(PREFIX_LEN);
    prefix.copy_from_slice(&codec::serialize_prefix(&header, &flags));
    let (nonce_slot, ct_slot) = rest.split_at_mut(NPUBBYTES);

    // The nonce arrives as a parameter: drawn by `seal` from the CSPRNG in
    // production, supplied by the test seam otherwise — never derived from
    // a counter, a timestamp, or the payload on any path.
    nonce_slot.copy_from_slice(nonce.as_bytes());

    // The AAD is borrowed from the prefix region of the frame being
    // built — the single construction point shared with open. The borrow
    // is of `prefix`, which IS the first 9 bytes of the frame buffer.
    let aad = frame_aad(prefix).ok_or(SealError::Sodium(SodiumError::Internal))?;
    // ct_slot is exactly payload.len() + ABYTES by the splits above, so
    // the wrapper's length preconditions hold by construction.
    sodium::aead_encrypt(key, nonce, aad, payload, ct_slot)?;
    Ok(frame_len)
}

/// Open a standard-mode `frame`, writing the recovered payload into `out`
/// and returning the parsed header, validated flags, and payload length.
///
/// Rejections are checked cheapest-first — prefix parse (short input, then
/// the flags constant-bit garbage filter), standard-mode gate, declared
/// length vs actual size (BEFORE the AEAD call: it fixes the ciphertext
/// slice bounds), key lookup by `(from_id, wire epoch)` (RECEIVE
/// selection) — and every one of them returns the SAME opaque
/// [`OpenError::Rejected`] (module docs: oracle avoidance).
///
/// Decryption uses a separate output buffer:
/// `frame` is borrowed immutably and is intact after any failure, and on
/// tag failure the sodium wrapper wipes the would-be plaintext region of
/// `out`. A too-small `out` surfaces from the wrapper as InvalidLength and
/// maps to the same opaque rejection as everything else.
pub fn open(
    store: &KeyStore,
    frame: &[u8],
    out: &mut [u8],
) -> Result<(Header, Flags, usize), OpenError> {
    // Prefix parse: TooShort and the flags constant-bit garbage filter
    // (before any keystore access — the Epoch only exists after this).
    // The typed cause is recorded into the counters HERE, at the
    // reject point; the caller still gets the one opaque variant.
    let (header, flags) = match codec::parse_prefix(frame) {
        Ok(hf) => hf,
        Err(e) => {
            stats::record_reject(RejectReason::from_codec(e));
            return Err(OpenError::Rejected);
        }
    };

    // A shared cluster PSK can decrypt traffic for any provisioned peer, so
    // destination addressing is a mandatory receive gate, not merely a
    // socket-side filtering optimisation.
    if header.to_id != store.local_id() {
        stats::record_reject(RejectReason::Plaintext);
        return Err(OpenError::Rejected);
    }

    // Standard mode only: a DEK frame (bit 0 set) is not malformed, but it
    // is not for THIS function — the public dispatch routes it to the DEK
    // open, so in production this arm never fires. It is mode ROUTING, not
    // a wire rejection: the frame is valid for the other parser, and the
    // enum deliberately has no variant for it. Uncounted.
    if flags.mode() != Mode::Standard {
        return Err(OpenError::Rejected);
    }

    // Declared-vs-actual size gate, BEFORE the AEAD call: the declared
    // length fixes the ciphertext slice bounds, so it must be validated
    // first (the prefix codec leaves this check to the mode layer).
    // EXACT equality: a frame that claims a length inconsistent with its
    // own size is rejected. u16 + 37 <= 65572, so no overflow is possible.
    let declared = header.length as usize;
    if frame.len() != declared + OVERHEAD {
        stats::record_reject(RejectReason::LenMismatch);
        return Err(OpenError::Rejected);
    }

    // RECEIVE key selection is by fromId and the wire epoch (module
    // docs): we open with the key we share with the claimed source. The
    // AAD binds fromId into the tag, so a forged fromId fails
    // authentication against that key. A miss is classified HERE, where
    // the store is in scope: a peer with no entries at all is
    // a topology problem (NoPeer), a peer holding other epochs is a
    // rotation problem (NoEpoch) — counted separately by design.
    let stored = match store.key_for_receive(header.from_id, flags.epoch()) {
        Some(k) => k,
        None => {
            stats::record_reject(if store.peer_known(header.from_id) {
                RejectReason::NoEpoch
            } else {
                RejectReason::NoPeer
            });
            return Err(OpenError::Rejected);
        }
    };
    let key_bytes: &[u8; KEYBYTES] = stored
        .expose()
        .try_into()
        .map_err(|_| OpenError::Rejected)?;
    let key = Key::from_borrowed(key_bytes);

    // Frame geometry, fixed by the gates above: 9-byte prefix ‖ 12-byte
    // nonce ‖ declared + 16 bytes of ciphertext-and-tag. Every get() is
    // in bounds by construction (frame.len() == declared + 37 >= 37), and
    // each is mapped anyway, so no path can panic.
    let aad = frame_aad(frame).ok_or(OpenError::Rejected)?;
    let nonce_bytes = frame
        .get(PREFIX_LEN..PREFIX_LEN + NPUBBYTES)
        .ok_or(OpenError::Rejected)?;
    let nonce_array: [u8; NPUBBYTES] = nonce_bytes.try_into().map_err(|_| OpenError::Rejected)?;
    let nonce = Nonce::from_bytes(nonce_array);
    let ciphertext = frame
        .get(PREFIX_LEN + NPUBBYTES..)
        .ok_or(OpenError::Rejected)?;

    let payload_len = match sodium::aead_decrypt(key, &nonce, aad, ciphertext, out) {
        Ok(n) => n,
        Err(SodiumError::AuthFailed) => {
            stats::record_reject(RejectReason::AuthFailed);
            return Err(OpenError::Rejected);
        }
        // A too-small caller output buffer (InvalidLength) is a CALLER
        // bug, not a wire condition — the FFI always supplies a
        // frame-sized buffer — and Internal is impossible: neither is a
        // reject reason, so neither is counted. The opaque collapse is
        // unchanged.
        Err(_) => return Err(OpenError::Rejected),
    };
    Ok((header, flags, payload_len))
}

// ---------------------------------------------------------------------------
// Test-only seam: deterministic nonce injection. `#[cfg(test)]` — COMPILED
// OUT of every non-test build, and `pub(crate)` so only this crate's own
// tests can name it. Deterministic nonces must NEVER be reachable in
// production: GCM nonce reuse under one key destroys both confidentiality
// and authenticity (the keystream XOR of the two plaintexts leaks and the
// GCM authentication key becomes recoverable), and per-link keys mean one
// link carries many frames under one key, so a caller-controllable nonce
// would be a live exploit primitive, not a convenience. This seam exists
// for known-answer vectors and nothing else;
// `seal_dek_deterministic` is the DEK-mode twin.
// ---------------------------------------------------------------------------

/// Standard seal with a supplied nonce, returning the complete frame.
/// TEST-ONLY known-answer seam: pins the header, flags, AAD
/// span and frame geometry byte-for-byte against fixed inputs. Reaches
/// the identical [`seal_core`] the production path uses — the only
/// difference is where the nonce comes from.
#[cfg(test)]
pub(crate) fn seal_standard_deterministic(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
    nonce: [u8; NPUBBYTES],
) -> Result<Vec<u8>, SealError> {
    // Bound BEFORE allocating the frame buffer, exactly as the public
    // dispatch shim in dek.rs does: oversize is reportable, never a
    // truncated length field.
    if payload.len() > MAX_PAYLOAD {
        return Err(SealError::PayloadTooLarge(payload.len()));
    }
    // payload.len() <= 65470, so the addition cannot overflow.
    let mut frame = vec![0u8; payload.len() + OVERHEAD];
    match seal_core(
        store,
        to_id,
        channel,
        epoch,
        payload,
        &Nonce::from_bytes(nonce),
        &mut frame,
    ) {
        Ok(n) => {
            debug_assert_eq!(n, frame.len(), "frame is N + 37 by construction");
            Ok(frame)
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Tests. Panicking asserts are fine here: test code never ships in the
// cdylib.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const LOCAL: u16 = 100;
    const PEER_A: u16 = 200;
    const PEER_B: u16 = 201;

    fn ep(bits: u8) -> Epoch {
        Epoch::new(bits).expect("test epochs are in range")
    }

    /// Same skip pattern as sodium.rs: Debian trixie arm64 ships a
    /// libsodium without the ARM crypto-extension path.
    fn gcm_or_skip() -> bool {
        sodium::init().expect("init");
        if !sodium::aes_gcm_available() {
            eprintln!("skipping: AES-256-GCM hardware path unavailable");
            return false;
        }
        true
    }

    /// Loopback store: local node LOCAL with one link key installed under
    /// the loopback peer slot (LOCAL, epoch 3) — peer really is this node.
    fn loopback_store(fill: u8) -> KeyStore {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        ks.install(LOCAL, ep(3), &[fill; KEYBYTES])
            .expect("install");
        ks
    }

    /// Includes NUL bytes (index 0 and every 256th) and high bytes
    /// (>= 0x80) for any length above 128.
    fn ascending_payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 256) as u8).collect()
    }

    /// Fixed-seed pseudo-random payload: hand-rolled xorshift64 (the same
    /// zero-dependency discipline as the codec property test — no external
    /// crate). The seed is a FIXED constant, so every run exercises the
    /// identical byte pattern: this is a byte-pattern case, not a
    /// randomness experiment.
    fn prand_payload(n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x & 0xFF) as u8
            })
            .collect()
    }

    #[test]
    fn overhead_and_limits_are_the_documented_numbers() {
        assert_eq!(OVERHEAD, 37);
        assert_eq!(MAX_UDP_DATAGRAM, 65507);
        assert_eq!(MAX_PAYLOAD, 65470);
        assert_eq!(OVERHEAD, PREFIX_LEN + NPUBBYTES + ABYTES);
    }

    #[test]
    fn round_trip_byte_exact_across_lengths_and_byte_patterns() {
        if !gcm_or_skip() {
            return;
        }
        let ks = loopback_store(0x11);
        // Lengths: 0 and 1 (degenerate); 35/36/37/38 around the frame
        // overhead; 1400 (a typical full datagram). Patterns: embedded NULs and high bytes
        // (ascending), all-zero, all-0xFF, all-0xDE, and a fixed-seed
        // pseudo-random fill.
        for &n in &[0usize, 1, 35, 36, 37, 38, 1400] {
            for payload in [
                ascending_payload(n),
                vec![0x00u8; n],
                vec![0xFFu8; n],
                vec![0xDEu8; n],
                prand_payload(n),
            ] {
                let mut frame = vec![0u8; n + OVERHEAD];
                let written = seal(&ks, LOCAL, 100, ep(3), &payload, &mut frame).expect("seal");
                assert_eq!(written, n + OVERHEAD, "frame size for payload {n}");

                let mut out = vec![0u8; n];
                let (header, flags, plen) = open(&ks, &frame, &mut out).expect("open");
                assert_eq!(plen, n, "payload length for {n}");
                assert_eq!(out, payload, "byte-exact payload for {n}");
                assert_eq!(header.from_id, LOCAL);
                assert_eq!(header.to_id, LOCAL);
                assert_eq!(header.channel, 100);
                assert_eq!(header.length as usize, n);
                // The returned flags: standard mode, DEK bit 0, epoch 3.
                assert_eq!(flags, Flags::new(Mode::Standard, ep(3)));
                assert_eq!(flags.mode(), Mode::Standard);
                assert_eq!(flags.epoch().bits(), 3);
            }
        }
    }

    #[test]
    fn frame_layout_matches_the_spec_byte_for_byte() {
        if !gcm_or_skip() {
            return;
        }
        // Loopback store holding the loopback key under epoch 5.
        let mut ks = KeyStore::new(LOCAL).expect("new");
        ks.install(LOCAL, ep(5), &[0x22u8; KEYBYTES])
            .expect("install");
        let payload = ascending_payload(37);
        let mut frame = vec![0u8; payload.len() + OVERHEAD];
        let written = seal(&ks, LOCAL, 100, ep(5), &payload, &mut frame).expect("seal");
        assert_eq!(written, 37 + OVERHEAD);
        // Header big-endian, field order fromId|toId|channel|length.
        assert_eq!(&frame[0..8], &[0, 100, 0, 100, 0, 100, 0, 37]);
        // Flags: DEK bit 0, fixed pattern 01, epoch 5 -> 0x2C.
        assert_eq!(frame[8], 0x2C);
        assert_eq!(frame[8] & 0x01, 0, "standard mode: DEK bit is 0");
        // Nonce occupies bytes 9..21 and is not all zero (2^-96 event).
        assert!(frame[9..21].iter().any(|&b| b != 0));
        // Ciphertext is bytes 21..21+N, tag the final 16 bytes.
        assert_eq!(frame.len() - 21 - payload.len(), ABYTES);
        // The codec parses the prefix back to the same typed values.
        let (h, f) = codec::parse_prefix(&frame).expect("prefix");
        assert_eq!(
            h,
            Header {
                from_id: 100,
                to_id: 100,
                channel: 100,
                length: 37
            }
        );
        assert_eq!(f, Flags::new(Mode::Standard, ep(5)));
        // The AAD borrow IS the frame's first 9 bytes, by construction.
        assert_eq!(frame_aad(&frame), Some(&frame[..PREFIX_LEN]));
    }

    #[test]
    fn aad_covers_from_id_same_key_material_under_two_ids() {
        if !gcm_or_skip() {
            return;
        }
        // The same 32-byte key material is
        // installed for two different fromId values. Relabelling the sealed
        // frame's fromId to the other id leaves the key lookup SUCCEEDING,
        // so rejection can only come from the tag covering the fromId
        // bytes. If the AAD omitted them, the relabelled frame would
        // verify and this test would wrongly pass.
        let material = [0x5Au8; KEYBYTES];
        let mut ks = KeyStore::new(LOCAL).expect("new");
        ks.install(LOCAL, ep(5), &material).expect("loopback key");
        ks.install(LOCAL + 1, ep(5), &material)
            .expect("relabel target key");
        let payload = ascending_payload(64);
        let mut frame = vec![0u8; payload.len() + OVERHEAD];
        seal(&ks, LOCAL, 100, ep(5), &payload, &mut frame).expect("seal");

        // The unmodified frame still opens.
        let mut out = vec![0u8; payload.len()];
        let (_, _, plen) = open(&ks, &frame, &mut out).expect("unmodified opens");
        assert_eq!(&out[..plen], &payload[..]);

        // Relabel fromId 100 -> 101 (low bit of the second fromId byte):
        // rejected even though the key material is correct.
        let mut relabelled = frame.clone();
        relabelled[1] ^= 0x01;
        let mut out2 = vec![0u8; payload.len()];
        assert_eq!(open(&ks, &relabelled, &mut out2), Err(OpenError::Rejected));
    }

    #[test]
    fn aad_covers_all_nine_prefix_bytes() {
        if !gcm_or_skip() {
            return;
        }
        // Same-material installs arranged so that EVERY relabel below still
        // resolves a valid key: rejection then proves the tag covers the
        // flipped byte, not that the lookup missed.
        let material = [0xC3u8; KEYBYTES];
        let mut ks = KeyStore::new(LOCAL).expect("new");
        for (peer, epoch) in [(LOCAL, 5), (LOCAL + 1, 5), (356, 5), (LOCAL, 1)] {
            ks.install(peer, ep(epoch), &material).expect("install");
        }
        let payload = ascending_payload(64);
        let mut frame = vec![0u8; payload.len() + OVERHEAD];
        seal(&ks, LOCAL, 100, ep(5), &payload, &mut frame).expect("seal");
        let mut out = vec![0u8; payload.len()];
        open(&ks, &frame, &mut out).expect("unmodified opens");

        // Generous output buffer so no case below is rejected merely for
        // output size — every rejection is the tag or an earlier gate.
        let assert_rejected = |tampered: &[u8]| {
            let mut o = vec![0u8; payload.len() + 64];
            assert_eq!(open(&ks, tampered, &mut o), Err(OpenError::Rejected));
        };

        // Byte 0: fromId high byte (100 = 0x0064 -> 0x0164 = 356; key
        // installed there with the same material).
        let mut t = frame.clone();
        t[0] ^= 0x01;
        assert_rejected(&t);
        // Byte 1: fromId low byte (100 -> 101; same-material key there).
        let mut t = frame.clone();
        t[1] ^= 0x01;
        assert_rejected(&t);
        // Byte 2: toId high byte — the receive lookup (by fromId) is
        // UNAFFECTED, so this rejection is purely the AAD.
        let mut t = frame.clone();
        t[2] ^= 0x01;
        assert_rejected(&t);
        // Byte 3: toId low byte.
        let mut t = frame.clone();
        t[3] ^= 0x01;
        assert_rejected(&t);
        // Byte 4: channel high byte.
        let mut t = frame.clone();
        t[4] ^= 0x01;
        assert_rejected(&t);
        // Byte 5: channel low byte.
        let mut t = frame.clone();
        t[5] ^= 0x01;
        assert_rejected(&t);
        // Byte 6: length high byte — also caught by the size gate.
        let mut t = frame.clone();
        t[6] ^= 0x01;
        assert_rejected(&t);
        // Byte 7: length low byte. A bare flip is caught by the
        // declared-vs-actual size gate, so to exercise the tag's coverage
        // of this byte the frame is resized to match the new declaration:
        // the size gate then PASSES and only the AEAD (AAD over the
        // changed length byte, plus the shifted tag) can reject it.
        let mut t = frame.clone();
        t[7] ^= 0x01; // declared 64 -> 65
        t.push(0x00); // actual size now equals declared + 37
        assert_eq!(t.len(), 65 + OVERHEAD);
        assert_rejected(&t);
        // Byte 8: THE flags byte — the byte an "8-byte AAD" bug would
        // miss. Epoch 5 -> 1 with the SAME material installed under both
        // epochs: the lookup succeeds either way, so only AAD coverage of
        // byte 8 can reject this. If the AAD were one byte short the tag
        // would verify and the frame would wrongly open.
        let mut t = frame.clone();
        t[8] = Flags::new(Mode::Standard, ep(1)).to_byte();
        assert_rejected(&t);
        // DEK bit set: rejected by the standard-mode gate.
        let mut t = frame.clone();
        t[8] = Flags::new(Mode::Dek, ep(5)).to_byte();
        assert_rejected(&t);

        // Beyond the prefix: nonce, ciphertext and tag bytes are all
        // covered by the tag as well.
        let mut t = frame.clone();
        t[9] ^= 0x01; // nonce
        assert_rejected(&t);
        let mut t = frame.clone();
        t[21] ^= 0x01; // first ciphertext byte
        assert_rejected(&t);
        let mut t = frame.clone();
        let last = t.len() - 1;
        t[last] ^= 0x01; // last tag byte
        assert_rejected(&t);

        // And after all of that, the unmodified frame STILL opens.
        let mut out = vec![0u8; payload.len()];
        let (_, _, plen) = open(&ks, &frame, &mut out).expect("unmodified still opens");
        assert_eq!(&out[..plen], &payload[..]);
    }

    #[test]
    fn seal_rejects_oversized_payload_with_an_error_never_truncation() {
        if !gcm_or_skip() {
            return;
        }
        let ks = loopback_store(0x33);
        // The documented maximum SEALS, fills the datagram to exactly the
        // UDP ceiling, and the length field carries it exactly
        // (65470 < 65536: no truncation).
        let max_payload = vec![0xABu8; MAX_PAYLOAD];
        let mut frame = vec![0u8; MAX_PAYLOAD + OVERHEAD];
        let written = seal(&ks, LOCAL, 100, ep(3), &max_payload, &mut frame).expect("max seals");
        assert_eq!(written, MAX_UDP_DATAGRAM);
        assert_eq!(&frame[6..8], &65470u16.to_be_bytes());
        let mut out = vec![0u8; MAX_PAYLOAD];
        let (header, _, plen) = open(&ks, &frame, &mut out).expect("max opens");
        assert_eq!(plen, MAX_PAYLOAD);
        assert_eq!(header.length as usize, MAX_PAYLOAD);
        assert!(out.iter().all(|&b| b == 0xAB));

        // One byte over the maximum is a typed, reportable error...
        let over = vec![0u8; MAX_PAYLOAD + 1];
        let mut scratch = vec![0xAAu8; 64];
        assert_eq!(
            seal(&ks, LOCAL, 100, ep(3), &over, &mut scratch),
            Err(SealError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
        // Values that would truncate a u16 length field (70000 -> 4464)
        // are also rejected without writing output.
        let big = vec![0u8; 70000];
        assert_eq!(
            seal(&ks, LOCAL, 100, ep(3), &big, &mut scratch),
            Err(SealError::PayloadTooLarge(70000))
        );
        assert!(
            scratch.iter().all(|&b| b == 0xAA),
            "no partial frame on the error path"
        );
    }

    #[test]
    fn open_rejects_frames_whose_size_disagrees_with_declared_length() {
        if !gcm_or_skip() {
            return;
        }
        let ks = loopback_store(0x44);
        let payload = ascending_payload(100);
        let mut frame = vec![0u8; payload.len() + OVERHEAD];
        seal(&ks, LOCAL, 100, ep(3), &payload, &mut frame).expect("seal");

        // Actual < declared + 37 (truncated datagram), down to nothing.
        for cut in [frame.len() - 1, frame.len() - 16, PREFIX_LEN, 8, 0] {
            let mut out = vec![0u8; payload.len()];
            assert_eq!(
                open(&ks, &frame[..cut], &mut out),
                Err(OpenError::Rejected),
                "cut to {cut} bytes"
            );
        }
        // Actual > declared + 37 (padded datagram).
        let mut padded = frame.clone();
        padded.push(0x00);
        let mut out = vec![0u8; payload.len()];
        assert_eq!(open(&ks, &padded, &mut out), Err(OpenError::Rejected));

        // All-zero and all-ones garbage dies at the flags filter.
        for garbage in [vec![0u8; OVERHEAD], vec![0xFFu8; OVERHEAD]] {
            let mut out = vec![0u8; 64];
            assert_eq!(open(&ks, &garbage, &mut out), Err(OpenError::Rejected));
        }
    }

    #[test]
    fn open_rejects_dek_mode_frames_for_dispatch_layer() {
        if !gcm_or_skip() {
            return;
        }
        let ks = loopback_store(0x55);
        // A structurally valid DEK-mode prefix: valid constant bits, DEK
        // bit set, declared length consistent with the frame size — so the
        // rejection here comes from the standard-mode gate, not the parse
        // or size gates. The public dispatch routes it to DEK open.
        let header = Header {
            from_id: LOCAL,
            to_id: LOCAL,
            channel: 100,
            length: 10,
        };
        let prefix = codec::serialize_prefix(&header, &Flags::new(Mode::Dek, ep(3)));
        assert_eq!(prefix[8] & 0x01, 1, "constructed frame really is DEK-mode");
        let mut frame = vec![0u8; 10 + OVERHEAD];
        frame[..PREFIX_LEN].copy_from_slice(&prefix);
        let mut out = vec![0u8; 16];
        assert_eq!(open(&ks, &frame, &mut out), Err(OpenError::Rejected));
    }

    #[test]
    fn send_uses_toid_and_receive_uses_fromid_two_distinct_nodes() {
        if !gcm_or_skip() {
            return;
        }
        // TWO DIFFERENT node ids are essential: in a fromId == toId
        // loopback a transposed lookup hits the SAME slot and nothing is
        // proven. Two stores model the two ends of the A<->B link; each
        // holds the shared LINK key under the PEER's id plus a DECOY under
        // its OWN id. If either direction's lookup is transposed (send by
        // fromId, or receive by toId) it picks up the decoy and the frame
        // fails — so the successful exchange below proves both directions.
        let link = [0x42u8; KEYBYTES];
        let mut a = KeyStore::new(PEER_A).expect("new A"); // node A = 200
        a.install(PEER_B, ep(7), &link)
            .expect("A: link key under peer B");
        a.install(PEER_A, ep(7), &[0x99u8; KEYBYTES])
            .expect("A: decoy under own id");
        let mut b = KeyStore::new(PEER_B).expect("new B"); // node B = 201
        b.install(PEER_A, ep(7), &link)
            .expect("B: link key under peer A");
        b.install(PEER_B, ep(7), &[0x98u8; KEYBYTES])
            .expect("B: decoy under own id");

        let payload = ascending_payload(80);
        let mut frame = vec![0u8; payload.len() + OVERHEAD];
        // A seals FOR B: the key must be selected by toId (201 -> link
        // key), NOT by fromId (200 -> decoy).
        seal(&a, PEER_B, 100, ep(7), &payload, &mut frame).expect("seal A->B");
        // B opens: the key must be selected by fromId (200 -> link key),
        // NOT by toId (201 -> decoy).
        let mut out = vec![0u8; payload.len()];
        let (header, _, plen) = open(&b, &frame, &mut out).expect("B opens A's frame");
        assert_eq!(header.from_id, PEER_A);
        assert_eq!(header.to_id, PEER_B);
        assert_eq!(&out[..plen], &payload[..]);

        // A frame sealed for B cannot be opened as if from a different
        // peer when the peers hold different keys: node C shares NO key
        // material with A, so A's frame is opaque to it even though C has
        // an entry for the claimed fromId.
        let mut c = KeyStore::new(300).expect("new C");
        c.install(PEER_A, ep(7), &[0x77u8; KEYBYTES])
            .expect("C's different A-key");
        let mut out = vec![0u8; payload.len()];
        assert_eq!(open(&c, &frame, &mut out), Err(OpenError::Rejected));

        // Unknown key on RECEIVE: an absent key is a drop reason, and it
        // is the same opaque rejection as a tag failure.
        let b2 = KeyStore::new(PEER_B).expect("new empty B");
        let mut out = vec![0u8; payload.len()];
        assert_eq!(open(&b2, &frame, &mut out), Err(OpenError::Rejected));

        // Unknown key on SEND is a reportable local configuration error —
        // deliberately distinguishable from the opaque receive rejection.
        let empty = KeyStore::new(LOCAL).expect("new empty");
        let mut scratch = vec![0u8; 128];
        assert_eq!(
            seal(&empty, PEER_B, 100, ep(7), b"x", &mut scratch),
            Err(SealError::NoKey)
        );
    }

    #[test]
    fn nonces_are_distinct_across_many_seals_gross_error_check() {
        if !gcm_or_skip() {
            return;
        }
        // GROSS-ERROR smoke check, NOT a randomness proof: 256 samples can
        // only catch catastrophic wiring errors (a stuck counter, a zeroed
        // buffer, a nonce accidentally derived from the payload or
        // timestamp). A genuine CSPRNG collision here is a ~2^-96 event
        // per pair, so any duplicate means the nonce path is broken, not
        // unlucky.
        let ks = loopback_store(0x66);
        let payload = b"same payload every time";
        let mut seen: HashSet<[u8; NPUBBYTES]> = HashSet::new();
        for _ in 0..256 {
            let mut frame = vec![0u8; payload.len() + OVERHEAD];
            seal(&ks, LOCAL, 100, ep(3), payload, &mut frame).expect("seal");
            let nonce: [u8; NPUBBYTES] = frame[PREFIX_LEN..PREFIX_LEN + NPUBBYTES]
                .try_into()
                .expect("12 nonce bytes");
            assert!(
                seen.insert(nonce),
                "nonce repeated: CSPRNG wiring is broken"
            );
        }
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn failed_open_leaves_the_frame_intact_and_the_output_wiped() {
        if !gcm_or_skip() {
            return;
        }
        // The separate-output decision's payoff: a forgery destroys
        // nothing. The input frame is borrowed immutably and must be
        // byte-identical after the failure; the sodium wrapper wipes the
        // would-be plaintext region of the output buffer, so unverified
        // plaintext never escapes.
        let ks = loopback_store(0x77);
        let payload = ascending_payload(64);
        let mut frame = vec![0u8; payload.len() + OVERHEAD];
        seal(&ks, LOCAL, 100, ep(3), &payload, &mut frame).expect("seal");

        let mut forged = frame.clone();
        forged[30] ^= 0x01; // inside the ciphertext region
        let forged_before = forged.clone();
        let mut out = vec![0xAAu8; payload.len()];
        assert_eq!(open(&ks, &forged, &mut out), Err(OpenError::Rejected));
        assert_eq!(forged, forged_before, "input frame untouched by failure");
        assert!(out.iter().all(|&b| b == 0), "would-be plaintext wiped");
    }

    #[test]
    fn seal_reports_a_too_small_output_buffer_and_writes_nothing() {
        if !gcm_or_skip() {
            return;
        }
        let ks = loopback_store(0x88);
        let payload = [0x42u8; 50];
        let mut out = vec![0xAAu8; 50 + OVERHEAD - 1]; // one byte short
        assert_eq!(
            seal(&ks, LOCAL, 100, ep(3), &payload, &mut out),
            Err(SealError::OutputTooSmall {
                needed: 50 + OVERHEAD,
                actual: 50 + OVERHEAD - 1
            })
        );
        assert!(out.iter().all(|&b| b == 0xAA), "no partial frame written");
        // Exact fit is accepted.
        let mut exact = vec![0u8; 50 + OVERHEAD];
        assert_eq!(
            seal(&ks, LOCAL, 100, ep(3), &payload, &mut exact),
            Ok(50 + OVERHEAD)
        );
    }

    #[test]
    fn open_with_a_short_output_buffer_is_the_same_opaque_rejection() {
        if !gcm_or_skip() {
            return;
        }
        let ks = loopback_store(0x99);
        let payload = ascending_payload(40);
        let mut frame = vec![0u8; payload.len() + OVERHEAD];
        seal(&ks, LOCAL, 100, ep(3), &payload, &mut frame).expect("seal");
        // One byte short of the declared payload: the wrapper's
        // InvalidLength maps to the SAME Rejected as a tag failure —
        // oracle avoidance is uniform even for caller buffer errors.
        let mut short = vec![0u8; payload.len() - 1];
        assert_eq!(open(&ks, &frame, &mut short), Err(OpenError::Rejected));
        // Zero payload with a zero-size output is NOT a rejection.
        let mut frame0 = vec![0u8; OVERHEAD];
        seal(&ks, LOCAL, 100, ep(3), &[], &mut frame0).expect("seal empty");
        let mut out0: [u8; 0] = [];
        let (_, _, plen0) = open(&ks, &frame0, &mut out0).expect("open empty");
        assert_eq!(plen0, 0);
    }
}
