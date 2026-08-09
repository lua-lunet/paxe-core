//! Known-answer vectors (item12): complete frames pinned byte-for-byte
//! against fully stated fixed inputs, with ALL randomness injected through
//! the `#[cfg(test)]` deterministic seams. This module is the ONLY test
//! surface in the crate that can detect a wrong wire format: every other
//! test seals with this implementation and opens with this same
//! implementation, so all of them would pass even if the bytes on the wire
//! were the wrong bytes — which is exactly how the deleted C shipped a
//! header of `length | flags | reserved | key_id` for its entire life
//! while its encoder and decoder agreed perfectly.
//!
//! A fixed input producing a fixed expected output, byte-for-byte, is the
//! only thing that catches a wrong field order, wrong offsets, wrong
//! endianness, a wrong AAD span, transposed KEK/DEK nonces, or an
//! overhead of 36 instead of 37.
//!
//! ## Provenance — stated honestly, per vector
//!
//! Every vector below has the SAME provenance, so it is stated once here
//! and referenced per vector:
//!
//! - **Layout hand-derived from PAXE.md.** The header field order
//!   (`fromId | toId | channel | length`, big-endian), the flags byte
//!   (bit 0 = DEK, bit 1 = 0, bit 2 = 1, bits 3–7 = epoch), every field
//!   offset, the 9-byte AAD span (header + flags), the 63/64 mode
//!   boundary, and the 37/83 overheads are hand-derived from PAXE.md
//!   "Wire Format", "Flags", "Associated Data" and "Mode Selection" —
//!   the parts that are tractable to derive by hand, and the parts the
//!   deleted C got wrong.
//! - **Primitive outputs from an INDEPENDENT implementation.** AES-256-GCM
//!   and ChaCha20-IETF are deterministic primitives, so given the fixed
//!   key, nonces, AAD and payload their outputs are fixed bytes. Those
//!   bytes were computed with the OpenSSL-backed Python `cryptography`
//!   library — NOT libsodium (which this crate uses), NOT this crate,
//!   NOT the trex reference — and only after that library was validated
//!   against two PUBLISHED known-answer vectors: the NIST/McGrew-Viega
//!   GCM test case (AES-256 zero key/IV/block) and RFC 8439 §2.4.2
//!   (ChaCha20-IETF). Derivation script: `.tmp/item12/gen_vectors.py`
//!   (uncommitted, in the gitignored scratch area; its method and
//!   self-checks are described here so the vectors are reproducible).
//! - **NOT taken from the trex reference implementation.** PAXE's
//!   intentional AAD divergence (the flags byte is inside the
//!   authenticated span here, outside it in the reference) means the
//!   authentication tags can never coincide, so no full frame can be
//!   borrowed from the reference.
//! - **ZERO self-generated / stability-only vectors.** No expected frame
//!   in this file was produced by running this implementation. Every
//!   vector below pins CORRECTNESS against the document and an
//!   independent implementation, not merely determinism.
//!
//! ## The seam safety rule (written down, per item12)
//!
//! The deterministic-injection seams these tests use —
//! [`standard::seal_standard_deterministic`] and
//! [`dek::seal_dek_deterministic`] — are `#[cfg(test)]` and `pub(crate)`:
//! they compile ONLY into this crate's own test harness, are compiled out
//! of every non-test build (debug or release), and cannot be named from
//! outside the crate even in a test build. Deterministic nonces must
//! NEVER be reachable in production: GCM nonce reuse under one key
//! destroys both confidentiality and authenticity (the keystream XOR of
//! the two plaintexts leaks and the GCM authentication key becomes
//! recoverable), and a fixed DEK destroys per-message key separation.
//! Per-link keys make this worse, not better: one link carries many
//! frames under one key. A caller-controllable nonce in production would
//! be a live exploit primitive. Release unreachability is verified by
//! the attributes here, by a successful `cargo build --release` (the
//! seams are absent from that compilation), by `nm` showing no such
//! symbols in the release cdylib, and by the fact that naming a seam
//! from non-test code fails compilation.
//!
//! ## Input discipline
//!
//! Every input is chosen so that a field transposition, reordering, or
//! wrong endianness CHANGES the expected frame: `fromId != toId`, every
//! u16 field has distinct high/low bytes, the epoch is non-zero in every
//! vector, the two DEK nonces differ from each other and from the
//! standard nonce, and every byte string is position-dependent. There
//! are no symmetric or zero-valued discriminators anywhere below.

// The whole module is test code; lib.rs declares it `#[cfg(test)]`, and
// the inner attribute is belt and braces: even if the declaration lost
// its gate, nothing here could leak into a non-test build.
#![cfg(test)]

use crate::codec::{CodecError, Mode};
use crate::dek::{self, OpenError};
use crate::keystore::{Epoch, KeyStore};
use crate::sodium::{self, KEYBYTES, NPUBBYTES};
use crate::standard;

// ---------------------------------------------------------------------------
// Fully stated inputs. These exact values are the inputs the expected
// frames were derived from; nothing is implicit.
// ---------------------------------------------------------------------------

/// The 32-byte per-link shared key (operator-injected out of band, per
/// PAXE.md "Key Management"). Position-dependent so a byte transposition
/// in key handling changes every vector.
const LINK_KEY: [u8; KEYBYTES] = [
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, //
    0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90, //
    0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8A, //
    0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF1, 0x02,
];

/// The canonical link's addressing: fromId 0x0A0B, toId 0x0C0D, channel
/// 0x0E0F (an application channel, >= 100). Distinct ids, distinct bytes
/// within each field, non-default channel: a transposition of any two
/// fields or an endianness flip changes every expected frame.
const FROM: u16 = 0x0A0B;
const TO: u16 = 0x0C0D;
const CHANNEL: u16 = 0x0E0F;
/// The canonical key epoch: 9 (non-zero in every vector, so the epoch
/// bits of the flags byte are always pinned against 0x00 drift).
const EPOCH: u8 = 9;
/// Vector 6's epoch: 21 — flags byte (21 << 3) | 0x04 = 0xAC.
const EPOCH6: u8 = 21;

/// Standard-mode nonce: C0..CB (12 bytes, position-dependent).
const NONCE: [u8; NPUBBYTES] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
];
/// DEK-mode KEK nonce: B0..BB. DISTINCT from the DEK nonce, so a nonce
/// transposition (wrap fed by the AEAD nonce or vice versa) changes the
/// expected frame.
const KEK_NONCE: [u8; NPUBBYTES] = [
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
];
/// DEK-mode DEK nonce: D0..DB. Distinct from KEK_NONCE on purpose.
const DEK_NONCE: [u8; NPUBBYTES] = [
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
];
/// The supplied per-frame DEK: E0..FF (32 bytes, position-dependent).
const DEK: [u8; KEYBYTES] = [
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, //
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, //
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, //
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
];

/// Vector 7's second addressing set: fromId 0x1234, toId 0x5678, channel
/// 0xBEEF (48879 — an application channel). All values differ from the
/// canonical set and from each other, with distinct bytes in each field.
const FROM7: u16 = 0x1234;
const TO7: u16 = 0x5678;
const CHANNEL7: u16 = 0xBEEF;

// Payloads, fully stated (the Rust constructors below reproduce exactly
// the byte strings the derivation script used):
//   V1: the empty payload.
//   V2: b"paxe item12 v2: standard short payload"  (38 bytes, < 64)
const V2_PAYLOAD: &[u8] = b"paxe item12 v2: standard short payload";
//   V3: 0x01,0x02,..,0x3F  (63 bytes — the largest standard payload)
//   V4: 0x01,0x02,..,0x40  (64 bytes — the smallest DEK payload)
//   V5: 0xFF,0xFE,..,0x80  (128 bytes — descending, distinct from V4)
//   V6: b"epoch-21-vector"  (15 bytes)
const V6_PAYLOAD: &[u8] = b"epoch-21-vector";
//   V7: b"fields"  (6 bytes)
const V7_PAYLOAD: &[u8] = b"fields";

fn v3_payload() -> Vec<u8> {
    (1u8..=63).collect()
}
fn v4_payload() -> Vec<u8> {
    (1u8..=64).collect()
}
fn v5_payload() -> Vec<u8> {
    (0u8..128).map(|i| 0xFFu8.wrapping_sub(i)).collect()
}

// ---------------------------------------------------------------------------
// Expected frames, as complete hex. Provenance for ALL of them (see the
// module docs): layout hand-derived from PAXE.md; AES-256-GCM and
// ChaCha20-IETF primitive outputs computed independently (OpenSSL-backed
// `cryptography`, validated against the published NIST GCM and RFC 8439
// known-answer vectors before use). NONE are self-generated from this
// crate; none pin merely stability.
// ---------------------------------------------------------------------------

/// V1 — standard, empty payload. 9-byte prefix ‖ 12-byte nonce ‖ 16-byte
/// tag, no ciphertext: exactly 37 bytes, the minimum frame size.
const V1_FRAME_HEX: &str = concat!(
    "0a0b0c0d0e0f00004cc0c1c2c3c4c5c6",
    "c7c8c9cacb8004030239e4c9ab5cde8e",
    "dee6c3cccf"
);

/// V2 — standard, 38-byte payload (< 64): confirms standard mode is what
/// a short payload produces on the wire (flags 0x4C, DEK bit clear,
/// frame = 38 + 37).
const V2_FRAME_HEX: &str = concat!(
    "0a0b0c0d0e0f00264cc0c1c2c3c4c5c6",
    "c7c8c9cacb11e08e8e014c94dba52037",
    "1d411ecffe2a26717d89c5bc800ee4e3",
    "3262fe2f6d78a58b8a02e2a3238285a9",
    "a47557a4cc9bb799715d8e"
);

/// V3 — standard at the boundary: 63 bytes, the largest payload that
/// stays standard. Header length 0x003F, flags 0x4C, frame = 63 + 37.
const V3_FRAME_HEX: &str = concat!(
    "0a0b0c0d0e0f003f4cc0c1c2c3c4c5c6",
    "c7c8c9cacb6083f5ef2423e7b6c11b0e",
    "313a22face48400307f8b2d9fc378d90",
    "410d94103d38fec4c146a0c972a363b7",
    "3559b963107e12ccf2ca02e996d34986",
    "2c6aa821ecbed7270576422168bc479e",
    "b6cc5278"
);

/// V4 — DEK at the boundary: 64 bytes, the smallest payload that
/// switches. Header length 0x0040, flags 0x4D (DEK bit set), frame =
/// 64 + 83. Pins the selection boundary on the wire, not only in a Rust
/// assertion on `select_mode`.
const V4_FRAME_HEX: &str = concat!(
    "0a0b0c0d0e0f00404db0b1b2b3b4b5b6",
    "b7b8b9babbb7cd400be4e0fea2826dd1",
    "ccd8b388a84910d7396b71e033e25112",
    "50b26041fbd0d1d2d3d4d5d6d7d8d9da",
    "db004008ce2a85131f531e775010895d",
    "e346efa1f0564f55ede85707decb2cb6",
    "f725cf2c3551ba8362d70140bb0b8721",
    "5d1eae52dfa9c851d2b3899decbace14",
    "cc2c0465be30014701f76fa258a9b4f6",
    "ba0e0a"
);

/// V5 — DEK, 128-byte payload. Pins all six DEK field offsets (prefix
/// 0–8, KEK nonce 9–20, wrapped DEK 21–52, DEK nonce 53–64, inner length
/// 65–66, ciphertext 67.., tag last 16), the two nonces distinctly, and
/// the inner length field (0x0080 == header length). Frame = 128 + 83.
const V5_FRAME_HEX: &str = concat!(
    "0a0b0c0d0e0f00804db0b1b2b3b4b5b6",
    "b7b8b9babbb7cd400be4e0fea2826dd1",
    "ccd8b388a84910d7396b71e033e25112",
    "50b26041fbd0d1d2d3d4d5d6d7d8d9da",
    "db0080f632d47dede3adee89acee71a3",
    "1fb80f5f0ca8b7ab1116a7f92235d448",
    "0bdb0fd2c9af427d9e29f1be47f57fdf",
    "a1e04eac235730af2e4d7963104436ea",
    "30d284ea14aef9cb0a996e3849c0015a",
    "f18d6ff9479e199352591a19f5b66490",
    "931208e489729fe869ec5c4aa552623c",
    "a8fd89d1ad153b4e4b6d6a22297332e8",
    "3987abb118603040c621cf0ce307c1cd",
    "cbdbe1"
);

/// V6 — non-zero epoch 21: flags byte 0xAC = (21 << 3) | 0x04. Proves
/// the epoch lands in flags bits 3–7, and (with the tamper case in the
/// negative test) that it is authenticated.
const V6_FRAME_HEX: &str = concat!(
    "0a0b0c0d0e0f000facc0c1c2c3c4c5c6",
    "c7c8c9cacb04f199884908d28fe56760",
    "5e434387582df42dfa32d78a7009b5e3",
    "b8cd0d41"
);

/// V7 — distinct fromId/toId (0x1234 → 0x5678) and a non-default channel
/// (0xBEEF): pins field order and endianness against transposition.
const V7_FRAME_HEX: &str = concat!(
    "12345678beef00064cc0c1c2c3c4c5c6",
    "c7c8c9cacb07e8938745565d9038dcd0",
    "d0d7f3e18f21a1cc955d76"
);

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Hand-rolled hex decode (zero dependencies policy: no hex crate).
fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0, "hex must be whole bytes");
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("hex digit");
        let lo = (pair[1] as char).to_digit(16).expect("hex digit");
        out.push(((hi << 4) | lo) as u8);
    }
    out
}

fn ep(bits: u8) -> Epoch {
    Epoch::new(bits).expect("test epochs are in range")
}

/// The SENDER's store: local id `frm`, link key installed under the
/// PEER (`to`) — send-side lookup is by toId (item03 asymmetry).
fn sender(frm: u16, to: u16, epoch: u8) -> KeyStore {
    let mut s = KeyStore::new(frm).expect("sender store");
    s.install(to, ep(epoch), &LINK_KEY).expect("sender install");
    s
}

/// The RECEIVER's store: local id `to`, link key installed under the
/// PEER (`frm`) — receive-side lookup is by fromId (item03 asymmetry).
fn receiver(frm: u16, to: u16, epoch: u8) -> KeyStore {
    let mut r = KeyStore::new(to).expect("receiver store");
    r.install(frm, ep(epoch), &LINK_KEY)
        .expect("receiver install");
    r
}

/// Same environment skip pattern as the other crypto tests: AES-GCM
/// needs the hardware path (Debian trixie arm64 ships a libsodium
/// without it). Unavailability is an environment property, never a
/// vector failure.
fn gcm() -> bool {
    sodium::init().is_ok() && sodium::aes_gcm_available()
}

/// Seal `payload` through the STANDARD deterministic seam and assert the
/// complete frame, byte-for-byte, against the expected hex; then assert
/// the expected frame opens byte-exactly through the production receive
/// path with the stated header and flags.
fn assert_standard_vector(
    frm: u16,
    to: u16,
    channel: u16,
    epoch: u8,
    payload: &[u8],
    expected_hex: &str,
) {
    let expected = unhex(expected_hex);
    assert_eq!(
        expected.len(),
        payload.len() + standard::OVERHEAD,
        "standard frame is N + 37 by definition"
    );
    let frame = standard::seal_standard_deterministic(
        &sender(frm, to, epoch),
        to,
        channel,
        ep(epoch),
        payload,
        NONCE,
    )
    .expect("deterministic standard seal");
    assert_eq!(
        frame, expected,
        "standard frame must match the independently derived bytes"
    );

    // The expected frame — the bytes derived from PAXE.md, not the bytes
    // this implementation produced — opens through the production path.
    let (h, f, plain) = dek::open(&receiver(frm, to, epoch), &expected).expect("open expected");
    assert_eq!(
        plain, payload,
        "byte-exact payload out of the expected frame"
    );
    assert_eq!(h.from_id, frm);
    assert_eq!(h.to_id, to);
    assert_eq!(h.channel, channel);
    assert_eq!(h.length as usize, payload.len());
    assert_eq!(f.mode(), Mode::Standard);
    assert_eq!(f.epoch(), ep(epoch));
}

/// Same for the DEK deterministic seam.
fn assert_dek_vector(
    frm: u16,
    to: u16,
    channel: u16,
    epoch: u8,
    payload: &[u8],
    expected_hex: &str,
) -> Vec<u8> {
    let expected = unhex(expected_hex);
    assert_eq!(
        expected.len(),
        payload.len() + dek::DEK_OVERHEAD,
        "DEK frame is N + 83 by definition"
    );
    let frame = dek::seal_dek_deterministic(
        &sender(frm, to, epoch),
        to,
        channel,
        ep(epoch),
        payload,
        KEK_NONCE,
        DEK,
        DEK_NONCE,
    )
    .expect("deterministic DEK seal");
    assert_eq!(
        frame, expected,
        "DEK frame must match the independently derived bytes"
    );

    let (h, f, plain) = dek::open(&receiver(frm, to, epoch), &expected).expect("open expected");
    assert_eq!(
        plain, payload,
        "byte-exact payload out of the expected frame"
    );
    assert_eq!(h.from_id, frm);
    assert_eq!(h.to_id, to);
    assert_eq!(h.channel, channel);
    assert_eq!(h.length as usize, payload.len());
    assert_eq!(f.mode(), Mode::Dek);
    assert_eq!(f.epoch(), ep(epoch));
    expected
}

// ---------------------------------------------------------------------------
// The seven positive vectors. Each asserts the FULL frame byte-for-byte.
// ---------------------------------------------------------------------------

#[test]
fn v1_standard_empty_payload_is_exactly_37_bytes() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }
    let expected = unhex(V1_FRAME_HEX);
    // THE minimum frame: prefix(9) + nonce(12) + tag(16), no ciphertext.
    assert_eq!(
        expected.len(),
        37,
        "standard empty frame is exactly 37 bytes"
    );
    // Hand-derived prefix: 0A0B 0C0D 0E0F 0000 | flags 0x4C = (9<<3)|0x04.
    assert_eq!(
        &expected[..9],
        &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x4C]
    );
    assert_eq!(&expected[9..21], &NONCE, "nonce at bytes 9-20");
    assert_standard_vector(FROM, TO, CHANNEL, EPOCH, &[], V1_FRAME_HEX);
}

#[test]
fn v2_standard_short_payload_confirms_standard_selection() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }
    assert!(
        V2_PAYLOAD.len() < dek::DEK_THRESHOLD,
        "38 bytes is below the boundary"
    );
    let expected = unhex(V2_FRAME_HEX);
    assert_eq!(expected.len(), 38 + 37);
    assert_eq!(expected[8], 0x4C, "DEK bit clear: standard on the wire");
    assert_eq!(
        &expected[6..8],
        &38u16.to_be_bytes(),
        "length is the PLAINTEXT length"
    );
    assert_standard_vector(FROM, TO, CHANNEL, EPOCH, V2_PAYLOAD, V2_FRAME_HEX);
}

#[test]
fn v3_standard_at_63_is_the_largest_standard_frame() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }
    assert_eq!(v3_payload().len(), 63);
    let expected = unhex(V3_FRAME_HEX);
    assert_eq!(expected.len(), 63 + 37);
    assert_eq!(expected[8], 0x4C, "63 bytes stays standard ON THE WIRE");
    assert_eq!(&expected[6..8], &63u16.to_be_bytes());
    assert_standard_vector(FROM, TO, CHANNEL, EPOCH, &v3_payload(), V3_FRAME_HEX);
}

#[test]
fn v4_dek_at_64_is_the_smallest_dek_frame() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }
    assert_eq!(v4_payload().len(), 64);
    let expected = unhex(V4_FRAME_HEX);
    assert_eq!(expected.len(), 64 + dek::DEK_OVERHEAD);
    assert_eq!(
        expected[8], 0x4D,
        "64 bytes switches to DEK ON THE WIRE: (9<<3)|0x04|0x01"
    );
    // The six DEK field offsets, pinned against the expected bytes.
    assert_eq!(
        &expected[..9],
        &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x40, 0x4D]
    );
    assert_eq!(&expected[9..21], &KEK_NONCE, "KEK nonce at bytes 9-20");
    assert_eq!(&expected[53..65], &DEK_NONCE, "DEK nonce at bytes 53-64");
    assert_eq!(
        &expected[65..67],
        &64u16.to_be_bytes(),
        "inner length at bytes 65-66"
    );
    assert_eq!(
        &expected[21..53],
        &unhex(V5_FRAME_HEX)[21..53],
        "same key/nonce/DEK inputs as V5: the wrapped DEK field coincides (deterministic wrap)"
    );
    assert_dek_vector(FROM, TO, CHANNEL, EPOCH, &v4_payload(), V4_FRAME_HEX);
}

#[test]
fn v5_dek_larger_payload_pins_all_six_field_offsets() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }
    assert_eq!(v5_payload().len(), 128);
    let expected = assert_dek_vector(FROM, TO, CHANNEL, EPOCH, &v5_payload(), V5_FRAME_HEX);
    assert_eq!(expected.len(), 128 + dek::DEK_OVERHEAD);
    assert_eq!(&expected[9..21], &KEK_NONCE);
    assert_eq!(&expected[53..65], &DEK_NONCE);
    assert_eq!(
        &expected[65..67],
        &128u16.to_be_bytes(),
        "inner length == header length"
    );
    // The wrapped DEK (bytes 21-52) must NOT be the plaintext DEK and
    // must be the independently computed ChaCha20-IETF wrap — both pinned
    // by the full-frame comparison above; slice asserts are diagnostics.
    assert_ne!(&expected[21..53], &DEK, "the wrap must transform the DEK");
    // Ciphertext is bytes 67..67+N, the tag the final 16.
    assert_eq!(
        expected.len() - 67 - 128,
        16,
        "N ciphertext bytes then the tag"
    );
}

#[test]
fn v6_nonzero_epoch_lands_in_flags_bits_3_to_7() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }
    let expected = unhex(V6_FRAME_HEX);
    assert_eq!(expected.len(), 15 + 37);
    // (21 << 3) | 0x04 = 0xAC: epoch in bits 3-7, DEK bit clear, pattern 01.
    assert_eq!(expected[8], 0xAC, "epoch 21 lands in flags bits 3-7");
    assert_eq!(expected[8] >> 3, EPOCH6);
    assert_standard_vector(FROM, TO, CHANNEL, EPOCH6, V6_PAYLOAD, V6_FRAME_HEX);

    // The epoch is AUTHENTICATED: relabel the frame to epoch 22 — a valid
    // flags byte under which the receiver ALSO holds the same key — and
    // the lookup succeeds, so only the tag's coverage of the flags byte
    // can reject it. (Standard-mode open collapses the cause by design;
    // the rejection variant is the honest StandardRejected.)
    let mut r = receiver(FROM, TO, EPOCH6);
    r.install(FROM, ep(22), &LINK_KEY)
        .expect("same key under epoch 22");
    let mut tampered = expected.clone();
    tampered[8] = (22 << 3) | 0x04; // 0xB4: valid constant bits, epoch 22
    assert_eq!(tampered[8], 0xB4);
    assert_eq!(
        dek::open(&r, &tampered),
        Err(OpenError::StandardRejected),
        "epoch is inside the AAD: changing it must fail authentication"
    );
}

#[test]
fn v7_distinct_ids_and_channel_pin_field_order_and_endianness() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }
    let expected = unhex(V7_FRAME_HEX);
    assert_eq!(expected.len(), 6 + 37);
    // Hand-derived header: 1234 5678 BEEF 0006, big-endian, in field
    // order fromId | toId | channel | length. A transposition of any two
    // fields, or little-endian encoding, changes these bytes.
    assert_eq!(
        &expected[..8],
        &[0x12, 0x34, 0x56, 0x78, 0xBE, 0xEF, 0x00, 0x06]
    );
    assert_eq!(expected[8], 0x4C);
    assert_standard_vector(FROM7, TO7, CHANNEL7, EPOCH, V7_PAYLOAD, V7_FRAME_HEX);
}

// ---------------------------------------------------------------------------
// Negative vectors: mutations of the pinned frames that MUST be rejected,
// each with its expected in-crate reason (the FFI collapses all of these
// to one opaque drop; the typed reasons are the item08 reject causes).
// ---------------------------------------------------------------------------

#[test]
fn negative_vectors_reject_with_the_expected_reason() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }

    // N1 — AAD tamper on a standard frame: flip the channel low byte
    // (byte 5) of V2. The receive key lookup is by (fromId, epoch) and is
    // unaffected, so the rejection must come from the tag covering the
    // header bytes. Expected reason: authentication failure, surfaced
    // in-crate as the deliberately cause-erased StandardRejected (item05
    // collapses all standard-mode causes; the item08 counter is
    // rx_auth_fail).
    let mut n1 = unhex(V2_FRAME_HEX);
    n1[5] ^= 0x01;
    assert_eq!(
        dek::open(&receiver(FROM, TO, EPOCH), &n1),
        Err(OpenError::StandardRejected),
        "N1: tampered AAD byte must fail authentication"
    );

    // N2 — wrapped-DEK corruption on a DEK frame: flip one byte of the
    // wrapped-DEK field (offset 21) of V5. The wrap is unauthenticated by
    // construction, so this yields a WRONG DEK and the rejection must
    // surface at the payload tag check. Expected reason: AuthFailed
    // (item08 counter rx_auth_fail) — there is deliberately no
    // wrap-failure variant.
    let mut n2 = unhex(V5_FRAME_HEX);
    n2[21] ^= 0x01;
    assert_eq!(
        dek::open(&receiver(FROM, TO, EPOCH), &n2),
        Err(OpenError::AuthFailed),
        "N2: corrupted wrapped DEK surfaces at the payload tag"
    );

    // N3 — inner-length disagreement on a DEK frame: flip the inner
    // length high byte (offset 65) of V5 (0x0080 -> 0x0180). The inner
    // length sits OUTSIDE the AAD, so the tag still verifies; only the
    // explicit equality check catches it. Expected reason:
    // InnerLengthMismatch (item08 counter rx_dek_len_mismatch).
    let mut n3 = unhex(V5_FRAME_HEX);
    n3[65] ^= 0x01;
    assert_eq!(
        dek::open(&receiver(FROM, TO, EPOCH), &n3),
        Err(OpenError::InnerLengthMismatch),
        "N3: inner length must equal the header length"
    );

    // N4 — flags constant-bit violation: zero the flags byte of V2. The
    // protocol's cheap garbage filter rejects all-zero flags before any
    // cryptographic work. Expected reason: codec InvalidFlags(0x00)
    // (item08 counter rx_bad_flags).
    let mut n4 = unhex(V2_FRAME_HEX);
    n4[8] = 0x00;
    assert_eq!(
        dek::open(&receiver(FROM, TO, EPOCH), &n4),
        Err(OpenError::Prefix(CodecError::InvalidFlags(0x00))),
        "N4: all-zero flags must die at the constant-bit gate"
    );
}

// ---------------------------------------------------------------------------
// Seam properties: determinism, and agreement with the production path on
// every byte the production path shares (the 9-byte prefix; the rest of a
// production frame is fresh CSPRNG randomness by design). Also pins the
// 63/64 selection boundary on PRODUCTION frames, not only on seam output.
// ---------------------------------------------------------------------------

#[test]
fn seams_are_deterministic_and_match_production_prefixes() {
    if !gcm() {
        eprintln!("skipping: AES-GCM hardware path unavailable");
        return;
    }
    // Determinism: identical inputs through the seam, identical frames.
    let a = standard::seal_standard_deterministic(
        &sender(FROM, TO, EPOCH),
        TO,
        CHANNEL,
        ep(EPOCH),
        V2_PAYLOAD,
        NONCE,
    )
    .expect("seal a");
    let b = standard::seal_standard_deterministic(
        &sender(FROM, TO, EPOCH),
        TO,
        CHANNEL,
        ep(EPOCH),
        V2_PAYLOAD,
        NONCE,
    )
    .expect("seal b");
    assert_eq!(a, b, "the standard seam is deterministic");
    let c = dek::seal_dek_deterministic(
        &sender(FROM, TO, EPOCH),
        TO,
        CHANNEL,
        ep(EPOCH),
        &v4_payload(),
        KEK_NONCE,
        DEK,
        DEK_NONCE,
    )
    .expect("seal c");
    let d = dek::seal_dek_deterministic(
        &sender(FROM, TO, EPOCH),
        TO,
        CHANNEL,
        ep(EPOCH),
        &v4_payload(),
        KEK_NONCE,
        DEK,
        DEK_NONCE,
    )
    .expect("seal d");
    assert_eq!(c, d, "the DEK seam is deterministic");

    // Production path (fresh CSPRNG randomness per frame): the 9-byte
    // prefix and the total size must agree with the vectors exactly, and
    // the mode boundary must show on the wire flags byte.
    let cases: [(Vec<u8>, &str, u8); 5] = [
        (Vec::new(), V1_FRAME_HEX, 0x4C),
        (V2_PAYLOAD.to_vec(), V2_FRAME_HEX, 0x4C),
        (v3_payload(), V3_FRAME_HEX, 0x4C),
        (v4_payload(), V4_FRAME_HEX, 0x4D),
        (v5_payload(), V5_FRAME_HEX, 0x4D),
    ];
    for (payload, expected_hex, want_flags) in cases {
        let frame = dek::seal(&sender(FROM, TO, EPOCH), TO, CHANNEL, ep(EPOCH), &payload)
            .expect("production seal");
        let expected = unhex(expected_hex);
        assert_eq!(
            frame.len(),
            expected.len(),
            "production frame size for {}-byte payload",
            payload.len()
        );
        assert_eq!(
            &frame[..9],
            &expected[..9],
            "production prefix identical to the vector's (payload {} bytes)",
            payload.len()
        );
        assert_eq!(
            frame[8],
            want_flags,
            "mode boundary on the wire for {}-byte payload",
            payload.len()
        );
    }
}
