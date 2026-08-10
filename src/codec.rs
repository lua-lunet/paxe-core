//! The header and flags codec: total, cryptography-free parsing
//! and serialisation of the 9-byte frame prefix that leads every PAXE
//! datagram — the 8-byte header (`fromId | toId | channel | length`,
//! big-endian) and the 1-byte flags — parsed from attacker-controlled
//! input before any key is looked up and before any cryptography runs.
//!
//! This code runs on every unsolicited datagram, including malformed and
//! hostile ones. It accepts only the documented header layout, validates
//! the fixed flag bits, and represents the wire length as a bounded `u16`.
//!
//! ## Wire layout (PAXE.md is authoritative)
//!
//! ```text
//! bytes 0-1   fromId    u16 BE   source node identifier
//! bytes 2-3   toId      u16 BE   destination node identifier
//! bytes 4-5   channel   u16 BE   channel identifier (multiplexing)
//! bytes 6-7   length    u16 BE   PLAINTEXT payload length (NOT frame length)
//! byte  8     flags     u8       bit0: DEK | bit1: must be 0 |
//!                                bit2: must be 1 | bits3-7: key epoch 0-31
//! ```
//!
//! `length` is the length of the plaintext payload, not of the frame on
//! the wire; the frame is longer by the mode's per-frame overhead (37 or
//! 97 bytes).
//!
//! ## Totality: no panic on ANY input (hard requirement)
//!
//! Every possible input maps to `Ok((Header, Flags))` or a specific
//! [`CodecError`]. The release profile sets `panic = "abort"`, so a panic
//! here is a remotely triggerable kill of the whole LuaJIT host process —
//! one malformed datagram would take down every coroutine and connection
//! it serves. Totality is therefore achieved by construction, not by
//! testing alone:
//!
//! - The 9-byte prefix is obtained with a single fixed-size slice pattern
//!   behind `slice::get` — there is no indexing, no slicing, and no
//!   `unwrap`/`expect` anywhere in this module.
//! - Integer decoding uses only `u16::from_be_bytes` / `u16::to_be_bytes`
//!   on fixed-size arrays: explicit byte-order functions, no hand-rolled
//!   shifts, and no arithmetic on untrusted values that could overflow.
//! - The only fallible steps (short input, flags constant bits) are
//!   checked explicitly and returned as typed errors.
//!
//! ## Validation order: cheapest and most discriminating first
//!
//! 1. **Length gate** — fewer than [`PREFIX_LEN`] bytes presented:
//!    [`CodecError::TooShort`]. Nothing can be read until byte 8 exists.
//! 2. **Flags constant-bit gate** — one mask, `byte & 0x06 == 0x04`: bit 1
//!    set or bit 2 clear means [`CodecError::InvalidFlags`]. This is the
//!    protocol's cheap garbage filter: it rejects all-zero and all-ones
//!    bytes — the two most likely shapes of noise, truncation, or a
//!    wrong-protocol datagram — before any further work. It runs here,
//!    before header field extraction, and therefore strictly before any
//!    keystore access: keystore lookups take an [`Epoch`], and the ONLY
//!    way to obtain an `Epoch` from the wire is through
//!    [`Flags::from_byte`], which performs this gate. The ordering is
//!    enforced by the types, not by caller discipline.
//! 3. **Field extraction** — infallible big-endian decoding of the four
//!    u16 header fields plus the mode and epoch bits.
//!
//! The order is observable through the statistics counters and
//! through timing, so it is fixed here deliberately.
//!
//! ## Type-level guarantees (made impossible, not merely checked)
//!
//! - **Length cannot truncate.** [`Header::length`] is a `u16` and the
//!   encode path takes a `u16`, so a value exceeding 16 bits is
//!   unrepresentable. The payload-size bounds (PAXE.md "Limits": 65470
//!   standard / 65410 reusable-DEK) are enforced by the mode implementations before
//!   a `Header` is constructed.
//! - **Epoch out of range is unrepresentable.** [`Flags`] reuses the
//!   keystore's [`Epoch`] newtype, whose only constructor rejects values
//!   above 31. Serialising shifts the guaranteed-≤31 value into bits 3-7;
//!   nothing is masked, so no out-of-range epoch can be silently squeezed
//!   into the 5-bit field.
//! - **The constant bits are not settable.** [`Flags`] exposes only
//!   [`Mode`] and [`Epoch`]; bits 1 and 2 exist only as the validation
//!   mask on decode and as the fixed pattern emitted by
//!   [`Flags::to_byte`]. They are not part of the public type, so no
//!   caller can set them by hand.
//!
//! ## Deliberate boundary: `length` vs datagram size is NOT checked here
//!
//! This codec validates ONLY the structural well-formedness of the 9-byte
//! prefix. It deliberately does NOT compare `length` against the actual
//! datagram size: the expected frame size depends on the mode's per-frame
//! overhead (37 or 97 bytes), which is selected by the flags byte. The
//! standard and DEK open paths enforce exact length-versus-frame geometry.

use crate::keystore::Epoch;
use std::error::Error;
use std::fmt;

/// Header size in bytes: four big-endian u16 fields.
pub const HEADER_LEN: usize = 8;

/// Offset of the flags byte: immediately after the header.
pub const FLAGS_OFFSET: usize = HEADER_LEN;

/// Full prefix size: header plus flags byte. This is also the AAD length
/// (PAXE.md "Associated Data": the authenticated span is bytes 0-8).
pub const PREFIX_LEN: usize = 9;

/// Bit 0: 0 = standard frame, 1 = DEK frame.
const DEK_BIT: u8 = 0x01;

/// Bits 1-2 as one validation mask: bit 1 must be 0 and bit 2 must be 1,
/// i.e. `(byte & FIXED_MASK) == FIXED_PATTERN`. One mask rejects `0x00`
/// and `0xFF` — the cheapest, most discriminating garbage filter.
const FIXED_MASK: u8 = 0x06;
const FIXED_PATTERN: u8 = 0x04;

/// The frame mode selected by flags bit 0 (PAXE.md "Mode Selection").
/// The constant bits 1-2 are deliberately NOT part of this type or of
/// [`Flags`]: they are validation-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// DEK flag 0: payloads below 64 bytes, 37-byte overhead.
    Standard,
    /// Reusable-DEK flag 1: explicit fanout frames, 97-byte overhead.
    Dek,
}

/// The parsed 8-byte header. All four fields are plain `u16` — any bit
/// pattern is structurally valid, so decoding is infallible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    /// Source node identifier (wire bytes 0-1, big-endian).
    pub from_id: u16,
    /// Destination node identifier (wire bytes 2-3, big-endian).
    pub to_id: u16,
    /// Channel identifier (wire bytes 4-5, big-endian).
    pub channel: u16,
    /// PLAINTEXT payload length in bytes (wire bytes 6-7, big-endian) —
    /// NOT the frame length. Being a `u16`, a value exceeding 16 bits is
    /// unrepresentable on encode. The mode implementations bound the
    /// payload before constructing a `Header`.
    pub length: u16,
}

impl Header {
    /// Serialise as 8 big-endian bytes: `fromId | toId | channel | length`.
    /// Infallible: fixed arrays, explicit endian conversion, no arithmetic.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let [f0, f1] = self.from_id.to_be_bytes();
        let [t0, t1] = self.to_id.to_be_bytes();
        let [c0, c1] = self.channel.to_be_bytes();
        let [l0, l1] = self.length.to_be_bytes();
        [f0, f1, t0, t1, c0, c1, l0, l1]
    }

    /// Decode 8 big-endian bytes. Infallible: every 8-byte sequence is a
    /// structurally valid header; the only validated part of the prefix is
    /// the flags byte, checked separately in [`Flags::from_byte`].
    pub fn from_bytes(bytes: [u8; HEADER_LEN]) -> Self {
        let [f0, f1, t0, t1, c0, c1, l0, l1] = bytes;
        Header {
            from_id: u16::from_be_bytes([f0, f1]),
            to_id: u16::from_be_bytes([t0, t1]),
            channel: u16::from_be_bytes([c0, c1]),
            length: u16::from_be_bytes([l0, l1]),
        }
    }
}

/// A validated flags byte, exposing ONLY the two variable meanings: the
/// mode (standard/DEK) and the key epoch. The two constant bits are
/// validation-only and are not represented here — if they leaked into the
/// type, someone would eventually set them by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flags {
    mode: Mode,
    epoch: Epoch,
}

impl Flags {
    /// Build flags from a mode and an epoch. `Epoch` is the keystore's
    /// bounded newtype: values above 31 cannot be constructed, so an
    /// out-of-range epoch is unrepresentable here — never silently masked
    /// into the 5-bit wire field.
    pub fn new(mode: Mode, epoch: Epoch) -> Self {
        Flags { mode, epoch }
    }

    /// The frame mode (flags bit 0).
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The 5-bit key epoch (flags bits 3-7), as the keystore's bounded
    /// [`Epoch`] — directly usable for a keystore lookup.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Serialise to the wire byte: DEK bit, fixed pattern `01` in bits
    /// 1-2, epoch in bits 3-7. Infallible and non-overflowing:
    /// `epoch.bits()` is ≤ 31 by the `Epoch` type invariant, so the shift
    /// yields ≤ 0xF8 and every value fits in a u8.
    pub fn to_byte(&self) -> u8 {
        let mode_bit = match self.mode {
            Mode::Standard => 0,
            Mode::Dek => DEK_BIT,
        };
        mode_bit | FIXED_PATTERN | (self.epoch.bits() << 3)
    }

    /// Parse and validate a raw flags byte.
    ///
    /// The constant-bit gate runs FIRST and alone: one mask,
    /// `byte & 0x06 == 0x04`, rejecting any byte with bit 1 set or bit 2
    /// clear (`0x00` and `0xFF` included) before anything else is read
    /// from it — and, because keystore lookups require the [`Epoch`] only
    /// this function produces, strictly before any keystore access.
    pub fn from_byte(byte: u8) -> Result<Self, CodecError> {
        if byte & FIXED_MASK != FIXED_PATTERN {
            return Err(CodecError::InvalidFlags(byte));
        }
        let mode = if byte & DEK_BIT == 0 {
            Mode::Standard
        } else {
            Mode::Dek
        };
        // `byte >> 3` on a u8 keeps exactly bits 3-7: a value in 0..=31,
        // so Epoch::new cannot actually reject. The error arm is mapped
        // (not unwrapped) so that no code path can panic even if this
        // reasoning ever changes.
        let epoch = match Epoch::new(byte >> 3) {
            Ok(e) => e,
            Err(_) => return Err(CodecError::InvalidFlags(byte)),
        };
        Ok(Flags { mode, epoch })
    }
}

/// Every rejection the codec can report. Kept specific because these
/// reasons feed the statistics counters (too short, flags
/// constraint violation). No operation in this module panics —
/// `panic = "abort"` would kill the LuaJIT host process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// Fewer than [`PREFIX_LEN`] bytes were presented; carries the actual
    /// length. The datagram cannot even contain a full prefix.
    TooShort(usize),
    /// The flags byte failed the constant-bit gate (bit 1 set or bit 2
    /// clear); carries the offending byte. The protocol's cheap garbage
    /// filter, applied before any keystore access.
    InvalidFlags(u8),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::TooShort(n) => write!(
                f,
                "datagram too short: {n} bytes, need at least {PREFIX_LEN}"
            ),
            CodecError::InvalidFlags(b) => write!(
                f,
                "invalid flags byte {b:#04x}: bit 1 must be 0 and bit 2 must be 1"
            ),
        }
    }
}

impl Error for CodecError {}

/// Parse the 9-byte prefix of a datagram: the 8-byte header plus the flags
/// byte. Extra bytes beyond the prefix (nonce, ciphertext, tag) are left
/// to the mode implementations and ignored here.
///
/// TOTAL: every input maps to `Ok((Header, Flags))` or a specific
/// [`CodecError`]; no panic, no out-of-bounds index, no arithmetic
/// overflow for any input. Validation order is cheapest-and-most-
/// discriminating first — see the module docs.
pub fn parse_prefix(bytes: &[u8]) -> Result<(Header, Flags), CodecError> {
    // Gate 1 + field extraction via ONE fixed-size slice pattern: matches
    // iff exactly the 9 prefix bytes are present, binds them without any
    // indexing, and no other code path touches the input.
    let (header_bytes, flags_byte) = match bytes.get(..PREFIX_LEN) {
        Some(&[f0, f1, t0, t1, c0, c1, l0, l1, flags_byte]) => {
            ([f0, f1, t0, t1, c0, c1, l0, l1], flags_byte)
        }
        _ => return Err(CodecError::TooShort(bytes.len())),
    };
    // Gate 2: the flags constant-bit garbage filter, before header field
    // extraction and strictly before any keystore access (see module docs).
    let flags = Flags::from_byte(flags_byte)?;
    // Gate 3: infallible big-endian field extraction.
    Ok((Header::from_bytes(header_bytes), flags))
}

/// Serialise a header and flags into the 9-byte wire prefix: the header
/// big-endian, then the flags byte. Infallible: fixed arrays, explicit
/// endian conversion, bounded epoch shift; no arithmetic can overflow.
pub fn serialize_prefix(header: &Header, flags: &Flags) -> [u8; PREFIX_LEN] {
    let [f0, f1, t0, t1, c0, c1, l0, l1] = header.to_bytes();
    [f0, f1, t0, t1, c0, c1, l0, l1, flags.to_byte()]
}

// ---------------------------------------------------------------------------
// Tests. Panicking asserts are fine here: test code never ships in the
// cdylib.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(bits: u8) -> Epoch {
        Epoch::new(bits).expect("test epochs are in range")
    }

    /// Deterministic seeded generator, no external crate: xorshift64
    /// (Marsaglia). State must be nonzero; the seed is printed by the
    /// property test so any failure is reproducible byte-for-byte.
    struct XorShift64(u64);

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            XorShift64(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn next_prefix(&mut self) -> [u8; PREFIX_LEN] {
            let [a, b, c, d, e, f, g, h] = self.next_u64().to_le_bytes();
            let i = (self.next_u64() & 0xFF) as u8;
            [a, b, c, d, e, f, g, h, i]
        }
    }

    #[test]
    fn flags_byte_exhaustive_all_256_accept_reject_boundary() {
        let mut accepted = 0usize;
        for value in 0u16..=255 {
            let byte = value as u8;
            let boundary = byte & FIXED_MASK == FIXED_PATTERN;
            match Flags::from_byte(byte) {
                Ok(flags) => {
                    // Accepted => boundary holds, and mode/epoch extract correctly.
                    assert!(boundary, "accepted forbidden byte {byte:#04x}");
                    let want_mode = if byte & 0x01 == 0 {
                        Mode::Standard
                    } else {
                        Mode::Dek
                    };
                    assert_eq!(flags.mode(), want_mode, "mode wrong for {byte:#04x}");
                    assert_eq!(
                        flags.epoch().bits(),
                        byte >> 3,
                        "epoch wrong for {byte:#04x}"
                    );
                    // Accepted bytes serialise back to themselves exactly.
                    assert_eq!(flags.to_byte(), byte);
                    accepted += 1;
                }
                Err(CodecError::InvalidFlags(offending)) => {
                    // Rejected => boundary fails: bit 1 set or bit 2 clear.
                    assert_eq!(offending, byte);
                    assert!(!boundary, "rejected valid byte {byte:#04x}");
                    assert!(byte & 0x02 != 0 || byte & 0x04 == 0);
                }
                Err(other) => panic!("unexpected error for {byte:#04x}: {other:?}"),
            }
        }
        // Bits 1,2 pinned to 0,1 leave 6 free bits: exactly 64 accepted.
        assert_eq!(accepted, 64);
    }

    #[test]
    fn known_wire_vector_is_big_endian_and_field_ordered() {
        // Concrete bytes pin endianness and field order without the
        // implementation's own conversions masking a transposition.
        let prefix = [
            0x00, 0x01, // fromId = 1
            0x00, 0x02, // toId = 2
            0x00, 0x64, // channel = 100
            0x00, 0x40, // length = 64 (plaintext payload length)
            0x2C, // flags: DEK=0, pattern 01, epoch 5 (5 << 3 | 0x04)
        ];
        let (header, flags) = parse_prefix(&prefix).expect("valid prefix");
        assert_eq!(header.from_id, 1);
        assert_eq!(header.to_id, 2);
        assert_eq!(header.channel, 100);
        assert_eq!(header.length, 64);
        assert_eq!(flags.mode(), Mode::Standard);
        assert_eq!(flags.epoch().bits(), 5);
        // Serialise back to the identical bytes (round-trip both ways).
        assert_eq!(serialize_prefix(&header, &flags), prefix);
    }

    #[test]
    fn header_field_boundaries_round_trip_both_directions() {
        for &v in &[0u16, 1, u16::MAX] {
            for field in 0..4 {
                let mut h = Header {
                    from_id: 0x1111,
                    to_id: 0x2222,
                    channel: 0x3333,
                    length: 0x4444,
                };
                match field {
                    0 => h.from_id = v,
                    1 => h.to_id = v,
                    2 => h.channel = v,
                    _ => h.length = v,
                }
                // value -> bytes -> value
                let bytes = h.to_bytes();
                assert_eq!(Header::from_bytes(bytes), h, "field {field} value {v}");
                // bytes -> value -> bytes
                assert_eq!(Header::from_bytes(bytes).to_bytes(), bytes);
            }
        }
        // All-zero and all-max headers round-trip as wholes, through the
        // full prefix codec as well.
        for h in [
            Header {
                from_id: 0,
                to_id: 0,
                channel: 0,
                length: 0,
            },
            Header {
                from_id: u16::MAX,
                to_id: u16::MAX,
                channel: u16::MAX,
                length: u16::MAX,
            },
        ] {
            let flags = Flags::new(Mode::Dek, ep(31));
            let bytes = serialize_prefix(&h, &flags);
            let (h2, f2) = parse_prefix(&bytes).expect("round-trip");
            assert_eq!(h2, h);
            assert_eq!(f2, flags);
        }
    }

    #[test]
    fn mode_epoch_round_trip_is_exact_for_all_combinations() {
        for mode in [Mode::Standard, Mode::Dek] {
            for bits in 0..=31u8 {
                let flags = Flags::new(mode, ep(bits));
                let back = Flags::from_byte(flags.to_byte()).expect("valid flags");
                assert_eq!(back, flags, "mode {mode:?} epoch {bits}");
                assert_eq!(back.mode(), mode);
                assert_eq!(back.epoch().bits(), bits);
            }
        }
    }

    #[test]
    fn epoch_boundaries_and_out_of_range_unrepresentable() {
        // 0 and 31 round-trip, landing the exact wire patterns.
        assert_eq!(Flags::new(Mode::Standard, ep(0)).to_byte(), 0x04);
        assert_eq!(Flags::new(Mode::Dek, ep(0)).to_byte(), 0x05);
        assert_eq!(Flags::new(Mode::Standard, ep(31)).to_byte(), 0xFC);
        assert_eq!(Flags::new(Mode::Dek, ep(31)).to_byte(), 0xFD);
        for (byte, bits) in [(0x04u8, 0u8), (0x05, 0), (0xFC, 31), (0xFD, 31)] {
            let f = Flags::from_byte(byte).expect("boundary byte");
            assert_eq!(f.epoch().bits(), bits);
            assert_eq!(f.to_byte(), byte);
        }
        // 32 and above are unrepresentable on encode: the only way to put
        // an epoch into Flags is the keystore's Epoch newtype, whose single
        // constructor rejects them. There is no epoch-from-raw path in
        // this module, so nothing can be silently masked into 5 bits.
        assert!(Epoch::new(32).is_err());
        assert!(Epoch::new(u8::MAX).is_err());
    }

    #[test]
    fn all_zero_and_all_ones_prefixes_are_rejected_by_flags_gate() {
        assert_eq!(
            parse_prefix(&[0x00; PREFIX_LEN]),
            Err(CodecError::InvalidFlags(0x00))
        );
        assert_eq!(
            parse_prefix(&[0xFF; PREFIX_LEN]),
            Err(CodecError::InvalidFlags(0xFF))
        );
    }

    #[test]
    fn short_inputs_report_too_short_and_extras_are_ignored() {
        for n in 0..PREFIX_LEN {
            let buf = [0x2Cu8; PREFIX_LEN]; // a valid flags byte, unreachable
            assert_eq!(
                parse_prefix(&buf[..n]),
                Err(CodecError::TooShort(n)),
                "length {n}"
            );
        }
        // A full frame prefix plus mode bytes: the codec parses only the
        // 9-byte prefix and leaves the rest to the mode implementations.
        let mut frame = [0xAAu8; 64];
        let prefix = serialize_prefix(
            &Header {
                from_id: 7,
                to_id: 8,
                channel: 100,
                length: 42,
            },
            &Flags::new(Mode::Dek, ep(9)),
        );
        frame[..PREFIX_LEN].copy_from_slice(&prefix);
        let (h, f) = parse_prefix(&frame).expect("prefix of a longer frame");
        assert_eq!(h.length, 42);
        assert_eq!(f, Flags::new(Mode::Dek, ep(9)));
    }

    #[test]
    fn seeded_property_no_panic_and_total_mapping() {
        // Deterministic seeded generator; the seed is printed up front (and
        // embedded in every assert message) so a failure reproduces exactly
        // with PAXE_CODEC_PROP_SEED=<hex>.
        const DEFAULT_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
        let seed = std::env::var("PAXE_CODEC_PROP_SEED")
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(DEFAULT_SEED);
        eprintln!(
            "codec property seed: {seed:#018x} (reproduce with PAXE_CODEC_PROP_SEED={seed:#x})"
        );
        let mut rng = XorShift64::new(seed);

        const ITERATIONS: usize = 1_000_000;
        let mut accepted = 0usize;
        // Explicit degenerate shapes first, then the random stream.
        let degenerates: [[u8; PREFIX_LEN]; 2] = [[0x00; PREFIX_LEN], [0xFF; PREFIX_LEN]];
        for (i, prefix) in degenerates.iter().enumerate() {
            let result = parse_prefix(prefix);
            assert_eq!(
                result,
                Err(CodecError::InvalidFlags(prefix[FLAGS_OFFSET])),
                "degenerate {i} seed {seed:#x}"
            );
        }
        for i in 0..ITERATIONS {
            let prefix = rng.next_prefix();
            let result = parse_prefix(&prefix); // must not panic: total mapping
            let flags_byte = prefix[FLAGS_OFFSET];
            // The accept/reject boundary is exactly the constant-bit gate.
            assert_eq!(
                result.is_ok(),
                flags_byte & FIXED_MASK == FIXED_PATTERN,
                "boundary mismatch iter {i} seed {seed:#x} flags {flags_byte:#04x}"
            );
            match result {
                Ok((header, flags)) => {
                    accepted += 1;
                    // Serialising the parsed values reproduces the input
                    // prefix byte-for-byte.
                    assert_eq!(
                        serialize_prefix(&header, &flags),
                        prefix,
                        "round-trip iter {i} seed {seed:#x}"
                    );
                    // Header decode agrees with direct big-endian reads.
                    assert_eq!(
                        header.from_id,
                        u16::from_be_bytes([prefix[0], prefix[1]]),
                        "iter {i} seed {seed:#x}"
                    );
                    assert_eq!(flags.epoch().bits(), flags_byte >> 3);
                }
                Err(e) => {
                    // The only possible rejection for a 9-byte input.
                    assert_eq!(
                        e,
                        CodecError::InvalidFlags(flags_byte),
                        "iter {i} seed {seed:#x}"
                    );
                }
            }
            // Totality below the prefix length: every truncation is a
            // typed TooShort, never a panic.
            let cut = (rng.next_u64() % (PREFIX_LEN as u64)) as usize;
            assert_eq!(
                parse_prefix(&prefix[..cut]),
                Err(CodecError::TooShort(cut)),
                "truncation {cut} iter {i} seed {seed:#x}"
            );
        }
        // Sanity: the stream exercised both outcomes in bulk.
        assert!(
            accepted > 100_000,
            "seed {seed:#x}: accept count {accepted}"
        );
        assert!(
            accepted < ITERATIONS - 100_000,
            "seed {seed:#x}: accept count {accepted}"
        );
    }
}
