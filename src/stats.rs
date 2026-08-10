//! Statistics counters and the failure policy.
//!
//! Because open() deliberately withholds rejection reasons from the caller
//! (a receiver that explains why a forgery failed is a decryption oracle,
//! PAXE.md "Failure Handling"), these counters are the ONLY diagnostic
//! channel an operator has. They are load-bearing, and they are designed
//! around the questions an operator actually asks: is this a botched key
//! rollout ([`RejectReason::NoEpoch`]), a topology problem
//! ([`RejectReason::NoPeer`]), an MTU/framing problem ([`RejectReason::
//! TooShort`], [`RejectReason::LenMismatch`]), garbage or wrong-protocol
//! traffic ([`RejectReason::BadFlags`]), or authentication failures
//! ([`RejectReason::AuthFailed`])?
//!
//! ## Exhaustive by construction
//!
//! The reject reasons are an ENUM, and the counter array is DERIVED from
//! that enum: [`RejectReason::COUNT`] is computed from the last variant,
//! so the array always has exactly one slot per reason — a reason cannot
//! exist without a counter. Three compile-time tripwires guard the
//! mapping: the counter array length (derived), [`RejectReason::ALL`]
//! (a fixed-size array literal — adding a variant without adding it here
//! fails to compile), and [`RejectReason::line`] (an exhaustive `match` —
//! adding a variant without a log line fails to compile). There is no
//! string table or shared "unrecognised" bucket; each enum variant has
//! its own log-once bit.
//!
//! ## The invariant
//!
//! ```text
//! rx_total == rx_ok + sum(rx_rejects[*])
//! ```
//!
//! Every frame presented to a CONFIGURED receiver is counted in rx_total
//! exactly once, and lands in exactly one of: opened (rx_ok) or dropped
//! with exactly one recorded reason. The reasons are recorded AT THE
//! REJECT POINTS in dek.rs/standard.rs (the only places the typed cause
//! still exists); rx_total/rx_ok are counted at the FFI boundary
//! (lib.rs), the one place that knows whether a receiver is configured.
//! Two paths are deliberately NOT counted, and the invariant is stated
//! over configured receivers precisely to exclude them:
//!
//! - **Unconfigured receiver** (open before set_local_id): the module is
//!   not running PAXE at all; the frame is dropped untallied.
//! - **Impossible internal results** (`OpenError::Sodium`, the mapped
//!   unreachable arms): not wire conditions, so no reason counter fits,
//!   and rx_total is not taken either. They cannot occur in practice;
//!   counting them as any real reason would falsify the counters.
//!
//! ## Delta measurement is the API
//!
//! Counters are process-global (single-threaded by construction — the one
//! LuaJIT VM thread — so the thread-local `Cell`s below ARE the process
//! state, matching how lib.rs holds the keystore), cumulative u64, and
//! NEVER reset by any API — not even by `lunet_paxe_shutdown`: a restart
//! must never make a monitoring delta go negative. Consumers measure
//! DELTAS between two snapshots; no test asserts an absolute value.
//!
//! ## The failure policy
//!
//! Three behaviours, selected process-wide via `lunet_paxe_fail_policy_set`:
//!
//! - **silent** (default): drop and count only. Nothing is written.
//! - **log_once**: the first drop OF EACH REASON writes one stderr line;
//!   repeats are counted silently. The memo is a bitmask over the ENUM
//!   (one bit per [`RejectReason`]) — no string comparison, no shared
//!   bucket.
//! - **verbose**: every drop writes a line. Unbounded by design; the
//!   operator opted into the firehose.
//!
//! Two policy details matter:
//!
//! - **Log-once reset scope.** The memo resets on `lunet_paxe_shutdown`
//!   (a re-initialised module starts a fresh window) and whenever the
//!   policy is SET to log_once — "once" is scoped to one continuous
//!   log_once window, and re-entering the policy is the operator's
//!   deliberate "tell me again, once" knob. An attacker cannot reset
//!   the memo (only the local operator can, through the FFI), so within
//!   a window each reason logs at most once regardless of volume — that
//!   is the rate limiting.
//! - **No fromId or epoch in log lines.** Every field available at
//!   rejection time (fromId, epoch, declared length, frame size) is
//!   attacker-controlled and UNVERIFIED — that is why the frame is
//!   being dropped. Logging them would let an unauthenticated sender
//!   write arbitrary-looking peer identities into operator logs at the
//!   policy's rate: a deception channel ("peer 7 is misconfigured"
//!   when peer 7 is fine), and under verbose a high-volume one. The
//!   counters carry the diagnostic signal without that exposure — a
//!   moved counter cannot lie about WHICH counter moved.
//!
//! Policy lines carry a fixed `[PAXE] ` prefix so they are distinguishable
//! from trace-build output (which will also appear on stderr when that
//! build lands); tests assert the prefix, never stderr emptiness, so they
//! cannot invert between build modes.
//!
//! The `record_*` entry points are public because a host that implements
//! its own pre-`open` gate has to keep the invariant
//! `rx_total == rx_ok + sum(reject reasons)` true itself — the in-crate
//! `lunet_paxe_frame_for_us` does exactly that when it rejects a datagram
//! addressed elsewhere. They are counters, not a control surface: calling
//! them cannot change what a frame decodes to.

use crate::codec::{CodecError, Mode};
use std::cell::Cell;

// ---------------------------------------------------------------------------
// Reject reasons — the exhaustive enumeration of why a frame can be
// dropped. One counter per variant, derived (see the module docs).
// ---------------------------------------------------------------------------

/// Every reason a received frame can be rejected. Ordering follows the
/// gate order on the receive path (cheap structural checks first), which
/// is also the pinned snapshot order for the FFI — see
/// [`Stats::fields`].
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Not a PAXE frame addressed to this node at all: under the 9-byte
    /// prefix, or a header `toId` (bytes 2-3) that is not the configured
    /// local id — plaintext, foreign-protocol or misaddressed traffic on
    /// a protected socket. Recorded ONLY at the protected-socket boundary
    /// (`lunet_paxe_frame_for_us`), by an EXPLICIT addressing
    /// check that runs before the codec — never by coincidence of the
    /// flags constant-bit gate, which crafted plaintext could pass. This
    /// is the first gate on the socket receive path, so it sorts first.
    Plaintext = 0,
    /// Fewer bytes than the parse needs: under the prefix or the reusable-DEK
    /// minimum frame size.
    TooShort,
    /// Flags constant-bit violation: bit 1 set or bit 2 clear. The
    /// protocol's cheap garbage filter, first check after the length gate.
    BadFlags,
    /// Declared plaintext length inconsistent with the actual frame size.
    LenMismatch,
    /// No key installed for the frame's fromId under ANY epoch: a
    /// TOPOLOGY problem — the link was never provisioned (or the frame
    /// is not for this cluster). Counted separately from NoEpoch because
    /// the operator action differs entirely.
    NoPeer,
    /// The fromId IS provisioned but not under the frame's epoch: a
    /// ROTATION problem — the two ends disagree about which epoch is
    /// live. Counted separately from NoPeer (see above).
    NoEpoch,
    /// The AES-GCM tag did not verify: wrong key, tampered ciphertext,
    /// tampered AAD, or a wrong DEK from a corrupted wrapped DEK (the
    /// wrap cannot fail on its own — see the module docs).
    AuthFailed,
}

impl RejectReason {
    /// Number of reasons, DERIVED from the enum: the counter array is
    /// always exactly one slot per reason. A reason cannot exist without
    /// a counter.
    pub const COUNT: usize = RejectReason::AuthFailed as usize + 1;

    /// Every reason, in declaration order. A fixed-size array literal:
    /// adding a variant without listing it here is a COMPILE ERROR (the
    /// length no longer matches COUNT), not a silent omission.
    // Exercised by the invariant tests and reject_sum; the FFI snapshot
    // reads fields() instead.
    #[allow(dead_code)]
    pub const ALL: [RejectReason; RejectReason::COUNT] = [
        RejectReason::Plaintext,
        RejectReason::TooShort,
        RejectReason::BadFlags,
        RejectReason::LenMismatch,
        RejectReason::NoPeer,
        RejectReason::NoEpoch,
        RejectReason::AuthFailed,
    ];

    /// Array index of this reason's counter. `< COUNT` by construction
    /// (repr(usize), dense from 0).
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The complete policy log line for this reason, INCLUDING the
    /// `[PAXE] ` prefix that distinguishes policy output from trace-build
    /// output on stderr. An exhaustive match: adding a variant without a
    /// line is a compile error. Carries NO fromId/epoch/sizes — those are
    /// unverified at rejection time (see the module docs).
    pub const fn line(self) -> &'static str {
        match self {
            RejectReason::Plaintext => "[PAXE] drop: plaintext on a protected socket",
            RejectReason::TooShort => "[PAXE] drop: frame too short",
            RejectReason::BadFlags => "[PAXE] drop: flags constant-bit violation",
            RejectReason::LenMismatch => {
                "[PAXE] drop: declared length inconsistent with frame size"
            }
            RejectReason::NoPeer => "[PAXE] drop: unknown peer",
            RejectReason::NoEpoch => "[PAXE] drop: unknown epoch for known peer",
            RejectReason::AuthFailed => "[PAXE] drop: authentication failure",
        }
    }

    /// The codec's rejections map onto the first two reasons (prefix too
    /// short, flags gate). Shared by dek.rs and standard.rs so the two
    /// call sites cannot diverge on the mapping.
    pub fn from_codec(e: CodecError) -> Self {
        match e {
            CodecError::TooShort(_) => RejectReason::TooShort,
            CodecError::InvalidFlags(_) => RejectReason::BadFlags,
        }
    }
}

// The log-once memo is one bit per reason in a u64; this fails the build
// if the enum ever outgrows the mask.
const _: () = assert!(RejectReason::COUNT <= 64);

// ---------------------------------------------------------------------------
// Failure policy.
// ---------------------------------------------------------------------------

/// The process-wide drop logging policy (module docs). Default: silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPolicy {
    /// Drop and count only; nothing is written. The default.
    Silent,
    /// One stderr line for the first drop of each reason per window.
    LogOnce,
    /// One stderr line per drop. Unbounded, operator-opted-in.
    Verbose,
}

impl FailPolicy {
    /// The canonical spelling, accepted by `lunet_paxe_fail_policy_set`
    /// (paxe.lua lowercases before calling, so uppercase forms reach here
    /// already canonical).
    // Exercised by the round-trip test; the FFI sets by name and never
    // reads it back.
    #[allow(dead_code)]
    pub const fn name(self) -> &'static str {
        match self {
            FailPolicy::Silent => "silent",
            FailPolicy::LogOnce => "log_once",
            FailPolicy::Verbose => "verbose",
        }
    }

    /// Parse the canonical spellings exactly. Anything else is a malformed
    /// argument at the FFI (paxe.lua pre-validates and returns false
    /// instead, so this arm is unreachable from Lua — defence in depth).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "silent" => Some(FailPolicy::Silent),
            "log_once" => Some(FailPolicy::LogOnce),
            "verbose" => Some(FailPolicy::Verbose),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The counters.
// ---------------------------------------------------------------------------

/// Number of u64 fields in the FFI snapshot ([`Stats::fields`]). paxe.lua
/// probes with a null pointer to size its buffer, and asserts its name
/// table has exactly this many entries so a drift fails loudly.
pub const SNAPSHOT_FIELD_COUNT: usize = 13;

/// The process-global cumulative counters. `Copy` so snapshots are plain
/// values; deltas are measured between two snapshots (module docs: no
/// absolute-value assertions anywhere).
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    /// Frames presented to a configured receiver (opened + dropped).
    pub rx_total: u64,
    /// Frames successfully opened.
    pub rx_ok: u64,
    /// Drops by reason. Length DERIVED from the enum: one slot per reason,
    /// always. Indexed by [`RejectReason::index`].
    pub rx_rejects: [u64; RejectReason::COUNT],
    /// Frames successfully sealed.
    pub tx_total: u64,
    /// Of tx_total, sealed standard frames.
    pub tx_standard: u64,
    /// Of tx_total, reusable-DEK frames explicitly recorded by a Rust host
    /// after it accepts the frames returned by `dek::seal_fanout`. The C ABI
    /// has no fanout sealer and therefore never advances this counter.
    pub tx_dek: u64,
    /// Seals rejected for an oversized payload (reportable RC_ERR, never
    /// a truncated length field).
    pub tx_oversize: u64,
}

impl Stats {
    /// The all-zero initial value, const-constructible for the thread-local.
    const ZERO: Stats = Stats {
        rx_total: 0,
        rx_ok: 0,
        rx_rejects: [0; RejectReason::COUNT],
        tx_total: 0,
        tx_standard: 0,
        tx_dek: 0,
        tx_oversize: 0,
    };

    /// One reason's counter. Indexed access that cannot panic even in
    /// principle (falls back to 0 on the unreachable out-of-range).
    pub fn reject(&self, reason: RejectReason) -> u64 {
        self.rx_rejects.get(reason.index()).copied().unwrap_or(0)
    }

    /// Sum of all reject-reason counters. The invariant:
    /// `rx_total == rx_ok + reject_sum()` (module docs).
    // The invariant lives in the tests; production reads individual
    /// counters via fields().
    #[allow(dead_code)]
    pub fn reject_sum(&self) -> u64 {
        let mut sum = 0u64;
        for reason in RejectReason::ALL {
            sum = sum.saturating_add(self.reject(reason));
        }
        sum
    }

    /// The snapshot as a flat array in the PINNED FFI order. paxe.lua
    /// maps these indices to counter names; both sides carry the order as
    /// a comment, the count is asserted at the Lua boundary, and a Rust
    /// unit test pins the mapping.
    pub fn fields(&self) -> [u64; SNAPSHOT_FIELD_COUNT] {
        [
            self.rx_total,
            self.rx_ok,
            self.reject(RejectReason::Plaintext),
            self.reject(RejectReason::TooShort),
            self.reject(RejectReason::BadFlags),
            self.reject(RejectReason::LenMismatch),
            self.reject(RejectReason::NoPeer),
            self.reject(RejectReason::NoEpoch),
            self.reject(RejectReason::AuthFailed),
            self.tx_total,
            self.tx_standard,
            self.tx_dek,
            self.tx_oversize,
        ]
    }
}

// ---------------------------------------------------------------------------
// Process state. Single-threaded by construction (every caller runs on
// the one LuaJIT VM thread), so thread-local Cells are the honest
// structure — the same pattern lib.rs uses for the keystore, and fully
// safe code: Cell cannot have a borrow conflict, so no path can panic.
// ---------------------------------------------------------------------------

thread_local! {
    /// The cumulative counters. NEVER reset by any API (module docs:
    /// deltas, and a restart must not make them go negative).
    static STATS: Cell<Stats> = const { Cell::new(Stats::ZERO) };

    /// The active failure policy. Process-wide, independent of the
    /// keystore lifecycle (settable before init, unaffected by clear).
    static POLICY: Cell<FailPolicy> = const { Cell::new(FailPolicy::Silent) };

    /// The log-once memo: one bit per [`RejectReason`]. It resets on
    /// shutdown and when entering the log_once policy.
    static LOGGED: Cell<u64> = const { Cell::new(0) };
}

/// Mutate the counters in place. Cell get/set: no borrow, no panic.
fn bump(f: impl Fn(&mut Stats)) {
    STATS.with(|c| {
        let mut s = c.get();
        f(&mut s);
        c.set(s);
    });
}

/// A frame was opened: received total AND success both advance (the
/// invariant counts every received frame exactly once).
pub fn record_rx_ok() {
    bump(|s| {
        s.rx_total = s.rx_total.saturating_add(1);
        s.rx_ok = s.rx_ok.saturating_add(1);
    });
}

/// A frame was dropped with its reason already recorded at the reject
/// point: only the received total advances here.
pub fn record_rx_drop() {
    bump(|s| {
        s.rx_total = s.rx_total.saturating_add(1);
    });
}

/// Record a frame accepted for transmission: transmit total plus the mode
/// split.
///
/// The C ABI calls this for each standard frame it seals. Reusable-DEK fanout
/// is Rust API-only: a Rust host must call this once for each returned fanout
/// frame it actually accepts for transmission, using [`Mode::Dek`].
pub fn record_tx_sealed(mode: Mode) {
    bump(|s| {
        s.tx_total = s.tx_total.saturating_add(1);
        match mode {
            Mode::Standard => s.tx_standard = s.tx_standard.saturating_add(1),
            Mode::Dek => s.tx_dek = s.tx_dek.saturating_add(1),
        }
    });
}

/// A seal was rejected for an oversized payload.
pub fn record_tx_oversize() {
    bump(|s| {
        s.tx_oversize = s.tx_oversize.saturating_add(1);
    });
}

/// Record a rejection reason, at the reject point (the only place the
/// typed cause still exists), and apply the failure policy.
pub fn record_reject(reason: RejectReason) {
    bump(|s| {
        if let Some(c) = s.rx_rejects.get_mut(reason.index()) {
            // In bounds by construction (index < COUNT); the get_mut form
            // keeps even the impossible case panic-free.
            *c = c.saturating_add(1);
        }
    });
    if should_log(reason) {
        emit(reason);
    }
}

/// The cumulative snapshot for the FFI and for delta-measuring tests.
pub fn snapshot() -> Stats {
    STATS.with(|c| c.get())
}

/// The active policy.
pub fn policy() -> FailPolicy {
    POLICY.with(|c| c.get())
}

/// Select the policy. Entering log_once starts a FRESH window (the memo
/// resets): re-entering the policy is the operator's "tell me again,
/// once" knob described in the module docs.
pub fn set_policy(p: FailPolicy) {
    POLICY.with(|c| c.set(p));
    if p == FailPolicy::LogOnce {
        reset_log_once_memo();
    }
}

/// Reset the log-once memo. Called by `lunet_paxe_shutdown` (a
/// re-initialised module starts a fresh window) and by set_policy on
/// entering log_once. The counters are NOT touched — they never reset.
///
/// `try_with`, not `with`: the atexit exit hook can run after the
/// thread-local has been destroyed (destructor order at process exit is
/// reverse-registration, and the memo may have been initialised after the
/// hook was registered). A destroyed memo means there is nothing left to
/// reset — and `with` would panic, which under `panic = "abort"` would
/// turn process exit into an abort.
pub fn reset_log_once_memo() {
    let _ = LOGGED.try_with(|c| c.set(0));
}

/// The policy decision for one rejection. Under log_once this test-and-
/// sets the reason's bit in the memo — per-reason memoisation against
/// the ENUM, no strings, no shared bucket.
fn should_log(reason: RejectReason) -> bool {
    match policy() {
        FailPolicy::Silent => false,
        FailPolicy::Verbose => true,
        FailPolicy::LogOnce => LOGGED.with(|m| {
            let bits = m.get();
            // index < COUNT <= 64 (const-asserted above): the shift
            // cannot overflow.
            let bit = 1u64 << reason.index();
            if bits & bit != 0 {
                return false;
            }
            m.set(bits | bit);
            true
        }),
    }
}

/// Write one policy line to stderr. NOT eprintln!: that macro panics on
/// a broken stderr, and `panic = "abort"` would turn a failed log write
/// into a host process kill. The Result is ignored by design — policy
/// logging is best-effort diagnostics, never worth a crash.
fn emit(reason: RejectReason) {
    use std::io::Write;
    let mut err = std::io::stderr();
    let _ = writeln!(err, "{}", reason.line());
}

// ---------------------------------------------------------------------------
// Tests. Each test runs on its own thread, so the thread-local state
// starts zeroed; deltas are still used throughout — no absolute values.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn delta(before: &Stats, after: &Stats, reason: RejectReason) -> u64 {
        after.reject(reason) - before.reject(reason)
    }

    #[test]
    fn every_reason_has_a_counter_an_all_entry_and_a_line() {
        // The structural guarantees, exercised: dense indices in bounds,
        // ALL covers every index exactly once, and every line carries the
        // prefix that distinguishes policy output from trace output.
        let mut seen = [false; RejectReason::COUNT];
        for reason in RejectReason::ALL {
            assert!(reason.index() < RejectReason::COUNT);
            assert!(!seen[reason.index()], "duplicate index for {reason:?}");
            seen[reason.index()] = true;
            assert!(
                reason.line().starts_with("[PAXE] drop: "),
                "line for {reason:?} must carry the [PAXE] prefix"
            );
        }
        assert!(seen.iter().all(|&s| s), "every counter slot is reachable");
        assert_eq!(RejectReason::COUNT, 7, "the seven enumerated reasons");
        // The exact lines (the smoke run greps stderr for these).
        assert_eq!(
            RejectReason::Plaintext.line(),
            "[PAXE] drop: plaintext on a protected socket"
        );
        assert_eq!(
            RejectReason::TooShort.line(),
            "[PAXE] drop: frame too short"
        );
        assert_eq!(
            RejectReason::BadFlags.line(),
            "[PAXE] drop: flags constant-bit violation"
        );
        assert_eq!(
            RejectReason::LenMismatch.line(),
            "[PAXE] drop: declared length inconsistent with frame size"
        );
        assert_eq!(RejectReason::NoPeer.line(), "[PAXE] drop: unknown peer");
        assert_eq!(
            RejectReason::NoEpoch.line(),
            "[PAXE] drop: unknown epoch for known peer"
        );
        assert_eq!(
            RejectReason::AuthFailed.line(),
            "[PAXE] drop: authentication failure"
        );
    }

    #[test]
    fn codec_errors_map_to_the_first_two_reasons() {
        assert_eq!(
            RejectReason::from_codec(CodecError::TooShort(3)),
            RejectReason::TooShort
        );
        assert_eq!(
            RejectReason::from_codec(CodecError::InvalidFlags(0x00)),
            RejectReason::BadFlags
        );
    }

    #[test]
    fn snapshot_fields_follow_the_pinned_ffi_order() {
        // Construct a state with a DISTINCT value per counter so any
        // transposition in fields() is visible, via the recording API.
        record_rx_ok(); // rx_total 1, rx_ok 1
        for reason in RejectReason::ALL {
            record_rx_drop();
            record_reject(reason);
        }
        record_tx_sealed(Mode::Standard);
        record_tx_sealed(Mode::Dek);
        record_tx_sealed(Mode::Dek);
        record_tx_oversize();
        let s = snapshot();
        let f = s.fields();
        assert_eq!(f.len(), SNAPSHOT_FIELD_COUNT);
        let before = Stats::default();
        assert_eq!(f[0] - before.rx_total, 8, "rx_total: 1 ok + 7 drops");
        assert_eq!(f[1] - before.rx_ok, 1, "rx_ok");
        for (i, reason) in RejectReason::ALL.iter().enumerate() {
            assert_eq!(f[2 + i], 1, "reject counter for {reason:?}");
        }
        assert_eq!(f[9] - before.tx_total, 3, "tx_total");
        assert_eq!(f[10] - before.tx_standard, 1, "tx_standard");
        assert_eq!(f[11] - before.tx_dek, 2, "tx_dek");
        assert_eq!(f[12] - before.tx_oversize, 1, "tx_oversize");
        // THE invariant, over the recording API alone.
        assert_eq!(f[0], f[1] + s.reject_sum(), "rx_total == rx_ok + rejects");
    }

    #[test]
    fn recording_is_delta_friendly_and_never_reset_by_policy_ops() {
        let before = snapshot();
        record_reject(RejectReason::NoPeer);
        record_reject(RejectReason::NoPeer);
        let after = snapshot();
        assert_eq!(delta(&before, &after, RejectReason::NoPeer), 2);
        assert_eq!(delta(&before, &after, RejectReason::NoEpoch), 0);
        // Policy churn and the memo reset leave the counters untouched.
        set_policy(FailPolicy::Verbose);
        set_policy(FailPolicy::LogOnce);
        reset_log_once_memo();
        set_policy(FailPolicy::Silent);
        let end = snapshot();
        assert_eq!(delta(&before, &end, RejectReason::NoPeer), 2);
        assert_eq!(end.rx_total - before.rx_total, 0);
    }

    #[test]
    fn policy_set_get_and_spellings() {
        assert_eq!(FailPolicy::from_name("silent"), Some(FailPolicy::Silent));
        assert_eq!(FailPolicy::from_name("log_once"), Some(FailPolicy::LogOnce));
        assert_eq!(FailPolicy::from_name("verbose"), Some(FailPolicy::Verbose));
        assert_eq!(FailPolicy::from_name("drop"), None);
        assert_eq!(
            FailPolicy::from_name("LOG_ONCE"),
            None,
            "exact spellings; Lua lowercases"
        );
        assert_eq!(FailPolicy::from_name(""), None);
        assert_eq!(FailPolicy::Silent.name(), "silent");
        assert_eq!(FailPolicy::LogOnce.name(), "log_once");
        assert_eq!(FailPolicy::Verbose.name(), "verbose");

        set_policy(FailPolicy::Verbose);
        assert_eq!(policy(), FailPolicy::Verbose);
        set_policy(FailPolicy::Silent);
        assert_eq!(policy(), FailPolicy::Silent);
    }

    #[test]
    fn log_once_memoises_per_reason_against_the_enum_bitmask() {
        set_policy(FailPolicy::LogOnce);
        // First occurrence per reason logs; repeat is memoised.
        assert!(should_log(RejectReason::NoEpoch));
        assert!(!should_log(RejectReason::NoEpoch));
        assert!(!should_log(RejectReason::NoEpoch));
        // A different reason is not suppressed: one bit per enum variant.
        assert!(should_log(RejectReason::NoPeer));
        assert!(!should_log(RejectReason::NoPeer));
        // The memo is a bitmask over the enum: exactly these two bits set.
        let bits = LOGGED.with(|m| m.get());
        assert_eq!(
            bits,
            (1u64 << RejectReason::NoEpoch.index()) | (1u64 << RejectReason::NoPeer.index())
        );
        // Every other reason still logs its first occurrence.
        for reason in RejectReason::ALL {
            if reason != RejectReason::NoEpoch && reason != RejectReason::NoPeer {
                assert!(should_log(reason), "first occurrence of {reason:?}");
            }
        }
        let bits = LOGGED.with(|m| m.get());
        assert_eq!(bits, (1u64 << RejectReason::COUNT) - 1, "all eight bits");

        // Reset scope: entering log_once starts a fresh window...
        set_policy(FailPolicy::LogOnce);
        assert_eq!(
            LOGGED.with(|m| m.get()),
            0,
            "re-entering log_once resets the memo"
        );
        assert!(should_log(RejectReason::NoEpoch));
        // ...and so does an explicit reset (the shutdown path).
        reset_log_once_memo();
        assert!(should_log(RejectReason::NoEpoch));
        // Silent and verbose do not consult the memo at all.
        set_policy(FailPolicy::Silent);
        assert!(!should_log(RejectReason::NoPeer));
        set_policy(FailPolicy::Verbose);
        assert!(should_log(RejectReason::NoPeer));
        assert!(should_log(RejectReason::NoPeer), "verbose never memoises");
        set_policy(FailPolicy::Silent);
    }

    #[test]
    fn reject_recording_respects_the_active_policy_without_panicking() {
        // record_reject under each policy: counters always move; the memo
        // only advances under log_once. (stderr emission itself is
        // shell-verified by the smoke run; here we pin behaviour.)
        let before = snapshot();
        set_policy(FailPolicy::Verbose);
        record_reject(RejectReason::AuthFailed);
        set_policy(FailPolicy::Silent);
        record_reject(RejectReason::AuthFailed);
        let after = snapshot();
        assert_eq!(delta(&before, &after, RejectReason::AuthFailed), 2);
        assert_eq!(
            LOGGED.with(|m| m.get()),
            0,
            "neither verbose nor silent touches the memo"
        );
    }
}
