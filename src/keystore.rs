//! The secure keystore: per-link key material held ONLY in
//! libsodium guarded allocations, keyed by `(peer node id, epoch)`.
//!
//! - **Material lives only in guarded memory.** [`StoredKey`] owns a
//!   [`sodium::GuardedAllocation`] (`sodium_malloc`: guard pages + canary),
//!   explicitly `sodium_mlock`ed at install, and erased with
//!   `sodium_memzero` on the way out. Key bytes are never on the stack,
//!   never in a `Vec`, never in BSS. The constructor is the only way in
//!   and it copies caller bytes straight into the guarded region.
//! - **No copies can escape.** `StoredKey` is not `Copy` and not `Clone`,
//!   its `Debug` prints a redacted placeholder, and the only accessor is
//!   [`StoredKey::expose`], which yields a borrowed `&[u8]` tied to the
//!   key's lifetime — never an owned array. Rust's move semantics make
//!   "the key is never duplicated into unguarded memory" a
//!   compiler-checked property.
//! - **Honest deletion.** The container is a `BTreeMap<(u16, Epoch),
//!   StoredKey>`. Removal drops the value and runs its destructor: there
//!   are no tombstones or probe-chain deletion hazards.
//!
//! ## Addressing: `(peer, epoch)`, and the send/receive asymmetry
//!
//! Keys are per LINK (per unordered node pair; see PAXE.md "Key
//! Management"), so the store is indexed by the peer — the OTHER end of
//! the link — plus a 5-bit epoch. The local node id is configured once at
//! [`KeyStore::new`] and is implicit in every entry; it is not part of the
//! key. Which header field supplies the peer differs by direction, and
//! getting it backwards still decrypts loopback traffic correctly, so a
//! same-node round-trip test cannot see the bug:
//!
//! - **Send** ([`KeyStore::key_for_send`]): the peer is the frame's
//!   `toId` — we seal with the key we share with the destination.
//! - **Receive** ([`KeyStore::key_for_receive`]): the peer is the frame's
//!   `fromId` — we open with the key we share with the source.
//!
//! The two entry points are deliberately separate so every call site names
//! the direction and cannot transpose the asymmetry silently. Tests use
//! two different node ids because `fromId == toId` would resolve either
//! lookup to the same slot and prove nothing.
//!
//! ## Capacity bound
//!
//! [`MAX_ENTRIES`] = 1024, explicit and documented (PAXE.md "Key
//! Management"). That covers a 512-node cluster mid-rotation (two live
//! epochs per peer) or 32 peers holding all 32 epochs each. The bound
//! also caps wired memory: each entry is one guarded allocation (~one
//! locked page), so a full store pins roughly 4 MiB of RAM. Exceeding the
//! bound is [`KeystoreError::Full`]. OS lock limits (RLIMIT_MEMLOCK) can
//! bite first; that surfaces as
//! [`KeystoreError::Sodium`], equally explicit.
//!
//! ## Erasure: three paths, plus what survives `panic = "abort"`
//!
//! Key material is erased on all three paths:
//!
//! 1. **Explicit clear** — [`KeyStore::clear`] drops every entry.
//! 2. **Epoch retirement / overwrite** — [`KeyStore::retire`] removes one
//!    entry; [`KeyStore::install`] over an occupied slot drops the
//!    replaced key. Only that slot's material is erased.
//! 3. **Shutdown** — dropping the `KeyStore` drops the map, which drops
//!    every `StoredKey`.
//!
//! Every drop runs `sodium_memzero` over the material and then
//! `sodium_free` (which itself zeroes, verifies the canary, unlocks and
//! releases). BUT the crate is built `panic = "abort"`: on an abort,
//! destructors do not run, so drop-ordering erasure cannot be the only
//! protection. Crash-time protection is platform-specific:
//!
//! - **Swap:** `sodium_mlock` pins the guarded pages in RAM on every
//!   supported platform; locked pages never reach swap.
//! - **Swap, Windows:** the lock budget there is not an rlimit but the
//!   process minimum working set — 200KB by default, roughly 48 locked
//!   pages for the whole process, one of which every stored key consumes.
//!   `sodium::mlock` raises that budget on a quota refusal and retries,
//!   so a node holding dozens of per-link keys still gets every one of
//!   them locked instead of `MlockFailed` at some arbitrary key count.
//! - **Core dumps, Linux:** libsodium's `sodium_mlock` sets
//!   `MADV_DONTDUMP`, so the guarded pages are excluded from the kernel
//!   core.
//! - **Core dumps, macOS:** mlock gives NO exclusion — Darwin has no
//!   `MADV_DONTDUMP`. The abort-time defence on Darwin is
//!   `setrlimit(RLIMIT_CORE, 0)` at
//!   `lunet_paxe_init` — the kernel then writes no core at all, so no
//!   page, guarded or not, can disclose material through one. Default
//!   on, with `LUNET_PAXE_ALLOW_CORE_DUMPS=1` as the documented
//!   debugging opt-out (see lib.rs and PAXE.md "Security
//!   Considerations").
//!
//! Drop erasure covers normal exit, clear and retirement; the
//! platform-split mechanisms above cover the crash-without-destructors
//! case.
//!
//! ## Thread safety: single-threaded by construction
//!
//! Decision: **single-threaded by construction, enforced by the
//! compiler.** `KeyStore` is `!Send` and `!Sync` — the
//! `GuardedAllocation` inside every `StoredKey` holds a `NonNull<u8>`,
//! which is `!Send`/`!Sync`, and this crate adds no `unsafe impl` to
//! override that. Rust therefore rejects any move or share of the store
//! across threads at compile time.
//!
//! Justification: every caller runs on the one LuaJIT VM thread — the
//! Lua-facing API is entered through the LuaJIT FFI from Lua state, and
//! the UDP receive path drives Lua from the libuv
//! loop thread. No second thread ever touches the store. A `Mutex` would
//! buy nothing and would import a poisoning failure mode that
//! `panic = "abort"` converts into a process kill with no unwind. If a
//! future embedding genuinely calls from multiple threads, the owner must
//! synchronise externally (e.g. wrap the whole store in a `Mutex`) — that
//! is the public constraint.

use crate::sodium::{self, GuardedAllocation, SodiumError, KEYBYTES};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// Maximum number of live `(peer, epoch)` entries. Explicit, documented
/// (see module docs and PAXE.md), and reported as [`KeystoreError::Full`]
/// rather than silently refused.
pub const MAX_ENTRIES: usize = 1024;

/// The largest valid epoch: the 5-bit field in flags bits 3-7 holds 0-31.
pub const MAX_EPOCH: u8 = 31;

/// A validated key epoch (0-31). Construction is the only validation
/// point: an `Epoch` value can never hold an out-of-range bits pattern,
/// so no lookup or install path re-checks it. Not secret, so the full
/// value-semantics derive set is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u8);

impl Epoch {
    /// Wrap a raw epoch value. Values above 31 (not representable in the
    /// 5-bit wire field) are rejected as [`KeystoreError::InvalidEpoch`].
    pub fn new(bits: u8) -> Result<Self, KeystoreError> {
        if bits > MAX_EPOCH {
            return Err(KeystoreError::InvalidEpoch(bits));
        }
        Ok(Epoch(bits))
    }

    /// The raw 0-31 value, e.g. for the codec to place into flags bits 3-7.
    pub fn bits(self) -> u8 {
        self.0
    }
}

/// Every failure the keystore can report. No operation in this module
/// panics — `panic = "abort"` would kill the LuaJIT host process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreError {
    /// An epoch above 31 was presented. Rejected before any storage op.
    InvalidEpoch(u8),
    /// The store holds [`MAX_ENTRIES`] entries and the install targets a
    /// NEW `(peer, epoch)` slot. Clear, reportable — the operator must
    /// retire epochs or raise the documented bound. Overwriting an
    /// existing slot at capacity is allowed (it does not grow the store).
    Full,
    /// The guarded allocation or its `mlock` failed (typically
    /// RLIMIT_MEMLOCK). Wrapped from the sodium boundary.
    Sodium(SodiumError),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeystoreError::InvalidEpoch(bits) => {
                write!(f, "invalid key epoch {bits}: must be 0-{MAX_EPOCH}")
            }
            KeystoreError::Full => write!(
                f,
                "keystore at capacity ({MAX_ENTRIES} entries); retire an epoch before installing more"
            ),
            KeystoreError::Sodium(e) => write!(f, "secure-memory failure: {e}"),
        }
    }
}

impl Error for KeystoreError {}

impl From<SodiumError> for KeystoreError {
    fn from(e: SodiumError) -> Self {
        KeystoreError::Sodium(e)
    }
}

/// One 32-byte per-link key held in a libsodium guarded allocation.
///
/// Deliberately NOT `Copy`, NOT `Clone`, and with a redacted `Debug`:
/// each is a way material otherwise leaks into unguarded memory (a copy
/// on the stack, a clone in a `Vec`, bytes in a log line). The only way
/// to read the bytes is [`expose`](StoredKey::expose), a borrowed slice
/// whose lifetime is tied to this key — an owned array can never be
/// obtained, so nothing can move the material out of the guarded region.
pub struct StoredKey {
    /// Exactly `KEYBYTES` bytes of guarded, canaried, page-locked memory.
    mem: GuardedAllocation,
}

impl StoredKey {
    /// Copy `material` into a fresh guarded allocation and lock its
    /// pages. The explicit `mlock` is load-bearing even though
    /// `sodium_malloc` locks implicitly: it makes lock failure a hard,
    /// reportable error here rather than a silent best-effort, and locked
    /// pages are what keep material out of swap on every platform and out
    /// of core dumps ON LINUX (`MADV_DONTDUMP`). On macOS mlock excludes
    /// nothing from cores — the core-dump defence there is the init-time
    /// `RLIMIT_CORE` suppression. See the module docs for the
    /// full platform split that survives `panic = "abort"`.
    ///
    /// On any failure the partial allocation is dropped — `sodium_free`
    /// zeroes and releases it — so no error path leaks guarded memory.
    pub fn new(material: &[u8; KEYBYTES]) -> Result<Self, SodiumError> {
        let mut mem = GuardedAllocation::new(KEYBYTES)?;
        // Lengths are compile-time equal, so this copy cannot panic.
        mem.as_mut_slice().copy_from_slice(material);
        sodium::mlock(mem.as_mut_slice())?;
        Ok(StoredKey { mem })
    }

    /// Borrow the key material. Returns a slice tied to `&self`; the
    /// guarded allocation is released only by `Drop`, so the slice can
    /// never dangle. This is the ONLY accessor — there is deliberately no
    /// owned-array accessor.
    pub fn expose(&self) -> &[u8] {
        self.mem.as_slice()
    }
}

impl fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material into a log. Exact placeholder (a unit
        // test pins this string) so redaction cannot silently regress.
        write!(f, "StoredKey([..; {KEYBYTES}])")
    }
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        // Explicit erase on every drop path (clear, retirement, shutdown).
        // The subsequent GuardedAllocation drop calls sodium_free, which
        // zeroes AGAIN before unlocking and freeing — belt and braces,
        // with the explicit pass guaranteeing the wipe even if the
        // libsodium release behaviour ever changes.
        sodium::memzero(self.mem.as_mut_slice());
    }
}

/// The keystore: `(peer node id, epoch)` -> per-link key, for one node.
///
/// See the module docs for the addressing model (including the
/// send/`toId` vs receive/`fromId` asymmetry), the capacity bound, the
/// three erasure paths, and the single-threaded-by-construction decision.
pub struct KeyStore {
    /// This node's own id, configured once. Not part of any key: per-link
    /// keys are indexed by the peer alone because "local" is the same for
    /// every entry in this store. Used by the codec/AAD layers and for
    /// diagnostics.
    local_id: u16,
    /// Honest structure: removal drops the value and runs its destructor.
    /// No tombstones, no terminate-at-first-hole probe — per-entry delete
    /// (epoch retirement) is an ordinary `BTreeMap::remove`, not a special
    /// case the probing rules have to survive.
    entries: BTreeMap<(u16, Epoch), StoredKey>,
}

impl KeyStore {
    /// Create an empty store for node `local_id`. Initialises libsodium
    /// (idempotent) so no later operation in this module can run against
    /// an uninitialised library.
    pub fn new(local_id: u16) -> Result<Self, KeystoreError> {
        sodium::init()?;
        Ok(KeyStore {
            local_id,
            entries: BTreeMap::new(),
        })
    }

    /// The local node id configured at initialisation.
    pub fn local_id(&self) -> u16 {
        self.local_id
    }

    /// Install `material` as the key shared with `peer` under `epoch`.
    ///
    /// Overwriting an occupied `(peer, epoch)` slot replaces the key and
    /// erases the old material (the replaced `StoredKey` is dropped);
    /// this is how an epoch's key is changed. Installing into a NEW slot
    /// when the store already holds [`MAX_ENTRIES`] entries fails with
    /// [`KeystoreError::Full`] — checked BEFORE any allocation, so the
    /// error path touches no guarded memory.
    pub fn install(
        &mut self,
        peer: u16,
        epoch: Epoch,
        material: &[u8; KEYBYTES],
    ) -> Result<(), KeystoreError> {
        if !self.entries.contains_key(&(peer, epoch)) && self.entries.len() >= MAX_ENTRIES {
            return Err(KeystoreError::Full);
        }
        let key = StoredKey::new(material)?;
        if let Some(replaced) = self.entries.insert((peer, epoch), key) {
            // Erasure of the overwritten key happens here, on this drop.
            drop(replaced);
        }
        Ok(())
    }

    /// SEND-side lookup: `to_id` is the destination of the frame being
    /// sealed. The peer on a send is the REMOTE end of the link, i.e. the
    /// frame's `toId` — we seal with the key we share with the
    /// destination. Do not pass the local id here (unless the destination
    /// really is this node): see the module-docs asymmetry section.
    ///
    /// Returns `None` when no key exists for that `(peer, epoch)` — an
    /// absent key is a drop reason on the wire, not an error.
    pub fn key_for_send(&self, to_id: u16, epoch: Epoch) -> Option<&StoredKey> {
        self.entries.get(&(to_id, epoch))
    }

    /// RECEIVE-side lookup: `from_id` is the claimed source of the frame
    /// being opened. The peer on a receive is the REMOTE end of the link,
    /// i.e. the frame's `fromId` — we open with the key we share with the
    /// source (the AAD binds `fromId` into the tag, so a forged `fromId`
    /// fails authentication against that key). Do not pass the
    /// destination/`toId` here: with per-link keys the key belongs to the
    /// SENDER relationship, and transposing the two still decrypts
    /// loopback traffic — see the module-docs asymmetry section.
    ///
    /// Returns `None` when no key exists for that `(peer, epoch)` — an
    /// absent key is a drop reason on the wire, not an error.
    pub fn key_for_receive(&self, from_id: u16, epoch: Epoch) -> Option<&StoredKey> {
        self.entries.get(&(from_id, epoch))
    }

    /// SEND-side current-epoch lookup: the highest-numbered epoch
    /// installed for `to_id`, with its key. This is the epoch a sender
    /// uses, and it makes the PAXE.md rotation procedure automatic:
    /// "install the new key under a new epoch ... switch senders over"
    /// happens AT INSTALL, because the newest epoch is always the current
    /// send epoch; "retire the old epoch" then removes the superseded
    /// key. Numeric epochs are the rotation ordering, so highest ==
    /// newest by convention (documented in PAXE.md "Lua API"). The
    /// Lua-facing seal takes no epoch parameter precisely so
    /// this rule is the only selection on the send path.
    ///
    /// Entries for one peer are contiguous under the `(peer, epoch)`
    /// BTreeMap ordering, so `next_back` of the peer's range is the
    /// highest epoch. Returns `None` when no epoch is installed for the
    /// peer at all.
    pub fn key_for_send_current(&self, to_id: u16) -> Option<(Epoch, &StoredKey)> {
        self.entries
            .range((to_id, Epoch(0))..=(to_id, Epoch(MAX_EPOCH)))
            .next_back()
            .map(|(&(_, epoch), key)| (epoch, key))
    }

    /// Whether ANY epoch is installed for `peer`. Receive-side reason
    /// classification for the counters: a key miss against a peer
    /// with no entries at all is "unknown peer" (a TOPOLOGY problem — the
    /// link was never provisioned), while a miss against a peer holding
    /// other epochs is "unknown epoch" (a ROTATION problem — the two ends
    /// disagree about which epoch is live). The two are counted
    /// separately precisely because the operator action differs.
    pub fn peer_known(&self, peer: u16) -> bool {
        self.entries
            .range((peer, Epoch(0))..=(peer, Epoch(MAX_EPOCH)))
            .next()
            .is_some()
    }

    /// Retire one epoch for one peer: remove ONLY that slot's key,
    /// erasing its material. Returns `true` if a key was retired. All
    /// other epochs for the same peer — and all other peers — are
    /// untouched; that non-shadowing property is what makes rolling key
    /// changes possible.
    pub fn retire(&mut self, peer: u16, epoch: Epoch) -> bool {
        // Removal drops the StoredKey: memzero + sodium_free. Erasure is
        // scoped to exactly this slot by the map's key.
        self.entries.remove(&(peer, epoch)).is_some()
    }

    /// Erase every key in the store (explicit-clear erasure path).
    pub fn clear(&mut self) {
        // Dropping each value runs StoredKey::drop -> memzero, then
        // sodium_free zeroes again and releases.
        self.entries.clear();
    }

    /// Number of live `(peer, epoch)` entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests. Panicking asserts are fine here: test code never ships in the
// cdylib.
//
// ERASURE — what is asserted vs what is guaranteed by construction:
// You cannot read freed guarded memory to prove it was zeroed (the guard
// pages exist precisely to fault on such a read), so these tests do NOT
// fake that claim. Asserted directly: the observable consequences of
// erasure — retired/cleared/overwritten slots no longer resolve, the
// surviving slots are byte-identical, the store shrinks, and `Debug`
// output contains no material. Guaranteed by construction (and stated,
// not tested): every removal path drops the `StoredKey`, whose
// destructor runs `sodium_memzero` and then `sodium_free` (which zeroes
// again); `sodium_mlock` keeps the pages out of swap on every platform
// and out of core dumps on Linux (`MADV_DONTDUMP`) — and on macOS the
// init-time `RLIMIT_CORE` suppression keeps the kernel from
// writing a core at all. Those are the protections that survive
// `panic = "abort"`; the module docs carry the full platform split.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sodium::ct_eq;

    const LOCAL: u16 = 100;
    const PEER: u16 = 200;

    fn ep(bits: u8) -> Epoch {
        Epoch::new(bits).expect("test epochs are in range")
    }

    fn material(fill: u8) -> [u8; KEYBYTES] {
        [fill; KEYBYTES]
    }

    #[test]
    fn install_and_lookup_on_both_directions() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        ks.install(PEER, ep(3), &material(0x11)).expect("install");
        assert_eq!(ks.len(), 1);

        let send = ks.key_for_send(PEER, ep(3)).expect("send lookup");
        assert!(ct_eq(send.expose(), &material(0x11)));
        let recv = ks.key_for_receive(PEER, ep(3)).expect("receive lookup");
        assert!(ct_eq(recv.expose(), &material(0x11)));

        // Wrong epoch and unknown peer are absences, not errors.
        assert!(ks.key_for_send(PEER, ep(4)).is_none());
        assert!(ks.key_for_receive(PEER, ep(4)).is_none());
        assert!(ks.key_for_send(PEER + 1, ep(3)).is_none());
        assert_eq!(ks.local_id(), LOCAL);
    }

    #[test]
    fn overwrite_same_slot_replaces_material() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        ks.install(PEER, ep(1), &material(0xAA))
            .expect("install old");
        ks.install(PEER, ep(1), &material(0xBB)).expect("overwrite");

        // Asserted: the slot resolves to the NEW material and the store
        // did not grow. By construction (not asserted): the replaced
        // StoredKey was dropped at install time, running memzero +
        // sodium_free over the old bytes.
        let k = ks.key_for_send(PEER, ep(1)).expect("lookup");
        assert!(ct_eq(k.expose(), &material(0xBB)));
        assert_eq!(ks.len(), 1);
    }

    #[test]
    fn two_epochs_for_one_peer_coexist_without_shadowing() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        ks.install(PEER, ep(1), &material(0x01)).expect("old epoch");
        ks.install(PEER, ep(2), &material(0x02)).expect("new epoch");

        // Both live simultaneously — the entire point of epochs (rolling
        // key change with no flag day). Neither shadows the other.
        let old = ks.key_for_receive(PEER, ep(1)).expect("epoch 1");
        assert!(ct_eq(old.expose(), &material(0x01)));
        let new = ks.key_for_receive(PEER, ep(2)).expect("epoch 2");
        assert!(ct_eq(new.expose(), &material(0x02)));
        assert_eq!(ks.len(), 2);
    }

    #[test]
    fn retirement_erases_only_that_epoch() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        ks.install(PEER, ep(1), &material(0x01)).expect("old epoch");
        ks.install(PEER, ep(2), &material(0x02)).expect("new epoch");

        assert!(ks.retire(PEER, ep(1)));
        // Asserted: the retired slot is gone, the surviving epoch is
        // byte-identical, and the store shrank by exactly one. By
        // construction: the removed StoredKey's drop zeroed its guarded
        // allocation before release; the surviving key was never touched.
        assert!(ks.key_for_receive(PEER, ep(1)).is_none());
        let new = ks.key_for_receive(PEER, ep(2)).expect("epoch 2 survives");
        assert!(ct_eq(new.expose(), &material(0x02)));
        assert_eq!(ks.len(), 1);

        // Retiring an absent slot reports false and changes nothing.
        assert!(!ks.retire(PEER, ep(1)));
        assert_eq!(ks.len(), 1);
    }

    #[test]
    fn capacity_bound_is_explicit_and_overwrite_at_capacity_works() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        let mut installed = 0usize;
        for i in 0..MAX_ENTRIES {
            // Distinct slots: peers 0..MAX_ENTRIES under epoch 0.
            match ks.install(i as u16, ep(0), &material(0x5A)) {
                Ok(()) => installed += 1,
                Err(KeystoreError::Sodium(e)) => {
                    // Environment limit (e.g. RLIMIT_MEMLOCK in a locked
                    // down container), not a code defect: a full store
                    // pins ~4 MiB of wired memory. Same skip pattern as
                    // the AES-GCM hardware-availability tests in sodium.rs.
                    eprintln!(
                        "skipping capacity test at {installed} entries: \
                         OS refused more locked memory: {e}"
                    );
                    return;
                }
                Err(other) => panic!("install {i} failed unexpectedly: {other}"),
            }
        }
        assert_eq!(installed, MAX_ENTRIES);
        assert_eq!(ks.len(), MAX_ENTRIES);

        // A NEW slot past the bound is a clear, typed error — never a
        // silent refusal.
        let rc = ks.install(PEER, ep(1), &material(0x99));
        assert_eq!(rc, Err(KeystoreError::Full));
        assert_eq!(ks.len(), MAX_ENTRIES);

        // Overwriting an EXISTING slot at capacity is allowed: it does
        // not grow the store.
        ks.install(0, ep(0), &material(0x77))
            .expect("overwrite at capacity");
        let k = ks.key_for_send(0, ep(0)).expect("lookup");
        assert!(ct_eq(k.expose(), &material(0x77)));
        assert_eq!(ks.len(), MAX_ENTRIES);
    }

    #[test]
    fn send_uses_toid_receive_uses_fromid_with_two_distinct_nodes() {
        // TWO DIFFERENT node ids are essential: with fromId == toId a
        // transposed send/receive lookup returns the SAME slot (loopback
        // decrypts under either), so a same-id test proves nothing.
        // Here the loopback slot (peer == local id) and the peer slot
        // hold DIFFERENT material, so any transposition is visible.
        let mut ks = KeyStore::new(LOCAL).expect("new");
        let peer_key = material(0x0A);
        let loopback_key = material(0x0B);
        ks.install(PEER, ep(7), &peer_key).expect("peer key");
        ks.install(LOCAL, ep(7), &loopback_key)
            .expect("loopback key");

        // Send side: the peer is the frame's toId. Sealing a frame
        // addressed to PEER must yield the PEER link key — not the
        // loopback key, and not nothing.
        let send = ks.key_for_send(PEER, ep(7)).expect("send to peer");
        assert!(ct_eq(send.expose(), &peer_key));
        // Receive side: the peer is the frame's fromId. Opening a frame
        // claiming fromId == PEER must yield the same PEER link key.
        let recv = ks.key_for_receive(PEER, ep(7)).expect("receive from peer");
        assert!(ct_eq(recv.expose(), &peer_key));

        // The two directions agree with each other and DISAGREE with the
        // loopback slot: the store resolves strictly by the id it is
        // given, never silently substituting the local id.
        assert!(ct_eq(send.expose(), recv.expose()));
        assert!(!ct_eq(send.expose(), &loopback_key));

        // And the loopback slot is still resolvable when the peer really
        // is this node (toId == fromId == local id).
        let loop_send = ks.key_for_send(LOCAL, ep(7)).expect("send to self");
        assert!(ct_eq(loop_send.expose(), &loopback_key));
        let loop_recv = ks.key_for_receive(LOCAL, ep(7)).expect("receive from self");
        assert!(ct_eq(loop_recv.expose(), &loopback_key));
    }

    #[test]
    fn send_current_is_the_highest_installed_epoch_and_follows_retirement() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        // Nothing installed: no current send epoch.
        assert!(ks.key_for_send_current(PEER).is_none());

        ks.install(PEER, ep(1), &material(0x01)).expect("epoch 1");
        ks.install(PEER, ep(5), &material(0x05)).expect("epoch 5");
        ks.install(PEER, ep(3), &material(0x03)).expect("epoch 3");

        // Highest wins regardless of installation order, with ITS key.
        let (epoch, key) = ks.key_for_send_current(PEER).expect("current");
        assert_eq!(epoch, ep(5));
        assert!(ct_eq(key.expose(), &material(0x05)));

        // Rotation: install a newer epoch and the sender switches at once.
        ks.install(PEER, ep(6), &material(0x06)).expect("epoch 6");
        let (epoch, _) = ks.key_for_send_current(PEER).expect("current");
        assert_eq!(epoch, ep(6));

        // Retire the newest: the sender falls back to the next-highest.
        assert!(ks.retire(PEER, ep(6)));
        let (epoch, key) = ks.key_for_send_current(PEER).expect("current");
        assert_eq!(epoch, ep(5));
        assert!(ct_eq(key.expose(), &material(0x05)));

        // The lookup is scoped to the peer: another peer's epochs are
        // invisible, and retiring the last epoch returns to None.
        assert!(ks.key_for_send_current(PEER + 1).is_none());
        ks.retire(PEER, ep(1));
        ks.retire(PEER, ep(3));
        ks.retire(PEER, ep(5));
        assert!(ks.key_for_send_current(PEER).is_none());
    }

    #[test]
    fn peer_known_distinguishes_topology_from_rotation() {
        // The split: no entries at all for the peer -> unknown
        // peer; entries under other epochs -> unknown epoch.
        let mut ks = KeyStore::new(LOCAL).expect("new");
        assert!(!ks.peer_known(PEER));
        ks.install(PEER, ep(3), &material(0x01)).expect("install");
        assert!(ks.peer_known(PEER));
        assert!(!ks.peer_known(PEER + 1));
        // Retiring the peer's last epoch makes the peer unknown again.
        assert!(ks.retire(PEER, ep(3)));
        assert!(!ks.peer_known(PEER));
    }

    #[test]
    fn epoch_above_31_is_rejected() {
        assert!(Epoch::new(0).is_ok());
        assert_eq!(Epoch::new(MAX_EPOCH).expect("31").bits(), 31);
        assert_eq!(Epoch::new(32), Err(KeystoreError::InvalidEpoch(32)));
        assert_eq!(Epoch::new(255), Err(KeystoreError::InvalidEpoch(255)));
    }

    #[test]
    fn debug_never_contains_material() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        // 0xAB would show as "ab" in any hex-dumping Debug.
        ks.install(PEER, ep(0), &material(0xAB)).expect("install");
        let k = ks.key_for_send(PEER, ep(0)).expect("lookup");
        // Pinned exact placeholder: redaction cannot silently regress to
        // a derived or formatted dump.
        assert_eq!(format!("{k:?}"), "StoredKey([..; 32])");
    }

    #[test]
    fn clear_erases_everything() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        ks.install(PEER, ep(1), &material(0x01)).expect("a");
        ks.install(PEER, ep(2), &material(0x02)).expect("b");
        ks.install(PEER + 1, ep(1), &material(0x03)).expect("c");
        assert_eq!(ks.len(), 3);

        ks.clear();
        // Asserted: no slot resolves and the store is empty. By
        // construction: every dropped StoredKey was memzero'd and
        // sodium_free'd during the clear.
        assert!(ks.is_empty());
        assert_eq!(ks.len(), 0);
        assert!(ks.key_for_send(PEER, ep(1)).is_none());
        assert!(ks.key_for_receive(PEER + 1, ep(1)).is_none());
    }

    #[test]
    fn expose_yields_a_borrowed_exact_size_slice() {
        let mut ks = KeyStore::new(LOCAL).expect("new");
        let m = material(0x42);
        ks.install(PEER, ep(0), &m).expect("install");
        let k = ks.key_for_send(PEER, ep(0)).expect("lookup");
        // Exact size and content. "Borrowed only, never owned" is a
        // type-level property (the only accessor returns &[u8]; the type
        // is !Copy/!Clone) — stated, like the other by-construction
        // guarantees, rather than directly testable.
        assert_eq!(k.expose().len(), KEYBYTES);
        assert!(ct_eq(k.expose(), &m));
    }
}
