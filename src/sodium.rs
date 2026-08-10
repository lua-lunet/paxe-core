//! The libsodium FFI boundary — the single most safety-critical module in
//! the crate.
//!
//! Containment rule: **this is the only module in the
//! crate that may contain an `extern "C"` block, declare `unsafe`, or call
//! libsodium.** Everything else consumes the safe wrappers below as
//! ordinary safe Rust, which keeps the audit surface for "is the FFI
//! correct" to this one file. The crate root enforces the unsafe half of
//! that rule with `#![deny(unsafe_code)]`.
//!
//! Every extern declaration carries its contract — buffer sizes, aliasing
//! and in-place rules, return-value meaning, failure modes — taken from
//! libsodium's documentation (doc.libsodium.org).
//!
//! Wrapper discipline:
//! - No caller ever touches a raw pointer: keys, nonces and tags are
//!   fixed-size newtypes, buffers are slices (pointer + length derived
//!   from the slice so they cannot disagree).
//! - No wrapper can panic: every length is checked before the FFI call,
//!   all arithmetic on untrusted lengths uses `checked_*`, and no
//!   `unwrap`/`expect`/indexing appears outside `#[cfg(test)]`. With
//!   `panic = "abort"` a panic would kill the LuaJIT host process.
//! - AES-GCM unavailability is a first-class, reportable error, never a
//!   panic and never a silent substitution of another cipher (which would
//!   break wire compatibility).

// The crate root sets `#![deny(unsafe_code)]`; this module is the sole,
// deliberate exception.
#![allow(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::os::raw::{c_char, c_int, c_uchar, c_ulonglong, c_void};
use std::ptr::NonNull;

/// AES-256-GCM key size in bytes, per libsodium.
pub const KEYBYTES: usize = 32;
/// AES-256-GCM public nonce size in bytes, per libsodium.
pub const NPUBBYTES: usize = 12;
/// AES-256-GCM authentication tag size in bytes, per libsodium.
pub const ABYTES: usize = 16;

// ---------------------------------------------------------------------------
// Raw extern declarations. Private: nothing outside this module can name
// them. Every declaration states its contract.
// ---------------------------------------------------------------------------

mod ffi {
    use super::{c_char, c_int, c_uchar, c_ulonglong, c_void};

    extern "C" {
        /// CONTRACT (libsodium docs, "Initialization"):
        /// Returns the library version string (e.g. "1.0.21").
        pub fn sodium_version_string() -> *const c_char;

        /// Initialises the library: seeds the CSPRNG, probes CPU features,
        /// sets up the guarded-heap canary. MUST run before any other
        /// libsodium function.
        ///
        /// THREE outcomes, and conflating them is a bug:
        ///   0  — fresh success;
        ///   1  — the library was ALREADY initialised (still success);
        ///  -1  — failure.
        /// Thread-safe and safe to call repeatedly; later calls return 1.
        pub fn sodium_init() -> c_int;

        /// CONTRACT (libsodium docs, "AES-256-GCM"):
        /// Returns 1 if this libsodium build can use the hardware AES-GCM
        /// implementation on this CPU (AES-NI + PCLMULQDQ on x86_64; ARMv8
        /// crypto extensions on aarch64), 0 otherwise.
        ///
        /// 0 happens on real platforms: Debian trixie arm64 ships a
        /// libsodium built WITHOUT the ARM crypto-extension path even on
        /// CPUs that expose it (documented in docker/gate.sh). Callers
        /// MUST surface 0 as an error the operator can see — never panic
        /// (panic = abort kills the LuaJIT host) and never silently fall
        /// back to a different cipher (that breaks wire compatibility).
        pub fn crypto_aead_aes256gcm_is_available() -> c_int;

        /// CONTRACT: sizes reported by the LINKED library (32 / 12 / 16 in
        /// every libsodium that has AES-GCM). Exposed as functions
        /// precisely so ABI drift is detectable at runtime; the startup
        /// check compares them against our compile-time constants and a
        /// mismatch is a hard error, not a buffer overflow.
        pub fn crypto_aead_aes256gcm_keybytes() -> usize;
        pub fn crypto_aead_aes256gcm_npubbytes() -> usize;
        pub fn crypto_aead_aes256gcm_abytes() -> usize;

        /// CONTRACT (libsodium docs, "AES-256-GCM / Combined mode"):
        /// Encrypts `m[0..mlen)` under key `k[32]` and public nonce
        /// `npub[12]`, authenticating `ad[0..adlen)` alongside. Writes
        /// ciphertext followed by the 16-byte tag into `c`, i.e. exactly
        /// `mlen + 16` bytes; `c` must have room for them.
        ///
        /// - `clen_p` (may be NULL) receives the actual ciphertext length,
        ///   `mlen + crypto_aead_aes256gcm_abytes()`.
        /// - `nsec` is unused by this construction and MUST be NULL.
        /// - IN-PLACE ALIASING: `c` and `m` may point to the same buffer
        ///   (in-place encryption is supported).
        /// - Returns 0. Encryption performs no verification, so it has no
        ///   failure mode; a non-zero return is undocumented. The wrapper
        ///   checks it anyway (defensive, maps to an internal error) so no
        ///   wrapper ever needs to panic.
        pub fn crypto_aead_aes256gcm_encrypt(
            c: *mut c_uchar,
            clen_p: *mut c_ulonglong,
            m: *const c_uchar,
            mlen: c_ulonglong,
            ad: *const c_uchar,
            adlen: c_ulonglong,
            nsec: *const c_uchar,
            npub: *const c_uchar,
            k: *const c_uchar,
        ) -> c_int;

        /// CONTRACT (libsodium docs, "AES-256-GCM / Combined mode"):
        /// Verifies the tag and decrypts `c[0..clen)` (where
        /// `clen = plaintext_len + 16`) under `npub[12]` / `k[32]`,
        /// authenticating `ad[0..adlen)`. Writes `clen - 16` plaintext
        /// bytes into `m`; `m` must have room for them.
        ///
        /// - `mlen_p` (may be NULL) receives the actual plaintext length.
        /// - RETURN VALUE IS THE AUTHENTICATION VERDICT: 0 on success,
        ///   -1 if the tag does not verify (wrong key, wrong nonce, wrong
        ///   AAD, or corrupted ciphertext). On -1, `*mlen_p` is set to 0
        ///   and the contents of `m` are unspecified — the wrapper wipes
        ///   the would-be plaintext region with `sodium_memzero` before
        ///   reporting the failure, so unverified plaintext can never
        ///   escape to a caller.
        /// - `clen < 16` is INVALID INPUT, not an auth failure; the
        ///   wrapper rejects it before this function is ever called.
        /// - `nsec` is unused and MUST be NULL.
        /// - IN-PLACE ALIASING: `m` and `c` may point to the same buffer.
        pub fn crypto_aead_aes256gcm_decrypt(
            m: *mut c_uchar,
            mlen_p: *mut c_ulonglong,
            nsec: *mut c_uchar,
            c: *const c_uchar,
            clen: c_ulonglong,
            ad: *const c_uchar,
            adlen: c_ulonglong,
            npub: *const c_uchar,
            k: *const c_uchar,
        ) -> c_int;

        /// CONTRACT (libsodium docs, "Generating random data"):
        /// Fills `buf[0..size)` with unpredictable bytes from the system
        /// CSPRNG (seeded at `sodium_init`, reseeded as required). Cannot
        /// fail (void return).
        ///
        /// This is the ONLY permitted randomness source for nonces and
        /// DEKs. GCM nonce reuse under one key is catastrophic, so: never
        /// a counter alone, never `rand()`, never a timestamp.
        pub fn randombytes_buf(buf: *mut c_void, size: usize);

        /// CONTRACT (libsodium docs, "Secure memory / Guarded heap"):
        /// Returns a guarded heap allocation of `size` bytes: the region
        /// sits between inaccessible guard pages, carries a canary that
        /// `sodium_free` verifies, and its pages are `mlock`ed where the
        /// OS allows. mlock keeps pages out of SWAP on every supported
        /// platform; exclusion from CORE DUMPS is Linux-only
        /// (`MADV_DONTDUMP` — Darwin has no equivalent; see
        /// `disable_core_dumps`).
        ///
        /// - Returns NULL on failure — including RLIMIT_MEMLOCK exhaustion
        ///   from the implicit mlock, so failure is an OS-limit condition
        ///   the caller must handle, not corruption.
        /// - `size == 0` is permitted and returns a unique freeable
        ///   pointer. Contents are unspecified (NOT promised zeroed).
        /// - The pointer must ONLY be released with `sodium_free`.
        pub fn sodium_malloc(size: usize) -> *mut c_void;

        /// CONTRACT: releases a `sodium_malloc` allocation: verifies the
        /// canary (aborting on heap corruption), zeroes the region,
        /// munlocks the pages, then frees them. NULL-safe. Calling it on a
        /// pointer from any other allocator is undefined behaviour.
        pub fn sodium_free(ptr: *mut c_void);

        /// CONTRACT (libsodium docs, "Secure memory / Locking"):
        /// Pins `addr[0..len)` in RAM (rounded to whole pages): the pages
        /// cannot be swapped out. On Linux libsodium additionally sets
        /// `MADV_DONTDUMP`, excluding the pages from core dumps; on
        /// Darwin it CANNOT because no equivalent mechanism exists;
        /// `disable_core_dumps` closes that gap process-wide.
        /// Returns 0, or -1 on failure — typically ENOMEM when
        /// RLIMIT_MEMLOCK is exhausted. Failure is an OS-limit condition,
        /// not corruption; the caller decides policy.
        pub fn sodium_mlock(addr: *mut c_void, len: usize) -> c_int;

        /// CONTRACT: FIRST zeroes `addr[0..len)` with `sodium_memzero`,
        /// THEN unlocks the pages. Returns 0 or -1. The erase-then-unlock
        /// ordering is libsodium's own and is the reason to call this
        /// rather than open-coding unlock + memzero.
        pub fn sodium_munlock(addr: *mut c_void, len: usize) -> c_int;

        /// CONTRACT (libsodium docs, "Secure memory / Zeroing"):
        /// Writes zeroes over `pnt[0..len)` in a way the compiler cannot
        /// optimise away (SecureZeroMemory / explicit_bzero / memset_s /
        /// an explicit memory barrier, per platform). Use for every secret
        /// at end of life; plain `fill(0)` on a Rust slice may legally be
        /// elided by LLVM when the buffer is dead afterwards.
        pub fn sodium_memzero(pnt: *mut c_void, len: usize);

        /// CONTRACT (libsodium docs, "Helpers / Comparing"):
        /// Constant-time comparison of `b1_[0..len)` with `b2_[0..len)`:
        /// returns 0 iff equal, -1 otherwise, with runtime independent of
        /// where the first difference is.
        ///
        /// Declared so that ANY secret-dependent equality check (tags,
        /// keys) uses it. `==` on secret bytes is a timing side channel;
        /// this exists so nobody reaches for `==` later.
        pub fn sodium_memcmp(b1_: *const c_void, b2_: *const c_void, len: usize) -> c_int;

        /// CONTRACT (ISO C, `stdlib.h`): registers `cb` to run at NORMAL
        /// process termination (return from `main` / `exit()`), in
        /// reverse registration order. Returns 0 on success, non-zero on
        /// failure (glibc: ENOMEM). Not called on `abort()`/`SIGKILL` —
        /// there is no hookable path there for anyone.
        ///
        /// This is libc, not libsodium: declared here because this module
        /// is the crate's sole `extern "C"` containment boundary,
        /// and runtime-owned key erasure at process exit needs
        /// it. The callback must not touch Rust thread-locals through
        /// panicking accessors — they may already be destroyed (see
        /// lib.rs `shutdown_state`, which uses `try_with`).
        pub fn atexit(cb: extern "C" fn()) -> c_int;

        /// CONTRACT (POSIX.1-2008, `<sys/resource.h>`): fetch the soft
        /// (`rlim_cur`) and hard (`rlim_max`) limits for `resource` into
        /// `*rlim`. Returns 0 on success, -1 with errno set on failure —
        /// practically unreachable for a valid resource constant and a
        /// valid out-pointer.
        ///
        /// This is libc, not libsodium: declared here because this module
        /// is the crate's sole `extern "C"` containment boundary,
        /// and startup core-dump suppression needs it. The
        /// declarations are Unix-only; the wrappers below are cfg-gated
        /// the same way and carry a no-op stub elsewhere.
        #[cfg(all(unix, target_pointer_width = "64"))]
        pub fn getrlimit(resource: c_int, rlim: *mut super::RLimit) -> c_int;

        /// CONTRACT (POSIX.1-2008, `<sys/resource.h>`): install the limits
        /// for `resource` from `*rlim`. Returns 0 on success, -1 with
        /// errno set on failure. EPERM happens only when RAISING the hard
        /// limit as an unprivileged process — this crate never does that:
        /// the hard limit is read back with `getrlimit` and passed through
        /// unchanged, and only the soft limit moves, strictly downward.
        #[cfg(all(unix, target_pointer_width = "64"))]
        pub fn setrlimit(resource: c_int, rlim: *const super::RLimit) -> c_int;
    }

    // kernel32, not libsodium: declared here because this module is the
    // crate's sole extern containment boundary, and the Windows
    // page-locking budget below needs them. `extern "system"` is the
    // Win32 calling convention (stdcall on x86, identical to "C"
    // elsewhere); `HANDLE` is an opaque pointer and `BOOL` is a 32-bit
    // int that is zero on failure.
    #[cfg(windows)]
    extern "system" {
        /// CONTRACT (Win32, processthreadsapi.h): returns the PSEUDO
        /// handle for the calling process. It is not a real handle: it
        /// needs no `CloseHandle`, it can never fail, and it carries full
        /// access rights, so `PROCESS_SET_QUOTA` (what
        /// `SetProcessWorkingSetSize` requires) is always present.
        pub fn GetCurrentProcess() -> *mut c_void;

        /// CONTRACT (Win32, memoryapi.h): writes the process's current
        /// minimum and maximum working-set sizes, in BYTES, through the
        /// two out-pointers. Returns 0 on failure (`GetLastError` set),
        /// non-zero on success.
        pub fn GetProcessWorkingSetSize(
            process: *mut c_void,
            minimum: *mut usize,
            maximum: *mut usize,
        ) -> c_int;

        /// CONTRACT (Win32, memoryapi.h): sets the process's minimum and
        /// maximum working-set sizes, in BYTES. Returns 0 on failure
        /// (`GetLastError` set), non-zero on success. The minimum is the
        /// quota `VirtualLock` draws its locked pages from — raising it
        /// is the documented way to lock more than the default handful of
        /// pages. Failure is possible (the caller may lack
        /// SE_INC_WORKING_SET_NAME) and is never fatal here.
        pub fn SetProcessWorkingSetSize(
            process: *mut c_void,
            minimum: usize,
            maximum: usize,
        ) -> c_int;
    }
}

// ---------------------------------------------------------------------------
// Windows page-locking budget.
//
// On Unix the mlock budget is RLIMIT_MEMLOCK, which is generous enough for
// per-link keys and is a system-administration matter when it is not. On
// Windows libsodium's `sodium_mlock` is `VirtualLock`, whose budget is the
// process MINIMUM WORKING SET — 200KB by default, i.e. roughly 48 lockable
// pages for the WHOLE process, and each guarded key allocation costs one.
// Microsoft's documented remedy is exactly this: "Applications that need to
// lock larger numbers of pages must first call the SetProcessWorkingSetSize
// function to increase their minimum and maximum working set sizes"
// (learn.microsoft.com, VirtualLock).
//
// Growing lazily on the specific quota error rather than eagerly at init
// keeps the default-sized process untouched until a lock actually needs the
// room, and keeps the fix correct no matter which entry point allocated the
// first key (the unit tests never call `lunet_paxe_init`).
// ---------------------------------------------------------------------------

/// Raise the process working set so `VirtualLock` has quota for `len` more
/// bytes, and report whether the caller should retry the lock.
///
/// Returns false — leaving the working set untouched — unless the most
/// recent OS error is one of the two quota refusals, so an mlock that
/// failed for any other reason never silently inflates the process, and
/// false once cumulative growth reaches the ceiling, so a pathological
/// caller cannot grow the working set without bound.
#[cfg(windows)]
fn grow_locked_page_budget(len: usize) -> bool {
    /// `ERROR_WORKING_SET_QUOTA`: "Insufficient quota to complete the
    /// requested service" — what `VirtualLock` reports when the minimum
    /// working set has no room left for another locked page.
    const ERROR_WORKING_SET_QUOTA: i32 = 1453;
    /// `ERROR_NOT_ENOUGH_QUOTA`: the other quota spelling Windows uses for
    /// the same refusal. Both mean "raise the working set"; neither means
    /// the region or the caller is wrong.
    const ERROR_NOT_ENOUGH_QUOTA: i32 = 1816;
    /// Headroom added per growth, on top of the failing request: 8MiB is
    /// 2048 pages, far more per-link keys than any node holds, so in
    /// practice this runs once for the lifetime of the process.
    const HEADROOM: usize = 8 * 1024 * 1024;
    /// Ceiling on CUMULATIVE growth across all calls.
    const MAX_TOTAL: usize = 64 * 1024 * 1024;

    // Must be read before any other Win32 call: `sodium_mlock` maps
    // straight onto `VirtualLock`, so the thread's last error is still
    // the one the failed lock set.
    match std::io::Error::last_os_error().raw_os_error() {
        Some(ERROR_WORKING_SET_QUOTA) | Some(ERROR_NOT_ENOUGH_QUOTA) => {}
        _ => return false,
    }

    /// Bytes of growth already requested. Serialises concurrent growth so
    /// two threads cannot both read the same working-set size and have
    /// one of the two increments silently lost.
    static GRANTED: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
    // A poisoned mutex means another thread panicked mid-growth; the
    // counter is still a plain integer with no broken invariant, so
    // recover rather than propagate (a panic here would abort the host).
    let mut granted = match GRANTED.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let step = len.saturating_add(HEADROOM);
    let total = granted.saturating_add(step);
    if total > MAX_TOTAL {
        return false;
    }

    let mut minimum: usize = 0;
    let mut maximum: usize = 0;
    // SAFETY: both out-pointers address live, aligned `usize`s owned by
    // this frame, and the pseudo handle is always valid.
    let queried = unsafe {
        ffi::GetProcessWorkingSetSize(ffi::GetCurrentProcess(), &mut minimum, &mut maximum)
    };
    if queried == 0 {
        return false;
    }
    let new_minimum = minimum.saturating_add(step);
    // The maximum must never sit below the minimum, or the call is
    // rejected outright.
    let new_maximum = maximum.saturating_add(step).max(new_minimum);
    // SAFETY: the pseudo handle is always valid and both sizes are plain
    // by-value integers.
    if unsafe { ffi::SetProcessWorkingSetSize(ffi::GetCurrentProcess(), new_minimum, new_maximum) }
        == 0
    {
        return false;
    }

    *granted = total;
    true
}

// ---------------------------------------------------------------------------
// Process core-dump suppression. Unix-only: RLIMIT_CORE is POSIX;
// Windows crash dumps (WER) are a different mechanism outside this crate's
// scope, where `disable_core_dumps` below is a no-op stub.
// ---------------------------------------------------------------------------

/// `RLIMIT_CORE` — the maximum core-file-size resource. The value is 4 on
/// BOTH Linux and Darwin (and the BSDs): stable across every Unix this
/// crate targets.
#[cfg(all(unix, target_pointer_width = "64"))]
const RLIMIT_CORE: c_int = 4;

/// POSIX `struct rlimit`. `rlim_t` is `unsigned long` on Linux and
/// `uint64_t` on Darwin — 64 bits on every supported target either way,
/// hence the fixed `u64` fields and the 64-bit cfg gate.
#[cfg(all(unix, target_pointer_width = "64"))]
#[repr(C)]
struct RLimit {
    /// The soft limit: the value the kernel actually enforces.
    rlim_cur: u64,
    /// The hard limit: the ceiling to which the soft limit may be raised.
    rlim_max: u64,
}

/// Register `cb` to run at normal process termination. The runtime, not a
/// script, owns key erasure at exit. Best-effort by
/// contract: a registration failure (practically unreachable — glibc
/// ENOMEM) is ignored; the thread-local destructor remains active on
/// platforms that run it for the main thread.
/// Failing `init` over it would punish every platform for one platform's
/// deficiency. Registered ONCE by the caller (an atomic guard); multiple
/// registrations would still be harmless because the shutdown they run is
/// idempotent.
///
/// The cdylib must never be dlclosed after registration (a dangling
/// handler would crash the exiting process); the LuaJIT FFI loader holds
/// the library for the process lifetime, so this cannot happen in
/// practice.
pub fn register_exit_hook(cb: extern "C" fn()) {
    // SAFETY: `cb` is a valid function pointer with the exact ABI atexit
    // requires; atexit itself is thread-safe per POSIX. The return value
    // is deliberately discarded per the best-effort contract above.
    unsafe {
        ffi::atexit(cb);
    }
}

/// Disable core dumps for the ENTIRE process: set the `RLIMIT_CORE` soft
/// limit to 0 so the kernel writes no core file on any fatal signal —
/// SIGABRT included, which is the `panic = "abort"` crash shape. This is
/// the strongest available guarantee that keystore material can never
/// reach disk through a crash. Linux also excludes locked guarded pages
/// with `MADV_DONTDUMP`; macOS has no page-level equivalent. With
/// `RLIMIT_CORE` set to zero there is no core file, so no page can disclose
/// material through one.
///
/// The hard limit is read back with `getrlimit` and passed through
/// unchanged: lowering it would be irreversible for an unprivileged
/// process and is deliberately not done, so the documented debugging
/// opt-out (`LUNET_PAXE_ALLOW_CORE_DUMPS=1`, checked by the caller in
/// lib.rs) keeps the inherited limit intact instead of having to raise
/// anything back.
///
/// Scope honesty: rlimits are process-wide and this crate is a cdylib in
/// the lunet-run host. That is sound because loading PAXE is itself the
/// opt-in — a process only ever calls `lunet_paxe_init` by an explicit
/// `require("lunet.paxe")`, i.e. exactly when it starts holding cluster
/// key material, and a process holding cluster keys must not dump cores
/// by default. A host that never loads PAXE is untouched.
///
/// Failure is reported, never panicked on (practically unreachable:
/// lowering the soft limit cannot EPERM). The caller warns loudly rather
/// than failing init — the same best-effort philosophy as the `atexit`
/// registration above.
#[cfg(all(unix, target_pointer_width = "64"))]
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    let mut current = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `current` is valid, aligned space for one struct rlimit and
    // RLIMIT_CORE is a valid resource constant.
    if unsafe { ffi::getrlimit(RLIMIT_CORE, &mut current) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let requested = RLimit {
        rlim_cur: 0,
        rlim_max: current.rlim_max,
    };
    // SAFETY: `requested` is a valid struct rlimit; only the soft limit
    // changes, and strictly downward, so an unprivileged caller cannot
    // hit EPERM.
    if unsafe { ffi::setrlimit(RLIMIT_CORE, &requested) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The non-Unix / non-64-bit stub: no `RLIMIT_CORE` mechanism exists to
/// suppress there (Windows crash dumps are WER, outside this crate's
/// scope), so suppression is trivially "done".
#[cfg(not(all(unix, target_pointer_width = "64")))]
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors. Everything a caller can act on is a variant here; no wrapper
// panics.
// ---------------------------------------------------------------------------

/// Every failure the FFI boundary can report. Callers match on this; none
/// of these conditions ever abort the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SodiumError {
    /// `sodium_init()` returned -1.
    InitFailed,
    /// The linked libsodium reports a size that disagrees with our
    /// compile-time constant: (item, ours, libsodium's). An ABI mismatch
    /// surfaced as a clear error instead of a buffer overflow.
    AbiMismatch(&'static str, usize, usize),
    /// `crypto_aead_aes256gcm_is_available()` returned 0: this CPU or
    /// this libsodium build lacks the hardware AES-GCM path (e.g. Debian
    /// trixie arm64; see docker/gate.sh). Reportable — never a panic,
    /// never a silent cipher substitution.
    AesGcmUnavailable,
    /// AEAD tag verification failed: wrong key, nonce or AAD, or a
    /// corrupted/forged ciphertext. The output buffer was wiped.
    AuthFailed,
    /// A length precondition was violated (output buffer too small, or a
    /// ciphertext shorter than one tag). Rejected before any FFI call.
    InvalidLength,
    /// `sodium_malloc` returned NULL (allocation failure or
    /// RLIMIT_MEMLOCK exhaustion from the implicit mlock).
    AllocFailed,
    /// `sodium_mlock` failed (typically RLIMIT_MEMLOCK).
    MlockFailed,
    /// `sodium_munlock` failed.
    MunlockFailed,
    /// libsodium returned a value its documentation says cannot happen.
    /// Kept so no wrapper ever has to panic on the impossible.
    Internal,
}

impl fmt::Display for SodiumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SodiumError::InitFailed => write!(f, "sodium_init failed"),
            SodiumError::AbiMismatch(what, ours, theirs) => write!(
                f,
                "libsodium ABI mismatch on {what}: crate constant {ours}, linked library reports {theirs}"
            ),
            SodiumError::AesGcmUnavailable => write!(
                f,
                "AES-256-GCM unavailable: no hardware crypto path in this libsodium build/CPU"
            ),
            SodiumError::AuthFailed => write!(f, "authentication failed"),
            SodiumError::InvalidLength => write!(f, "invalid buffer length"),
            SodiumError::AllocFailed => write!(f, "guarded allocation failed"),
            SodiumError::MlockFailed => write!(f, "sodium_mlock failed"),
            SodiumError::MunlockFailed => write!(f, "sodium_munlock failed"),
            SodiumError::Internal => write!(f, "impossible libsodium result"),
        }
    }
}

impl Error for SodiumError {}

// ---------------------------------------------------------------------------
// Fixed-size secret/parameter types. Distinct newtypes over distinct array
// sizes: a 12-byte nonce cannot be passed where a 32-byte key is expected,
// and the transposition simply does not compile. PartialEq is deliberately
// NOT derived on any of these: secret equality goes through `ct_eq`.
// ---------------------------------------------------------------------------

macro_rules! fixed_bytes {
    ($(#[$meta:meta])* $name:ident, $n:expr) => {
        $(#[$meta])*
        // repr(transparent): layout-identical to the wrapped array, which is
        // what makes Key::from_borrowed (below) a sound reinterpretation.
        #[repr(transparent)]
        #[derive(Clone)]
        pub struct $name([u8; $n]);

        impl $name {
            /// Wrap an exactly-sized array. The size is in the type, so no
            /// length check can be forgotten and none can fail.
            pub fn from_bytes(bytes: [u8; $n]) -> Self {
                $name(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; $n] {
                &self.0
            }

            pub fn as_mut_bytes(&mut self) -> &mut [u8; $n] {
                &mut self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Never print secret/parameter bytes into a log.
                write!(f, "{}([..; {}])", stringify!($name), $n)
            }
        }
    };
}

fixed_bytes! {
    /// A 32-byte AES-256-GCM secret key.
    Key, KEYBYTES
}
fixed_bytes! {
    /// A 12-byte nonce. Fresh from the CSPRNG per use; never reused under
    /// the same key.
    Nonce, NPUBBYTES
}
fixed_bytes! {
    /// A 16-byte AEAD authentication tag.
    Tag, ABYTES
}

impl Key {
    /// Borrow an exactly-sized byte array as a `Key` WITHOUT copying it.
    ///
    /// A `StoredKey` exposes its
    /// guarded material only as a borrowed `&[u8]`, and the seal/open paths
    /// must feed that material to the AEAD wrappers directly
    /// from the guarded allocation. The only other constructor,
    /// [`Key::from_bytes`], takes an owned array — forcing a 32-byte
    /// unguarded stack copy of the link key on every datagram, which is
    /// precisely the leak the keystore's type discipline exists to prevent.
    ///
    /// The returned reference borrows `bytes`, so it can never outlive the
    /// guarded allocation it points into.
    ///
    /// SAFETY: `Key` is `repr(transparent)` over `[u8; KEYBYTES]` — same
    /// size, same alignment, and every bit pattern is valid — so
    /// reinterpreting the reference is layout-exact and sound.
    pub fn from_borrowed(bytes: &[u8; KEYBYTES]) -> &Key {
        unsafe { &*(bytes as *const [u8; KEYBYTES] as *const Key) }
    }
}

// ---------------------------------------------------------------------------
// Initialisation, ABI check, availability.
// ---------------------------------------------------------------------------

/// The two non-failure outcomes of `sodium_init`, kept distinct because
/// callers and logs care about the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitStatus {
    /// First initialisation of the process (return 0).
    Fresh,
    /// Library was already initialised (return 1). Still success.
    AlreadyInitialised,
}

/// Initialise libsodium. Must run before any other wrapper. Distinguishes
/// all three documented outcomes; failure is `Err(InitFailed)`, never a
/// panic.
pub fn init() -> Result<InitStatus, SodiumError> {
    match unsafe { ffi::sodium_init() } {
        0 => Ok(InitStatus::Fresh),
        1 => Ok(InitStatus::AlreadyInitialised),
        _ => Err(SodiumError::InitFailed),
    }
}

/// Return the linked libsodium version string (e.g. "1.0.21").
/// Must be called after `init()`. Never fails — libsodium 1.0.0+ always
/// provides this symbol.
pub fn version_string() -> &'static str {
    let ptr = unsafe { ffi::sodium_version_string() };
    if ptr.is_null() {
        return "(unknown)";
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or("(non-UTF-8 version string)")
}

/// Startup ABI check: compare our compile-time KEY/NPUB/ABYTE sizes
/// against what the LINKED library reports. A mismatch is a clear error
/// here instead of a buffer overflow later. Cheap; call once at startup
/// after `init`.
pub fn check_sizes() -> Result<(), SodiumError> {
    let checks: [(&'static str, usize, usize); 3] = [
        ("KEYBYTES", KEYBYTES, unsafe {
            ffi::crypto_aead_aes256gcm_keybytes()
        }),
        ("NPUBBYTES", NPUBBYTES, unsafe {
            ffi::crypto_aead_aes256gcm_npubbytes()
        }),
        ("ABYTES", ABYTES, unsafe {
            ffi::crypto_aead_aes256gcm_abytes()
        }),
    ];
    for (name, ours, theirs) in checks {
        if ours != theirs {
            return Err(SodiumError::AbiMismatch(name, ours, theirs));
        }
    }
    Ok(())
}

/// Is the hardware AES-256-GCM path usable? Pure probe, no side effects.
pub fn aes_gcm_available() -> bool {
    unsafe { ffi::crypto_aead_aes256gcm_is_available() == 1 }
}

/// Require the hardware AES-256-GCM path. Unavailability is a first-class
/// reportable error — the caller decides what to do (refuse to enable
/// PAXE, surface it to the operator). Never panics, never substitutes a
/// weaker cipher.
pub fn require_aes_gcm() -> Result<(), SodiumError> {
    if aes_gcm_available() {
        Ok(())
    } else {
        Err(SodiumError::AesGcmUnavailable)
    }
}

// ---------------------------------------------------------------------------
// AEAD seal / open. nsec is always NULL inside these wrappers (the
// construction does not use a secret nonce), so no caller can get it wrong.
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `key`/`nonce`, authenticating `aad`, into
/// `out`, which must be at least `plaintext.len() + ABYTES` bytes. Returns
/// the number of bytes written — exactly `plaintext.len() + ABYTES`.
///
/// Does NOT check hardware availability: call `require_aes_gcm()` at
/// startup; per-datagram availability checks would just cost cycles.
pub fn aead_encrypt(
    key: &Key,
    nonce: &Nonce,
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, SodiumError> {
    let needed = match plaintext.len().checked_add(ABYTES) {
        Some(n) => n,
        None => return Err(SodiumError::InvalidLength),
    };
    if out.len() < needed {
        return Err(SodiumError::InvalidLength);
    }
    let mut written: c_ulonglong = 0;
    let rc = unsafe {
        ffi::crypto_aead_aes256gcm_encrypt(
            out.as_mut_ptr(),
            &mut written,
            plaintext.as_ptr(),
            plaintext.len() as c_ulonglong,
            aad.as_ptr(),
            aad.len() as c_ulonglong,
            std::ptr::null(),
            nonce.0.as_ptr(),
            key.0.as_ptr(),
        )
    };
    if rc != 0 || written != needed as c_ulonglong {
        // Undocumented per the contract comment; mapped, never panicked.
        return Err(SodiumError::Internal);
    }
    Ok(needed)
}

/// Verify and decrypt `ciphertext` (plaintext + 16-byte tag) under
/// `key`/`nonce`, authenticating `aad`, into `out`, which must be at least
/// `ciphertext.len() - ABYTES` bytes. Returns the plaintext length.
///
/// On tag mismatch the would-be plaintext region of `out` is wiped with
/// `sodium_memzero` and `AuthFailed` is returned: unverified plaintext
/// never escapes this wrapper.
pub fn aead_decrypt(
    key: &Key,
    nonce: &Nonce,
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, SodiumError> {
    let plen = match ciphertext.len().checked_sub(ABYTES) {
        Some(n) => n,
        // Shorter than one tag: invalid input, NOT an auth failure.
        None => return Err(SodiumError::InvalidLength),
    };
    if out.len() < plen {
        return Err(SodiumError::InvalidLength);
    }
    let mut written: c_ulonglong = 0;
    let rc = unsafe {
        ffi::crypto_aead_aes256gcm_decrypt(
            out.as_mut_ptr(),
            &mut written,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            aad.as_ptr(),
            aad.len() as c_ulonglong,
            nonce.0.as_ptr(),
            key.0.as_ptr(),
        )
    };
    if rc != 0 {
        // Tag mismatch: do not let unverified plaintext leak. `out` holds
        // at least plen bytes (checked above), so this wipe is in bounds.
        memzero(&mut out[..plen]);
        return Err(SodiumError::AuthFailed);
    }
    if written != plen as c_ulonglong {
        return Err(SodiumError::Internal);
    }
    Ok(plen)
}

// Randomness. CSPRNG only — never any other source.
// ---------------------------------------------------------------------------

/// Fill `buf` with CSPRNG bytes. The only randomness source in the crate.
pub fn randombytes_fill(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    unsafe { ffi::randombytes_buf(buf.as_mut_ptr() as *mut c_void, buf.len()) };
}

/// A fresh 32-byte key (e.g. a per-datagram DEK) from the CSPRNG.
pub fn random_key() -> Key {
    let mut k = Key([0u8; KEYBYTES]);
    randombytes_fill(k.as_mut_bytes());
    k
}

/// The dedicated nonce generator: a fresh 12-byte nonce that can ONLY
/// come from the CSPRNG. "Always CSPRNG, never reuse" is enforced and
/// reviewed in this one place.
pub fn random_nonce() -> Nonce {
    let mut n = Nonce([0u8; NPUBBYTES]);
    randombytes_fill(n.as_mut_bytes());
    n
}

// ---------------------------------------------------------------------------
// Secure memory.
// ---------------------------------------------------------------------------

/// A guarded, canaried, page-locked heap allocation owned by libsodium.
/// Callers see slices, never the raw pointer; drop returns the memory to
/// libsodium, which verifies the canary, zeroes, unlocks and frees.
pub struct GuardedAllocation {
    ptr: NonNull<u8>,
    len: usize,
}

impl GuardedAllocation {
    /// Allocate `len` guarded bytes via `sodium_malloc`. `len == 0` is
    /// allowed (libsodium returns a unique freeable pointer). Failure —
    /// including RLIMIT_MEMLOCK exhaustion from the implicit mlock — is
    /// `Err(AllocFailed)`, never a panic. Contents are unspecified.
    pub fn new(len: usize) -> Result<Self, SodiumError> {
        let raw = unsafe { ffi::sodium_malloc(len) } as *mut u8;
        match NonNull::new(raw) {
            Some(ptr) => Ok(GuardedAllocation { ptr, len }),
            None => Err(SodiumError::AllocFailed),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// View the allocation as a slice. The pointer is valid for `len`
    /// bytes for the lifetime of `&self` by construction (only `Drop`
    /// releases it), so this is sound.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for GuardedAllocation {
    fn drop(&mut self) {
        // Verifies the canary, zeroes, munlocks, frees. Never panics.
        unsafe { ffi::sodium_free(self.ptr.as_ptr() as *mut c_void) };
    }
}

/// Pin the pages backing `buf` in RAM: not swappable on any platform;
/// excluded from core dumps on LINUX only (`MADV_DONTDUMP` — Darwin has
/// no equivalent; core-dump suppression there is `disable_core_dumps`).
/// Failure (typically RLIMIT_MEMLOCK) is reported, never
/// panicked on; the caller decides policy.
///
/// On Windows the budget is not an rlimit but the process minimum working
/// set (200KB by default — about 48 locked pages for the whole process,
/// one per guarded key), so a quota refusal there is retried ONCE after
/// [`grow_locked_page_budget`] raises that budget. A lock that still
/// fails, or fails for any other reason, is reported unchanged: locking
/// is never downgraded to best-effort, because the pages staying out of
/// swap is the guarantee the keystore is built on.
pub fn mlock(buf: &mut [u8]) -> Result<(), SodiumError> {
    if buf.is_empty() {
        return Ok(());
    }
    if try_mlock(buf) {
        return Ok(());
    }
    #[cfg(windows)]
    if grow_locked_page_budget(buf.len()) && try_mlock(buf) {
        return Ok(());
    }
    Err(SodiumError::MlockFailed)
}

/// One `sodium_mlock` attempt: true on success. Split out so the Windows
/// retry above locks the same region through exactly the same call.
fn try_mlock(buf: &mut [u8]) -> bool {
    unsafe { ffi::sodium_mlock(buf.as_mut_ptr() as *mut c_void, buf.len()) == 0 }
}

/// Zero `buf` and then unlock its pages (libsodium's erase-then-unlock
/// ordering).
pub fn munlock(buf: &mut [u8]) -> Result<(), SodiumError> {
    if buf.is_empty() {
        return Ok(());
    }
    match unsafe { ffi::sodium_munlock(buf.as_mut_ptr() as *mut c_void, buf.len()) } {
        0 => Ok(()),
        _ => Err(SodiumError::MunlockFailed),
    }
}

/// Erase `buf` with zeros the optimiser cannot elide. Use for every
/// secret at end of life.
pub fn memzero(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    unsafe { ffi::sodium_memzero(buf.as_mut_ptr() as *mut c_void, buf.len()) };
}

/// Constant-time equality over equal-length slices. Length mismatch
/// returns false without calling into libsodium (that leaks only the
/// length, which for fixed-size tags is public). Use this for ANY
/// secret-dependent comparison; never `==` on secret bytes.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.is_empty() {
        return true;
    }
    unsafe {
        ffi::sodium_memcmp(
            a.as_ptr() as *const c_void,
            b.as_ptr() as *const c_void,
            a.len(),
        ) == 0
    }
}

// ---------------------------------------------------------------------------
// Tests. Panicking asserts are fine here: test code never ships in the
// cdylib.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn key_zero() -> Key {
        Key::from_bytes([0u8; KEYBYTES])
    }

    fn nonce_zero() -> Nonce {
        Nonce::from_bytes([0u8; NPUBBYTES])
    }

    #[test]
    fn init_distinguishes_three_outcomes_and_never_fails_twice() {
        // Tests run in parallel threads, so either success outcome is
        // acceptable on any given call — but never failure, and a second
        // call must also succeed.
        let first = init().expect("sodium_init failed");
        assert!(matches!(
            first,
            InitStatus::Fresh | InitStatus::AlreadyInitialised
        ));
        let second = init().expect("second sodium_init failed");
        assert!(matches!(
            second,
            InitStatus::Fresh | InitStatus::AlreadyInitialised
        ));
    }

    #[test]
    fn compile_time_sizes_match_linked_library() {
        init().expect("init");
        check_sizes().expect("ABI mismatch against linked libsodium");
        assert_eq!(KEYBYTES, 32);
        assert_eq!(NPUBBYTES, 12);
        assert_eq!(ABYTES, 16);
    }

    #[test]
    fn aes_gcm_availability_is_reportable_never_panics() {
        init().expect("init");
        match require_aes_gcm() {
            Ok(()) => assert!(aes_gcm_available()),
            Err(SodiumError::AesGcmUnavailable) => assert!(!aes_gcm_available()),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    /// NIST GCMVS / McGrew-Viega known answers for the zero key, zero
    /// nonce: these pin the FFI argument order and buffer semantics — the
    /// classic extern-signature hazards a compiler cannot catch.
    #[test]
    fn aes_gcm_known_answer_zero_key() {
        init().expect("init");
        if !aes_gcm_available() {
            eprintln!("skipping AES-GCM KAT: hardware path unavailable");
            return;
        }
        let key = key_zero();
        let nonce = nonce_zero();

        // Case 1: empty plaintext, empty AAD -> 16-byte tag.
        let expected_tag = [
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
            0x73, 0x8b,
        ];
        let mut out = [0u8; ABYTES];
        let n = aead_encrypt(&key, &nonce, &[], &[], &mut out).expect("encrypt empty");
        assert_eq!(n, ABYTES);
        assert!(ct_eq(&out, &expected_tag));

        // Case 2: 16 zero bytes -> known ciphertext + tag.
        let expected_ct = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18,
        ];
        let expected_tag2 = [
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
            0xb9, 0x19,
        ];
        let pt = [0u8; 16];
        let mut out2 = [0u8; 32];
        let n2 = aead_encrypt(&key, &nonce, &[], &pt, &mut out2).expect("encrypt block");
        assert_eq!(n2, 32);
        assert!(ct_eq(&out2[..16], &expected_ct));
        assert!(ct_eq(&out2[16..], &expected_tag2));

        // And both round-trip.
        let mut back = [0u8; 16];
        let m = aead_decrypt(&key, &nonce, &[], &out2, &mut back).expect("decrypt");
        assert_eq!(m, 16);
        assert!(ct_eq(&back, &pt));
        let mut back1 = [];
        let m1 = aead_decrypt(&key, &nonce, &[], &out, &mut back1).expect("decrypt empty");
        assert_eq!(m1, 0);
    }

    #[test]
    fn aead_roundtrip_with_aad_and_tamper_detection() {
        init().expect("init");
        if !aes_gcm_available() {
            eprintln!("skipping AEAD roundtrip: hardware path unavailable");
            return;
        }
        let key = random_key();
        let nonce = random_nonce();
        let aad = b"paxe header+flags";
        let pt = b"datagram payload, longer than a tag";
        let mut ct = [0u8; 64];
        let clen = aead_encrypt(&key, &nonce, aad, pt, &mut ct).expect("encrypt");
        assert_eq!(clen, pt.len() + ABYTES);

        let mut back = [0u8; 64];
        let plen = aead_decrypt(&key, &nonce, aad, &ct[..clen], &mut back).expect("decrypt");
        assert_eq!(plen, pt.len());
        assert!(ct_eq(&back[..plen], pt));

        // Flip a ciphertext bit: must be AuthFailed, and the output
        // buffer must be wiped (it was pre-filled with 0xAA).
        let mut forged = ct;
        forged[0] ^= 0x01;
        let mut scratch = [0xAAu8; 64];
        let rc = aead_decrypt(&key, &nonce, aad, &forged[..clen], &mut scratch);
        assert_eq!(rc, Err(SodiumError::AuthFailed));
        assert!(scratch[..pt.len()].iter().all(|&b| b == 0));

        // Wrong AAD must also fail authentication.
        let rc2 = aead_decrypt(&key, &nonce, b"wrong", &ct[..clen], &mut back);
        assert_eq!(rc2, Err(SodiumError::AuthFailed));
    }

    #[test]
    fn aead_length_violations_are_rejected_before_ffi() {
        init().expect("init");
        if !aes_gcm_available() {
            return;
        }
        let key = key_zero();
        let nonce = nonce_zero();
        // Output buffer one byte short.
        let mut small = [0u8; ABYTES];
        assert_eq!(
            aead_encrypt(&key, &nonce, &[], &[1u8], &mut small),
            Err(SodiumError::InvalidLength)
        );
        // Ciphertext shorter than a tag is invalid input, not AuthFailed.
        let mut out = [0u8; 16];
        assert_eq!(
            aead_decrypt(&key, &nonce, &[], &[0u8; ABYTES - 1], &mut out),
            Err(SodiumError::InvalidLength)
        );
        // Decrypt output buffer too small.
        let ct = [0u8; ABYTES + 8];
        let mut tiny = [0u8; 4];
        assert_eq!(
            aead_decrypt(&key, &nonce, &[], &ct, &mut tiny),
            Err(SodiumError::InvalidLength)
        );
    }

    #[test]
    fn randomness_comes_from_the_csprng() {
        init().expect("init");
        let n1 = random_nonce();
        let n2 = random_nonce();
        assert!(
            !ct_eq(n1.as_bytes(), n2.as_bytes()),
            "two CSPRNG nonces colliding is a 2^-96 event"
        );
        let k = random_key();
        assert!(!ct_eq(k.as_bytes(), &[0u8; KEYBYTES]));
        let mut buf = [0u8; 64];
        randombytes_fill(&mut buf);
        assert!(!ct_eq(&buf, &[0u8; 64]));
        randombytes_fill(&mut []); // no call, no panic
    }

    #[test]
    fn guarded_allocation_roundtrip_and_drop() {
        init().expect("init");
        {
            let mut g = GuardedAllocation::new(64).expect("sodium_malloc");
            assert_eq!(g.len(), 64);
            assert!(!g.is_empty());
            for (i, b) in g.as_mut_slice().iter_mut().enumerate() {
                *b = i as u8;
            }
            assert_eq!(g.as_slice()[17], 17);
            assert_eq!(g.as_slice().len(), 64);
        } // drop: canary check + zero + munlock + free inside libsodium

        // Zero-length allocation is a valid, freeable pointer.
        let z = GuardedAllocation::new(0).expect("sodium_malloc(0)");
        assert!(z.is_empty());
    }

    #[test]
    fn mlock_then_munlock_zeroes_the_region() {
        init().expect("init");
        let mut g = GuardedAllocation::new(32).expect("alloc");
        for b in g.as_mut_slice().iter_mut() {
            *b = 0x5A;
        }
        mlock(g.as_mut_slice()).expect("mlock");
        munlock(g.as_mut_slice()).expect("munlock");
        // Contract: munlock zeroes BEFORE unlocking.
        assert!(g.as_slice().iter().all(|&b| b == 0));
        mlock(&mut []).expect("empty mlock is a no-op");
        munlock(&mut []).expect("empty munlock is a no-op");
    }

    /// Windows-only regression pin: `VirtualLock` draws from the process
    /// MINIMUM WORKING SET, 200KB (about 48 pages) by default, and every
    /// guarded key costs a page — so a node with a few dozen live per-link
    /// keys used to hit `ERROR_WORKING_SET_QUOTA` and report `MlockFailed`
    /// even though nothing was wrong with the key or the allocation. This
    /// holds 128 key-sized guarded regions locked AT ONCE, comfortably past
    /// the default quota, which fails without the working-set growth in
    /// `mlock`. Not run on Unix: there the budget is RLIMIT_MEMLOCK, which
    /// is as low as 64KiB in some containers, so the same assertion would
    /// pin an environment limit rather than this crate's behaviour.
    #[cfg(windows)]
    #[test]
    fn many_locked_keys_outlast_the_default_windows_quota() {
        init().expect("init");
        let mut held = Vec::new();
        for i in 0..128 {
            let mut g = GuardedAllocation::new(KEYBYTES).expect("alloc");
            mlock(g.as_mut_slice()).unwrap_or_else(|e| panic!("mlock #{i}: {e:?}"));
            held.push(g);
        }
        for g in held.iter_mut() {
            munlock(g.as_mut_slice()).expect("munlock");
        }
    }

    #[test]
    fn memzero_erases() {
        init().expect("init");
        let mut buf = [0xA5u8; 48];
        memzero(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
        memzero(&mut []); // no call, no panic
    }

    #[test]
    fn ct_eq_semantics() {
        init().expect("init");
        assert!(ct_eq(b"same", b"same"));
        assert!(!ct_eq(b"same", b"diff"));
        assert!(!ct_eq(b"short", b"longer"));
        assert!(ct_eq(&[], &[]));
    }

    /// The wrapper must move ONLY the soft limit, to exactly 0,
    /// and pass the inherited hard limit through untouched (raising or
    /// lowering the hard limit would both be defects: EPERM / irreversible
    /// lock-in). Runs once per process; the effect is process-wide, which
    /// is the behaviour under test.
    #[test]
    #[cfg(all(unix, target_pointer_width = "64"))]
    fn disable_core_dumps_zeroes_soft_limit_and_preserves_hard() {
        let mut before = RLimit {
            rlim_cur: u64::MAX,
            rlim_max: u64::MAX,
        };
        assert_eq!(unsafe { ffi::getrlimit(RLIMIT_CORE, &mut before) }, 0);

        disable_core_dumps().expect("lowering the soft limit cannot fail");

        let mut after = RLimit {
            rlim_cur: u64::MAX,
            rlim_max: 0,
        };
        assert_eq!(unsafe { ffi::getrlimit(RLIMIT_CORE, &mut after) }, 0);
        assert_eq!(after.rlim_cur, 0, "soft limit must be exactly 0");
        assert_eq!(
            after.rlim_max, before.rlim_max,
            "hard limit must pass through unchanged"
        );
        // Idempotent: a second call (every lunet_paxe_init calls this) is
        // a successful no-op.
        disable_core_dumps().expect("re-disable is a no-op");
    }
}
