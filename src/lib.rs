//! # lunet-paxe
//!
//! PAXE datagram encryption for lunet, built as a `cdylib` and loaded at
//! runtime by the `lunet.paxe` Lua module through the LuaJIT FFI. It is a
//! pure opt-in extension and is never linked into `lunet-run`.
//!
//! The crate contains the libsodium boundary ([`sodium`]), guarded
//! per-peer key storage ([`keystore`]), total header/flags parsing
//! ([`codec`]), standard and DEK frame protection ([`standard`], [`dek`]),
//! opaque rejection statistics ([`stats`]), and the Lua-facing C ABI.
//! [`lunet_paxe_frame_for_us`] is the protected-socket plaintext and
//! addressing gate. [`lunet_paxe_init`] registers process-exit key erasure
//! and disables core dumps by default; `LUNET_PAXE_ALLOW_CORE_DUMPS=1` is
//! the documented debugging opt-out.
//!
//! ## The C ABI
//!
//! All module state (the keystore, i.e. ALL key material) lives behind
//! the FFI in thread-local storage; Lua never holds keys except
//! transiently when passing one into `lunet_paxe_keystore_set` (the
//! VM-transit limitation documented in PAXE.md). Buffers cross as
//! (pointer, length); ids and epochs cross as u32 so out-of-range values
//! are representable and rejected with a named constraint rather than
//! silently truncated. Return codes:
//!
//! - `RC_OK` (0): success.
//! - `RC_OK_ABSENT` (1): success, but the addressed slot did not exist
//!   (keystore_retire of an absent `(peer, epoch)`).
//! - `RC_ERR` (-1): OPERATIONAL failure. The message is in the
//!   last-error buffer; `paxe.lua` returns `nil, message`.
//! - `RC_INVAL` (-2): MALFORMED ARGUMENT — a bug in the calling script.
//!   The message (naming the constraint) is in the last-error buffer;
//!   `paxe.lua` RAISES it as a Lua error.
//! - `RC_DROP` (-3): `open` rejected the frame. EVERY frame-level
//!   failure — parse, unknown key, authentication, even an unconfigured
//!   keystore — collapses to this ONE opaque outcome, and the typed
//!   in-crate reason is never written to the last-error buffer: a
//!   receiver that explains why a forgery failed is a decryption oracle
//!   (PAXE.md "Failure Handling"). The typed reason is recorded into the
//!   counters at the reject point, BEFORE the collapse (see
//!   [`stats`]); it never crosses the FFI.
//!
//! ## Dependency policy: zero crates
//!
//! This crate has **no** crate dependencies — not even `libc`. All
//! cryptography and all secure-memory handling comes from libsodium via
//! hand-written `extern "C"` declarations in [`sodium`], **statically
//! linked into this cdylib** by `build.rs`:
//! `sodium_malloc` / `sodium_mlock` / `sodium_memzero` provide guarded,
//! locked, reliably-zeroed key storage, which is exactly where
//! sysadmin-injected shared cluster keys belong.
//!
//! ## NO PANIC ON ANY INPUT — hard constraint
//!
//! The release profile sets `panic = "abort"`, because unwinding across an
//! FFI boundary into LuaJIT is undefined behaviour. The consequence is
//! absolute: **any Rust panic aborts the entire LuaJIT host process**,
//! taking down every coroutine, socket and connection it serves. A panic
//! must therefore be *impossible* on any input, not merely unlikely:
//!
//! - No indexing, slicing or arithmetic on attacker-controlled datagram
//!   bytes that can panic: no `buf[i]`, no `a + b` on untrusted lengths, no
//!   `unwrap`/`expect` on anything derived from the wire.
//! - Use `get()`, `chunks_exact()`, checked arithmetic and explicit error
//!   returns instead.
//! - Every `extern "C"` entry point validates every pointer and length
//!   before use.
//!
//! All parsing and FFI paths are designed around this totality requirement.
//!
//! ## FFI containment
//!
//! [`sodium`] is the ONLY module in this crate that may contain an
//! `extern "C"` block or call libsodium, and the only module with a
//! module-level `unsafe` allowance (enforced below by
//! `#![deny(unsafe_code)]`). The exported symbols in THIS file
//! carry per-function `#[allow(unsafe_code)]` for the LuaJIT-facing
//! pointer glue (raw pointer ⇄ slice conversion at the trust boundary) —
//! the same per-symbol pattern [`lunet_paxe_version`] established. Every
//! export validates every pointer and length before any unsafe block
//! runs. [`sodium`] declares the libsodium primitives by hand
//! — zero crate dependencies, not even `libc` — each with its contract
//! written at the declaration, and exposes safe wrappers: fixed-size
//! key/nonce/tag newtypes, slice-derived pointer+length pairs, a startup
//! ABI size check, CSPRNG-only nonce generation, guarded allocations, and
//! AES-GCM unavailability as a reportable error. libsodium is statically
//! linked into this cdylib by `build.rs`.

// Every module except sodium.rs is plain safe Rust; unsafe is denied here
// and re-allowed by inner attribute inside sodium.rs alone.
#![deny(unsafe_code)]

pub mod codec;
pub mod dek;
pub mod keystore;
pub mod sodium;
pub mod standard;
pub mod stats;
// Known-answer vectors exist ONLY in test builds: the whole
// module is test code pinned against the #[cfg(test)] deterministic
// seams, so it is compiled out of every non-test build by construction.
#[cfg(test)]
mod vectors;

// The C ABI, on by default. Private: nothing in-crate calls it, and Rust
// consumers use the modules above. The exported symbols are
// `#[no_mangle] extern "C"`, so they land in the cdylib regardless of
// module visibility.
//
// It is a FEATURE because a host that exports its own `lunet_paxe_*` ABI —
// lunet's `ext/paxe` does, to keep its `liblunet_paxe` artifact name — would
// otherwise collide with these symbols at link time ("symbol multiply
// defined"). Such a host builds with `default-features = false` and links
// the modules above directly. Everyone else, including crates.io consumers
// and this crate's own cdylib, gets the ABI without asking.
#[cfg(feature = "ffi")]
mod ffi;
