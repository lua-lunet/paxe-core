/* paxe-core C ABI.
 *
 * Sans-io: no sockets, no threads, no runtime, no callbacks. You hand it a
 * payload and get a sealed frame back, or hand it a frame and get a payload.
 * Every call is synchronous and returns a status code; nothing is allocated on
 * your behalf, so every output goes into a buffer you supply.
 *
 * Byte-slice arguments are (ptr, len) pairs and are never retained past the
 * call. Node ids, channels and epochs cross as u32 for LuaJIT's convenience but
 * are range-checked against their real widths (u16, u16, 0-31) on entry.
 *
 * STATE. This layer owns process-global session state: the keystore, the local
 * node identity, the failure policy and the last-error buffer. Key material
 * never crosses this boundary outward. The state is thread-local and the call
 * model is one thread — the LuaJIT VM thread — by construction.
 *
 * PANICS. The library is built panic = "abort" because unwinding through an FFI
 * boundary is undefined behaviour. No input to any function below may panic;
 * that is a hard design rule, not an aspiration.
 */
#ifndef PAXE_H
#define PAXE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. Every entry point returning int returns one of these. */
#define PAXE_OK          0
#define PAXE_OK_ABSENT   1   /* success, but the slot was already empty     */
#define PAXE_ERR       (-1)  /* operation failed; see paxe_last_error       */
#define PAXE_INVAL     (-2)  /* bad argument; see paxe_last_error           */
#define PAXE_DROP      (-3)  /* frame rejected — reason deliberately absent */

/* Mode written to *mode by lunet_paxe_open. */
#define PAXE_MODE_STANDARD 0
#define PAXE_MODE_DEK      1

/* Number of u64 counters lunet_paxe_stats writes. Also returned by calling it
 * with out = NULL, which is the supported way to size the buffer. */
#define PAXE_STATS_FIELDS 13

/* ---- Constants, computed by the codec. Never restate these as literals: they
 * are read from the library precisely so they cannot drift. ---------------- */
uint32_t lunet_paxe_overhead_standard(void);
uint32_t lunet_paxe_overhead_dek(void);
uint32_t lunet_paxe_max_payload_standard(void);
uint32_t lunet_paxe_max_payload_dek(void);

/* Crate version, NUL-terminated and static. */
const char *lunet_paxe_version(void);

/* ---- Lifecycle ---------------------------------------------------------- */

/* Initialise libsodium and assert the AES-256-GCM hardware requirement.
 * Idempotent. Returns PAXE_ERR where the hardware path is unavailable: there is
 * no software fallback, by design. */
int lunet_paxe_init(void);

/* Configure this node's identity. Call ONCE; a second call without an
 * intervening shutdown returns PAXE_ERR rather than silently re-creating the
 * keystore and erasing every installed key. node_id must fit u16. */
int lunet_paxe_set_local_id(uint32_t node_id);

/* Zero and free every key, and forget the local identity. Idempotent. The
 * statistics counters are NOT reset; the log-once memo is. */
void lunet_paxe_shutdown(void);

/* ---- Keys --------------------------------------------------------------- */

/* Install the 32-byte key shared with peer under epoch (0-31). The material is
 * copied into guarded memory during the call and never retained by the caller's
 * pointer. Overwriting an occupied slot erases the old key. */
int lunet_paxe_keystore_set(uint32_t peer, uint32_t epoch,
                            const uint8_t *key, size_t key_len);

/* Retire one (peer, epoch) slot. PAXE_OK if a key was erased,
 * PAXE_OK_ABSENT if the slot was already empty. */
int lunet_paxe_keystore_retire(uint32_t peer, uint32_t epoch);

/* Erase every installed key. A no-op when unconfigured. */
int lunet_paxe_keystore_clear(void);

/* ---- Frames ------------------------------------------------------------- */

/* This C ABI exposes one-recipient standard sealing only. It has no
 * reusable-DEK fanout sealer. It can still open a reusable-DEK frame received
 * from a Rust host, and the reusable-DEK constants above describe that format. */

/* Seal payload for to_id on channel as a standard frame. The epoch is the
 * NEWEST installed for to_id, so
 * installing a new epoch switches senders to it. channel must fit u16 and must
 * not fall in the reserved system range 1-99; channel 0 is permitted.
 *
 * out must have room for payload_len + 37 bytes; the frame length actually
 * written goes to *out_len. */
int lunet_paxe_seal(const uint8_t *payload, size_t payload_len,
                    uint32_t to_id, uint32_t channel,
                    uint8_t *out, size_t out_cap, size_t *out_len);

/* Open one received frame. On PAXE_OK the payload is in out, its length in
 * *out_len, and the AUTHENTICATED sender, channel and mode in *from_id,
 * *channel and *mode.
 *
 * On ANY failure — malformed, unknown peer, unknown epoch, authentication —
 * returns PAXE_DROP and writes nothing, including nothing to the last-error
 * buffer. The reason is never surfaced: a caller that could distinguish these
 * is a decryption oracle. Diagnose with lunet_paxe_stats deltas instead.
 *
 * out need be no larger than frame_len; a payload is always shorter than the
 * frame carrying it. */
int lunet_paxe_open(const uint8_t *frame, size_t frame_len,
                    uint8_t *out, size_t out_cap, size_t *out_len,
                    uint32_t *from_id, uint32_t *channel, uint32_t *mode);

/* Cheap pre-filter: is this frame addressed to the configured local id? Reads
 * the plaintext header only and authenticates NOTHING — a frame passing this
 * may still be rejected by lunet_paxe_open, and a hostile sender can set any
 * toId it likes. Use it to skip work, never to make a trust decision.
 *
 * NOTE the return values are NOT status codes: 1 means "addressed to us" and 0
 * means "not ours, already counted as a plaintext drop". A null pointer still
 * returns PAXE_INVAL, so test for 1 rather than for non-zero. */
#define PAXE_FRAME_FOR_US     1
#define PAXE_FRAME_NOT_FOR_US 0
int lunet_paxe_frame_for_us(const uint8_t *frame, size_t frame_len);

/* ---- Diagnostics -------------------------------------------------------- */

/* Write PAXE_STATS_FIELDS cumulative counters into out and return the count.
 * Call with out = NULL and out_cap = 0 to learn the count without writing.
 *
 * Counters NEVER reset while the process lives — measure DELTAS. The invariant
 * rx_total == rx_ok + sum(the seven rx_ reject reasons) holds at every point.
 * Field order is pinned by a test and matches the loader's field list. */
uint32_t lunet_paxe_stats(uint64_t *out, size_t out_cap);

/* Select the drop logging policy: "silent" (default), "log_once" or "verbose".
 * Returns PAXE_INVAL for an unknown spelling. */
int lunet_paxe_fail_policy_set(const uint8_t *name, size_t name_len);

/* The message for the last PAXE_ERR or PAXE_INVAL, with its length written to
 * *len. NOT NUL-terminated — use the length. Returns NULL when there is no
 * message. Never written by a PAXE_DROP. The buffer belongs to the library and
 * is valid until the next failing call on this thread. */
const uint8_t *lunet_paxe_last_error(size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* PAXE_H */
