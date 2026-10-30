#!/usr/bin/env python3
"""FFI canary: drives the built cdylib's C ABI from an independent
foreign-function client (Python ctypes).

Run behind the ffi-canary feature:

    cargo test --features ffi-canary

The spawner (tests/ffi_canary.rs) builds the cdylib and hands its path
as argv[1]. Every check prints PASS; any mismatch exits nonzero.

The canary deliberately contains no transcribed test vectors: every
frame flows in memory from the ABI's own seal output to its open call,
so a canary failure is a fact about the C ABI itself, never about a
copied constant. Committed-vector fidelity is proven separately by the
in-crate known-answer tests, which produce and open.

Checks:
  init / configure / install                       -> RC_OK
  seal (standard mode) through the ABI             -> RC_OK
  open at the recipient identity                   -> exact payload back
  tampered frame (one flipped ciphertext byte)     -> opaque drop
  frame opened at the wrong local identity         -> opaque drop
  open while unconfigured                          -> opaque drop
  reconfigure without shutdown                     -> RC_INVAL
"""

import ctypes
import sys

RC_OK = 0
RC_INVAL = -2
RC_DROP = -3

U32 = ctypes.c_uint32
SIZE = ctypes.c_size_t

# Synthetic test keys as byte literals — never secrets, never committed
# in any human-readable key format.
KEY = bytes([
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
    0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
    0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8A,
    0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF1, 0x02,
])

NODE_A = 100
NODE_B = 200
EPOCH = 9
CHANNEL = 0x0E0F  # application range; the system reserves 1..=99

PAYLOAD = b"ffi canary round trip payload"

failures = 0


def check(label, condition, detail=""):
    global failures
    if condition:
        print(f"PASS {label}")
    else:
        failures += 1
        print(f"CANARY FAIL: {label} {detail}")


def main():
    if len(sys.argv) != 2:
        print("usage: ffi_canary.py <path-to-cdylib>")
        sys.exit(2)
    lib = ctypes.CDLL(sys.argv[1])

    lib.lunet_paxe_init.restype = ctypes.c_int
    lib.lunet_paxe_set_local_id.argtypes = [U32]
    lib.lunet_paxe_set_local_id.restype = ctypes.c_int
    lib.lunet_paxe_keystore_set.argtypes = [U32, U32, ctypes.c_char_p, SIZE]
    lib.lunet_paxe_keystore_set.restype = ctypes.c_int
    lib.lunet_paxe_seal.argtypes = [
        ctypes.c_char_p, SIZE, U32, U32,
        ctypes.c_char_p, SIZE, ctypes.POINTER(SIZE),
    ]
    lib.lunet_paxe_seal.restype = ctypes.c_int
    lib.lunet_paxe_open.argtypes = [
        ctypes.c_char_p, SIZE, ctypes.c_char_p, SIZE,
        ctypes.POINTER(SIZE), ctypes.POINTER(U32),
        ctypes.POINTER(U32), ctypes.POINTER(U32),
    ]
    lib.lunet_paxe_open.restype = ctypes.c_int
    lib.lunet_paxe_shutdown.argtypes = []
    lib.lunet_paxe_shutdown.restype = ctypes.c_int

    def configure(node, peer, epoch, key):
        rc = lib.lunet_paxe_set_local_id(U32(node))
        check(f"set_local_id({node})", rc == RC_OK, f"rc={rc}")
        rc = lib.lunet_paxe_keystore_set(U32(peer), U32(epoch), key, SIZE(len(key)))
        check(f"keystore_set(peer={peer}, epoch={epoch})", rc == RC_OK, f"rc={rc}")

    check("init", lib.lunet_paxe_init() == RC_OK)

    # Node A seals for node B through the ABI (production seal path).
    configure(NODE_A, NODE_B, EPOCH, KEY)
    out = ctypes.create_string_buffer(len(PAYLOAD) + 128)
    out_len = SIZE()
    rc = lib.lunet_paxe_seal(PAYLOAD, len(PAYLOAD), U32(NODE_B),
                             U32(CHANNEL), out, SIZE(len(out)),
                             ctypes.byref(out_len))
    check("seal (standard mode, through the ABI)", rc == RC_OK, f"rc={rc}")
    frame = out.raw[: out_len.value]
    check("frame carries the payload plus overhead",
          len(frame) == len(PAYLOAD) + 37,  # prefix 9 + nonce 12 + tag 16
          f"len={len(frame)}")

    # Tamper: one flipped byte in the ciphertext must drop opaquely.
    tampered = bytearray(frame)
    tampered[-1] ^= 0x01
    rc = open_rc(lib, bytes(tampered))
    check("tampered frame drops opaquely", rc == RC_DROP, f"rc={rc}")

    # A frame addressed to B, opened while still identifying as A, is
    # the wrong-recipient case: opaque drop, no oracle.
    rc = open_rc(lib, frame)
    check("frame opened at the wrong identity drops opaquely", rc == RC_DROP, f"rc={rc}")

    # Unconfigured open (fresh process state after shutdown) drops.
    check("shutdown", lib.lunet_paxe_shutdown() == RC_OK)
    rc = open_rc(lib, frame)
    check("open while unconfigured drops opaquely", rc == RC_DROP, f"rc={rc}")

    # The round-trip hop: become B, install the link key, open, and
    # recover the exact payload that A sealed.
    configure(NODE_B, NODE_A, EPOCH, KEY)
    out2 = ctypes.create_string_buffer(len(frame))
    out_len2 = SIZE()
    from_id, chan, mode = U32(), U32(), U32()
    rc = lib.lunet_paxe_open(frame, len(frame), out2, len(out2),
                             ctypes.byref(out_len2), ctypes.byref(from_id),
                             ctypes.byref(chan), ctypes.byref(mode))
    check("open at the recipient identity", rc == RC_OK, f"rc={rc}")
    got = out2.raw[: out_len2.value]
    check("payload round-trips exactly", got == PAYLOAD, f"got {got!r}")
    check("from id reports the sender", from_id.value == NODE_A,
          f"got {from_id.value}")
    check("mode reports standard", mode.value == 0, f"got {mode.value}")
    check("channel round-trips", chan.value == CHANNEL, f"got {chan.value}")

    # Reconfigure without shutdown is a named protocol error (RC_INVAL),
    # not a silent reset.
    rc = lib.lunet_paxe_set_local_id(U32(NODE_A))
    check("reconfigure without shutdown is RC_INVAL", rc == RC_INVAL, f"rc={rc}")

    check("final shutdown", lib.lunet_paxe_shutdown() == RC_OK)

    if failures:
        print(f"CANARY RED: {failures} check(s) failed")
        sys.exit(1)
    print("CANARY GREEN: the C ABI round-trips from an independent client")


def open_rc(lib, frame):
    """Open a frame with all output pointers discarded; returns rc only."""
    out = ctypes.create_string_buffer(len(frame))
    return lib.lunet_paxe_open(
        bytes(frame), len(frame), out, len(out),
        ctypes.byref(SIZE()), ctypes.byref(U32()),
        ctypes.byref(U32()), ctypes.byref(U32()))


if __name__ == "__main__":
    main()
