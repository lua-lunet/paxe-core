#!/usr/bin/env bash
# Independent known-answer verification of the PAXE AES-256-GCM vectors.
#
# What this pins that the Rust unit tests CANNOT: that the hex constants in
# src/vectors.rs are the bytes a SECOND, independent AES-256-GCM
# implementation (OpenSSL EVP, via the Python `cryptography` package) produces
# from the same key/nonce/AAD/plaintext — not merely bytes this crate's own
# seal happened to emit. If the AAD layout, the field widths, or the byte
# order drifted, this script would catch it even if the Rust tests still
# passed (a self-consistent-but-wrong crate round-trips its own frames).
#
# It does NOT import, link, or call paxe in any form. The expected hex is
# read straight from src/vectors.rs; the computed bytes come from OpenSSL.
#
# Prerequisites: python3 with the `cryptography` package (pip3 install
# cryptography). On macOS that pulls a bundled OpenSSL; on Debian it uses
# the system libssl.
#
# Exit 0 only if every vector matches byte-for-byte.

set -u
cd "$(dirname "$0")/.."
ROOT=$PWD

python3 - "$ROOT/src/vectors.rs" <<'PYTHON'
import re, sys, sys as _sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VECTORS = _sys.argv[1]
src = open(VECTORS, encoding="utf-8").read()

def grab_hex(name):
    # concat!("...""...") across several string literals — join them.
    block = re.search(rf"const {name}: &str = concat!\((.*?)\);", src, re.S).group(1)
    parts = re.findall(r'"([0-9a-fA-F]*)"', block)
    return bytes.fromhex("".join(parts))

def grab_u16(name):
    return int(re.search(rf"const {name}: u16 = (0x[0-9a-fA-F]+|\d+);", src).group(1), 0)

def grab_u32(name):
    return int(re.search(rf"const {name}: u32 = (0x[0-9a-fA-F]+|\d+);", src).group(1), 0)

def grab_u8(name):
    return int(re.search(rf"const {name}: u8 = (\d+);", src).group(1), 0)

def grab_array(name):
    # Two forms in vectors.rs:
    #   const X: [u8; SOMENAME] = [ 0xA1, 0xB2, ... ];   (explicit list)
    #   const X: [u8; SOMENAME] = [0xE0; SOMENAME];       (repeat form)
    # The size is a const identifier, not a literal, so match [u8; <ident>].
    # The repeat form is distinguished by a ';' inside the brackets.
    m = re.search(rf"const {name}: \[u8; \w+\] = \[(.*?)\];", src, re.S)
    body = m.group(1)
    if ";" in body:
        # repeat form: <fill>; <size-ident>
        fill, size_ident = body.split(";", 1)
        fill = int(fill.strip(), 0)
        size = {"KEYBYTES": 32, "NPUBBYTES": 12}[size_ident.strip()]
        return bytes([fill] * size)
    vals = re.findall(r"0x[0-9a-fA-F]+|\d+", body)
    return bytes(int(v, 0) for v in vals)

# --- constants mirrored from src/vectors.rs (single source of truth) ---
PSK = grab_array("PSK")
FROM = grab_u16("FROM")
TO = grab_u16("TO")
CHANNEL = grab_u32("CHANNEL")          # u32 after the PR
EPOCH = grab_u8("EPOCH")
NONCE = grab_array("NONCE")
V2 = re.search(r'const V2: &\[u8\] = b"([^"]*)";', src).group(1).encode("latin-1")

FANOUT_PAYLOAD = re.search(r'const FANOUT_PAYLOAD: &\[u8\] = b"([^"]*)";', src).group(1).encode("latin-1")
FANOUT_DEK = grab_array("FANOUT_DEK")
FANOUT_BODY_NONCE = grab_array("FANOUT_BODY_NONCE")
# FANOUT_ENVELOPE_NONCES is [[0xB0;12],[0xB1;12]]
ENV_NONCES = [bytes([0xB0]*12), bytes([0xB1]*12)]

# second recipient: 0x0C0E, epoch 8, PSK [0x55;32]
TO2 = 0x0C0E
EPOCH2 = 8
PSK2 = bytes([0x55]*32)

# --- wire constants ---
KEYBYTES = 32
NPUBBYTES = 12
ABYTES = 16
PREFIX_LEN = 9

def flags_byte(mode_dek, epoch):
    # bit0: DEK, bit1: must be 0, bit2: must be 1 (0x04), bits3-7: epoch
    return (0x01 if mode_dek else 0x00) | 0x04 | (epoch << 3)

failures = []

def check(label, got, want):
    if got == want:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")
        print(f"       got  ({len(got)}): {got.hex()}")
        print(f"       want ({len(want)}): {want.hex()}")
        failures.append(label)

# === Standard frame ==================================================
# AAD = the 9-byte prefix: fromId|toId|channel:u32|flags
prefix = (FROM.to_bytes(2, "big") + TO.to_bytes(2, "big")
          + CHANNEL.to_bytes(4, "big") + bytes([flags_byte(False, EPOCH)]))
assert len(prefix) == PREFIX_LEN
ct_tag = AESGCM(PSK).encrypt(NONCE, V2, prefix)
frame = prefix + NONCE + ct_tag
check("standard frame matches V2_FRAME_HEX", frame, grab_hex("V2_FRAME_HEX"))

# === Reusable-DEK fanout (two recipients) ============================
# Body AAD = BE16(fromId) | BE32(channel) | 0x05  (7 bytes), key = DEK
body_aad = FROM.to_bytes(2, "big") + CHANNEL.to_bytes(4, "big") + bytes([0x05])
assert len(body_aad) == 7
body_ct_tag = AESGCM(FANOUT_DEK).encrypt(FANOUT_BODY_NONCE, FANOUT_PAYLOAD, body_aad)
body = FANOUT_BODY_NONCE + body_ct_tag
body_nonce = FANOUT_BODY_NONCE
body_tag = body_ct_tag[-ABYTES:]

recipients = [
    (TO,  EPOCH,  PSK,  ENV_NONCES[0]),
    (TO2, EPOCH2, PSK2, ENV_NONCES[1]),
]
frames = []
for to_id, epoch, psk, env_nonce in recipients:
    pfx = (FROM.to_bytes(2, "big") + to_id.to_bytes(2, "big")
           + CHANNEL.to_bytes(4, "big") + bytes([flags_byte(True, epoch)]))
    assert len(pfx) == PREFIX_LEN
    # Envelope AAD = prefix(9) | body_nonce(12) | body_tag(16) = 37 bytes
    env_aad = pfx + body_nonce + body_tag
    assert len(env_aad) == 37
    enc_dek_tag = AESGCM(psk).encrypt(env_nonce, FANOUT_DEK, env_aad)
    assert len(enc_dek_tag) == KEYBYTES + ABYTES
    frames.append(pfx + env_nonce + enc_dek_tag + body)

check("fanout frame 0 matches FANOUT_FIRST_FRAME_HEX",
      frames[0], grab_hex("FANOUT_FIRST_FRAME_HEX"))
check("fanout frame 1 matches FANOUT_SECOND_FRAME_HEX",
      frames[1], grab_hex("FANOUT_SECOND_FRAME_HEX"))

# Structural invariants the Rust test also asserts.
check("fanout bodies identical from offset 69",
      frames[0][69:], frames[1][69:])
check("fanout prefixes differ before offset 69",
      frames[0][:69] != frames[1][:69], True)

if failures:
    print(f"\nFAIL: {len(failures)} vector(s) mismatched: {failures}")
    _sys.exit(1)
print("\nPASS: all AES-256-GCM vectors match an independent OpenSSL EVP computation")
PYTHON
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "aes_gcm KAT: FAIL" >&2
  exit 1
fi
echo "aes_gcm KAT: PASS"
