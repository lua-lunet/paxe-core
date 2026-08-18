#!/usr/bin/env python3
"""Generate the PAXE AES-256-GCM known-answer vector fixture.

Computes the standard and reusable-DEK fanout frames INDEPENDENTLY of the
paxe crate, using AES-256-GCM from the Python `cryptography` package (OpenSSL
EVP under the hood), and writes them to tests/aes_gcm_vectors.json as a
machine-readable fixture. The Rust integration test `tests/kat_from_json.rs`
loads that fixture, re-runs the crate's own deterministic seal seams with the
same inputs, and asserts byte-for-byte equality.

This makes the KAT repeatable without making anyone repeat it by hand: the
fixture is checked in, and regeneration is one `make` target away (see
tests/README.md). The generator never imports or calls paxe; it only reads
the input constants from src/vectors.rs so there is a single source of
truth for the key/nonce/AAD/plaintext.

Usage:
    python3 tests/gen_aes_gcm_vectors.py [src/vectors.rs] [tests/aes_gcm_vectors.json]
"""
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VECTORS_RS = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "src" / "vectors.rs"
OUT_JSON = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "aes_gcm_vectors.json"

src = VECTORS_RS.read_text(encoding="utf-8")


def grab_hex(name: str) -> bytes:
    block = re.search(rf"const {name}: &str = concat!\((.*?)\);", src, re.S).group(1)
    parts = re.findall(r'"([0-9a-fA-F]*)"', block)
    return bytes.fromhex("".join(parts))


def grab_u16(name: str) -> int:
    return int(re.search(rf"const {name}: u16 = (0x[0-9a-fA-F]+|\d+);", src).group(1), 0)


def grab_u32(name: str) -> int:
    return int(re.search(rf"const {name}: u32 = (0x[0-9a-fA-F]+|\d+);", src).group(1), 0)


def grab_u8(name: str) -> int:
    return int(re.search(rf"const {name}: u8 = (\d+);", src).group(1), 0)


def grab_array(name: str) -> bytes:
    # Two forms: explicit list, or [0xVV; SIZE_IDENT].
    m = re.search(rf"const {name}: \[u8; \w+\] = \[(.*?)\];", src, re.S)
    body = m.group(1)
    if ";" in body:
        fill, size_ident = body.split(";", 1)
        size = {"KEYBYTES": 32, "NPUBBYTES": 12}[size_ident.strip()]
        return bytes([int(fill.strip(), 0)] * size)
    vals = re.findall(r"0x[0-9a-fA-F]+|\d+", body)
    return bytes(int(v, 0) for v in vals)


def grab_bytes_literal(name: str) -> bytes:
    m = re.search(rf'const {name}: &\[u8\] = b"([^"]*)";', src)
    return m.group(1).encode("latin-1")


# --- inputs (single source of truth: src/vectors.rs) ---
PSK = grab_array("PSK")
FROM = grab_u16("FROM")
TO = grab_u16("TO")
CHANNEL = grab_u32("CHANNEL")
EPOCH = grab_u8("EPOCH")
NONCE = grab_array("NONCE")
V2 = grab_bytes_literal("V2")

FANOUT_PAYLOAD = grab_bytes_literal("FANOUT_PAYLOAD")
FANOUT_DEK = grab_array("FANOUT_DEK")
FANOUT_BODY_NONCE = grab_array("FANOUT_BODY_NONCE")
ENV_NONCES = [bytes([0xB0] * 12), bytes([0xB1] * 12)]

# Second recipient for the fanout vector (from the Rust test).
TO2 = 0x0C0E
EPOCH2 = 8
PSK2 = bytes([0x55] * 32)

ABYTES = 16
PREFIX_LEN = 9


def flags_byte(mode_dek: bool, epoch: int) -> int:
    return (0x01 if mode_dek else 0x00) | 0x04 | (epoch << 3)


def h(b: bytes) -> str:
    return b.hex()


# === Standard frame ==================================================
# AAD = 9-byte prefix: fromId|toId|channel:u32|flags
std_prefix = (
    FROM.to_bytes(2, "big")
    + TO.to_bytes(2, "big")
    + CHANNEL.to_bytes(4, "big")
    + bytes([flags_byte(False, EPOCH)])
)
assert len(std_prefix) == PREFIX_LEN
std_ct_tag = AESGCM(PSK).encrypt(NONCE, V2, std_prefix)
std_frame = std_prefix + NONCE + std_ct_tag

# === Reusable-DEK fanout (two recipients) ============================
# Body AAD = BE16(fromId) | BE32(channel) | 0x05  (7 bytes), key = DEK
body_aad = FROM.to_bytes(2, "big") + CHANNEL.to_bytes(4, "big") + bytes([0x05])
assert len(body_aad) == 7
body_ct_tag = AESGCM(FANOUT_DEK).encrypt(FANOUT_BODY_NONCE, FANOUT_PAYLOAD, body_aad)
body = FANOUT_BODY_NONCE + body_ct_tag
body_nonce = FANOUT_BODY_NONCE
body_tag = body_ct_tag[-ABYTES:]

recipients = [
    (TO, EPOCH, PSK, ENV_NONCES[0]),
    (TO2, EPOCH2, PSK2, ENV_NONCES[1]),
]
fanout_frames = []
for to_id, epoch, psk, env_nonce in recipients:
    pfx = (
        FROM.to_bytes(2, "big")
        + to_id.to_bytes(2, "big")
        + CHANNEL.to_bytes(4, "big")
        + bytes([flags_byte(True, epoch)])
    )
    assert len(pfx) == PREFIX_LEN
    env_aad = pfx + body_nonce + body_tag
    assert len(env_aad) == 37
    enc_dek_tag = AESGCM(psk).encrypt(env_nonce, FANOUT_DEK, env_aad)
    assert len(enc_dek_tag) == 32 + ABYTES
    fanout_frames.append(pfx + env_nonce + enc_dek_tag + body)

fixture = {
    "schema": 1,
    "generator": "tests/gen_aes_gcm_vectors.py (independent OpenSSL EVP via Python cryptography)",
    "note": "Expected frames are computed by an independent AES-256-GCM implementation, not by the paxe crate. The Rust test loads this file and checks the crate's own output against it.",
    "standard": {
        "psk_hex": h(PSK),
        "from_id": FROM,
        "to_id": TO,
        "channel": CHANNEL,
        "epoch": EPOCH,
        "nonce_hex": h(NONCE),
        "plaintext_hex": h(V2),
        "aad_hex": h(std_prefix),
        "frame_hex": h(std_frame),
    },
    "fanout": {
        "from_id": FROM,
        "channel": CHANNEL,
        "payload_hex": h(FANOUT_PAYLOAD),
        "dek_hex": h(FANOUT_DEK),
        "body_nonce_hex": h(FANOUT_BODY_NONCE),
        "body_aad_hex": h(body_aad),
        "recipients": [
            {
                "to_id": to_id,
                "epoch": epoch,
                "psk_hex": h(psk),
                "envelope_nonce_hex": h(env_nonce),
                "frame_hex": h(frame),
            }
            for (to_id, epoch, psk, env_nonce), frame in zip(recipients, fanout_frames)
        ],
    },
}

OUT_JSON.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
print(f"wrote {OUT_JSON}")
print(f"  standard frame: {len(std_frame)} bytes")
print(f"  fanout frames:   {[len(f) for f in fanout_frames]} bytes")
