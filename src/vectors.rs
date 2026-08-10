//! Fixed-input vectors for PAXE frames.
//!
//! Deterministic seams are test-only. They keep the production API free of
//! caller-selected key or nonce material while pinning wire bytes in tests.
//!
//! Provenance: expected bytes were produced by the independent OpenSSL EVP
//! helper in `.tmp/vector-generation/aes_gcm.c`. Before deriving these frames,
//! that helper reproduced NIST SP 800-38D's AES-256-GCM zero-key, zero-IV,
//! one-block vector (`cea7403d…`, tag `d0d1c8a7…`). The helper takes explicit
//! key, nonce, AAD, and plaintext hex; it does not call this crate.

#![cfg(test)]

use crate::dek;
use crate::keystore::{Epoch, KeyStore};
use crate::sodium::{self, KEYBYTES, NPUBBYTES};
use crate::standard;

const PSK: [u8; KEYBYTES] = [
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
    0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8A, 0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF1, 0x02,
];
const FROM: u16 = 0x0A0B;
const TO: u16 = 0x0C0D;
const CHANNEL: u16 = 0x0E0F;
const EPOCH: u8 = 9;
const NONCE: [u8; NPUBBYTES] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
];
const V2: &[u8] = b"paxe vector v2: standard short payload";
const V2_FRAME_HEX: &str = concat!(
    "0a0b0c0d0e0f00264cc0c1c2c3c4c5c6",
    "c7c8c9cacb11e08e8e015385ddbc7e77",
    "1d411ecffe2a26717d89c5bc800ee4e3",
    "3262fe2f6d78a58b8a02e2df006dacb1",
    "c29f486e281c8629c07438"
);
const FANOUT_PAYLOAD: &[u8] = b"fixed reusable-DEK vector";
const FANOUT_DEK: [u8; KEYBYTES] = [0xE0; KEYBYTES];
const FANOUT_BODY_NONCE: [u8; NPUBBYTES] = [0xD0; NPUBBYTES];
const FANOUT_ENVELOPE_NONCES: [[u8; NPUBBYTES]; 2] = [[0xB0; NPUBBYTES], [0xB1; NPUBBYTES]];
const FANOUT_FIRST_FRAME_HEX: &str = concat!(
    "0a0b0c0d0e0f00194db0b0b0b0b0b0b0b0b0b0b0b0",
    "c665b11725373b2d9daf03c359fb50ae3cc278c30626f74b0f7b18a58e3adf15",
    "9a76fa93aa7be62374da6ae0424c00ee",
    "d0d0d0d0d0d0d0d0d0d0d0d0",
    "5187e7d3f6791322348227884ecce454c12d780f76a3e7020e",
    "9eef0b426b666a549efd00e0b39b1498"
);
const FANOUT_SECOND_FRAME_HEX: &str = concat!(
    "0a0b0c0e0e0f001945b1b1b1b1b1b1b1b1b1b1b1b1",
    "73e405815863bcfc7997415ba535082c35316fd14fa1a3011d2102dc8589fa80",
    "4b0af213316738de2ba30b20407169dd",
    "d0d0d0d0d0d0d0d0d0d0d0d0",
    "5187e7d3f6791322348227884ecce454c12d780f76a3e7020e",
    "9eef0b426b666a549efd00e0b39b1498"
);

fn ep(value: u8) -> Epoch {
    Epoch::new(value).expect("epoch")
}
fn gcm() -> bool {
    sodium::init().is_ok() && sodium::aes_gcm_available()
}
fn store() -> KeyStore {
    let mut store = KeyStore::new(FROM).expect("store");
    store.install(TO, ep(EPOCH), &PSK).expect("install");
    store
}
fn unhex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex");
            let low = (pair[1] as char).to_digit(16).expect("hex");
            ((high << 4) | low) as u8
        })
        .collect()
}

#[test]
fn standard_known_answer_vector_is_exact() {
    if !gcm() {
        return;
    }
    let frame = standard::seal_standard_deterministic(&store(), TO, CHANNEL, ep(EPOCH), V2, NONCE)
        .expect("seal");
    assert_eq!(frame, unhex(V2_FRAME_HEX));
}

#[test]
fn reusable_dek_two_recipient_known_answer_vector_is_exact() {
    if !gcm() {
        return;
    }
    let mut sender = store();
    sender
        .install(0x0C0E, ep(8), &[0x55; KEYBYTES])
        .expect("install second");
    let frames = dek::seal_fanout_deterministic(
        &sender,
        &[TO, 0x0C0E],
        CHANNEL,
        FANOUT_PAYLOAD,
        FANOUT_DEK,
        FANOUT_BODY_NONCE,
        &FANOUT_ENVELOPE_NONCES,
    )
    .expect("fanout");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].frame, unhex(FANOUT_FIRST_FRAME_HEX));
    assert_eq!(frames[1].frame, unhex(FANOUT_SECOND_FRAME_HEX));
    assert_eq!(frames[0].frame[69..], frames[1].frame[69..]);
    assert_ne!(frames[0].frame[..69], frames[1].frame[..69]);
    assert_eq!(
        frames[0].frame.len(),
        FANOUT_PAYLOAD.len() + dek::DEK_OVERHEAD
    );
}
