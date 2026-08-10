//! Reusable-DEK fanout frames and standard-frame dispatch.
//!
//! A fanout frame carries one payload body encrypted under a fresh DEK and a
//! separately authenticated DEK envelope for its recipient:
//!
//! ```text
//! Prefix(9) | EnvelopeNonce(12) | EncryptedDEK(32) | EnvelopeTag(16)
//!           | BodyNonce(12) | BodyCiphertext(N) | BodyTag(16)
//! ```
//!
//! The body is identical in every frame emitted by one fanout operation. The
//! prefix and envelope are recipient-specific. One-recipient sealing always
//! uses the standard frame in `standard`.

use crate::codec::{self, CodecError, Flags, Header, Mode, PREFIX_LEN};
use crate::keystore::{Epoch, KeyStore, StoredKey};
use crate::sodium::{self, Key, Nonce, SodiumError, ABYTES, KEYBYTES, NPUBBYTES};
use crate::standard;
use crate::stats::{self, RejectReason};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

const UDP_DATAGRAM_MAX: usize = 65_507;
const ENVELOPE_LEN: usize = KEYBYTES + ABYTES;
const BODY_START: usize = PREFIX_LEN + NPUBBYTES + ENVELOPE_LEN;
const BODY_TAG_LEN: usize = ABYTES;

/// Reusable-DEK frame overhead: prefix, envelope nonce, encrypted DEK,
/// envelope tag, body nonce, and body tag.
pub const DEK_OVERHEAD: usize = BODY_START + NPUBBYTES + BODY_TAG_LEN;
/// Largest reusable-DEK plaintext that fits in a UDP datagram.
pub const DEK_MAX_PAYLOAD: usize = UDP_DATAGRAM_MAX - DEK_OVERHEAD;

const _: () = {
    assert!(PREFIX_LEN == 9);
    assert!(BODY_START == 69);
    assert!(DEK_OVERHEAD == 97);
};

mod layout {
    use super::*;

    pub const ENVELOPE_NONCE: usize = PREFIX_LEN;
    pub const ENCRYPTED_DEK: usize = ENVELOPE_NONCE + NPUBBYTES;
    pub const ENVELOPE_TAG: usize = ENCRYPTED_DEK + KEYBYTES;
    pub const BODY_NONCE: usize = ENVELOPE_TAG + ABYTES;
    pub const BODY: usize = BODY_NONCE + NPUBBYTES;
}

/// A complete recipient-addressed frame emitted by [`seal_fanout`].
#[derive(Debug, PartialEq, Eq)]
pub struct FanoutFrame {
    pub to_id: u16,
    pub epoch: Epoch,
    pub frame: Vec<u8>,
}

/// Local errors from sealing. Receive failures deliberately use [`OpenError`]
/// and remain opaque at the public boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    Oversize(usize),
    NoKey,
    EmptyRecipients,
    DuplicateRecipient(u16),
    NonceCountMismatch,
    Sodium(SodiumError),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversize(n) => write!(f, "payload too large: {n} bytes"),
            Self::NoKey => write!(f, "no PSK installed for the destination peer"),
            Self::EmptyRecipients => write!(f, "fanout needs at least one recipient"),
            Self::DuplicateRecipient(peer) => write!(f, "duplicate fanout recipient {peer}"),
            Self::NonceCountMismatch => write!(f, "envelope nonce count does not match recipients"),
            Self::Sodium(e) => write!(f, "libsodium failure: {e}"),
        }
    }
}

impl Error for SealError {}

impl From<SodiumError> for SealError {
    fn from(value: SodiumError) -> Self {
        Self::Sodium(value)
    }
}

/// Internal receive causes. The FFI maps all non-internal causes to one drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    Prefix(CodecError),
    TooShort(usize),
    LengthMismatch,
    NoKey,
    AuthFailed,
    StandardRejected,
    Sodium(SodiumError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prefix(e) => write!(f, "{e}"),
            Self::TooShort(n) => write!(f, "reusable-DEK frame too short: {n} bytes"),
            Self::LengthMismatch => write!(f, "declared length disagrees with frame size"),
            Self::NoKey => write!(f, "no PSK installed for source and epoch"),
            Self::AuthFailed => write!(f, "authentication failed"),
            Self::StandardRejected => write!(f, "standard frame rejected"),
            Self::Sodium(e) => write!(f, "libsodium failure: {e}"),
        }
    }
}

impl Error for OpenError {}

struct KeyGuard(Key);

impl KeyGuard {
    fn random() -> Self {
        Self(sodium::random_key())
    }

    fn from_bytes(bytes: [u8; KEYBYTES]) -> Self {
        Self(Key::from_bytes(bytes))
    }

    fn key(&self) -> &Key {
        &self.0
    }
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        sodium::memzero(self.0.as_mut_bytes());
    }
}

fn psk(stored: &StoredKey) -> Result<&Key, SodiumError> {
    let bytes: &[u8; KEYBYTES] = stored
        .expose()
        .try_into()
        .map_err(|_| SodiumError::Internal)?;
    Ok(Key::from_borrowed(bytes))
}

fn body_aad(from_id: u16, channel: u16, length: u16) -> [u8; 7] {
    let [f0, f1] = from_id.to_be_bytes();
    let [c0, c1] = channel.to_be_bytes();
    let [l0, l1] = length.to_be_bytes();
    [f0, f1, c0, c1, l0, l1, 0x05]
}

fn envelope_aad(prefix: &[u8], body_nonce: &[u8], body_tag: &[u8]) -> Result<[u8; 37], SealError> {
    let prefix: &[u8; PREFIX_LEN] = prefix
        .try_into()
        .map_err(|_| SealError::Sodium(SodiumError::Internal))?;
    let body_nonce: &[u8; NPUBBYTES] = body_nonce
        .try_into()
        .map_err(|_| SealError::Sodium(SodiumError::Internal))?;
    let body_tag: &[u8; ABYTES] = body_tag
        .try_into()
        .map_err(|_| SealError::Sodium(SodiumError::Internal))?;
    let mut aad = [0u8; 37];
    aad[..PREFIX_LEN].copy_from_slice(prefix);
    aad[PREFIX_LEN..PREFIX_LEN + NPUBBYTES].copy_from_slice(body_nonce);
    aad[PREFIX_LEN + NPUBBYTES..].copy_from_slice(body_tag);
    Ok(aad)
}

/// Seal one recipient with its selected PSK. This always emits a standard
/// frame; reusable-DEK mode is explicit through [`seal_fanout`].
pub fn seal(
    store: &KeyStore,
    to_id: u16,
    channel: u16,
    epoch: Epoch,
    payload: &[u8],
) -> Result<Vec<u8>, SealError> {
    if payload.len() > standard::MAX_PAYLOAD {
        return Err(SealError::Oversize(payload.len()));
    }
    let mut frame = vec![0u8; payload.len() + standard::OVERHEAD];
    match standard::seal(store, to_id, channel, epoch, payload, &mut frame) {
        Ok(_) => Ok(frame),
        Err(standard::SealError::PayloadTooLarge(n)) => Err(SealError::Oversize(n)),
        Err(standard::SealError::NoKey) => Err(SealError::NoKey),
        Err(standard::SealError::Sodium(e)) => Err(SealError::Sodium(e)),
        Err(standard::SealError::OutputTooSmall { .. }) => {
            Err(SealError::Sodium(SodiumError::Internal))
        }
    }
}

/// Encrypt one payload once and return a complete reusable-DEK frame for each
/// recipient. Recipient order is preserved.
pub fn seal_fanout(
    store: &KeyStore,
    recipients: &[u16],
    channel: u16,
    payload: &[u8],
) -> Result<Vec<FanoutFrame>, SealError> {
    validate_fanout(store, recipients, payload)?;
    let envelope_nonces: Vec<Nonce> = recipients.iter().map(|_| sodium::random_nonce()).collect();
    seal_fanout_core(
        store,
        recipients,
        channel,
        payload,
        KeyGuard::random(),
        sodium::random_nonce(),
        &envelope_nonces,
    )
}

fn validate_fanout(store: &KeyStore, recipients: &[u16], payload: &[u8]) -> Result<(), SealError> {
    if recipients.is_empty() {
        return Err(SealError::EmptyRecipients);
    }
    if payload.len() > DEK_MAX_PAYLOAD {
        return Err(SealError::Oversize(payload.len()));
    }
    let mut seen = BTreeSet::new();
    for &to_id in recipients {
        if !seen.insert(to_id) {
            return Err(SealError::DuplicateRecipient(to_id));
        }
        if store.key_for_send_current(to_id).is_none() {
            return Err(SealError::NoKey);
        }
    }
    Ok(())
}

fn seal_fanout_core(
    store: &KeyStore,
    recipients: &[u16],
    channel: u16,
    payload: &[u8],
    dek: KeyGuard,
    body_nonce: Nonce,
    envelope_nonces: &[Nonce],
) -> Result<Vec<FanoutFrame>, SealError> {
    validate_fanout(store, recipients, payload)?;
    if envelope_nonces.len() != recipients.len() {
        return Err(SealError::NonceCountMismatch);
    }
    let mut seen = BTreeSet::new();
    let mut selected = Vec::with_capacity(recipients.len());
    for &to_id in recipients {
        if !seen.insert(to_id) {
            return Err(SealError::DuplicateRecipient(to_id));
        }
        let (epoch, stored) = store.key_for_send_current(to_id).ok_or(SealError::NoKey)?;
        selected.push((to_id, epoch, stored));
    }
    let length = u16::try_from(payload.len()).map_err(|_| SealError::Oversize(payload.len()))?;
    let body_aad = body_aad(store.local_id(), channel, length);
    let mut body = vec![0u8; NPUBBYTES + payload.len() + ABYTES];
    body[..NPUBBYTES].copy_from_slice(body_nonce.as_bytes());
    sodium::aead_encrypt(
        dek.key(),
        &body_nonce,
        &body_aad,
        payload,
        &mut body[NPUBBYTES..],
    )?;
    let body_tag_start = body.len() - ABYTES;
    let body_tag = &body[body_tag_start..];

    let mut frames = Vec::with_capacity(selected.len());
    for ((to_id, epoch, stored), envelope_nonce) in selected.into_iter().zip(envelope_nonces) {
        let header = Header {
            from_id: store.local_id(),
            to_id,
            channel,
            length,
        };
        let flags = Flags::new(Mode::Dek, epoch);
        let prefix = codec::serialize_prefix(&header, &flags);
        let aad = envelope_aad(&prefix, &body[..NPUBBYTES], body_tag)?;
        let mut frame = Vec::with_capacity(payload.len() + DEK_OVERHEAD);
        frame.extend_from_slice(&prefix);
        frame.extend_from_slice(envelope_nonce.as_bytes());
        frame.resize(BODY_START, 0);
        sodium::aead_encrypt(
            psk(stored)?,
            envelope_nonce,
            &aad,
            dek.key().as_bytes(),
            &mut frame[layout::ENCRYPTED_DEK..BODY_START],
        )?;
        frame.extend_from_slice(&body);
        frames.push(FanoutFrame {
            to_id,
            epoch,
            frame,
        });
    }
    Ok(frames)
}

/// Dispatch a received frame by its validated mode flag.
pub fn open(store: &KeyStore, frame: &[u8]) -> Result<(Header, Flags, Vec<u8>), OpenError> {
    let (header, flags) = match codec::parse_prefix(frame) {
        Ok(value) => value,
        Err(e) => {
            stats::record_reject(RejectReason::from_codec(e));
            return Err(OpenError::Prefix(e));
        }
    };
    if flags.mode() == Mode::Standard {
        let mut out = vec![0u8; header.length as usize];
        return match standard::open(store, frame, &mut out) {
            Ok((h, f, n)) => {
                out.truncate(n);
                Ok((h, f, out))
            }
            Err(_) => Err(OpenError::StandardRejected),
        };
    }
    open_dek(store, frame, header, flags)
}

fn open_dek(
    store: &KeyStore,
    frame: &[u8],
    header: Header,
    flags: Flags,
) -> Result<(Header, Flags, Vec<u8>), OpenError> {
    if frame.len() < DEK_OVERHEAD {
        stats::record_reject(RejectReason::TooShort);
        return Err(OpenError::TooShort(frame.len()));
    }
    let declared = header.length as usize;
    if frame.len() != declared + DEK_OVERHEAD {
        stats::record_reject(RejectReason::LenMismatch);
        return Err(OpenError::LengthMismatch);
    }
    let stored = match store.key_for_receive(header.from_id, flags.epoch()) {
        Some(value) => value,
        None => {
            stats::record_reject(if store.peer_known(header.from_id) {
                RejectReason::NoEpoch
            } else {
                RejectReason::NoPeer
            });
            return Err(OpenError::NoKey);
        }
    };
    let envelope_nonce: [u8; NPUBBYTES] = frame[layout::ENVELOPE_NONCE..layout::ENCRYPTED_DEK]
        .try_into()
        .map_err(|_| OpenError::Sodium(SodiumError::Internal))?;
    let body_nonce: [u8; NPUBBYTES] = frame[layout::BODY_NONCE..layout::BODY]
        .try_into()
        .map_err(|_| OpenError::Sodium(SodiumError::Internal))?;
    let body_tag = frame
        .get(frame.len() - ABYTES..)
        .ok_or(OpenError::Sodium(SodiumError::Internal))?;
    let envelope_aad = envelope_aad(
        &frame[..PREFIX_LEN],
        &frame[layout::BODY_NONCE..layout::BODY],
        body_tag,
    )
    .map_err(|e| match e {
        SealError::Sodium(s) => OpenError::Sodium(s),
        _ => OpenError::Sodium(SodiumError::Internal),
    })?;
    let envelope = frame
        .get(layout::ENCRYPTED_DEK..layout::BODY_NONCE)
        .ok_or(OpenError::Sodium(SodiumError::Internal))?;
    let mut dek_bytes = [0u8; KEYBYTES];
    match sodium::aead_decrypt(
        psk(stored).map_err(OpenError::Sodium)?,
        &Nonce::from_bytes(envelope_nonce),
        &envelope_aad,
        envelope,
        &mut dek_bytes,
    ) {
        Ok(_) => {}
        Err(SodiumError::AuthFailed) => {
            stats::record_reject(RejectReason::AuthFailed);
            return Err(OpenError::AuthFailed);
        }
        Err(e) => return Err(OpenError::Sodium(e)),
    }
    let dek = KeyGuard::from_bytes(dek_bytes);
    let mut out = vec![0u8; declared];
    let body = frame
        .get(layout::BODY..)
        .ok_or(OpenError::Sodium(SodiumError::Internal))?;
    match sodium::aead_decrypt(
        dek.key(),
        &Nonce::from_bytes(body_nonce),
        &body_aad(header.from_id, header.channel, header.length),
        body,
        &mut out,
    ) {
        Ok(n) => {
            out.truncate(n);
            Ok((header, flags, out))
        }
        Err(SodiumError::AuthFailed) => {
            stats::record_reject(RejectReason::AuthFailed);
            Err(OpenError::AuthFailed)
        }
        Err(e) => Err(OpenError::Sodium(e)),
    }
}

#[cfg(test)]
pub(crate) fn seal_fanout_deterministic(
    store: &KeyStore,
    recipients: &[u16],
    channel: u16,
    payload: &[u8],
    dek: [u8; KEYBYTES],
    body_nonce: [u8; NPUBBYTES],
    envelope_nonces: &[[u8; NPUBBYTES]],
) -> Result<Vec<FanoutFrame>, SealError> {
    let envelope_nonces: Vec<Nonce> = envelope_nonces
        .iter()
        .copied()
        .map(Nonce::from_bytes)
        .collect();
    seal_fanout_core(
        store,
        recipients,
        channel,
        payload,
        KeyGuard::from_bytes(dek),
        Nonce::from_bytes(body_nonce),
        &envelope_nonces,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u16 = 100;
    const B: u16 = 200;
    const C: u16 = 201;
    const D: u16 = 202;

    fn ep(value: u8) -> Epoch {
        Epoch::new(value).expect("epoch")
    }
    fn gcm() -> bool {
        sodium::init().is_ok() && sodium::aes_gcm_available()
    }
    fn sender() -> KeyStore {
        let mut store = KeyStore::new(A).expect("store");
        store.install(B, ep(1), &[0x11; KEYBYTES]).expect("B");
        store.install(C, ep(2), &[0x22; KEYBYTES]).expect("C");
        store.install(D, ep(3), &[0x33; KEYBYTES]).expect("D");
        store
    }
    fn receiver(id: u16, epoch: Epoch, key: [u8; KEYBYTES]) -> KeyStore {
        let mut store = KeyStore::new(id).expect("store");
        store.install(A, epoch, &key).expect("install");
        store
    }

    #[test]
    fn one_recipient_seal_is_always_standard() {
        if !gcm() {
            return;
        }
        let store = sender();
        for n in [0, 63, 64, 65, 1400, standard::MAX_PAYLOAD] {
            let payload = vec![0xA5; n];
            let frame = seal(&store, B, 100, ep(1), &payload).expect("seal");
            assert_eq!(frame.len(), n + standard::OVERHEAD);
            assert_eq!(
                codec::parse_prefix(&frame).expect("prefix").1.mode(),
                Mode::Standard
            );
        }
    }

    #[test]
    fn fanout_reuses_body_and_opens_for_each_recipient() {
        if !gcm() {
            return;
        }
        let frames = seal_fanout(&sender(), &[C, B, D], 137, b"fanout payload").expect("fanout");
        assert_eq!(
            frames.iter().map(|f| f.to_id).collect::<Vec<_>>(),
            vec![C, B, D]
        );
        assert!(
            frames
                .windows(2)
                .all(|pair| pair[0].frame[layout::BODY_NONCE..]
                    == pair[1].frame[layout::BODY_NONCE..])
        );
        assert_ne!(
            &frames[0].frame[layout::ENVELOPE_NONCE..layout::BODY_NONCE],
            &frames[1].frame[layout::ENVELOPE_NONCE..layout::BODY_NONCE]
        );
        for frame in frames {
            let key = match frame.to_id {
                B => [0x11; KEYBYTES],
                C => [0x22; KEYBYTES],
                _ => [0x33; KEYBYTES],
            };
            let (_, flags, plaintext) =
                open(&receiver(frame.to_id, frame.epoch, key), &frame.frame).expect("open");
            assert_eq!(flags.mode(), Mode::Dek);
            assert_eq!(plaintext, b"fanout payload");
        }
    }

    #[test]
    fn fanout_preflight_and_geometry_reject_invalid_requests() {
        let store = sender();
        assert_eq!(
            seal_fanout(&store, &[], 1, b"x"),
            Err(SealError::EmptyRecipients)
        );
        assert_eq!(
            seal_fanout(&store, &[B, B], 1, b"x"),
            Err(SealError::DuplicateRecipient(B))
        );
        assert_eq!(
            seal_fanout(&store, &[B, 999], 1, b"x"),
            Err(SealError::NoKey)
        );
        assert_eq!(
            seal_fanout(&store, &[B], 1, &vec![0; DEK_MAX_PAYLOAD + 1]),
            Err(SealError::Oversize(DEK_MAX_PAYLOAD + 1))
        );
    }

    #[test]
    fn fanout_tampering_and_splicing_are_rejected() {
        if !gcm() {
            return;
        }
        let store = sender();
        let first = seal_fanout(&store, &[B, C], 7, b"first").expect("first");
        let second = seal_fanout(&store, &[B, C], 7, b"other").expect("second");
        for offset in [
            0,
            8,
            layout::ENVELOPE_NONCE,
            layout::ENCRYPTED_DEK,
            layout::ENVELOPE_TAG,
            layout::BODY_NONCE,
            layout::BODY,
            first[0].frame.len() - 1,
        ] {
            let mut forged = first[0].frame.clone();
            forged[offset] ^= 1;
            assert!(open(&receiver(B, ep(1), [0x11; KEYBYTES]), &forged).is_err());
        }
        let mut spliced = first[0].frame.clone();
        spliced[layout::BODY_NONCE..].copy_from_slice(&second[0].frame[layout::BODY_NONCE..]);
        assert!(open(&receiver(B, ep(1), [0x11; KEYBYTES]), &spliced).is_err());
    }
}
