# PAXE Protected Datagram Specification

This document is the normative, Markdown-driven contract for the wire format,
public behavior, and conformance tests. Implementation and tests must agree with
this document. PAXE is sans-io: it protects datagrams but does not own sockets,
retransmission, ordering, replay windows, key distribution, or key agreement.

## Cryptographic scope

PAXE uses AES-256-GCM and 32-byte pre-shared keys (PSKs). PSKs are provisioned
out of band by the host, such as from configuration, a secret manager, or an
operator-installed cluster secret. PAXE only looks up an already installed PSK;
it performs no handshake and contains no TLS, ECDHE, SRP, certificate, or network
key-management implementation.

The provisioning policy may install one cluster-wide PSK, distinct PSKs for
each pair of nodes, or overlapping epochs during rotation. The wire protocol
does not distinguish those policies. A PSK is addressed locally by `(peer,
epoch)`, where the epoch is in `0..=31`.

Every AES-GCM invocation uses a fresh 12-byte nonce from the operating system
CSPRNG. Key and nonce material must not be caller-selectable in production.

For a cluster-wide PSK, nonce accounting is cluster-wide too: count every
AES-GCM invocation made by every node with that PSK, including standard frames
and reusable-DEK envelopes. The birthday bound applies to that aggregate count;
at approximately `2^32` invocations, the probability of a 96-bit nonce
collision remains below `2^-32`. Rotation policy must therefore count the
whole cluster, not an individual link or sender.

## Common prefix

Every frame starts with this nine-byte prefix:

```text
offset  size  field      encoding
0       2     fromId     unsigned big-endian
2       2     toId       unsigned big-endian
4       2     channel    unsigned big-endian
6       2     length     plaintext payload length, unsigned big-endian
8       1     flags      bit layout below
```

The flags byte is:

```text
bit 0      0 = standard frame, 1 = reusable-DEK frame
bit 1      must be 0
bit 2      must be 1
bits 3-7   PSK epoch, 0..=31
```

All multibyte integers are unsigned big-endian values. `length` is the
plaintext length, not the datagram length. Frames with invalid constant flag
bits, an unsupported mode, or inconsistent geometry are rejected.

## Standard frame

Standard mode protects one payload for one recipient directly under the PSK.
It is always used by the one-recipient `seal` API, regardless of payload size.

```text
Prefix(9) | Nonce(12) | Ciphertext(length) | Tag(16)
```

The complete frame is `length + 37` bytes, so the largest standard plaintext in
a 65,507-byte UDP datagram is 65,470 bytes. AES-256-GCM inputs are:

```text
key        PSK selected by (toId, epoch) on seal
           PSK selected by (fromId, epoch) on open
nonce      the 12-byte Nonce field
plaintext  application payload
AAD        the exact nine-byte Prefix carried in the frame
```

Authenticating the prefix protects both the addressing metadata and every flag,
including the mode and PSK epoch.

## Reusable-DEK fanout frame

Fanout protects one logical payload once and emits one complete datagram per
recipient. The body fields are byte-for-byte identical in every recipient's
datagram. Only the recipient prefix and encrypted-DEK envelope differ.

```text
Prefix(9)
| EnvelopeNonce(12)
| EncryptedDEK(32)
| EnvelopeTag(16)
| BodyNonce(12)
| BodyCiphertext(length)
| BodyTag(16)
```

The complete frame is `length + 97` bytes, so the largest reusable-DEK
plaintext in a 65,507-byte UDP datagram is 65,410 bytes.

Sealing proceeds as follows:

1. Reject an empty recipient list, duplicate recipient identifiers, an
   oversized payload, or any recipient without a current PSK before generating
   randomness or returning output.
2. Generate a fresh 32-byte data-encryption key (DEK) and a fresh 12-byte body
   nonce.
3. Construct the recipient-independent body AAD:

   ```text
   BE16(fromId) | BE16(channel) | BE16(length) | 0x05
   ```

   `0x05` is the canonical reusable-DEK mode marker: DEK bit set, required
   constant bits valid, and no recipient-specific epoch bits.
4. Encrypt the payload once with AES-256-GCM under the DEK, body nonce, and body
   AAD to produce `BodyCiphertext` and `BodyTag`.
5. For each recipient, select that peer's current PSK epoch and construct its
   prefix with the reusable-DEK flag and selected epoch. Generate a fresh
   envelope nonce.
6. Construct the envelope AAD:

   ```text
   Prefix | BodyNonce | BodyTag
   ```

7. Encrypt the 32-byte DEK with AES-256-GCM under the recipient PSK, envelope
   nonce, and envelope AAD to produce `EncryptedDEK` and `EnvelopeTag`.
8. Emit the complete frame. Preserve the caller's recipient order.

Opening a reusable-DEK frame verifies exact frame geometry, selects the PSK by
`(fromId, epoch)`, authenticates and decrypts the DEK envelope, reconstructs the
recipient-independent body AAD, and authenticates and decrypts the body. No
plaintext is released unless both GCM tags verify.

The envelope AAD binds the recipient-specific prefix—including `toId`, mode,
and epoch—to the exact body nonce and tag. The body AAD binds the shared body to
the sender, channel, plaintext length, and reusable-DEK mode. Consequently,
changing flags, redirecting a frame, or splicing an envelope onto a different
body is detected.

## Public behavior

The one-recipient seal operation always produces a standard frame. Reusable-DEK
mode is available only through an explicit fanout operation. There is no
payload-size-based mode selection and no production API for forcing a mode.

The fanout operation is all-or-nothing. It validates every recipient and PSK
before producing frames, rejects duplicate recipients, preserves recipient
order, encrypts the body exactly once, and gives every recipient a distinct
envelope nonce and independently authenticated DEK envelope.

The C ABI deliberately exposes only the one-recipient standard sealer. A Rust
host using fanout records each returned reusable-DEK frame that it accepts for
transmission with `stats::record_tx_sealed(Mode::Dek)`; `tx_dek` does not
advance merely because fanout returned a vector.

Receivers choose the parser only from the validated mode flag. They never infer
the mode from payload or datagram size.

## Failure handling

Received datagrams are untrusted. Parsing uses checked arithmetic and bounded
slices and must not panic for any byte sequence. Authentication uses separate
output buffers; failed authentication releases no plaintext and does not modify
the input datagram.

The public receive boundary returns one opaque rejection result for malformed
frames, missing PSKs, and authentication failures. Detailed causes may be
recorded in local counters but must not cross the receive API, which avoids
turning the receiver into a decryption oracle.

## Key handling

Installed PSKs remain in guarded, locked memory and are erased when retired,
cleared, or dropped. Ephemeral DEKs are erased on every exit path. Core dumps
are disabled by default while the process holds key material, with the explicit
documented debugging opt-out.

The host is responsible for securely provisioning, rotating, and retiring PSKs.
Those operations are control-plane concerns and never appear on the PAXE wire.

## Conformance requirements

Tests must pin at least the following behavior:

- byte-exact standard and reusable-DEK known-answer vectors derived independently
  from the Rust implementation;
- standard sealing for small and large payloads;
- identical reusable body bytes and distinct envelopes for two or more recipients;
- recipient ordering, duplicate rejection, missing-PSK rejection, and
  all-or-nothing fanout;
- tampering with every prefix field, either nonce, either tag, encrypted DEK,
  or body ciphertext;
- envelope/body splice rejection across recipients and across separate fanouts;
- exact minimum, maximum, truncated, extended, and inconsistent-length geometry;
- opaque receive failures and no panic for arbitrary input.
