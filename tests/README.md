# paxe-core tests

## The suites

| Target | What it checks | Needs |
|---|---|---|
| `make test` | The Rust unit + bin suite (73 lib + 25 bin tests) | Rust toolchain, static libsodium |
| `make test-e2e` | Two `six-seven-server` nodes over real UDP sockets, every hop a PAXE frame | `cargo build --bins`, `python3`, `nc` |
| `make test-kat` | Loads `tests/aes_gcm_vectors.json` and checks the crate's own deterministic seal seams against it | the `kat` cargo feature (auto-passed by the target) |
| `make test-kat-independent` | Re-derives the vectors with OpenSSL EVP (Python `cryptography`) and checks them against the hex in `src/vectors.rs` | `python3` + `cryptography` package |
| `make check` | fmt-check + clippy + `test` + `test-kat` + `test-e2e` | all of the above |
| `make docker-gate` | The full `check` inside a Debian trixie container | docker (colima/aarch64, classic builder) |

## The AES-256-GCM known-answer vectors

The KAT has two layers, and they exist for different reasons:

1. **`src/vectors.rs`** (Rust unit tests) — pins the wire bytes the crate
   produces against hex constants. This catches regressions in the crate's
   own output, but a self-consistent-but-wrong crate would still pass it:
   the crate round-trips its own frames.

2. **`tests/aes_gcm_vectors.json`** (integration test, `tests/kat_from_json.rs`)
   — pins the wire bytes against a fixture computed by a **second,
   independent** AES-256-GCM implementation (OpenSSL EVP via Python's
   `cryptography` package). The generator (`tests/gen_aes_gcm_vectors.py`)
   never imports or calls the paxe crate; it reads the input constants from
   `src/vectors.rs` and computes the frames with OpenSSL. The Rust test
   re-runs the crate's deterministic seams with the same inputs and asserts
   byte-for-byte equality. If the AAD layout, field widths, or byte order
   drift, this test catches it even if layer 1 still passes.

The `kat` cargo feature (off by default) exposes the deterministic
caller-supplied-nonce seal seams that the integration test needs. Those seams
are test-only: deterministic nonces must never be reachable in production
(GCM nonce reuse under one key destroys confidentiality and authenticity).
`#[cfg(test)]` alone is not enough because integration tests compile this
crate as a normal dependency, so the seams are gated behind the feature.

## Regenerating the JSON fixture

The fixture is checked in (`tests/aes_gcm_vectors.json`) so the test is
repeatable without anyone re-running the generator. Regenerate it only when
the wire format or the vector inputs change.

### With docker (recommended — matches CI)

This uses the same Debian trixie image the gate runs in, so the OpenSSL
version and the Python environment are pinned:

```
make docker-regen
```

This builds `tests/Dockerfile.aes_gcm`, runs the generator inside the
container, and writes the JSON back to `tests/aes_gcm_vectors.json`. Review
the diff and commit it.

### Without docker

```
pip3 install cryptography
python3 tests/gen_aes_gcm_vectors.py
```

This writes `tests/aes_gcm_vectors.json` in place. On macOS the
`cryptography` package bundles its own OpenSSL, so the result is independent
of the system libssl.

### After regenerating

Run the KAT to confirm the crate still matches the new fixture:

```
make test-kat
```

If the wire format changed, also update the hex constants in
`src/vectors.rs` (the unit-test layer) and the documentation in `PAXE.md`.
