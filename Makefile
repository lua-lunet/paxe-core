# paxe-core: the Rust suite, and the demo server the core is exercised with.
#
# Prerequisites: a Rust toolchain (rust-toolchain.toml pins it, rustup will
# fetch it) and a STATIC libsodium archive that build.rs can find. On Unix that
# means pkg-config knows about libsodium; set PAXE_SODIUM_LIB_DIR to point at a
# directory holding libsodium.a if it does not.
#
#   macOS:  brew install libsodium pkg-config
#   Debian: apt-get install libsodium-dev pkg-config
#
# The e2e target additionally needs python3 and nc, both of which ship with the
# platforms above. The kat and docker-gate targets need the `cryptography`
# Python package (pip3 install cryptography) and docker respectively.

.PHONY: help build check test test-e2e test-kat test-kat-independent fmt clippy clean docker-gate docker-regen

help:
	@echo "make test        - the Rust test suite"
	@echo "make test-e2e    - two real nodes over real sockets, forwarding over PAXE"
	@echo "make test-kat    - the AES-256-GCM known-answer test from the JSON fixture"
	@echo "make check       - fmt, clippy, the Rust suite, the KAT and the e2e run"
	@echo "make build       - release-build the cdylib, staticlib and the demo server"
	@echo "make docker-gate - the full gate in a Debian trixie container (colima/aarch64)"
	@echo "make docker-regen- regenerate tests/aes_gcm_vectors.json in the container"
	@echo "make fmt         - rustfmt in place"
	@echo "make clean       - cargo clean, and drop .tmp run logs"

build:
	cargo build --release --all-targets

test:
	cargo test

# Builds debug because that is what the script runs; keeping the two in step
# here means `make test-e2e` never silently tests a stale binary.
test-e2e:
	cargo build --bins
	bash tests/six_seven_e2e.sh

# The KAT integration test: loads tests/aes_gcm_vectors.json (generated
# independently by OpenSSL EVP) and checks the crate's own deterministic seal
# seams against it. Needs the `kat` feature to expose those seams.
test-kat:
	cargo test --test kat_from_json --features kat

# The independent AES-256-GCM KAT: re-derives the vectors with OpenSSL EVP
# (Python cryptography) and checks them against the hex in src/vectors.rs.
# Needs python3 with the `cryptography` package.
test-kat-independent:
	bash tests/aes_gcm_kat.sh

check: fmt-check clippy test test-kat test-e2e

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

# Full gate in a Debian trixie container: fmt, clippy, the Rust suite, the
# KAT integration test, the two-node e2e, and the independent KAT. Classic
# builder only (no BuildKit, no volume mounts) for colima/aarch64 hosts.
docker-gate:
	DOCKER_BUILDKIT=0 docker build -f tests/Dockerfile.aes_gcm -t paxe-aes-gcm:trixie .
	docker run --rm paxe-aes-gcm:trixie

# Regenerate the JSON fixture inside the container and copy it back. The
# image prints the generator's status lines then the JSON; extract from the
# first `{` onward so only the JSON lands in the checked-in file.
docker-regen:
	DOCKER_BUILDKIT=0 docker build -f tests/Dockerfile.aes_gcm -t paxe-aes-gcm:trixie .
	docker run --rm -e PAXE_MODE=regen paxe-aes-gcm:trixie | sed -n '/^{/,$$p' > tests/aes_gcm_vectors.json

clean:
	cargo clean
	rm -rf .tmp/logs
