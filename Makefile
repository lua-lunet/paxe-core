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
# platforms above.

.PHONY: help build check test test-e2e fmt clippy clean

help:
	@echo "make test      - the Rust test suite"
	@echo "make test-e2e  - two real nodes over real sockets, forwarding over PAXE"
	@echo "make check     - fmt, clippy, the Rust suite and the e2e run"
	@echo "make build     - release-build the cdylib, staticlib and the demo server"
	@echo "make fmt       - rustfmt in place"
	@echo "make clean     - cargo clean, and drop .tmp run logs"

build:
	cargo build --release --all-targets

test:
	cargo test

# Builds debug because that is what the script runs; keeping the two in step
# here means `make test-e2e` never silently tests a stale binary.
test-e2e:
	cargo build --bins
	bash tests/six_seven_e2e.sh

check: fmt-check clippy test test-e2e

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean
	rm -rf .tmp/logs
