//! FFI canary spawner.
//!
//! Drives the canary in `tests/ffi_canary.py` against the cdylib that
//! cargo builds alongside the test run. The canary exercises the exact
//! C ABI that the Lua runtime binds, from an independent foreign-function
//! client (python3 + ctypes): a green canary means the C ABI itself
//! round-trips, so any higher-level binding failure is in the binding,
//! not the ABI.
//!
//! Gated behind the `ffi-canary` feature: the canary needs a `python3`
//! interpreter, which is a development-environment concern, not a
//! build or publish dependency. Off by default; run with:
//!
//!     cargo test --features ffi-canary

#![cfg(feature = "ffi-canary")]

use std::process::Command;

#[test]
fn ffi_canary_round_trips_the_c_abi_from_an_independent_client() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let target_dir =
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| format!("{manifest}/target"));
    let dylib = if cfg!(target_os = "macos") {
        format!("{target_dir}/{profile}/libpaxe.dylib")
    } else {
        format!("{target_dir}/{profile}/libpaxe.so")
    };

    // `cargo test` builds the lib's rmeta/rlib for testing but not the
    // cdylib artefact, so build it here; the build lock is free by the
    // time tests run.
    if !std::path::Path::new(&dylib).exists() {
        let build = Command::new(env!("CARGO"))
            .args(["build", "--lib"])
            .current_dir(manifest)
            .output()
            .expect("spawn cargo build for the cdylib");
        assert!(
            build.status.success(),
            "cargo build failed:\n{}",
            String::from_utf8_lossy(&build.stderr)
        );
    }
    let dylib_path = std::path::Path::new(&dylib);
    assert!(dylib_path.exists(), "cdylib still missing at {dylib}");

    let output = Command::new("python3")
        .arg(format!("{manifest}/tests/ffi_canary.py"))
        .arg(&dylib)
        .output()
        .expect("spawn python3 for the FFI canary");

    io_report(&output);

    let outcome = if output.status.success() {
        "green"
    } else {
        "red"
    };
    assert!(
        output.status.success(),
        "FFI canary is {outcome}: python3 exited with {:?}",
        output.status.code()
    );
}

fn io_report(output: &std::process::Output) {
    use std::io::Write as _;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "--- canary stdout ---\n{stdout}");
    if !stderr.trim().is_empty() {
        let _ = write!(out, "--- canary stderr ---\n{stderr}");
    }
    let _ = out.flush();
}
