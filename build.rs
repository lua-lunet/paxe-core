//! Build script: locate a STATIC libsodium archive and link it into the
//! cdylib. Zero crate dependencies, so this drives `pkg-config` (Unix) or
//! probes the workspace vcpkg tree (Windows) by hand.
//!
//! Owner decision: libsodium is linked STATICALLY. This script therefore
//! hard-fails the build when no static archive is found; it never falls
//! back to the shared library. A silent dynamic fallback would defeat the
//! decision and must not happen.
//!
//! Resolution order:
//!   1. `PAXE_SODIUM_LIB_DIR` env var — directory containing `libsodium.a`
//!      (Unix) or `libsodium.lib` (Windows). This is the override for CI,
//!      cross builds and vendored prebuilts.
//!   2. Unix: `pkg-config --libs --static libsodium`, parsing its `-L`
//!      flags by hand, then verifying `libsodium.a` exists in one of the
//!      reported directories.
//!   3. Windows: `%VCPKG_ROOT%\installed\x64-windows\lib\libsodium.lib`,
//!      then `<workspace>/vcpkg/installed/x64-windows/lib/libsodium.lib`
//!      (the layout `contributing/deps/windows.ps1` produces).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PAXE_SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=VCPKG_ROOT");

    let dir = locate();
    let src = dir.join(archive_name());
    println!("cargo:rerun-if-changed={}", src.display());

    // `static=sodium` alone is NOT enough on Unix: when libsodium.a and
    // the shared library sit in the SAME -L directory (Homebrew, Debian),
    // the linker resolves -lsodium to the shared library and the cdylib
    // ends up with a dynamic dependency — verified with `otool -L`. The
    // +verbatim full-path form is equally unportable (rustc emits
    // `-l<path>`, which ld64 rejects outright).
    //
    // The robust zero-dep answer: copy the archive into a private OUT_DIR
    // directory that contains NO shared library, and put only that
    // directory on the search path. With no .dylib/.so beside it, the
    // `static=` link can only resolve to the archive.
    let out_dir =
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts"));
    let staged = out_dir.join(archive_name());
    // Remove any previous staging first. `fs::copy` reproduces the SOURCE
    // file's permissions, and a distribution archive is commonly owner
    // read-only (Homebrew ships libsodium.a as r--rw-r--). Copying onto
    // that fails with EACCES, so every build-script re-run in an OUT_DIR
    // that already held a staged archive would die — which is any rebuild
    // whose fingerprint is unchanged but whose RUSTFLAGS differ, e.g.
    // `cargo clippy -- -D warnings` after `cargo test`.
    if let Err(e) = std::fs::remove_file(&staged) {
        if e.kind() != std::io::ErrorKind::NotFound {
            panic!(
                "paxe-core build.rs: failed to clear the previously staged {}: {e}",
                staged.display()
            );
        }
    }
    std::fs::copy(&src, &staged).unwrap_or_else(|e| {
        panic!(
            "paxe-core build.rs: failed to stage {} into {}: {e}",
            src.display(),
            staged.display()
        )
    });
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static={}", link_name());
    if env::var("CARGO_CFG_WINDOWS").is_ok() {
        // libsodium's Windows RNG uses the legacy CryptoAPI entry points.
        println!("cargo:rustc-link-lib=advapi32");
    } else {
        // libsodium uses pthread on Unix. macOS folds pthread into
        // libSystem, so naming it is harmless there and required on Linux.
        println!("cargo:rustc-link-lib=pthread");
    }
}

/// Directory guaranteed to contain the static archive, or the build dies
/// with an actionable message.
fn locate() -> PathBuf {
    let archive = archive_name();

    if let Ok(dir) = env::var("PAXE_SODIUM_LIB_DIR") {
        let dir = PathBuf::from(dir);
        if dir.join(archive).is_file() {
            return dir;
        }
        fatal(&format!(
            "PAXE_SODIUM_LIB_DIR points at {}, which does not contain \
             {archive}. PAXE requires static linking and will not \
             fall back to the shared library.",
            dir.display()
        ));
    }

    if env::var("CARGO_CFG_WINDOWS").is_ok() {
        locate_vcpkg(archive)
    } else {
        locate_pkg_config(archive)
    }
}

/// Locate the static libsodium archive on Unix.
///
/// Resolution order:
///   1. `-L` dirs reported by `pkg-config --libs --static libsodium`
///   2. `pkg-config --variable=libdir libsodium` (more reliable when the
///      archive is in a default linker search path with no `-L` flag)
///   3. Standard system lib dirs (Debian/Ubuntu multiarch, RHEL, generic)
///
/// On Debian/Ubuntu, `libsodium-dev` installs into `/usr/lib/<host-tuple>/`
/// which is a default linker search path, so pkg-config emits no `-L` flag.
/// The `-L`-only parse therefore produces an empty candidate list and the
/// build fails. The `--variable=libdir` query and the system-dir fallback
/// close that gap.
fn locate_pkg_config(archive: &str) -> PathBuf {
    let mut search_dirs: Vec<PathBuf> = Vec::new();

    // 1. Parse -L flags from `pkg-config --libs --static libsodium`.
    if let Ok(output) = Command::new("pkg-config")
        .args(["--libs", "--static", "libsodium"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut tokens = text.split_whitespace();
            while let Some(tok) = tokens.next() {
                if tok == "-L" {
                    if let Some(dir) = tokens.next() {
                        search_dirs.push(PathBuf::from(dir));
                    }
                } else if let Some(dir) = tok.strip_prefix("-L") {
                    search_dirs.push(PathBuf::from(dir));
                }
            }
        }
    }

    // 2. `pkg-config --variable=libdir libsodium` — more reliable when the
    //    archive is in a default linker search path with no -L flag.
    if let Ok(output) = Command::new("pkg-config")
        .args(["--variable=libdir", "libsodium"])
        .output()
    {
        if output.status.success() {
            let dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !dir.is_empty() {
                search_dirs.push(PathBuf::from(dir));
            }
        }
    }

    // 3. Standard system lib dirs (Debian/Ubuntu multiarch, RHEL, generic).
    for dir in &[
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
        "/usr/local/lib",
    ] {
        search_dirs.push(PathBuf::from(dir));
    }

    for dir in &search_dirs {
        if dir.join(archive).is_file() {
            return dir.clone();
        }
    }
    fatal(&format!(
        "pkg-config found libsodium but no static archive {archive} in \
         any of: {search_dirs:?}. PAXE will not fall back to the shared \
         library. Both libsodium-dev \
         and Homebrew libsodium ship the archive; or set \
         PAXE_SODIUM_LIB_DIR."
    ));
}

/// Windows: the project's deps script installs `libsodium:x64-windows`
/// (static-lib triplet) into the workspace vcpkg clone.
fn locate_vcpkg(archive: &str) -> PathBuf {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(root) = env::var("VCPKG_ROOT") {
        candidates.push(
            PathBuf::from(root)
                .join("installed")
                .join("x64-windows")
                .join("lib"),
        );
    }
    if let Ok(manifest) = env::var("CARGO_MANIFEST_DIR") {
        candidates.push(
            PathBuf::from(manifest)
                .join("..")
                .join("..")
                .join("vcpkg")
                .join("installed")
                .join("x64-windows")
                .join("lib"),
        );
    }
    for dir in &candidates {
        if dir.join(archive).is_file() {
            return dir.clone();
        }
    }
    fatal(&format!(
        "no static libsodium.lib found. Probed: {candidates:?}. Run \
         `vcpkg install libsodium:x64-windows` (see \
         contributing/deps/windows.ps1) or set PAXE_SODIUM_LIB_DIR."
    ));
}

fn archive_name() -> &'static str {
    if env::var("CARGO_CFG_WINDOWS").is_ok() {
        "libsodium.lib"
    } else {
        "libsodium.a"
    }
}

fn link_name() -> &'static str {
    if env::var("CARGO_CFG_WINDOWS").is_ok() {
        "libsodium"
    } else {
        "sodium"
    }
}

fn fatal(msg: &str) -> ! {
    // A build script reports a hard configuration error by panicking; the
    // panic aborts cargo, it never reaches the cdylib or its host process.
    panic!("paxe-core build.rs: {msg}");
}
