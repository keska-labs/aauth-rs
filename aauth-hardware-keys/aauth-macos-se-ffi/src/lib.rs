//! Locates the Cargo-built, adhoc-codesigned `se-helper` CLI.
//!
//! On macOS aarch64, `build.rs` compiles `swift/main.swift`, codesigns it, and
//! copies it to `target/{debug,release}/se-helper`.

use std::env;
use std::path::PathBuf;

/// Resolve the `se-helper` binary path.
///
/// Lookup order:
/// 1. `AAUTH_SE_HELPER` environment variable
/// 2. Compile-time path from this crate's `build.rs` (`AAUTH_SE_HELPER_PATH`)
/// 3. `se-helper` next to the current executable
pub fn helper_path() -> Option<PathBuf> {
    if let Ok(p) = env::var("AAUTH_SE_HELPER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        if let Some(p) = option_env!("AAUTH_SE_HELPER_PATH") {
            let p = PathBuf::from(p);
            if p.is_file() {
                return Some(p);
            }
        }
        if let Ok(exe) = env::current_exe() {
            if let Some(dir) = exe.parent() {
                let p = dir.join("se-helper");
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }

    None
}
