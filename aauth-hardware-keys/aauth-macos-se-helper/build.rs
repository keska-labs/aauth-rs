use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=swift/main.swift");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os != "macos" || target_arch != "aarch64" {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let helper_out = out_dir.join("se-helper");
    let swift_src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("swift/main.swift");

    let status = Command::new("swiftc")
        .args(["-O", "-o"])
        .arg(&helper_out)
        .arg(&swift_src)
        .status()
        .expect("swiftc required for se-helper (Xcode or CLT)");

    if !status.success() {
        panic!("swiftc failed to build se-helper");
    }

    let sign = Command::new("codesign")
        .args(["--force", "--sign", "-"])
        .arg(&helper_out)
        .status()
        .expect("codesign required for se-helper");

    if !sign.success() {
        panic!("codesign failed for se-helper");
    }

    let profile_dir = profile_target_dir();
    let profile_helper = profile_dir.join("se-helper");
    if let Err(e) = fs::create_dir_all(&profile_dir) {
        panic!(
            "failed to create profile dir {}: {e}",
            profile_dir.display()
        );
    }
    if let Err(e) = fs::copy(&helper_out, &profile_helper) {
        panic!(
            "failed to copy se-helper to {}: {e}",
            profile_helper.display()
        );
    }

    // Prefer the profile-dir copy so cargo test / cargo run find it beside binaries.
    println!(
        "cargo:rustc-env=AAUTH_SE_HELPER_PATH={}",
        profile_helper.display()
    );
}

/// `target/{debug|release}` for the current build.
fn profile_target_dir() -> PathBuf {
    if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
        return PathBuf::from(target_dir).join(profile);
    }
    // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out
    PathBuf::from(env::var("OUT_DIR").unwrap())
        .ancestors()
        .nth(3)
        .expect("unexpected OUT_DIR layout")
        .to_path_buf()
}
