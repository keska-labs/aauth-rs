use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=swift/SecureEnclaveBridge.swift");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os != "macos" || target_arch != "aarch64" {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib_path = out_dir.join("libaauth_se_bridge.a");
    let swift_src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("swift/SecureEnclaveBridge.swift");

    let status = Command::new("swiftc")
        .args([
            "-emit-library",
            "-static",
            "-module-name",
            "AauthSeBridge",
            "-O",
            "-o",
        ])
        .arg(&lib_path)
        .arg(&swift_src)
        .status()
        .expect("swiftc required for Secure Enclave (Xcode or CLT)");

    if !status.success() {
        panic!("swiftc failed to build Secure Enclave bridge");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=aauth_se_bridge");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
}
