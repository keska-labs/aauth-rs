//! Raw C ABI for the in-process Secure Enclave Swift bridge.
//!
//! On macOS aarch64, `build.rs` compiles `swift/SecureEnclaveBridge.swift` into a
//! static library and links Foundation / Security / CryptoKit. Callers own all
//! pointer lifetimes: buffers returned by the Swift side must be freed with
//! [`aauth_se_free`].

use std::ffi::c_void;
use std::os::raw::c_char;

unsafe extern "C" {
    /// Free a pointer allocated by the SE bridge (`strdup` / `allocate`).
    pub unsafe fn aauth_se_free(ptr: *mut c_void);

    /// Whether CryptoKit reports Secure Enclave available.
    pub unsafe fn aauth_se_is_available() -> bool;

    /// Generate a P-256 key for `label`; on success writes JWK JSON to `out_jwk_json`.
    pub unsafe fn aauth_se_generate(
        label: *const c_char,
        out_jwk_json: *mut *mut c_char,
        error_out: *mut *mut c_char,
    ) -> bool;

    /// Sign a 32-byte SHA-256 digest given as hex; writes raw r||s to `out_sig`.
    pub unsafe fn aauth_se_sign_hash(
        label: *const c_char,
        hex_hash: *const c_char,
        out_sig: *mut *mut u8,
        out_sig_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> bool;

    /// Public JWK JSON for an existing key label.
    pub unsafe fn aauth_se_public_key(
        label: *const c_char,
        out_jwk_json: *mut *mut c_char,
        error_out: *mut *mut c_char,
    ) -> bool;

    /// Newline-separated key labels; caller frees with [`aauth_se_free`].
    pub unsafe fn aauth_se_list(out_labels: *mut *mut c_char, error_out: *mut *mut c_char) -> bool;

    /// Delete a key by label from the keychain.
    pub unsafe fn aauth_se_delete(label: *const c_char, error_out: *mut *mut c_char) -> bool;
}
