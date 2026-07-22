import Foundation
import CryptoKit
import Security

// AAuth Secure Enclave Helper (in-process)
// Port of packages-js local-keys/se-helper/main.swift — CryptoKit + keychain.
// Linked into aauth-macos-se-ffi; Rust calls via @_cdecl instead of a CLI subprocess.
//
// Original CLI usage (for reference):
//   se-helper generate <label>        — create key, print JSON with public JWK
//   se-helper sign <label> <hex-hash> — sign SHA-256 hash, print JSON with base64url signature
//   se-helper list                    — list all aauth keys, print JSON array
//   se-helper delete <label>          — delete a key
//   se-helper public-key <label>      — get public key for existing key

// MARK: - Commands

func generateKey(label: String) throws -> P256.Signing.PublicKey {
    guard SecureEnclave.isAvailable else {
        throw SEError.notAvailable
    }

    // Check if key already exists
    if (try? loadKeyData(label: label)) != nil {
        throw SEError.keyExists(label)
    }

    // Create key in Secure Enclave
    let key = try SecureEnclave.P256.Signing.PrivateKey(
        compactRepresentable: false
    )

    // Store the key's dataRepresentation in keychain
    // This is an opaque blob that CryptoKit can use to reconnect to the SE key
    let keyData = key.dataRepresentation

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.aauth.secure-enclave",
        kSecAttrAccount as String: label,
        kSecValueData as String: keyData,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw SEError.keychainError("SecItemAdd failed: \(status)")
    }

    return key.publicKey
}

func signHash(label: String, hexHash: String) throws -> Data {
    let key = try loadKey(label: label)
    let hashData = try hexToData(hexHash)

    guard hashData.count == 32 else {
        throw SEError.invalidHash("Expected 32 bytes (SHA-256), got \(hashData.count)")
    }

    // Sign the pre-computed hash using the SE key
    let signature = try key.signature(for: RawDigest(hashData))

    return signature.rawRepresentation
}

func listKeys() throws -> [[String: Any]] {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.aauth.secure-enclave",
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    var keys: [[String: Any]] = []

    if status == errSecSuccess, let items = result as? [[String: Any]] {
        for item in items {
            if let account = item[kSecAttrAccount as String] as? String {
                keys.append([
                    "label": account,
                    "algorithm": "ES256",
                    "backend": "secure-enclave",
                ])
            }
        }
    }

    return keys
}

func deleteKey(label: String) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.aauth.secure-enclave",
        kSecAttrAccount as String: label,
    ]

    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw SEError.keychainError("SecItemDelete failed: \(status)")
    }
}

func getPublicKey(label: String) throws -> [String: String] {
    let key = try loadKey(label: label)
    return publicKeyToJWK(key.publicKey)
}

// MARK: - Key Loading

func loadKeyData(label: String) throws -> Data {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.aauth.secure-enclave",
        kSecAttrAccount as String: label,
        kSecReturnData as String: true,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess, let data = result as? Data else {
        throw SEError.keyNotFound(label)
    }

    return data
}

func loadKey(label: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
    let data = try loadKeyData(label: label)
    // dataRepresentation is an opaque handle that reconnects to the SE key
    return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
}

// MARK: - Helpers

func publicKeyToJWK(_ publicKey: P256.Signing.PublicKey) -> [String: String] {
    let raw = publicKey.rawRepresentation // 64 bytes: x || y
    let x = raw.prefix(32)
    let y = raw.suffix(32)

    return [
        "kty": "EC",
        "crv": "P-256",
        "x": base64url(x),
        "y": base64url(y),
        "alg": "ES256",
        "use": "sig",
    ]
}

/// Wraps pre-computed hash bytes so CryptoKit can sign them directly
struct RawDigest: Digest {
    static var byteCount = 32
    private var bytes: Data

    init(_ data: Data) {
        self.bytes = data
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    static func hash<D: DataProtocol>(data: D) -> RawDigest {
        fatalError("Not used")
    }

    typealias Bytes = Data

    func hash(into hasher: inout Hasher) {
        hasher.combine(bytes)
    }

    static func == (lhs: RawDigest, rhs: RawDigest) -> Bool {
        lhs.bytes == rhs.bytes
    }
}

func base64url(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func base64url(_ data: some DataProtocol) -> String {
    base64url(Data(data))
}

func hexToData(_ hex: String) throws -> Data {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        guard nextIndex <= hex.endIndex,
              let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
            throw SEError.invalidHash("Invalid hex")
        }
        data.append(byte)
        index = nextIndex
    }
    return data
}

func jwkToJSONString(_ jwk: [String: String]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: jwk, options: [.sortedKeys])
    guard let str = String(data: data, encoding: .utf8) else {
        throw SEError.keychainError("failed to encode JWK JSON")
    }
    return str
}

// MARK: - Errors

enum SEError: Error, CustomStringConvertible {
    case notAvailable
    case keyExists(String)
    case keyNotFound(String)
    case keychainError(String)
    case invalidHash(String)
    case invalidLabel

    var description: String {
        switch self {
        case .notAvailable: return "Secure Enclave not available"
        case .keyExists(let l): return "Key already exists: \(l)"
        case .keyNotFound(let l): return "Key not found: \(l)"
        case .keychainError(let m): return "Keychain error: \(m)"
        case .invalidHash(let m): return "Invalid hash: \(m)"
        case .invalidLabel: return "invalid label"
        }
    }
}

// MARK: - C ABI bridge (Rust / aauth-macos-se-ffi)

private func setError(_ out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, _ message: String) {
    guard let out = out else { return }
    message.withCString { cstr in
        out.pointee = strdup(cstr)
    }
}

private func writeBytes(
    _ data: Data,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<Int>?
) {
    guard let out = out, let outLen = outLen else { return }
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
    data.copyBytes(to: buf, count: data.count)
    out.pointee = buf
    outLen.pointee = data.count
}

private func writeCString(
    _ string: String,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) {
    guard let out = out else { return }
    string.withCString { cstr in
        out.pointee = strdup(cstr)
    }
}

private func labelString(_ label: UnsafePointer<CChar>?) -> String? {
    guard let label = label else { return nil }
    let s = String(cString: label)
    return s.isEmpty ? nil : s
}

@_cdecl("aauth_se_free")
public func aauth_se_free(_ ptr: UnsafeMutableRawPointer?) {
    free(ptr)
}

@_cdecl("aauth_se_is_available")
public func aauth_se_is_available() -> Bool {
    SecureEnclave.isAvailable
}

@_cdecl("aauth_se_generate")
public func aauth_se_generate(
    _ label: UnsafePointer<CChar>?,
    _ outJwkJson: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    guard let label = labelString(label) else {
        setError(errorOut, SEError.invalidLabel.description)
        return false
    }
    do {
        let publicKey = try generateKey(label: label)
        let json = try jwkToJSONString(publicKeyToJWK(publicKey))
        writeCString(json, outJwkJson)
        return true
    } catch {
        setError(errorOut, "\(error)")
        return false
    }
}

@_cdecl("aauth_se_sign_hash")
public func aauth_se_sign_hash(
    _ label: UnsafePointer<CChar>?,
    _ hexHash: UnsafePointer<CChar>?,
    _ outSig: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outSigLen: UnsafeMutablePointer<Int>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    guard let label = labelString(label), let hexHash = labelString(hexHash) else {
        setError(errorOut, "invalid label or hash")
        return false
    }
    do {
        let rawSig = try signHash(label: label, hexHash: hexHash)
        writeBytes(rawSig, outSig, outSigLen)
        return true
    } catch {
        setError(errorOut, "\(error)")
        return false
    }
}

@_cdecl("aauth_se_public_key")
public func aauth_se_public_key(
    _ label: UnsafePointer<CChar>?,
    _ outJwkJson: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    guard let label = labelString(label) else {
        setError(errorOut, SEError.invalidLabel.description)
        return false
    }
    do {
        let json = try jwkToJSONString(getPublicKey(label: label))
        writeCString(json, outJwkJson)
        return true
    } catch {
        setError(errorOut, "\(error)")
        return false
    }
}

/// Returns newline-separated labels (from listKeys accounts); caller frees with `aauth_se_free`.
@_cdecl("aauth_se_list")
public func aauth_se_list(
    _ outLabels: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    do {
        let keys = try listKeys()
        let labels = keys.compactMap { $0["label"] as? String }
        writeCString(labels.joined(separator: "\n"), outLabels)
        return true
    } catch {
        setError(errorOut, "\(error)")
        return false
    }
}

@_cdecl("aauth_se_delete")
public func aauth_se_delete(
    _ label: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Bool {
    guard let label = labelString(label) else {
        setError(errorOut, SEError.invalidLabel.description)
        return false
    }
    do {
        try deleteKey(label: label)
        return true
    } catch {
        setError(errorOut, "\(error)")
        return false
    }
}
