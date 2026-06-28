use rand::Rng;

/// Crockford base32 alphabet — omits I, L, O, U to avoid visual ambiguity.
pub const CROCKFORD32: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate an 8-symbol Crockford base32 interaction code (40 bits of entropy)
/// in canonical form: `XXXX-XXXX`.
pub fn generate_code() -> String {
    let mut buf = [0u8; 5];
    rand::rng().fill_bytes(&mut buf);
    let mut n = 0u128;
    for b in buf {
        n = (n << 8) | u128::from(b);
    }
    let raw: String = (0..8)
        .map(|i| {
            let idx = ((n >> ((7 - i) * 5)) & 31) as usize;
            CROCKFORD32.chars().nth(idx).unwrap()
        })
        .collect();
    format!("{}-{}", &raw[..4], &raw[4..])
}

/// Canonicalize a user-presented interaction code to `XXXX-XXXX` form for lookup.
pub fn canonicalize_code(code: &str) -> String {
    let bare = code
        .replace('-', "")
        .to_uppercase()
        .replace(['I', 'L'], "1")
        .replace('O', "0");
    format!(
        "{}-{}",
        &bare[..4.min(bare.len())],
        &bare[4.min(bare.len())..8.min(bare.len())]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_code_format() {
        let code = generate_code();
        assert!(code.chars().all(|c| c == '-' || CROCKFORD32.contains(c)));
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
    }

    #[test]
    fn canonicalize_folds_aliases() {
        assert_eq!(canonicalize_code("a1b2-c3d4"), "A1B2-C3D4");
        assert_eq!(canonicalize_code("A1BO-C3D4"), "A1B0-C3D4");
    }
}
