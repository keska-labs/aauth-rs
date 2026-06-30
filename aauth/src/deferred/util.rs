pub fn generate_pending_id() -> String {
    (0..16)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

pub fn pending_location(base_url: &str, pending_path: &str, id: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = pending_path.trim_start_matches('/');
    format!("{base}/{path}/{id}")
}

pub const DEFAULT_PENDING_TTL_SECS: u64 = 600;
