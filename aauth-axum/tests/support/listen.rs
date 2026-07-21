//! Bind + serve helpers for integration tests and examples.

use axum::Router;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// A background `axum::serve` task with its advertised base URL.
pub struct Serving {
    pub url: String,
    handle: JoinHandle<()>,
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Bind `127.0.0.1:0` (or `AAUTH_E2E_BIND`) and return the listener plus advertised URL.
///
/// When `AAUTH_E2E_PUBLIC_BASE` is set, that value is used as the advertised URL so a
/// tunnel can front the listener for hybrid hosted tests.
pub async fn bind() -> (TcpListener, String) {
    let bind_addr = std::env::var("AAUTH_E2E_BIND")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let listener = TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("bind {bind_addr}: {e}"));
    let addr = listener.local_addr().expect("local addr");
    let url = std::env::var("AAUTH_E2E_PUBLIC_BASE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
        .unwrap_or_else(|| format!("http://{addr}"));
    (listener, url)
}

/// Bind an ephemeral port only (ignores `AAUTH_E2E_*`). Use when serving multiple
/// local parties so each gets its own origin.
pub async fn bind_ephemeral() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    (listener, format!("http://{addr}"))
}

/// Spawn `axum::serve` in the background.
///
/// `url` is the advertised base URL returned on [`Serving`] (may differ from the
/// bind address when a tunnel is used).
pub fn serve(listener: TcpListener, app: Router, url: impl Into<String>) -> Serving {
    let url = url.into();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    Serving { url, handle }
}
