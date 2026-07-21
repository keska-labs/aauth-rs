//! Helpers to drive interop tests via the `@aauth/fetch` CLI.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde::Deserialize;
use serde_json::Value;

const DEFAULT_WHOAMI: &str = "https://whoami.aauth.dev";
const DEFAULT_HOSTED_PERSON_SERVER: &str = "https://person.hello.coop";

/// Hosted whoami resource URL (override with `AAUTH_E2E_WHOAMI`).
pub fn whoami_url() -> String {
    std::env::var("AAUTH_E2E_WHOAMI").unwrap_or_else(|_| DEFAULT_WHOAMI.to_string())
}

/// Hosted Person Server URL (override with `AAUTH_E2E_PERSON_SERVER`).
pub fn hosted_person_server_url() -> String {
    std::env::var("AAUTH_E2E_PERSON_SERVER")
        .unwrap_or_else(|_| DEFAULT_HOSTED_PERSON_SERVER.to_string())
}

/// Public base URL for local servers (tunnel). Required for hybrid hosted tests.
pub fn public_base_url() -> Option<String> {
    std::env::var("AAUTH_E2E_PUBLIC_BASE")
        .ok()
        .filter(|s| !s.is_empty())
}

pub fn aauth_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AAUTH_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").expect(
        "HOME unset and AAUTH_DIR unset — set AAUTH_DIR to your @aauth/bootstrap config root",
    );
    PathBuf::from(home).join(".aauth")
}

/// True when `~/.aauth` (or `AAUTH_DIR`) looks bootstrapped.
pub fn bootstrap_available() -> bool {
    aauth_dir().join("config.json").is_file()
}

/// Rewrite a local `http://127.0.0.1:port/...` URL to use [`public_base_url`].
pub fn publicize_url(local_url: &str) -> Option<String> {
    let base = public_base_url()?;
    let base = base.trim_end_matches('/');
    let parsed = url::Url::parse(local_url).ok()?;
    let path = parsed.path();
    let query = parsed.query().map(|q| format!("?{q}")).unwrap_or_default();
    Some(format!("{base}{path}{query}"))
}

/// Options for one `npx @aauth/fetch` invocation.
#[derive(Debug, Clone, Default)]
pub struct FetchCliOptions {
    pub person_server: Option<String>,
    pub non_interactive: bool,
    pub browser: bool,
    pub emit: bool,
    pub poll_timeout_secs: Option<u64>,
    pub extra_args: Vec<String>,
}

impl FetchCliOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn person_server(mut self, url: impl Into<String>) -> Self {
        self.person_server = Some(url.into());
        self
    }

    pub fn non_interactive(mut self) -> Self {
        self.non_interactive = true;
        self
    }

    /// Auto-open the consent URL in a browser (hosted PS flows).
    pub fn browser(mut self) -> Self {
        self.browser = true;
        self
    }

    pub fn emit(mut self) -> Self {
        self.emit = true;
        self
    }

    pub fn poll_timeout_secs(mut self, secs: u64) -> Self {
        self.poll_timeout_secs = Some(secs);
        self
    }

    pub fn extra_args(mut self, args: Vec<String>) -> Self {
        self.extra_args = args;
        self
    }
}

fn build_aauth_fetch_command(resource: &str, options: &FetchCliOptions) -> Command {
    let mut cmd = Command::new("npx");
    cmd.args(["--yes", "@aauth/fetch", resource])
        .env("NO_COLOR", "1");

    if let Some(ps) = &options.person_server {
        cmd.args(["--person-server", ps]);
    }
    if options.non_interactive {
        cmd.arg("--non-interactive");
    }
    if options.browser {
        cmd.arg("--browser");
    }
    if options.emit {
        cmd.arg("--emit");
    }
    if let Some(secs) = options.poll_timeout_secs {
        cmd.args(["--poll-timeout", &secs.to_string()]);
    }
    for arg in &options.extra_args {
        cmd.arg(arg);
    }
    cmd
}

/// Run `npx --yes @aauth/fetch <resource> …` on a blocking pool so the axum
/// server keeps serving tunnel traffic on the tokio runtime.
pub async fn run_aauth_fetch(resource: &str, options: FetchCliOptions) -> Output {
    let resource = resource.to_string();
    tokio::task::spawn_blocking(move || {
        build_aauth_fetch_command(&resource, &options)
            .output()
            .unwrap_or_else(|e| {
                panic!(
                    "failed to run `npx @aauth/fetch` ({e}). Install Node and ensure npx is on PATH."
                )
            })
    })
    .await
    .expect("join fetch CLI task")
}

/// Successful CLI stdout as UTF-8 text (panics on non-zero exit).
pub async fn fetch_stdout(resource: &str, options: FetchCliOptions) -> String {
    let output = run_aauth_fetch(resource, options).await;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "`npx @aauth/fetch {resource}` failed (exit {}). stderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );
    stdout
}

/// Parse `--emit` JSON from CLI stdout.
#[derive(Debug, Deserialize)]
pub struct FetchEmit {
    pub response: Option<Value>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(rename = "signingKey")]
    pub signing_key: Option<Value>,
    #[serde(default)]
    pub aauth_access_token: Option<String>,
}

pub async fn fetch_emit(resource: &str, options: FetchCliOptions) -> FetchEmit {
    let options = FetchCliOptions {
        emit: true,
        ..options
    };
    let stdout = fetch_stdout(resource, options).await;
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("failed to parse @aauth/fetch --emit JSON ({e}). stdout:\n{stdout}")
    })
}
