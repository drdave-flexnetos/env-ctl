//! Auto-inject: the engine owns the per-provider env mapping; `secretctl run` stays dumb. The
//! relay bearer + base-URL/proxy/CA env are overlaid onto the CHILD process only — the real key
//! never enters the child env, shell history, or git.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPlaneMode {
    BaseUrlRepoint,
    HttpsProxyMitm,
    NativeSubtoken,
}

/// The provider-shaped env delta to overlay onto the child (e.g. `ANTHROPIC_BASE_URL` +
/// `ANTHROPIC_API_KEY=<bearer>`, or `HTTPS_PROXY` + the CA-bundle env keys).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedInjection {
    pub provider: crate::broker::Provider,
    pub mode: DataPlaneMode,
    pub env: std::collections::BTreeMap<String, String>,
    pub ca_env_keys: Vec<String>,
    pub proxy_url: Option<String>,
    pub base_url: Option<String>,
}

pub struct ChildEnvPlan {
    pub injection: ResolvedInjection,
    /// pid the ephemeral bearer is peer-bound to (HF-8).
    pub child_pid_hint: Option<u32>,
}

/// Engine-owned provider table: builds the env delta for a given provider + bearer.
pub fn injection_template(
    _p: crate::broker::Provider,
    _bearer: &str,
    _proxy: &str,
    _ca_pem_path: &str,
) -> ResolvedInjection {
    todo!()
}

/// Fail-closed profile discovery: only operator-trusted roots / at-or-below cwd; attaching a
/// named relay from a discovered profile requires explicit confirmation (FS-S15).
pub fn discover_profile(
    _cwd: &std::path::Path,
    _trusted_roots: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    todo!()
}
