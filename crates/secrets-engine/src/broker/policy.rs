//! Relay policies (the "virtual card" + its limits) and the single TTL choke point.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Anthropic,
    Openai,
    Github,
    Generic,
}

/// Canonical upstream host allowlist per provider (HF-11) — the swap REFUSES any other host, so a
/// relay can never be re-pointed at an attacker-controlled endpoint.
pub fn canonical_upstreams(_p: Provider) -> &'static [&'static str] {
    todo!()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Connect,
    Options,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayKind {
    Named,
    Ephemeral,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SwapMode {
    BaseUrlRepoint { upstream_base: String },
    ProxyMitm,
    NativeSubToken { ttl_secs: i64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayId(pub String);

/// A relay policy. The `policy_ttl_secs` is the long lifetime (1y/90d); the WIRE bearer minted
/// under it is always clamped to `<=24h`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayPolicy {
    pub relay_id: String,
    pub kind: RelayKind,
    pub provider: Provider,
    pub secret_name: String,
    pub swap: SwapMode,
    pub host_allow: Vec<String>,
    pub path_allow: Vec<String>,
    pub method_allow: Vec<Method>,
    pub policy_ttl_secs: i64,
    pub rate_per_min: Option<u32>,
    pub quota_total: Option<u64>,
    pub enabled: bool,
    pub revoked: bool,
}

/// The minted wire bearer returned to clients. Only its hash is persisted; `raw` never touches
/// disk and is zeroized on drop.
pub struct Bearer {
    pub relay_id: String,
    pub token_id: String,
    pub raw: Zeroizing<String>,
    pub expires_at: String,
}

pub const MAX_BEARER_TTL_SECS: i64 = 24 * 60 * 60;

/// The single TTL choke point (HF-15): clamps the requested TTL against the policy TTL AND the
/// 24h ceiling, saturating (never wraps), and refuses a dead/negative TTL (FS-S3). Returns the
/// absolute `expires_at` epoch-seconds, or `None` to refuse.
pub fn clamp_ttl(now: i64, policy_ttl_secs: i64, requested_ttl_secs: i64) -> Option<i64> {
    let ttl = requested_ttl_secs
        .min(policy_ttl_secs)
        .min(MAX_BEARER_TTL_SECS);
    if ttl <= 0 {
        return None;
    }
    Some(now.saturating_add(ttl))
}
