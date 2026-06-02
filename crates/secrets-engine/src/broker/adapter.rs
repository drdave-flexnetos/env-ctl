//! Per-provider request adapters: rewrite the auth header (relay → real key), enforce the path /
//! method allowlist, and pass streaming/SSE bodies through unbuffered (Anthropic streaming). One
//! adapter per `Provider`; the generic adapter covers everything else. Implemented in Phase 4.
use super::policy::Provider;

pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> Provider;
}
