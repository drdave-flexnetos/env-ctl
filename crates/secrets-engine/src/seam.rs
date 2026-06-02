//! The behavioral seams (the envctl `HookRunner` family) — all `Send + Sync` so the `Engine`
//! stays `Send + Sync`. Real impls live here; fakes for tests are injected via `Engine::with_seams`.
use zeroize::Zeroizing;

/// Wall + monotonic clock. `boottime_ms` is a `CLOCK_BOOTTIME` cross-check for clock-rollback
/// defense on the 24h relay window (OI-6).
pub trait Clock: Send + Sync {
    fn now(&self) -> chrono::DateTime<chrono::Utc>;
    fn boottime_ms(&self) -> i64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
    /// `CLOCK_BOOTTIME` in milliseconds: a monotonic counter since boot that INCLUDES suspend time
    /// and CANNOT be stepped backward by the operator, NTP, or a settimeofday() rollback — exactly
    /// the property the OI-6 relay rollback fence needs. Read via `rustix::time::clock_gettime`
    /// (pure-Rust linux_raw syscall on Linux; no C). Saturating ms conversion; never panics.
    fn boottime_ms(&self) -> i64 {
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        ts.tv_sec
            .saturating_mul(1000)
            .saturating_add(ts.tv_nsec / 1_000_000)
    }
}

/// USB key probe. Resolves the GPT PARTUUID as a pre-filter, then returns the keyfile bytes so
/// the engine can PROVE possession (by unwrapping the USB keyslot). `None` => USB absent or
/// possession unproven (fail-closed). UUID match alone is NOT presence (CF-4/OI-5).
pub trait UsbProbe: Send + Sync {
    fn keyfile_for(&self, partition_uuid: &str) -> Option<Zeroizing<Vec<u8>>>;
}
pub struct RealUsbProbe;
impl UsbProbe for RealUsbProbe {
    fn keyfile_for(&self, _uuid: &str) -> Option<Zeroizing<Vec<u8>>> {
        todo!()
    }
}

pub struct MintRequest {
    pub provider: crate::broker::Provider,
    pub repos: Vec<String>,
    pub perms: Vec<String>,
    pub ttl_secs: i64,
}
pub struct ScopedToken {
    pub token: Zeroizing<Vec<u8>>,
    pub expires_at: i64,
}
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("provider does not support native sub-tokens")]
    Unsupported,
    #[error("{0}")]
    Other(String),
}
/// Optional native scoped sub-token minting (GitHub fine-grained PAT / App token, OpenAI project
/// key). Defaults to `Unsupported` so the proxy-swap path is the universal fallback.
pub trait ProviderMint: Send + Sync {
    fn mint_scoped(&self, _p: &MintRequest) -> Result<ScopedToken, MintError> {
        Err(MintError::Unsupported)
    }
}
pub struct NoMint;
impl ProviderMint for NoMint {}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream io: {0}")]
    Io(String),
    #[error("upstream host not allowlisted: {0}")]
    HostNotAllowed(String),
}
/// The egress sender. The daemon impl MUST verify TLS against the FROZEN webpki-roots store —
/// never the local CA or the OS store (FS-S7) — and only after the engine has confirmed the
/// upstream host is in the provider's canonical allowlist (HF-11).
#[async_trait::async_trait]
pub trait Upstream: Send + Sync {
    async fn send(
        &self,
        req: crate::EgressReq,
        real_key: &Zeroizing<Vec<u8>>,
    ) -> Result<crate::EgressResp, UpstreamError>;
}
