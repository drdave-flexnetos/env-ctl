//! env-ctl secrets engine: the single shared library. No printing, no UI, no clap.
//!
//! Both the daemon (`secretd`) and any future GUI drive the vault + credential broker through
//! the *identical* `Engine` API below; the CLI (`secretctl`) talks to the daemon over gRPC.
//! Mirrors `envctl_engine`: the engine never prints — it emits a structured `SecretEvent`
//! stream over an `std::sync::mpsc` channel. The engine core is synchronous; only the egress
//! swap path (`Engine::relay_swap` + the `Upstream` seam) is async.
//!
//! Phase 0 is a scaffold: types/traits are real and compile; behavior bodies are `todo!()`
//! except the two safety primitives that the Phase-0 tests exercise — `clamp_ttl` and the
//! fail-closed `check_sec_guards`.
#![allow(dead_code)] // Phase-0 scaffold: many fields/bodies are placeholders until later phases.

pub mod event; // SecretEvent, EventSink (std mpsc), Stream, AuditRecord
pub mod error; // EngineError (thiserror, setup-time only), VaultState
pub mod seam; // Clock, UsbProbe, ProviderMint, Upstream + SystemClock/RealUsbProbe + fakes
pub mod guard; // SecGuard, check_sec_guards, UnlockContext (fail-closed)
pub mod paths; // Paths (XDG, env-ctl-namespaced)
pub mod keyslot; // Keyslot, Kdf, Argon2Params, wrap/unwrap (LUKS-style dual KEK) + header MAC
pub mod vault; // Vault state machine + Store trait + crypto (seal/open) + canonical AAD
pub mod broker; // Broker, RelayPolicy, Bearer, decide(), token verify, clamp_ttl, SwapOutcome
pub mod ca; // LocalCa (feature mitm-ca)
pub mod inject; // ChildEnvPlan, ResolvedInjection, injection_template, run_wrapped

pub use broker::{
    clamp_ttl, Bearer, DenyReason, Method, Provider, RelayDecision, RelayId, RelayKind,
    RelayPolicy, SwapMode, SwapOutcome, MAX_BEARER_TTL_SECS,
};
pub use error::{EngineError, VaultState};
pub use event::{AuditRecord, EventSink, SecretEvent, Stream};
pub use guard::{check_sec_guards, Destructiveness, SecGuard, UnlockContext};
pub use keyslot::{Argon2Params, Factor, Kdf, Keyslot};
pub use seam::{Clock, ProviderMint, RealUsbProbe, SystemClock, Upstream, UsbProbe};

use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

/// Top-level engine handle: owns the vault, the broker, and an optional local CA, plus the
/// `Send + Sync` seams. Cheaply cloneable (`Arc` inside) so it can move into worker tasks.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    paths: paths::Paths,
    vault: RwLock<vault::Vault>, // Locked | Unlocked { dek: Dek }
    broker: RwLock<broker::Broker>,
    ca: RwLock<Option<ca::LocalCa>>,
    // dyn-dispatched seams; the supertrait `: Send + Sync` keeps Engine Send+Sync.
    clock: Box<dyn Clock>,
    usb: Box<dyn UsbProbe>,
    provider: Box<dyn ProviderMint>,
    upstream: Box<dyn Upstream>, // pins frozen webpki roots in the daemon impl (FS-S7)
    owner_uid: u32,
}

/// Which unlock factor the operator is presenting.
pub enum Unlock {
    Usb,
    Passphrase(Zeroizing<String>),
}

pub struct SecretMeta {
    pub name: String,
    pub provider: Provider,
    pub note: String,
    pub broker_only: bool,
}

/// A canonicalized egress request as seen by the broker (host is the *verified* inner Host).
pub struct EgressReq {
    pub method: Method,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub bytes_out: u64,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<u32>,
}

pub struct EgressResp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub allowed: bool,
}

impl Engine {
    /// Open an engine backed by the real seams (`SystemClock`, `RealUsbProbe`, ...).
    pub fn open(_paths: paths::Paths) -> anyhow::Result<Engine> {
        todo!()
    }

    /// Construct an engine with injected seams (the `envctl with_runner` analogue, for tests).
    pub fn with_seams(
        _paths: paths::Paths,
        _clock: Box<dyn Clock>,
        _usb: Box<dyn UsbProbe>,
        _provider: Box<dyn ProviderMint>,
        _upstream: Box<dyn Upstream>,
    ) -> anyhow::Result<Engine> {
        todo!()
    }

    pub fn unlock(&self, _u: Unlock, _sink: &EventSink) -> anyhow::Result<VaultState> {
        todo!()
    }
    /// Zeroizes the DEK + CA issuer in RAM (the true panic stop).
    pub fn lock(&self, _sink: &EventSink) -> anyhow::Result<()> {
        todo!()
    }
    pub fn secret_put(
        &self,
        _m: SecretMeta,
        _body: Zeroizing<Vec<u8>>,
        _sink: &EventSink,
    ) -> anyhow::Result<()> {
        todo!()
    }
    /// `reveal` is apply-gated + audited + refused for `broker_only` secrets (HF-5/OI-2).
    pub fn secret_get(
        &self,
        _name: &str,
        _reveal: bool,
        _apply: bool,
        _sink: &EventSink,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        todo!()
    }
    /// USB-possession-gated, `<=24h`, peer-bound.
    pub fn relay_mint(
        &self,
        _spec: RelayPolicy,
        _requested_ttl_secs: i64,
        _peer_uid: Option<u32>,
        _peer_pid: Option<u32>,
        _sink: &EventSink,
    ) -> anyhow::Result<Bearer> {
        todo!()
    }
    /// Fail-closed; returns the count of bearers/policies flipped (HF-16).
    pub fn relay_revoke(&self, _relay_id: &str, _apply: bool, _sink: &EventSink) -> anyhow::Result<u32> {
        todo!()
    }
    /// Single-bearer revocation (OI-10).
    pub fn relay_revoke_bearer(
        &self,
        _token_id: &str,
        _apply: bool,
        _sink: &EventSink,
    ) -> anyhow::Result<u32> {
        todo!()
    }
    /// Hot path: default-deny by construction — the real key is fetched only inside `Allowed`;
    /// any internal error becomes `InternalRefused` (a durable-audited 403), never `send()` (CF-9).
    pub async fn relay_swap(&self, _bearer: &str, _req: &EgressReq, _sink: &EventSink) -> SwapOutcome {
        todo!()
    }
    /// Operator-issued NON-MITM leaves only; REFUSES `usage = mitm_leaf` (CF-5).
    pub fn ca_issue(
        &self,
        _cn: &str,
        _sans: &[String],
        _usage: &str,
        _sink: &EventSink,
    ) -> anyhow::Result<String> {
        todo!()
    }
    pub fn run_child(
        &self,
        _plan: inject::ChildEnvPlan,
        _argv: Vec<String>,
        _sink: &EventSink,
    ) -> anyhow::Result<i32> {
        todo!()
    }
}
