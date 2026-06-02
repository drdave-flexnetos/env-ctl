# env-ctl — Phase-0 Scaffold Spec

Precise enough to hand-write a COMPILING Phase-0 scaffold on stable rust 1.80, edition 2021. Engine core is sync; only `Upstream::send` and `Engine::relay_swap` are async. `todo!()` / `unimplemented!()` bodies are allowed; all types must derive and compile.

All review fixes are baked in: **ring** crypto backend (no aws-lc-rs/C), proto **vendored** inside the proto crate, destructive RPCs use **`bool apply`** (not `dry_run`), bearers are **peer-bound**, `clamp_ttl` takes **three args**, `UsbProbe` **proves keyfile possession**, the swap path returns a **`SwapOutcome`** (default-deny), the store is behind a **`Store` trait** (libSQL is reopened as OI-1, so Phase 0 ships only the `inmem-store` impl), and the engine lib name is **`envctl_secrets`**.

## Workspace layout

```
env-ctl/
  Cargo.toml                      # workspace (see below, embedded verbatim)
  rust-toolchain.toml             # exists (stable + rustfmt + clippy); a separate cargo +1.80.0 CI gate enforces MSRV
  crates/
    secrets-engine/  Cargo.toml + src/{lib,event,error,seam,guard,paths,keyslot,ca,inject}.rs
                                  + src/vault/{mod,store,crypto,aad}.rs + src/broker/{mod,policy,decide,token,adapter}.rs
    secrets-proto/   Cargo.toml + build.rs + src/lib.rs + proto/control.proto   # proto VENDORED in-crate (OI-15)
    secretd/         Cargo.toml + src/{main,grpc,proxy,peercred,audit}.rs
    secretctl/       Cargo.toml + src/{main,cli,render}.rs
```

## Workspace Cargo.toml (embedded verbatim)

```toml
[workspace]
resolver = "2"
members = [
  "crates/secrets-engine",
  "crates/secrets-proto",
  "crates/secretd",
  "crates/secretctl",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.80"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
# ---- shared with envctl on merge (caret-compatible; re-resolves to one unified lockfile) ----
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
anyhow = "1.0"
thiserror = "2.0"
chrono = { version = "0.4", default-features = false, features = ["clock"] }
clap = { version = "4.5", features = ["derive"] }
which = "7.0"
# MERGE NOTE (HF-17): envctl's row is features=["process"]; the merged row MUST union to ["process","net"].
rustix = { version = "0.38", features = ["process", "net"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# ---- async / network: pulled ONLY by secretd (+ proto/cli); engine stays sync ----
tokio = { version = "1.43", features = ["rt-multi-thread", "macros", "net", "sync", "fs", "process", "signal", "time", "io-util"] }
tonic = "0.12"
tonic-build = "0.12"
prost = "0.13"
tower = "0.5"
hyper = { version = "1.5", features = ["server", "http1", "http2"] }
hyper-util = { version = "0.1", features = ["tokio", "server", "client-legacy"] }
http-body-util = "0.1"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "http2", "stream"] }
webpki-roots = "0.26"   # REVIEW FIX (CF-6): explicit frozen Mozilla roots for upstream egress (never OS store / local CA)

# ---- store: backend behind a Store trait. libSQL is REOPENED (OI-1: it bundles C SQLite). Phase 0
# ---- ships only the inmem-store impl; the chosen pure-Rust backend lands in Phase 1 per the ruling.
# (no libsql row — the no-C CI gate `! cargo tree | grep libsql-ffi` must pass)

# ---- crypto (engine; pure-Rust, no C/SQLCipher) ----
chacha20poly1305 = "0.10"
argon2 = "0.5"
hkdf = "0.12"
sha2 = "0.10"
blake3 = "1.5"
zeroize = { version = "1.8", features = ["derive"] }
subtle = "2.6"
rand = "0.8"
getrandom = "0.2"

# ---- TLS / local CA: pin ONE rustls on the RING path (REVIEW FIX CF-2: NOT aws-lc-rs) ----
rustls = { version = "0.23", default-features = false, features = ["ring", "logging", "std", "tls12"] }
rustls-pemfile = "2.2"
rustls-pki-types = "1"
rcgen = { version = "0.13", default-features = false, features = ["ring", "pem"] }
x509-parser = "0.16"
async-trait = "0.1"

# ---- internal crates ----
envctl-secrets-engine = { path = "crates/secrets-engine" }
envctl-secrets-proto  = { path = "crates/secrets-proto" }

[profile.release]
opt-level = 2
```

## crates/secrets-engine/Cargo.toml (embedded verbatim)

```toml
[package]
name = "envctl-secrets-engine"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lib]
name = "envctl_secrets"        # REVIEW FIX: was the over-generic `secrets`
path = "src/lib.rs"

[features]
default = ["inmem-store", "mitm-ca"]   # default store is inmem until OI-1 is ruled (no C dep ships)
inmem-store = []                       # RAM-only vault for tests/CI (envctl DryRunRunner analogue)
mitm-ca = ["dep:rcgen", "dep:x509-parser", "dep:rustls", "dep:rustls-pemfile", "dep:rustls-pki-types"]  # OI-14: TLS optional
provider-github = []
provider-openai = []

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
toml = { workspace = true }
anyhow = { workspace = true }
thiserror = { workspace = true }
chrono = { workspace = true }
which = { workspace = true }
rustix = { workspace = true }
# crypto / store
chacha20poly1305 = { workspace = true }
argon2 = { workspace = true }
hkdf = { workspace = true }
sha2 = { workspace = true }
blake3 = { workspace = true }
zeroize = { workspace = true }
subtle = { workspace = true }
rand = { workspace = true }
getrandom = { workspace = true }
# tls/ca — OPTIONAL, only under mitm-ca (REVIEW FIX OI-14: a CA-less engine build drops TLS entirely)
rustls = { workspace = true, optional = true }
rustls-pemfile = { workspace = true, optional = true }
rustls-pki-types = { workspace = true, optional = true }
rcgen = { workspace = true, optional = true }
x509-parser = { workspace = true, optional = true }
# the one async seam
async-trait = { workspace = true }
```

> Note: the engine uses `std::sync::{mpsc, Mutex, RwLock}` only — NO tokio. `Upstream` is `#[async_trait]` so the daemon can implement it with hyper/reqwest, but the engine's own logic never `.await`s except inside `relay_swap`. The libSQL row is intentionally absent (OI-1). `store.rs` carries a `compile_error!` guard for the zero/both-backend cases (OI-14).

## crates/secrets-engine/src/lib.rs (module list + Engine signature)

```rust
//! env-ctl secrets engine: the single shared library. No printing, no UI, no clap.
pub mod event;    // SecretEvent, EventSink (std mpsc), Stream, AuditRecord
pub mod error;    // EngineError (thiserror, setup-time only), VaultState
pub mod seam;     // Clock, UsbProbe, ProviderMint, Upstream + SystemClock/RealUsbProbe + fakes
pub mod guard;    // SecGuard, check_sec_guards, UnlockContext (fail-closed)
pub mod paths;    // Paths (XDG, env-ctl-namespaced)
pub mod keyslot;  // Keyslot, Kdf, Argon2Params, wrap/unwrap (LUKS-style dual KEK) + header MAC
pub mod vault;    // Vault state machine + Store trait + crypto (seal/open) + canonical AAD
pub mod broker;   // Broker, RelayPolicy, Bearer, decide(), token verify, clamp_ttl, SwapOutcome
pub mod ca;       // LocalCa (feature mitm-ca)
pub mod inject;   // ChildEnvPlan, ResolvedInjection, injection_template, run_wrapped

pub use event::{SecretEvent, EventSink, Stream, AuditRecord};
pub use error::{EngineError, VaultState};
pub use seam::{Clock, UsbProbe, ProviderMint, Upstream, SystemClock, RealUsbProbe};
pub use guard::{SecGuard, UnlockContext, Destructiveness, check_sec_guards};
pub use broker::{RelayPolicy, RelayId, RelayKind, Bearer, Provider, Method, RelayDecision,
                 DenyReason, SwapMode, SwapOutcome, MAX_BEARER_TTL_SECS, clamp_ttl};
pub use keyslot::{Keyslot, Kdf, Argon2Params, Factor};

use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Engine { inner: Arc<EngineInner> }

struct EngineInner {
    paths: paths::Paths,
    vault: RwLock<vault::Vault>,              // Locked | Unlocked{ dek: Dek }
    broker: RwLock<broker::Broker>,
    ca: RwLock<Option<ca::LocalCa>>,
    clock: Box<dyn Clock>,                    // Send+Sync seams (Box<dyn HookRunner> analogue)
    usb: Box<dyn UsbProbe>,
    provider: Box<dyn ProviderMint>,
    upstream: Box<dyn Upstream>,              // pins frozen webpki roots in the daemon impl (FS-S7)
    owner_uid: u32,
}

pub enum Unlock { Usb, Passphrase(Zeroizing<String>) }
pub struct SecretMeta { pub name: String, pub provider: Provider, pub note: String, pub broker_only: bool }
pub struct EgressReq {
    pub method: Method, pub host: String, pub path: String,   // host = verified inner Host (HF-9)
    pub headers: Vec<(String,String)>, pub bytes_out: u64,
    pub peer_uid: Option<u32>, pub peer_pid: Option<u32>,     // for bearer peer binding (HF-8)
}
pub struct EgressResp { pub status: u16, pub headers: Vec<(String,String)>, pub allowed: bool }

impl Engine {
    // real seams
    pub fn open(paths: paths::Paths) -> anyhow::Result<Engine> { todo!() }
    // test ctor (= envctl with_runner)
    pub fn with_seams(paths: paths::Paths, clock: Box<dyn Clock>, usb: Box<dyn UsbProbe>,
        provider: Box<dyn ProviderMint>, upstream: Box<dyn Upstream>) -> anyhow::Result<Engine> { todo!() }

    pub fn unlock(&self, u: Unlock, sink: &EventSink) -> anyhow::Result<VaultState> { todo!() }
    pub fn lock(&self, sink: &EventSink) -> anyhow::Result<()> { todo!() }   // zeroizes DEK + CA Issuer (panic stop)
    pub fn secret_put(&self, m: SecretMeta, body: Zeroizing<Vec<u8>>, sink: &EventSink) -> anyhow::Result<()> { todo!() }
    // reveal is apply-gated + audited + refused for broker_only secrets (HF-5/OI-2)
    pub fn secret_get(&self, name: &str, reveal: bool, apply: bool, sink: &EventSink) -> anyhow::Result<Zeroizing<Vec<u8>>> { todo!() }
    pub fn relay_mint(&self, spec: RelayPolicy, requested_ttl_secs: i64, peer_uid: Option<u32>,
        peer_pid: Option<u32>, sink: &EventSink) -> anyhow::Result<Bearer> { todo!() }  // USB-possession-gated, <=24h, peer-bound
    pub fn relay_revoke(&self, relay_id: &str, apply: bool, sink: &EventSink) -> anyhow::Result<u32> { todo!() }  // fail-closed, count (HF-16)
    pub fn relay_revoke_bearer(&self, token_id: &str, apply: bool, sink: &EventSink) -> anyhow::Result<u32> { todo!() } // OI-10
    // hot path: default-deny by construction — real key fetched only inside Allow; any Err => Denied (CF-9)
    pub async fn relay_swap(&self, bearer: &str, req: &EgressReq, sink: &EventSink) -> SwapOutcome { todo!() }
    // operator-issued NON-MITM leaves only; REFUSES usage=mitm_leaf (CF-5)
    pub fn ca_issue(&self, cn: &str, sans: &[String], usage: &str, sink: &EventSink) -> anyhow::Result<String> { todo!() }
    pub fn run_child(&self, plan: inject::ChildEnvPlan, argv: Vec<String>, sink: &EventSink) -> anyhow::Result<i32> { todo!() }
}
```

## crates/secrets-engine/src/event.rs (the spine, EXACT envctl shape, std mpsc)

```rust
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver, Sender};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretEvent {
    VaultUnlocked { factor: crate::keyslot::Factor },
    VaultLocked,
    Audit(AuditRecord),
    SecretWritten { name: String, version: u32 },
    SecretRead { name: String, by_uid: u32 },
    RelayMinted { relay: String, kind: crate::broker::RelayKind, expires_at: String }, // bearer NEVER in payload
    RelayRotated { relay: String, expires_at: String },
    RelayRevoked { relay: String, reason: String },
    // REVIEW FIX (OI-11): token_id + client identity for per-swap traceability
    RelaySwapped { relay: String, host: String, method: String, allowed: bool,
                   token_id: String, client_uid: u32, client_label: String },
    GuardRefused { subject: String, reason: String },          // envctl shape
    CaIssued { serial: String, cn: String, not_after: String },
    LeafMinted { sni: String, relay: String, not_after: String },
    Log { source: String, stream: Stream, line: String },      // verbatim envctl
    ChildExited { code: i32 },
    RunFinished { summary: RunSummary },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream { Stdout, Stderr }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: i64, pub ts: String, pub actor_uid: Option<u32>, pub event_type: String,
    pub subject: Option<String>, pub detail: serde_json::Value, pub outcome: AuditOutcome,
    pub prev_hash: Vec<u8>, pub row_hash: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome { Ok, Refused, Failed }

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunSummary { pub failed: Vec<String>, pub refused: Vec<String> }
impl RunSummary { pub fn ok(&self) -> bool { self.failed.is_empty() && self.refused.is_empty() } }

#[derive(Clone)]
pub struct EventSink(Sender<SecretEvent>);   // COSMETIC, best-effort; durable audit is written separately (HF-14)
impl EventSink {
    pub fn channel() -> (EventSink, Receiver<SecretEvent>) {
        let (tx, rx) = std::sync::mpsc::channel(); (EventSink(tx), rx)
    }
    pub fn null() -> EventSink { let (tx, _rx) = std::sync::mpsc::channel(); EventSink(tx) }
    pub fn emit(&self, ev: SecretEvent) { let _ = self.0.send(ev); }   // drop-on-closed is fine for cosmetic events
}
```

## crates/secrets-engine/src/seam.rs (the HookRunner family — all Send+Sync)

```rust
use zeroize::Zeroizing;

pub trait Clock: Send + Sync {
    fn now(&self) -> chrono::DateTime<chrono::Utc>;
    fn boottime_ms(&self) -> i64;   // CLOCK_BOOTTIME cross-check for clock-rollback defense (OI-6)
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> { chrono::Utc::now() }
    fn boottime_ms(&self) -> i64 { todo!() }
}

pub trait UsbProbe: Send + Sync {
    /// resolve PARTUUID as a pre-filter, then return the keyfile bytes so the engine can PROVE
    /// possession (unwrap the USB keyslot). None => USB absent / possession unproven (fail-closed).
    /// REVIEW FIX (CF-4/OI-5): UUID match alone is NOT presence; possession is proven by the keyfile.
    fn keyfile_for(&self, partition_uuid: &str) -> Option<Zeroizing<Vec<u8>>>;
}
pub struct RealUsbProbe;
impl UsbProbe for RealUsbProbe { fn keyfile_for(&self, _uuid: &str) -> Option<Zeroizing<Vec<u8>>> { todo!() } }

pub struct MintRequest { pub provider: crate::broker::Provider, pub repos: Vec<String>, pub perms: Vec<String>, pub ttl_secs: i64 }
pub struct ScopedToken { pub token: Zeroizing<Vec<u8>>, pub expires_at: i64 }
#[derive(Debug, thiserror::Error)]
pub enum MintError { #[error("provider does not support native sub-tokens")] Unsupported, #[error("{0}")] Other(String) }
pub trait ProviderMint: Send + Sync {
    fn mint_scoped(&self, _p: &MintRequest) -> Result<ScopedToken, MintError> { Err(MintError::Unsupported) }
}
pub struct NoMint;
impl ProviderMint for NoMint {}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError { #[error("upstream io: {0}")] Io(String), #[error("upstream host not allowlisted: {0}")] HostNotAllowed(String) }
#[async_trait::async_trait]
pub trait Upstream: Send + Sync {
    /// The daemon impl MUST verify TLS against the FROZEN webpki-roots store, never the local CA or
    /// OS store (FS-S7), and only after the engine has confirmed the upstream host is in the
    /// provider's canonical allowlist (HF-11).
    async fn send(&self, req: crate::EgressReq, real_key: &Zeroizing<Vec<u8>>) -> Result<crate::EgressResp, UpstreamError>;
}
```

## crates/secrets-engine/src/error.rs (setup-time only)

```rust
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("vault db error in {path}: {source}")] Db { path: String, #[source] source: anyhow::Error },
    #[error("vault is locked")] Locked,
    #[error("unlock failed")] UnlockFailed,    // single generic message — never reveals which slot (OI-17)
    #[error("relay issuance refused: USB keyfile possession not proven (rotation gating)")] UsbAbsent,
    #[error("unknown relay '{0}'")] UnknownRelay(String),
    #[error("runtime dir not found or not 0700: {0}")] RuntimeDir(String),
    #[error("mlockall failed; refusing to start (FS-S4)")] MlockFailed,   // HF-4
    #[error("vault header MAC mismatch: keyslot set tampered (FS-S13)")] HeaderMacMismatch, // OI-8
    #[error("CA not initialized")] NoCa,
    #[error("audit chain broken at seq {0}")] AuditChainBroken(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultState { Uninitialized, Locked, LockedNeedPassphrase, Unlocked, Error }
```

## crates/secrets-engine/src/guard.rs

```rust
use std::time::SystemTime;
pub enum Destructiveness { Additive, Destructive, RootOfTrust }
pub enum SecGuard {
    UsbPresent { partition_uuid: String },          // PARTUUID pre-filter + keyfile-possession proof (CF-4)
    RelayValid { relay_id: String },                // enabled && !revoked(policy & bearer) && expiry>now && usb-gated
    LeafBackedByRelay { host: String },             // an active USB-gated relay's allowlist covers host (per SAN)
    PeerIsOwner,
    VaultEncryptedAtRest,
    DryRunUnlessApply { apply: bool, confirm: bool, destructive: Destructiveness }, // apply==false => REFUSE (CF-8)
}
pub struct UnlockContext {
    pub usb_keyfile_possessed: bool,                // PROVEN possession, not UUID match (CF-4)
    pub usb_partition_uuid: Option<String>,
    pub usb_absent_since: Option<SystemTime>,       // swap-time grace window (HF-6)
    pub peer_uid: Option<u32>, pub owner_uid: u32, pub now: SystemTime,
}
/// Some(reason) => REFUSE; None only on affirmative pass. FAIL-CLOSED: every uncertain branch refuses,
/// and a default-constructed (all-uncertain) ctx makes every guard refuse (Phase-0 acceptance).
pub fn check_sec_guards(_guards: &[SecGuard], _ctx: &UnlockContext) -> Option<String> { todo!() }
```

## crates/secrets-engine/src/keyslot.rs (key type sigs)

```rust
use serde::{Deserialize, Serialize}; use zeroize::{Zeroizing, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)] pub struct Dek(pub Zeroizing<[u8; 32]>);   // NOT Serialize
#[derive(ZeroizeOnDrop)] pub struct Kek(pub Zeroizing<[u8; 32]>);   // NOT Serialize

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] pub enum Factor { Usb, Passphrase, RequireBoth }  // RequireBoth = opt-in 2FA (CF-3)

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kdf { Argon2id(Argon2Params), HkdfSha256 }
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Argon2Params { pub m_kib: u32, pub t_cost: u32, pub p_lanes: u32 }   // version pinned to 0x13 in code
impl Default for Argon2Params { fn default() -> Self { Self { m_kib: 1_048_576, t_cost: 4, p_lanes: 4 } } }
pub const ARGON2_M_KIB_FLOOR: u32 = 262_144;   // 256 MiB; refuse to unwrap a slot below this (FS-S13)

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keyslot {
    pub id: i64, pub factor: Factor, pub label: String, pub kdf: Kdf,
    pub salt: Vec<u8>, pub usb_partition_uuid: Option<String>,   // GPT PARTUUID (OI-5)
    pub wrap_nonce: Vec<u8>, pub wrapped_dek: Vec<u8>, pub dek_generation: i64, pub enabled: bool,
}

// keyslot_aad binds ALL KDF-determining + identity fields, fixed-width canonical (HF-3).
pub fn keyslot_aad(slot: &Keyslot) -> Vec<u8> { todo!() }
// DEK wrapped under a KEK; AEAD tag is the correctness oracle (no separate verifier).
pub fn wrap_dek(_kek: Kek, _dek: &Dek, _aad: &[u8]) -> (Vec<u8>, Vec<u8>) { todo!() }   // (nonce24, ct||tag)
pub fn unwrap_dek(_kek: Kek, _nonce: &[u8], _wrapped: &[u8], _aad: &[u8]) -> Option<Dek> { todo!() } // consumes Kek (OI-7)
pub fn kek_from_usb(_keyfile: &Zeroizing<Vec<u8>>, _salt: &[u8]) -> Kek { todo!() }     // HKDF-SHA256, info=b"env-ctl/v1/kek/usb"
pub fn kek_from_passphrase(_pp: &Zeroizing<Vec<u8>>, _salt: &[u8], _p: Argon2Params) -> Kek { todo!() } // Argon2::new(Argon2id, V0x13, p)

// Vault header MAC over the keyslot set + params (OI-8); recomputed on unlock, refuse on drift.
pub fn header_mac(_dek: &Dek, _slots: &[Keyslot], _issuance_floor_ms: i64) -> Vec<u8> { todo!() }
```

## crates/secrets-engine/src/vault (Store trait + canonical AAD)

```rust
// vault/aad.rs — fixed-width canonical AAD, recomputed at decrypt, NEVER stored (HF-2).
#[repr(u8)] pub enum TableTag { SecretVersion = 1, CaKey = 2, Cert = 3, HmacKey = 4 }
pub fn record_aad(_tag: TableTag, _row_id: u64, _version: u64, _dek_generation: u64) -> Vec<u8> { todo!() }

// vault/store.rs — backend behind a trait (OI-1). Phase 0 ships only InMemStore.
#[cfg(all(not(feature = "inmem-store")))]
compile_error!("select a store backend feature (inmem-store, or the OI-1-ruled pure-Rust backend)");
pub trait Store: Send + Sync {
    fn get_meta(&self, k: &str) -> anyhow::Result<Option<String>>;
    fn put_meta(&self, k: &str, v: &str) -> anyhow::Result<()>;
    fn append_audit(&self, rec: &crate::event::AuditRecord) -> anyhow::Result<i64>; // DURABLE (HF-14)
    fn verify_audit_chain(&self) -> anyhow::Result<()>;
    // ... secrets/keyslots/relay/ca CRUD; full set in Phase 1 ...
}
pub struct InMemStore; // RAM-only test analogue
impl Store for InMemStore { /* todo!() bodies */ }
```

## crates/secrets-engine/src/broker (policy + decide + token + clamp_ttl + SwapOutcome)

```rust
// policy.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] pub enum Provider { Anthropic, Openai, Github, Generic }
// canonical upstream host allowlist per provider (HF-11) — REFUSE swap to anything else.
pub fn canonical_upstreams(_p: Provider) -> &'static [&'static str] { todo!() } // Anthropic=>["api.anthropic.com"], ...
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] pub enum Method { Get, Head, Post, Put, Patch, Delete, Connect, Options }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] pub enum RelayKind { Named, Ephemeral }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SwapMode { BaseUrlRepoint { upstream_base: String }, ProxyMitm, NativeSubToken { ttl_secs: i64 } }
#[derive(Clone, Debug, Serialize, Deserialize)] pub struct RelayId(pub String);
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayPolicy {
    pub relay_id: String, pub kind: RelayKind, pub provider: Provider, pub secret_name: String,
    pub swap: SwapMode, pub host_allow: Vec<String>, pub path_allow: Vec<String>, pub method_allow: Vec<Method>,
    pub policy_ttl_secs: i64, pub rate_per_min: Option<u32>, pub quota_total: Option<u64>,
    pub enabled: bool, pub revoked: bool,
}
// the minted wire bearer (returned to clients; hash stored, raw never persists)
pub struct Bearer { pub relay_id: String, pub token_id: String, pub raw: zeroize::Zeroizing<String>, pub expires_at: String }
pub const MAX_BEARER_TTL_SECS: i64 = 24 * 60 * 60;
// REVIEW FIX (HF-15): single choke point, 3 args, saturating, clamps requested AND policy AND ceiling.
pub fn clamp_ttl(now: i64, policy_ttl_secs: i64, requested_ttl_secs: i64) -> Option<i64> {
    let ttl = requested_ttl_secs.min(policy_ttl_secs).min(MAX_BEARER_TTL_SECS);
    if ttl <= 0 { return None; }                       // refuse dead/negative TTL (FS-S3)
    Some(now.saturating_add(ttl))
}

// decide.rs (PURE, sync, default-deny)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RelayDecision { Allow, Deny { reason: DenyReason } }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason { UnknownBearer, Disabled, Revoked, BearerRevoked, BearerExpired, PolicyExpired,
    HostNotAllowed, PathNotAllowed, MethodNotAllowed, UpstreamNotAllowed, PeerMismatch, SniHostMismatch,
    BudgetRequests, BudgetBytes, RateLimited, GateAbsent, ClockRollback }
// CanonRequest carries the verified Bearer ROW (HF-7), the inner host (HF-9), and peer (HF-8).
pub struct VerifiedBearer { pub policy_id: i64, pub token_id: String, pub expires_at_ms: i64,
    pub issued_at_ms: i64, pub client_uid: Option<u32>, pub client_pid: Option<u32>, pub revoked: bool }
pub struct CanonRequest { pub method: Method, pub host: String, pub sni: Option<String>,
    pub path: String, pub bytes_out: u64, pub peer_uid: Option<u32>, pub peer_pid: Option<u32> }
// takes the verified row by value (not a loose expires_at) + the gate + the floor; asserts policy match.
pub fn decide(_p: &RelayPolicy, _b: &VerifiedBearer, _req: &CanonRequest,
    _now_ms: i64, _usb_absent_since_ms: Option<i64>, _issuance_floor_ms: i64) -> RelayDecision { todo!() }

// token.rs
pub fn verify_bearer(_hmac_key: &[u8; 32], _presented: &str, _stored_mac: &[u8]) -> bool { todo!() } // subtle ct-eq

// mod.rs — the swap path returns SwapOutcome (default-deny by construction, CF-9): the real key is
// fetched ONLY inside Allowed; any internal error => InternalRefused (a durable-audited 403), never send().
pub enum SwapOutcome { Allowed(crate::EgressResp), Denied(DenyReason), InternalRefused(String) }
pub struct Broker; // policies, verifiers, budgets, hmac_key, adapters
```

## crates/secrets-engine/src/inject.rs

```rust
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] pub enum DataPlaneMode { BaseUrlRepoint, HttpsProxyMitm, NativeSubtoken }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedInjection {
    pub provider: crate::broker::Provider, pub mode: DataPlaneMode,
    pub env: std::collections::BTreeMap<String, String>,   // ANTHROPIC_BASE_URL, ANTHROPIC_API_KEY=<bearer>, ...
    pub ca_env_keys: Vec<String>, pub proxy_url: Option<String>, pub base_url: Option<String>,
}
pub struct ChildEnvPlan { pub injection: ResolvedInjection, pub child_pid_hint: Option<u32> } // pid-bound bearer (HF-8)
// engine-owned provider table; the CLI stays dumb.
pub fn injection_template(_p: crate::broker::Provider, _bearer: &str, _proxy: &str, _ca_pem_path: &str) -> ResolvedInjection { todo!() }
// fail-closed profile discovery: only operator-trusted roots / at-or-below cwd; named-relay attach needs confirm (FS-S15).
pub fn discover_profile(_cwd: &std::path::Path, _trusted_roots: &[std::path::PathBuf]) -> Option<std::path::PathBuf> { todo!() }
```

## crates/secrets-proto/Cargo.toml + build.rs + lib.rs (proto vendored in-crate)

```toml
[package]
name = "envctl-secrets-proto"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
include = ["src/**", "proto/**", "build.rs"]   # REVIEW FIX (OI-15): self-contained, drops in verbatim on merge
[lib]
name = "envctl_secrets_proto"
path = "src/lib.rs"
[dependencies]
tonic = { workspace = true }
prost = { workspace = true }
[build-dependencies]
tonic-build = { workspace = true }   # pulls prost-build
```
```rust
// build.rs — reference the VENDORED proto via CARGO_MANIFEST_DIR (REVIEW FIX OI-15: was ../../proto)
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")?;
    let proto = std::path::Path::new(&manifest).join("proto/control.proto");
    tonic_build::compile_protos(proto)?;
    Ok(())
}
// src/lib.rs
pub mod v1 { tonic::include_proto!("env_ctl.v1"); }
```

## crates/secretd/Cargo.toml (embedded verbatim — the ONLY place network/runtime deps live)

```toml
[package]
name = "envctl-secretd"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
[[bin]]
name = "secretd"
path = "src/main.rs"
[dependencies]
envctl-secrets-engine = { workspace = true }
envctl-secrets-proto  = { workspace = true }
tokio = { workspace = true }
tonic = { workspace = true }
prost = { workspace = true }
tower = { workspace = true }
hyper = { workspace = true }
hyper-util = { workspace = true }
http-body-util = { workspace = true }
reqwest = { workspace = true }
rustls = { workspace = true }
rustls-pemfile = { workspace = true }
webpki-roots = { workspace = true }   # frozen upstream root store (FS-S7)
anyhow = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
rustix = { workspace = true }
clap = { workspace = true }
```
`src/main.rs` (Phase-0): `#[tokio::main] async fn main()` that installs `rustls::crypto::ring::default_provider()` (CF-2), calls `mlockall`+`RLIMIT_CORE=0` (refuse to start on failure, HF-4), builds an `Engine`, sets up tracing-subscriber, and `todo!()`s the server bring-up. `src/peercred.rs`: a tower interceptor reading `SO_PEERCRED` via rustix `getsockopt`, refusing uid != owner. `src/proxy.rs`: a hyper server implementing `Upstream` via reqwest built with an explicit `RootCertStore` from `webpki_roots::TLS_SERVER_ROOTS` ONLY (never OS store / local CA); `todo!()` bodies. `src/audit.rs`: drains the cosmetic `SecretEvent` stream to the gRPC server-stream + on-disk log, while security outcomes are committed durably by the engine before each RPC returns.

## crates/secretctl/Cargo.toml (embedded verbatim) + clap tree

```toml
[package]
name = "envctl-secretctl"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
[[bin]]
name = "secretctl"
path = "src/main.rs"
[dependencies]
envctl-secrets-proto = { workspace = true }
tonic = { workspace = true }
tokio = { workspace = true, features = ["rt-multi-thread", "macros", "net"] }
clap = { workspace = true }
anyhow = { workspace = true }
serde_json = { workspace = true }
tracing-subscriber = { workspace = true }
```
clap tree (Phase-0 prints "not yet implemented", exit via `RunSummary::ok()`; destructive verbs default to dry-run, `--apply` to execute, `--confirm` for root-of-trust):
```
env-ctl [--json] [--socket <path>] <SUBCOMMAND>
  status | unlock [--passphrase-stdin] | lock
  secret  add <NAME> --provider <P> [--value-stdin] [--note <S>] [--overwrite] [--broker-only]
          get <NAME> [--reveal] [--apply] [--confirm]    # reveal is apply-gated + audited; broker-only refuses
          list [--provider <P>]
          rm <NAME> [--apply] [--confirm] | rotate <NAME> [--value-stdin] [--apply]
  relay   create <NAME> --secret <S> --provider <P> --mode <base-url|proxy|native>
                 [--upstream-base <URL>] [--host <H>...] [--path <PFX>...] [--method <M>...]
                 [--expires <DUR>] [--rate <N>] [--quota <N>] [--disabled]
          revoke <NAME> [--apply] [--confirm]
          revoke-token <TOKEN_ID> [--apply]               # single-bearer revocation (OI-10)
          list [--all] | mint <NAME> [--ttl <DUR<=24h>]
  ca      init [--apply] | rotate [--apply] [--confirm]
          issue <CN> [--san <S>...] [--ttl-days <N>] --usage <control-server|control-client>  # NEVER mitm_leaf
          renew <CN> [--apply] | revoke <CN> [--apply] [--confirm]
          trust [<target>...] [--system-bundle] [--apply] [--confirm]   # system-bundle = root-of-trust
  audit   [--actor <A>] [--relay <R>] [--since <T>] [--until <T>] [--limit <N>]
  run     [--relay <NAME>...] [--provider <P>] [--ephemeral] [--no-profile] [--profile <PATH>] -- <cmd> [args...]
```

## Build notes
- Pin `rustls = 0.23` AND `rcgen = 0.13` with `default-features = false` on the **ring** path; daemon installs the ring `CryptoProvider`. CI: `! cargo tree -i aws-lc-sys`, exactly one `rustls` node, ZERO `openssl-sys`.
- **No C deps gate:** `! cargo tree | grep -E 'libsql-ffi|sqlite3-sys|openssl-sys|aws-lc-sys'`. The libSQL row is intentionally absent pending OI-1.
- `reqwest` MUST be `default-features=false, ["rustls-tls","http2","stream"]` (no native-tls); the daemon seeds its upstream `RootCertStore` from `webpki_roots::TLS_SERVER_ROOTS` only (never native/OS roots) — forbid `rustls-tls-native-roots`/`danger_accept_invalid_certs` by CI grep.
- rcgen MUST resolve to the ring path, not aws-lc-rs.
- `secrets-engine` links NO tokio/tonic/hyper; verify with `cargo tree -p envctl-secrets-engine`.
- **MSRV gate:** `cargo +1.80.0 check --workspace` (the floating `stable` in rust-toolchain.toml is dev-only); pin `idna`/`icu` patch versions if 1.80 must hold.
- **Feature matrix:** build engine for `{default}`, `{--no-default-features --features inmem-store}`, `{inmem-store,mitm-ca}`; the `compile_error!` guard enforces exactly-one store backend.
- Phase-0 unit tests: (1) all-uncertain `UnlockContext` => every `SecGuard` refuses; (2) a default-constructed destructive proto request is dry-run (CF-8); (3) one `RelayPolicy` TOML deserializes; (4) `SwapMode`/`Kdf` round-trip; (5) proto `Event` <-> `SecretEvent` round-trip; (6) `EventSink::channel()`/`null()` emit/drain; (7) `clamp_ttl` never yields `expires - now > 86400` and refuses `<=0` ttl.
```
