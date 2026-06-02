//! The credential broker (virtual-credit-card model): real keys never leave the daemon; per-client
//! relay bearers are swapped for the real key at egress. Bearers rotate `<=24h` and are
//! USB-presence-gated.
pub mod adapter;
pub mod decide;
pub mod policy;
pub mod token;

pub use decide::{decide, CanonRequest, DenyReason, RelayDecision, VerifiedBearer};
pub use policy::{
    canonical_upstreams, clamp_ttl, Bearer, Method, Provider, RelayId, RelayKind, RelayPolicy,
    SwapMode, MAX_BEARER_TTL_SECS,
};
pub use token::verify_bearer;

/// The outcome of the egress swap path — default-deny by construction (CF-9). The real key is
/// fetched ONLY to build `Allowed`; any internal error becomes `InternalRefused` (a
/// durable-audited 403), never an upstream `send()`.
pub enum SwapOutcome {
    Allowed(crate::EgressResp),
    Denied(DenyReason),
    InternalRefused(String),
}

/// In-RAM broker state: policies, bearer verifiers, budgets, the bearer HMAC key, and adapters.
pub struct Broker;
