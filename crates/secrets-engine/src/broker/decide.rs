//! The PURE, sync, default-deny relay decision. Takes the already-verified bearer ROW (HF-7), the
//! canonicalized request (verified inner host, HF-9; peer identity, HF-8), the clock, the USB
//! absence marker, and the issuance floor. Any uncertainty => `Deny`.
use serde::{Deserialize, Serialize};

use super::policy::{Method, RelayPolicy};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RelayDecision {
    Allow,
    Deny { reason: DenyReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    UnknownBearer,
    Disabled,
    Revoked,
    BearerRevoked,
    BearerExpired,
    PolicyExpired,
    HostNotAllowed,
    PathNotAllowed,
    MethodNotAllowed,
    UpstreamNotAllowed,
    PeerMismatch,
    SniHostMismatch,
    BudgetRequests,
    BudgetBytes,
    RateLimited,
    GateAbsent,
    ClockRollback,
}

/// A bearer that has already been looked up + constant-time verified against the store.
pub struct VerifiedBearer {
    pub policy_id: i64,
    pub token_id: String,
    pub expires_at_ms: i64,
    pub issued_at_ms: i64,
    pub client_uid: Option<u32>,
    pub client_pid: Option<u32>,
    pub revoked: bool,
}

/// The canonicalized request the decision operates on.
pub struct CanonRequest {
    pub method: Method,
    pub host: String,
    pub sni: Option<String>,
    pub path: String,
    pub bytes_out: u64,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<u32>,
}

/// Pure decision: asserts policy↔bearer linkage, expiry vs `now` AND boottime floor, USB gate,
/// host/path/method/upstream allowlists, peer binding, and budgets. Default-deny on any mismatch.
pub fn decide(
    _p: &RelayPolicy,
    _b: &VerifiedBearer,
    _req: &CanonRequest,
    _now_ms: i64,
    _usb_absent_since_ms: Option<i64>,
    _issuance_floor_ms: i64,
) -> RelayDecision {
    todo!()
}
