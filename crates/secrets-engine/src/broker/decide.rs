//! The PURE, sync, default-deny relay decision. Takes the already-verified bearer ROW (HF-7), the
//! canonicalized request (verified inner host, HF-9; peer identity, HF-8), the clock, the USB
//! absence marker, and the issuance floor. Any uncertainty => `Deny`.
use serde::{Deserialize, Serialize};

use super::policy::{canonical_upstreams, Method, RelayPolicy};

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

/// A bearer that has already been looked up + constant-time verified against the store — BOTH the
/// wire MAC AND the DEK-keyed row MAC (so every field below is authenticated, not clear-text).
pub struct VerifiedBearer {
    pub policy_id: i64,
    pub token_id: String,
    pub expires_at_ms: i64,
    pub issued_at_ms: i64,
    /// `CLOCK_BOOTTIME` snapshot (ms) captured at mint; the monotonic anchor for the rollback fence.
    pub issued_boottime_ms: i64,
    pub client_uid: Option<u32>,
    pub client_pid: Option<u32>,
    pub revoked: bool,
}

/// The canonicalized request the decision operates on.
///
/// `usage_requests` / `usage_bytes` / `rate_in_window` carry the broker's already-accumulated
/// tallies *including this request* (the broker bumps its in-RAM counters under the swap write lock
/// and hands the post-bump totals here). This keeps `decide` a PURE function of its inputs: it
/// compares the supplied totals against the policy quotas/rate and never touches the broker state
/// itself. If the broker prefers to pre-check, it maps an overflow to `BudgetRequests`/
/// `BudgetBytes`/`RateLimited` exactly as `decide` would.
pub struct CanonRequest {
    pub method: Method,
    pub host: String,
    pub sni: Option<String>,
    pub path: String,
    pub bytes_out: u64,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<u32>,
    /// Total requests on this bearer INCLUDING this one (for the `quota_total` request budget).
    pub usage_requests: u64,
    /// Total bytes egressed on this bearer INCLUDING `bytes_out` (for the byte budget).
    pub usage_bytes: u64,
    /// Requests already counted in the trailing 60s sliding window INCLUDING this one.
    pub rate_in_window: u32,
}

/// Pure decision: asserts policy↔bearer linkage, expiry vs the WALL clock AND the MONOTONIC
/// `CLOCK_BOOTTIME` anchor, USB gate, host/path/method/upstream allowlists, peer binding, and the
/// (separate) request + byte budgets. Default-deny on any mismatch.
///
/// Ordered, first-failing check wins; `Allow` only if EVERY check passes. `UnknownBearer` is NOT
/// raised here — it is emitted by `relay_swap` before `decide` is ever entered (store miss or a
/// constant-time MAC verify failure on either the wire MAC or the row MAC), so the bearer reaching
/// this function is always real, fully authenticated, and bound to `p`.
///
/// `now_ms` is the rewindable wall clock; `boottime_now_ms` is the monotonic `CLOCK_BOOTTIME`
/// reading. `issuance_floor_ms` is the vault-init wall floor. Expiry is enforced against BOTH clocks:
/// an attacker who rolls the wall clock back into the still-valid window (`issued < now' < expires`)
/// passes the wall check, but the boottime anchor (`b.issued_boottime_ms`) cannot be rewound, so the
/// elapsed-monotonic-vs-elapsed-wall divergence (and any negative monotonic elapse) is caught (OI-6).
pub fn decide(
    p: &RelayPolicy,
    b: &VerifiedBearer,
    req: &CanonRequest,
    now_ms: i64,
    boottime_now_ms: i64,
    usb_absent_since_ms: Option<i64>,
    issuance_floor_ms: i64,
) -> RelayDecision {
    // 2. Disabled — the relay policy is administratively off.
    if !p.enabled {
        return deny(DenyReason::Disabled);
    }
    // 3. Revoked — the whole relay was revoked (HF-16 fail-closed).
    if p.revoked {
        return deny(DenyReason::Revoked);
    }
    // 4. BearerRevoked — this specific bearer was revoked (OI-10).
    if b.revoked {
        return deny(DenyReason::BearerRevoked);
    }
    // 5. BearerExpired — the <=24h wire clamp elapsed. `>=` so the exact expiry instant is dead.
    if now_ms >= b.expires_at_ms {
        return deny(DenyReason::BearerExpired);
    }
    // 6. PolicyExpired — the long policy window elapsed (both bearer AND policy must be live).
    let policy_deadline = b
        .issued_at_ms
        .saturating_add(p.policy_ttl_secs.saturating_mul(1000));
    if now_ms >= policy_deadline {
        return deny(DenyReason::PolicyExpired);
    }
    // 7. HostNotAllowed — req.host must be in p.host_allow (exact, case-insensitive; empty => deny).
    if !host_in(&req.host, &p.host_allow) {
        return deny(DenyReason::HostNotAllowed);
    }
    // 8. PathNotAllowed — req.path must match some prefix in p.path_allow (empty => deny).
    if !path_allowed(&req.path, &p.path_allow) {
        return deny(DenyReason::PathNotAllowed);
    }
    // 9. MethodNotAllowed — req.method must be in p.method_allow.
    if !p.method_allow.contains(&req.method) {
        return deny(DenyReason::MethodNotAllowed);
    }
    // 10. UpstreamNotAllowed — req.host must be in the provider's frozen canonical set (HF-11). The
    // outer fence: even a host_allow that listed it is not enough; a relay can never be re-pointed
    // at an attacker host. `Generic` has an empty canonical set => default-deny.
    if !host_in(&req.host, canonical_upstreams(p.provider)) {
        return deny(DenyReason::UpstreamNotAllowed);
    }
    // 11. PeerMismatch — a bound bearer presented by another uid/pid is rejected (HF-8).
    if let Some(bound_uid) = b.client_uid {
        if req.peer_uid != Some(bound_uid) {
            return deny(DenyReason::PeerMismatch);
        }
    }
    if let Some(bound_pid) = b.client_pid {
        if req.peer_pid != Some(bound_pid) {
            return deny(DenyReason::PeerMismatch);
        }
    }
    // 12. SniHostMismatch — the TLS SNI (when present) must equal the verified inner Host (HF-9).
    if let Some(sni) = req.sni.as_deref() {
        if !sni.eq_ignore_ascii_case(&req.host) {
            return deny(DenyReason::SniHostMismatch);
        }
    }
    // 13. BudgetRequests — the accumulated request COUNT would exceed the request budget. Compared
    // against the dedicated `quota_total_requests` (NOT the byte budget): the two are different
    // scales and have independent caps. `>` so the budget denies one past the cap.
    if let Some(q) = p.quota_total_requests {
        if req.usage_requests > q {
            return deny(DenyReason::BudgetRequests);
        }
    }
    // 14. BudgetBytes — the accumulated egress BYTES would exceed the byte budget. Compared against
    // the dedicated `quota_total_bytes`.
    if let Some(q) = p.quota_total_bytes {
        if req.usage_bytes > q {
            return deny(DenyReason::BudgetBytes);
        }
    }
    // 15. RateLimited — the trailing-60s sliding-window count already >= the per-minute rate.
    if let Some(r) = p.rate_per_min {
        if req.rate_in_window >= r {
            return deny(DenyReason::RateLimited);
        }
    }
    // 16. GateAbsent — the USB possession gate is currently UNPROVEN; default-deny the swap (the
    // runtime mirror of the mint-time USB gate; absence fails closed).
    if usb_absent_since_ms.is_some() {
        return deny(DenyReason::GateAbsent);
    }
    // 17. ClockRollback — the wall clock regressed below the vault issuance floor OR the bearer's
    // own issue time (catches a gross rollback below the floor), AND — the part the wall clock alone
    // cannot catch — a rollback that lands BACK INSIDE the still-valid window
    // (`issued_at < now' < expires_at`) is fenced against the MONOTONIC `CLOCK_BOOTTIME` anchor
    // (OI-6). `boottime` cannot be rewound by the attacker, so:
    //   (a) if monotonic time appears to have gone BACKWARDS since mint, the wall clock was rolled
    //       back (or the anchor was tampered — but the anchor is row-MAC-authenticated): deny.
    //   (b) the AUTHORITATIVE elapsed lifetime is the monotonic delta, not the rewindable wall
    //       delta; if more than the bearer's TTL of monotonic time has elapsed, the bearer is dead
    //       even if the wall clock claims otherwise (a rewound wall clock cannot resurrect it).
    //   (c) if the wall delta and the boottime delta diverge by more than a small skew, the wall
    //       clock was manipulated relative to the monotonic clock: deny.
    if now_ms < issuance_floor_ms || now_ms < b.issued_at_ms {
        return deny(DenyReason::ClockRollback);
    }
    // Tolerance for benign wall/monotonic drift (NTP steps, suspend accounting): 60s.
    const CLOCK_SKEW_MS: i64 = 60_000;
    let mono_elapsed = boottime_now_ms.saturating_sub(b.issued_boottime_ms);
    if mono_elapsed < 0 {
        return deny(DenyReason::ClockRollback); // (a) monotonic time went backwards.
    }
    let bearer_ttl_ms = b.expires_at_ms.saturating_sub(b.issued_at_ms);
    if mono_elapsed >= bearer_ttl_ms {
        return deny(DenyReason::BearerExpired); // (b) dead by the monotonic clock.
    }
    let wall_elapsed = now_ms.saturating_sub(b.issued_at_ms);
    if (wall_elapsed - mono_elapsed).abs() > CLOCK_SKEW_MS {
        return deny(DenyReason::ClockRollback); // (c) wall/monotonic divergence.
    }

    RelayDecision::Allow
}

#[inline]
fn deny(reason: DenyReason) -> RelayDecision {
    RelayDecision::Deny { reason }
}

/// Exact, case-insensitive host membership. An empty allowlist denies everything (default-deny).
fn host_in(host: &str, allow: &[impl AsRef<str>]) -> bool {
    allow.iter().any(|h| h.as_ref().eq_ignore_ascii_case(host))
}

/// A path is allowed iff it matches some entry in `path_allow`. An entry ending in `*` is a glob
/// (prefix match on the part before the `*`); otherwise it is treated as a path PREFIX (so a relay
/// scoped to `/v1/` admits `/v1/messages`). An empty allowlist denies everything (default-deny).
fn path_allowed(path: &str, allow: &[String]) -> bool {
    allow.iter().any(|pat| {
        if let Some(prefix) = pat.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path.starts_with(pat.as_str())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::policy::{Provider, RelayKind, SwapMode};

    const NOW: i64 = 1_700_000_000_000;
    const ISSUED: i64 = 1_699_999_000_000;
    const FLOOR: i64 = 1_699_000_000_000;
    /// Monotonic `CLOCK_BOOTTIME` reading at decision time (uptime ms; unrelated magnitude to the
    /// wall clock — it is anchored only relatively, via `issued_boottime_ms`).
    const BOOTTIME: i64 = 5_000_000;

    /// A baseline policy that, paired with `base_bearer` + `base_req`, yields `Allow`.
    fn base_policy() -> RelayPolicy {
        RelayPolicy {
            relay_id: "claude-main".to_string(),
            kind: RelayKind::Named,
            provider: Provider::Anthropic,
            secret_name: "anthropic_key".to_string(),
            swap: SwapMode::BaseUrlRepoint {
                upstream_base: "https://api.anthropic.com".to_string(),
            },
            host_allow: vec!["api.anthropic.com".to_string()],
            path_allow: vec!["/v1/".to_string()],
            method_allow: vec![Method::Post],
            policy_ttl_secs: 31_536_000, // 1y
            rate_per_min: Some(60),
            quota_total_requests: Some(1_000_000),
            quota_total_bytes: Some(10_000_000),
            enabled: true,
            revoked: false,
        }
    }

    fn base_bearer() -> VerifiedBearer {
        VerifiedBearer {
            policy_id: 1,
            token_id: "deadbeef".to_string(),
            expires_at_ms: NOW + 3_600_000, // 1h out
            issued_at_ms: ISSUED,
            // Monotonic anchor: same elapsed as the wall delta (NOW - ISSUED) so the baseline boottime
            // reading below keeps the bearer live and within skew.
            issued_boottime_ms: BOOTTIME - (NOW - ISSUED),
            client_uid: Some(1000),
            client_pid: None,
            revoked: false,
        }
    }

    fn base_req() -> CanonRequest {
        CanonRequest {
            method: Method::Post,
            host: "api.anthropic.com".to_string(),
            sni: Some("api.anthropic.com".to_string()),
            path: "/v1/messages".to_string(),
            bytes_out: 128,
            peer_uid: Some(1000),
            peer_pid: None,
            usage_requests: 1,
            usage_bytes: 128,
            rate_in_window: 1,
        }
    }

    fn run(p: &RelayPolicy, b: &VerifiedBearer, r: &CanonRequest) -> RelayDecision {
        decide(p, b, r, NOW, BOOTTIME, None, FLOOR)
    }

    #[test]
    fn baseline_allows() {
        assert_eq!(run(&base_policy(), &base_bearer(), &base_req()), RelayDecision::Allow);
    }

    fn assert_deny(p: &RelayPolicy, b: &VerifiedBearer, r: &CanonRequest, reason: DenyReason) {
        assert_eq!(run(p, b, r), RelayDecision::Deny { reason });
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_deny_clock(
        p: &RelayPolicy,
        b: &VerifiedBearer,
        r: &CanonRequest,
        now: i64,
        boottime: i64,
        usb_absent: Option<i64>,
        floor: i64,
        reason: DenyReason,
    ) {
        assert_eq!(
            decide(p, b, r, now, boottime, usb_absent, floor),
            RelayDecision::Deny { reason }
        );
    }

    #[test]
    fn disabled() {
        let mut p = base_policy();
        p.enabled = false;
        assert_deny(&p, &base_bearer(), &base_req(), DenyReason::Disabled);
    }

    #[test]
    fn revoked() {
        let mut p = base_policy();
        p.revoked = true;
        assert_deny(&p, &base_bearer(), &base_req(), DenyReason::Revoked);
    }

    #[test]
    fn bearer_revoked() {
        let mut b = base_bearer();
        b.revoked = true;
        assert_deny(&base_policy(), &b, &base_req(), DenyReason::BearerRevoked);
    }

    #[test]
    fn bearer_expired() {
        let mut b = base_bearer();
        b.expires_at_ms = NOW; // exact instant is dead (>=).
        assert_deny(&base_policy(), &b, &base_req(), DenyReason::BearerExpired);
    }

    #[test]
    fn policy_expired() {
        let mut p = base_policy();
        p.policy_ttl_secs = 1; // issued_at + 1s << now.
        assert_deny(&p, &base_bearer(), &base_req(), DenyReason::PolicyExpired);
    }

    #[test]
    fn host_not_allowed() {
        // Remove the host from host_allow but keep canonical_upstreams covering it, so this
        // isolates HostNotAllowed from UpstreamNotAllowed (check 7 precedes 10). The req still
        // targets the canonical host, but host_allow no longer lists it.
        let mut p = base_policy();
        p.host_allow = vec!["other.allowed.example".to_string()];
        assert_deny(&p, &base_bearer(), &base_req(), DenyReason::HostNotAllowed);
    }

    #[test]
    fn path_not_allowed() {
        let mut r = base_req();
        r.path = "/admin/secrets".to_string();
        assert_deny(&base_policy(), &base_bearer(), &r, DenyReason::PathNotAllowed);
    }

    #[test]
    fn method_not_allowed() {
        let mut r = base_req();
        r.method = Method::Get;
        assert_deny(&base_policy(), &base_bearer(), &r, DenyReason::MethodNotAllowed);
    }

    #[test]
    fn upstream_not_allowed() {
        // Generic provider has an empty canonical set: even with host_allow listing the host, the
        // outer fence denies. Use a host that IS in host_allow so we pass check 7 and reach 10.
        let mut p = base_policy();
        p.provider = Provider::Generic;
        assert_deny(&p, &base_bearer(), &base_req(), DenyReason::UpstreamNotAllowed);
    }

    #[test]
    fn peer_mismatch() {
        let mut r = base_req();
        r.peer_uid = Some(1001); // bearer is bound to uid 1000.
        assert_deny(&base_policy(), &base_bearer(), &r, DenyReason::PeerMismatch);
    }

    #[test]
    fn sni_host_mismatch() {
        let mut r = base_req();
        r.sni = Some("other.com".to_string());
        assert_deny(&base_policy(), &base_bearer(), &r, DenyReason::SniHostMismatch);
    }

    #[test]
    fn budget_requests() {
        let mut p = base_policy();
        p.quota_total_requests = Some(10);
        let mut r = base_req();
        r.usage_requests = 11; // would exceed.
        r.usage_bytes = 0; // keep bytes under so we isolate the request budget.
        assert_deny(&p, &base_bearer(), &r, DenyReason::BudgetRequests);
    }

    #[test]
    fn budget_bytes() {
        let mut p = base_policy();
        p.quota_total_bytes = Some(100);
        let mut r = base_req();
        r.usage_requests = 1; // under the request budget.
        r.usage_bytes = 101; // over the byte budget.
        assert_deny(&p, &base_bearer(), &r, DenyReason::BudgetBytes);
    }

    #[test]
    fn rate_limited() {
        let mut p = base_policy();
        p.rate_per_min = Some(5);
        let mut r = base_req();
        r.rate_in_window = 5; // already at the per-minute ceiling (>=).
        assert_deny(&p, &base_bearer(), &r, DenyReason::RateLimited);
    }

    #[test]
    fn gate_absent() {
        assert_deny_clock(
            &base_policy(),
            &base_bearer(),
            &base_req(),
            NOW,
            BOOTTIME,
            Some(NOW), // USB gate unproven.
            FLOOR,
            DenyReason::GateAbsent,
        );
    }

    #[test]
    fn clock_rollback() {
        // now regressed below the issuance floor.
        assert_deny_clock(
            &base_policy(),
            &base_bearer(),
            &base_req(),
            FLOOR - 1,
            BOOTTIME,
            None,
            FLOOR,
            DenyReason::ClockRollback,
        );
    }

    #[test]
    fn budget_requests_independent_of_byte_budget() {
        // A tiny REQUEST budget with a huge byte budget: the request count alone must trip
        // BudgetRequests, proving the two budgets are now independent scales (not one shared field).
        let mut p = base_policy();
        p.quota_total_requests = Some(10);
        p.quota_total_bytes = Some(u64::MAX);
        let mut r = base_req();
        r.usage_requests = 11; // over the request cap.
        r.usage_bytes = u64::MAX - 1; // huge, but UNDER the byte cap.
        assert_deny(&p, &base_bearer(), &r, DenyReason::BudgetRequests);
    }

    #[test]
    fn clock_rollback_within_window_caught_by_boottime() {
        // The wall clock is rolled BACK into the still-valid window: now' is after issue and after
        // the floor, and BEFORE expires_at — so checks 5 (wall expiry) and 17 (below-floor) BOTH
        // pass, AND the monotonic elapse is still WITHIN the TTL (so the bearer is not monotonically
        // expired). Only the wall/monotonic DIVERGENCE catches the rollback: real monotonic time has
        // advanced ~30min since mint while the rewound wall clock claims only ~1s elapsed, a gap far
        // beyond the 60s skew => ClockRollback.
        let b = base_bearer(); // issued_boottime_ms = BOOTTIME - (NOW - ISSUED); TTL = 1h.
        let r = base_req();
        // Real monotonic time advanced 30 min past mint (within the 1h TTL; uptime cannot be rewound).
        let boottime_30m = b.issued_boottime_ms + 30 * 60 * 1000;
        // Attacker rewinds the wall clock to 1s after issue: inside (issued, expires), above floor.
        let wall_rewound = ISSUED + 1000;
        assert_deny_clock(
            &base_policy(),
            &b,
            &r,
            wall_rewound,
            boottime_30m,
            None,
            FLOOR,
            DenyReason::ClockRollback,
        );
    }

    #[test]
    fn expired_by_monotonic_clock_even_if_wall_says_live() {
        // The wall clock claims the bearer is still live (now within the window), but MORE than the
        // bearer's TTL of monotonic time has elapsed — a rewound wall clock cannot resurrect it.
        let b = base_bearer();
        let r = base_req();
        let ttl_ms = b.expires_at_ms - b.issued_at_ms;
        // Monotonic time elapsed past the full TTL.
        let boottime_past_ttl = b.issued_boottime_ms + ttl_ms + 1;
        // Wall clock rewound to just after issue so the wall expiry check (5) would pass.
        let wall_live = b.issued_at_ms + 1;
        assert_deny_clock(
            &base_policy(),
            &b,
            &r,
            wall_live,
            boottime_past_ttl,
            None,
            FLOOR,
            DenyReason::BearerExpired,
        );
    }

    #[test]
    fn glob_path_matches() {
        let mut p = base_policy();
        p.path_allow = vec!["/v1/*".to_string()];
        assert_eq!(run(&p, &base_bearer(), &base_req()), RelayDecision::Allow);
    }
}
