//! The credential broker (virtual-credit-card model): real keys never leave the daemon; per-client
//! relay bearers are swapped for the real key at egress. Bearers rotate `<=24h` and are
//! USB-presence-gated.
pub mod adapter;
pub mod decide;
pub mod policy;
pub mod token;

pub use decide::{decide, CanonRequest, DenyReason, RelayDecision, VerifiedBearer};
pub use decide::RemotePeer;
pub use policy::{
    canonical_upstreams, clamp_ttl, Bearer, Method, Provider, RelayId, RelayKind, RelayPolicy,
    SwapMode, MAX_BEARER_TTL_SECS,
};
pub use token::{mac_bearer, mac_bearer_row, verify_bearer, verify_bearer_row};

use std::collections::HashMap;

use crate::keyslot::Dek;
use zeroize::Zeroizing;

/// BLAKE3 `derive_key` context for the per-bearer HMAC key. DEK-keyed and domain-separated, distinct
/// from `AUDIT_HEAD_KEY_INFO`/`HEADER_MAC_KEY_INFO` and every other BLAKE3 use in the crate. Because
/// the key is a pure function of the DEK (never stored), the ability to MINT or VERIFY any bearer
/// dies the instant the vault locks and the DEK is zeroized.
pub const BEARER_HMAC_KEY_INFO: &str = "env-ctl/v1/relay-bearer/key";

/// BLAKE3 `derive_key` context for the per-bearer ROW-METADATA MAC key. Distinct from
/// `BEARER_HMAC_KEY_INFO` (the wire-string key) and every other BLAKE3 use in the crate, so the
/// row-metadata authenticator can never be confused with the wire-bearer authenticator. Like the
/// wire key it is a pure function of the DEK (never stored), so the ability to MINT, REVOKE, or
/// VERIFY a bearer row dies the instant the vault locks.
pub const BEARER_ROW_MAC_KEY_INFO: &str = "env-ctl/v1/relay-bearer/row-mac/key";

/// Domain-separation prefix for the bearer-row MAC message.
const BEARER_ROW_MAC_DOMAIN: &[u8] = b"env-ctl/v1/relay-bearer/row";

/// The fixed, versionable bearer namespace literal. A parser can reject anything that is not ours in
/// O(1) before any store hit; bumping the version (`evrelay2_…`) is a clean wire break.
pub const BEARER_PREFIX: &str = "evrelay_";

/// Derive the per-process bearer HMAC key from the LIVE DEK (on demand, never cached in RAM). The
/// returned 32 bytes are wrapped in `Zeroizing` so they are wiped at the end of the relay op's
/// scope; the broker holds NO key field, so locking the vault cannot leave a live key behind.
pub fn broker_hmac_key(dek: &Dek) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(BEARER_HMAC_KEY_INFO, &dek.0))
}

/// Derive the per-process bearer ROW-METADATA MAC key from the LIVE DEK (on demand, never cached).
/// Domain-separated from `broker_hmac_key`; same lifetime discipline (`Zeroizing`, no key field on
/// the broker), so locking the vault revokes the ability to mint/revoke/verify a bearer row.
pub fn broker_row_mac_key(dek: &Dek) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(BEARER_ROW_MAC_KEY_INFO, &dek.0))
}

/// The plane a bearer is bound to (F12: the row MAC encodes the plane so a cross-kind row tamper
/// fails at the crypto level, not only at the `decide()` logic clause). LOCAL binds the connecting
/// process (uid/pid); REMOTE binds a registered remote client + its DPoP key thumbprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BearerBinding {
    Local {
        peer_uid: Option<u32>,
        peer_pid: Option<u32>,
    },
    Remote {
        client_id: String,
        dpop_jkt: [u8; 32],
    },
}

/// Canonical, unambiguous byte encoding of the security-critical bearer-row fields that the row MAC
/// authenticates (CRITICAL fix: bind the clear-text row state into a DEK-keyed authenticator). Every
/// field that `decide` later trusts is length-prefixed / fixed-width so no two distinct rows can
/// collide on the same message:
///   kind(u8) ‖ token_id (len-prefixed) ‖ policy_id ‖ expires_at_ms ‖ issued_at_ms ‖ issued_boottime_ms
///   ‖ client_uid (tagged Option) ‖ client_pid (tagged Option)
///   ‖ client_id (tagged, len-prefixed Option) ‖ dpop_jkt (tagged, 32B Option) ‖ revoked
/// `kind` (0=local, 1=remote) PLANE-separates the MAC (F12): a local row tampered to add a
/// `client_id`, or a remote row stripped to a local one, produces a different message and fails the
/// MAC — so cross-plane forgery is caught at the crypto level, before `decide()`. `revoked` is bound
/// directly; the engine recomputes the MAC at mint AND revoke (DEK live) so a legitimate write stays
/// valid while any store-level tamper fails closed (`UnknownBearer`).
#[allow(clippy::too_many_arguments)]
pub fn bearer_row_mac_message(
    token_id: &str,
    policy_id: i64,
    expires_at_ms: i64,
    issued_at_ms: i64,
    issued_boottime_ms: i64,
    client_uid: Option<u32>,
    client_pid: Option<u32>,
    client_id: Option<&str>,
    dpop_jkt: Option<&[u8; 32]>,
    revoked: bool,
) -> Vec<u8> {
    let tid = token_id.as_bytes();
    let cid = client_id.map(|s| s.as_bytes());
    let kind: u8 = if client_id.is_some() { 1 } else { 0 };
    let mut m = Vec::with_capacity(
        BEARER_ROW_MAC_DOMAIN.len() + 1 + 8 + tid.len() + 8 * 4 + 2 * 5 + 9 + cid.map_or(0, |c| c.len()) + 33 + 1,
    );
    m.extend_from_slice(BEARER_ROW_MAC_DOMAIN);
    m.push(kind);
    m.extend_from_slice(&(tid.len() as u64).to_be_bytes());
    m.extend_from_slice(tid);
    m.extend_from_slice(&policy_id.to_be_bytes());
    m.extend_from_slice(&expires_at_ms.to_be_bytes());
    m.extend_from_slice(&issued_at_ms.to_be_bytes());
    m.extend_from_slice(&issued_boottime_ms.to_be_bytes());
    encode_opt_u32(&mut m, client_uid);
    encode_opt_u32(&mut m, client_pid);
    encode_opt_bytes(&mut m, cid);
    encode_opt_jkt(&mut m, dpop_jkt);
    m.push(revoked as u8);
    m
}

/// Tagged, fixed-width `Option<u32>` encoding: a `0x00` tag + 4 zero bytes for `None`, a `0x01` tag
/// + big-endian value for `Some`, so `None` and `Some(0)` never alias.
fn encode_opt_u32(m: &mut Vec<u8>, v: Option<u32>) {
    match v {
        None => {
            m.push(0u8);
            m.extend_from_slice(&[0u8; 4]);
        }
        Some(x) => {
            m.push(1u8);
            m.extend_from_slice(&x.to_be_bytes());
        }
    }
}

/// Tagged, length-prefixed `Option<&[u8]>` encoding: a `0x00` tag for `None`; a `0x01` tag + a
/// big-endian u64 length + the bytes for `Some` (so `None` and `Some("")` never alias, and no two
/// distinct values collide).
fn encode_opt_bytes(m: &mut Vec<u8>, v: Option<&[u8]>) {
    match v {
        None => m.push(0u8),
        Some(b) => {
            m.push(1u8);
            m.extend_from_slice(&(b.len() as u64).to_be_bytes());
            m.extend_from_slice(b);
        }
    }
}

/// Tagged, fixed-width `Option<&[u8;32]>` (DPoP jkt) encoding: a `0x00` tag + 32 zero bytes for
/// `None`, a `0x01` tag + the 32 bytes for `Some` (so `None` and an all-zero jkt never alias).
fn encode_opt_jkt(m: &mut Vec<u8>, v: Option<&[u8; 32]>) {
    match v {
        None => {
            m.push(0u8);
            m.extend_from_slice(&[0u8; 32]);
        }
        Some(jkt) => {
            m.push(1u8);
            m.extend_from_slice(jkt);
        }
    }
}

/// Parse a raw wire bearer into `(token_id, whole_raw)`. Requires the `evrelay_` prefix; strips it;
/// splits on the FIRST `_` into `(token_id, secret)`; rejects either side empty or a non-alphanumeric
/// `token_id` (the mint uses lowercase hex, so the separator is unambiguous). Returns the `token_id`
/// slice (for the O(1) store load) AND the full `raw` (we MAC the WHOLE wire string, so a swapped
/// token_id with a valid secret will not verify). `None` => not our bearer / malformed.
pub fn parse_bearer(raw: &str) -> Option<(&str, &str)> {
    let rest = raw.strip_prefix(BEARER_PREFIX)?;
    let (token_id, secret) = rest.split_once('_')?;
    if token_id.is_empty() || secret.is_empty() {
        return None;
    }
    if !token_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some((token_id, raw))
}

/// The outcome of the egress swap path — default-deny by construction (CF-9). The real key is
/// fetched ONLY to build `Allowed`; any internal error becomes `InternalRefused` (a
/// durable-audited 403), never an upstream `send()`.
pub enum SwapOutcome {
    Allowed(crate::EgressResp),
    Denied(DenyReason),
    InternalRefused(String),
}

/// In-RAM broker state. Holds NO secret material — the bearer HMAC key is derived from the live DEK
/// on demand (`broker_hmac_key`), never cached, so locking the vault cannot leave a live key behind.
/// The `Store` is the source of truth for policies + bearers; these maps are best-effort caches /
/// ephemeral counters that may be empty and are lost on restart.
#[derive(Default)]
pub struct Broker {
    /// Warm policy cache keyed by `relay_id`; refilled from the store on a miss. Optional.
    pub policies: HashMap<String, crate::vault::RelayPolicyRow>,
    /// Sliding-window rate-limit + quota counters keyed by `token_id`; ephemeral (best-effort
    /// `RateLimited`/budget after a restart, since the durable bearer row has no live tally).
    pub counters: HashMap<String, BearerCounters>,
}

/// Per-bearer ephemeral usage counters. `window_start_ms`/`in_window` implement the trailing-60s
/// sliding rate window; `total_requests`/`total_bytes` accumulate against the `quota_total` budget.
#[derive(Clone, Copy, Debug, Default)]
pub struct BearerCounters {
    pub window_start_ms: i64,
    pub in_window: u32,
    pub total_requests: u64,
    pub total_bytes: u64,
}

impl Broker {
    /// Record one swap of `bytes` on `token_id` at `now_ms` and return the post-bump tallies that
    /// `decide` compares against the policy quotas/rate: `(total_requests, total_bytes,
    /// rate_in_window)`. The 60s window resets when `now_ms` has advanced past `window_start_ms +
    /// 60_000`. Counters are ephemeral; a restart resets them (best-effort enforcement).
    pub fn bump(&mut self, token_id: &str, now_ms: i64, bytes: u64) -> (u64, u64, u32) {
        let c = self.counters.entry(token_id.to_string()).or_default();
        if c.window_start_ms == 0 || now_ms.saturating_sub(c.window_start_ms) >= 60_000 {
            c.window_start_ms = now_ms;
            c.in_window = 0;
        }
        c.in_window = c.in_window.saturating_add(1);
        c.total_requests = c.total_requests.saturating_add(1);
        c.total_bytes = c.total_bytes.saturating_add(bytes);
        (c.total_requests, c.total_bytes, c.in_window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_mac_message_is_plane_separated() {
        let jkt = [0x11u8; 32];
        // Identical non-binding fields; the LOCAL (uid) vs REMOTE (client_id+jkt) planes MUST produce
        // different MAC messages (F12) — so a store tamper that flips a local row to remote, or swaps
        // the bound client_id/jkt, changes the message and fails the row MAC closed.
        let local = bearer_row_mac_message("tok", 1, 100, 50, 10, Some(1000), None, None, None, false);
        let remote =
            bearer_row_mac_message("tok", 1, 100, 50, 10, None, None, Some("phone"), Some(&jkt), false);
        assert_ne!(local, remote, "local and remote planes must not collide");

        // The bound client_id and jkt are each authenticated.
        let remote_other_cid =
            bearer_row_mac_message("tok", 1, 100, 50, 10, None, None, Some("laptop"), Some(&jkt), false);
        assert_ne!(remote, remote_other_cid, "client_id is bound");
        let jkt2 = [0x22u8; 32];
        let remote_other_jkt =
            bearer_row_mac_message("tok", 1, 100, 50, 10, None, None, Some("phone"), Some(&jkt2), false);
        assert_ne!(remote, remote_other_jkt, "dpop_jkt is bound");

        // Determinism + `revoked` binding (unchanged behavior) + None vs Some("") do not alias.
        assert_eq!(
            local,
            bearer_row_mac_message("tok", 1, 100, 50, 10, Some(1000), None, None, None, false)
        );
        let local_revoked =
            bearer_row_mac_message("tok", 1, 100, 50, 10, Some(1000), None, None, None, true);
        assert_ne!(local, local_revoked, "revoked is bound");
        let empty_cid =
            bearer_row_mac_message("tok", 1, 100, 50, 10, None, None, Some(""), Some(&jkt), false);
        assert_ne!(remote, empty_cid, "Some(\"\") client_id must not alias a real one");
    }
}
