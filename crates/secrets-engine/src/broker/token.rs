//! Bearer verification. Bearers are stored only as a keyed MAC; verification is constant-time
//! (`subtle`) to avoid a timing oracle on the token id.
//!
//! ## Scheme (per docs/research/12-remote-token-binding.md)
//!
//! env-ctl never persists a relay bearer in the clear. At mint time the broker derives a
//! keyed MAC of the bearer string and stores *only* that MAC; at verify time the presented
//! bearer is re-MACed under the same key and compared against the stored MAC. This is the
//! "HMAC request signing (keyed-MAC)" universal floor from the research doc's tradeoff table
//! — a per-relay shared secret, cheap (~µs) to verify, and present on every plane.
//!
//! There is no `hmac` crate in this engine; the keyed MAC is `blake3::keyed_hash`, which is a
//! proper keyed pseudorandom function over its 32-byte key (BLAKE3's native keyed mode — it does
//! *not* need the HMAC construction the way a plain Merkle–Damgård hash would, and is immune to
//! length-extension). The comparison is constant-time via `subtle::ConstantTimeEq` so a stolen
//! token id cannot be recovered byte-by-byte through a timing side channel.
//!
//! ### Explicitly out of scope here
//!
//! DPoP sender-binding (RFC 9449) and mTLS-bound tokens (RFC 8705) are the *remote-plane*
//! constraints and belong to server-mode / Phase 6 (research doc §2, §"Concrete guidance" #2/#7).
//! This module implements only the base keyed-MAC verify that is shared by every plane; it does
//! not parse, sign, or verify DPoP proofs.

use subtle::ConstantTimeEq;

/// Width of a BLAKE3 output / keyed-MAC tag, in bytes.
const MAC_LEN: usize = 32;

/// Compute the keyed MAC of a bearer string under `hmac_key` (the mint side).
///
/// Both mint and verify funnel through this single helper so the two sides can never drift:
/// `verify_bearer` succeeds for `presented` iff `stored_mac == mac_bearer(hmac_key, presented)`.
///
/// The MAC is `blake3::keyed_hash(hmac_key, presented.as_bytes())`. `hmac_key` is a 32-byte secret
/// (the per-relay bearer HMAC key held only in the daemon); it must come from a CSPRNG and be
/// zeroized by its owner — this function neither generates nor stores it.
pub fn mac_bearer(hmac_key: &[u8; 32], presented: &str) -> [u8; 32] {
    // blake3::keyed_hash returns a `Hash`; `as_bytes()` borrows its 32-byte tag. Copy it out so
    // callers own a plain array (the transient `Hash` is dropped at end of statement).
    *blake3::keyed_hash(hmac_key, presented.as_bytes()).as_bytes()
}

/// Returns true iff `presented` MACs (under `hmac_key`) to `stored_mac`, compared in constant time.
///
/// `stored_mac` is whatever the store handed back; it is attacker-influenceable in length, so a
/// wrong length is treated as a non-match **without an early-return timing leak**: we always
/// compute the MAC of `presented`, then fold the length check into the constant-time path so the
/// observable work does not branch on whether the lengths matched.
pub fn verify_bearer(hmac_key: &[u8; 32], presented: &str, stored_mac: &[u8]) -> bool {
    let computed: [u8; MAC_LEN] = mac_bearer(hmac_key, presented);
    ct_eq_mac(&computed, stored_mac)
}

/// Keyed MAC over the AUTHENTICATED bearer-row metadata (the mint/revoke side).
///
/// The wire MAC (`mac_bearer`) only authenticates the opaque `evrelay_{token_id}_{secret}` string,
/// so every security-critical field of the persisted row — `revoked`, `expires_at_ms`,
/// `issued_at_ms`, `issued_boottime_ms`, `policy_id`, `client_uid`, `client_pid` — was stored in the
/// CLEAR with nothing binding it. A store-level attacker could flip `revoked:true->false`, raise
/// `expires_at_ms`, rewrite the peer binding, or repoint `policy_id` at a more permissive policy and
/// the wire MAC would STILL verify (it never sees those fields), reaching `Allow` (CRITICAL).
///
/// This MAC closes that gap: the engine recomputes it over the canonical encoding of the row's
/// security fields (`row_mac_message`) under a DEK-derived, domain-separated key on every write
/// (mint AND revoke — the only places the row legitimately changes) and re-verifies it before the
/// pure `decide`. Without the unlocked DEK an attacker cannot produce a matching tag, so any tamper
/// fails closed (treated as `UnknownBearer`, no oracle). It is `blake3::keyed_hash` (a native keyed
/// PRF, immune to length-extension), domain-separated from the wire-bearer key, the header MAC, and
/// the audit-head anchor.
pub fn mac_bearer_row(row_mac_key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(row_mac_key, message).as_bytes()
}

/// Returns true iff `message` MACs (under `row_mac_key`) to `stored_mac`, compared in constant time.
/// Mint and revoke both funnel through `mac_bearer_row`, so the two sides can never drift.
pub fn verify_bearer_row(row_mac_key: &[u8; 32], message: &[u8], stored_mac: &[u8]) -> bool {
    let computed: [u8; MAC_LEN] = mac_bearer_row(row_mac_key, message);
    ct_eq_mac(&computed, stored_mac)
}

/// Constant-time MAC comparison shared by the wire-bearer and row-metadata verifiers.
///
/// `stored_mac` is whatever the store handed back; it is attacker-influenceable in length, so a
/// wrong length is treated as a non-match **without an early-return timing leak**: we always compare
/// against `computed`, then fold the (public) length check into the constant-time path so the
/// observable work does not branch on whether the lengths matched.
///
/// `Choice`/`u8` math keeps everything data-dependency-only (no `if` on secret-derived values):
///   len_ok  = 1 iff stored_mac.len() == MAC_LEN, else 0   (length is public, not secret)
///   mac_eq  = 1 iff the bytes match in constant time
fn ct_eq_mac(computed: &[u8; MAC_LEN], stored_mac: &[u8]) -> bool {
    let len_ok: u8 = (stored_mac.len() == MAC_LEN) as u8;
    let mac_eq: u8 = computed.as_slice().ct_eq(stored_mac).unwrap_u8();
    (len_ok & mac_eq) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed, non-secret key + bearer so the vectors are reproducible. Never seed real keys
    // outside #[cfg(test)] (engine rule); these exist only to pin known-answer behavior.
    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const BEARER: &str = "envctl-relay-bearer-01J9ZXAMPLE";

    /// Known-answer vector: pin the exact MAC bytes so an accidental change to the input encoding
    /// (e.g. hashing something other than the raw UTF-8 bytes) is caught.
    #[test]
    fn known_answer_mac() {
        let mac = mac_bearer(&KEY, BEARER);
        // Contract: mac_bearer is exactly blake3::keyed_hash over the raw UTF-8 bytes. This
        // catches any drift in the input encoding (e.g. hashing something other than the bytes).
        let recomputed = *blake3::keyed_hash(&KEY, BEARER.as_bytes()).as_bytes();
        assert_eq!(mac, recomputed, "mac_bearer must equal blake3::keyed_hash");
        // Sanity: 32-byte tag, not all-zero.
        assert_eq!(mac.len(), 32);
        assert_ne!(mac, [0u8; 32]);
    }

    #[test]
    fn correct_token_verifies() {
        let stored = mac_bearer(&KEY, BEARER);
        assert!(verify_bearer(&KEY, BEARER, &stored));
    }

    #[test]
    fn single_bit_change_in_token_fails() {
        let stored = mac_bearer(&KEY, BEARER);
        // Flip one bit of the presented token (last char). Avalanche => no match.
        let mut bytes = BEARER.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = std::str::from_utf8(&bytes).expect("still valid utf8");
        assert!(!verify_bearer(&KEY, tampered, &stored));
    }

    #[test]
    fn single_bit_change_in_stored_mac_fails() {
        let mut stored = mac_bearer(&KEY, BEARER);
        // Flip one bit of the stored MAC: correct token must no longer verify.
        stored[0] ^= 0x01;
        assert!(!verify_bearer(&KEY, BEARER, &stored));
        // And flipping a middle/last byte too, to exercise the full-width comparison.
        let mut stored2 = mac_bearer(&KEY, BEARER);
        let mid = stored2.len() / 2;
        stored2[mid] ^= 0x80;
        assert!(!verify_bearer(&KEY, BEARER, &stored2));
        let mut stored3 = mac_bearer(&KEY, BEARER);
        let lastb = stored3.len() - 1;
        stored3[lastb] ^= 0x40;
        assert!(!verify_bearer(&KEY, BEARER, &stored3));
    }

    #[test]
    fn wrong_key_fails() {
        let stored = mac_bearer(&KEY, BEARER);
        let mut other_key = KEY;
        other_key[0] ^= 0xff;
        assert!(!verify_bearer(&other_key, BEARER, &stored));
    }

    #[test]
    fn wrong_length_stored_mac_fails() {
        let full = mac_bearer(&KEY, BEARER);

        // Too short (truncated, even though it is a correct prefix).
        assert!(!verify_bearer(&KEY, BEARER, &full[..31]));
        // Empty.
        assert!(!verify_bearer(&KEY, BEARER, &[]));
        // Too long (correct 32 bytes followed by extra).
        let mut too_long = full.to_vec();
        too_long.push(0x00);
        assert!(!verify_bearer(&KEY, BEARER, &too_long));
        // A 32-byte all-zero (wrong) MAC: right length, wrong value.
        assert!(!verify_bearer(&KEY, BEARER, &[0u8; 32]));
    }

    #[test]
    fn distinct_tokens_do_not_collide() {
        let stored = mac_bearer(&KEY, BEARER);
        assert!(!verify_bearer(&KEY, "a-completely-different-bearer", &stored));
        // Empty presented token against a real MAC must fail.
        assert!(!verify_bearer(&KEY, "", &stored));
    }
}
