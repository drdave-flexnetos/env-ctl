//! LUKS-style dual-KEK keyslots: the DEK is wrapped under both a USB-keyfile KEK and a
//! passphrase KEK, so the one vault opens via EITHER factor. Keys are zeroized in RAM and never
//! serialized.
//!
//! Design is grounded in `docs/research/02-argon2id-keyslots.md`:
//! - Passphrase KEK = Argon2id (Algorithm::Argon2id, Version::V0x13) with the slot's stored
//!   `Argon2Params`; refuse to derive below the 256 MiB memory floor (FS-S13, research §1/§3) and
//!   below the iteration floor `ARGON2_T_COST_FLOOR` (downgrade guard covers m AND t, not m alone).
//!   The `argon2` dependency is built with its `zeroize` feature (workspace Cargo.toml) so the
//!   256 MiB-1 GiB Block memory arena and hash intermediates are wiped on drop — the module's
//!   "keys are zeroized in RAM" promise covers the scratch arena, not just the 32-byte KEK output.
//! - USB KEK = HKDF-SHA256 with domain-separated, versioned `info` (research §2/§HKDF). The
//!   keyfile is already 64 bytes of CSPRNG entropy, so a memory-hard KDF buys nothing.
//! - Envelope = XChaCha20-Poly1305, 32-byte key / 24-byte random nonce / 16-byte tag; the AEAD
//!   tag is the sole correctness oracle (research §AEAD, OI-7). The keyslot AAD binds the
//!   ciphertext to the slot's KDF-determining + identity metadata so a tampered header is
//!   rejected by the tag (HF-3).
//! - Header MAC = BLAKE3 keyed_hash over a canonical encoding of every slot + the issuance floor
//!   (OI-8). There is no `hmac` crate; BLAKE3 keyed_hash is itself a 256-bit MAC.
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// AEAD (XChaCha20-Poly1305): `Aead` for the Vec-returning, AAD-carrying encrypt/decrypt;
// `AeadCore`/`KeyInit` for nonce generation + keying; `OsRng` is the CSPRNG (getrandom-backed).
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

// KDFs.
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

/// Data-encryption key (root of the at-rest envelope). Never `Serialize`; zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek(pub [u8; 32]);

/// Key-encryption key derived from one unlock factor. Consumed by (un)wrap; zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Kek(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Factor {
    Usb,
    Passphrase,
    // NOTE (CF-3): a `RequireBoth` "true 2FA" factor was REMOVED. The unlock state machine only
    // ever selects `Passphrase`/`Usb` slots, so a `RequireBoth` slot was unreachable by every
    // unlock path and there was no code requiring BOTH factors before committing `Unlocked` — its
    // dual-control guarantee would have been purely nominal. It must not be re-added until unlock
    // actually unwraps under a KEK that combines both factor KEKs and refuses single-factor
    // presentation; otherwise enrolling it silently misrepresents the security contract.
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kdf {
    Argon2id(Argon2Params),
    HkdfSha256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_lanes: u32,
}
impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_kib: 1_048_576,
            t_cost: 4,
            p_lanes: 4,
        }
    }
}
/// 256 MiB floor; refuse to unwrap a slot whose params fall below this (FS-S13).
pub const ARGON2_M_KIB_FLOOR: u32 = 262_144;
/// Iteration (time-cost) floor. Memory-hardness dominates Argon2's cost, but the downgrade guard
/// must cover all three cost dimensions — a hostile header could otherwise request `m` at the
/// memory floor while pinning `t_cost = 1`, the weakest variant the memory floor alone still
/// permits. `3` follows OWASP / RustCrypto Argon2id guidance. `p_lanes >= 1` is enforced by
/// `argon2::Params::new` itself.
pub const ARGON2_T_COST_FLOOR: u32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keyslot {
    pub id: i64,
    pub factor: Factor,
    pub label: String,
    pub kdf: Kdf,
    pub salt: Vec<u8>,
    /// GPT PARTUUID of the key device for a USB slot (OI-5).
    pub usb_partition_uuid: Option<String>,
    pub wrap_nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub dek_generation: i64,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------------------------
// Canonical-encoding domain tags. Versioned so a future on-disk format change can't be confused
// with this one, and distinct per use so an AAD blob can never be replayed as a header-MAC blob.
// ---------------------------------------------------------------------------------------------
const AAD_DOMAIN: &[u8] = b"env-ctl/v1/keyslot-aad";
const HEADER_MAC_DOMAIN: &[u8] = b"env-ctl/v1/header-mac";
/// HKDF `info` for the USB-keyfile KEK (research §2): domain-separated + versioned.
const USB_KEK_INFO: &[u8] = b"env-ctl/v1/kek/usb";
/// BLAKE3 keyed_hash key for `header_mac`; combined with the DEK so the MAC is unforgeable
/// without the unlocked DEK and domain-separated from any other BLAKE3 use.
const HEADER_MAC_KEY_INFO: &[u8] = b"env-ctl/v1/header-mac/key";

// Fixed wire byte for each enum variant (canonical, stable — never reorder).
fn factor_byte(f: Factor) -> u8 {
    match f {
        Factor::Usb => 0x01,
        Factor::Passphrase => 0x02,
        // 0x03 was Factor::RequireBoth (removed; see the Factor enum). The wire bytes for the
        // remaining factors are unchanged, so existing keyslots stay readable.
    }
}

/// Append a length-prefixed byte field: `u32` BE length, then the bytes. Distinct-length-or-bytes
/// inputs never collide, so no two distinct slot states serialize to the same AAD (HF-3).
///
/// The `as u32` cast would wrap for a field >= 4 GiB, which could break canonical injectivity. Real
/// inputs (salts, UUIDs, nonces, a 48-byte wrapped DEK) are tiny, so this is a defensive invariant
/// only; a `debug_assert` catches a corrupt/oversized field in debug/test builds without adding
/// cost to the (already AEAD-dominated) release path.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(
        bytes.len() <= u32::MAX as usize,
        "length-prefixed field exceeds u32 width (canonical-encoding invariant)"
    );
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Append the KDF id byte + its fixed-width parameters. Argon2id carries `(m_kib, t_cost,
/// p_lanes)` as three BE `u32`s; HKDF-SHA256 carries the same three slots zeroed so the encoding
/// stays fixed-width across KDF kinds.
fn push_kdf(out: &mut Vec<u8>, kdf: &Kdf) {
    match kdf {
        Kdf::Argon2id(p) => {
            out.push(0x01);
            out.extend_from_slice(&p.m_kib.to_be_bytes());
            out.extend_from_slice(&p.t_cost.to_be_bytes());
            out.extend_from_slice(&p.p_lanes.to_be_bytes());
        }
        Kdf::HkdfSha256 => {
            out.push(0x02);
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
        }
    }
}

/// Binds all KDF-determining + identity fields, fixed-width canonical (HF-3).
///
/// Layout (all integers big-endian):
/// `AAD_DOMAIN | factor:u8 | kdf-id:u8 | m:u32 | t:u32 | p:u32 | len(salt):u32 | salt
///  | usb-present:u8 | len(uuid):u32 | uuid | dek_generation:i64 | id:i64`
///
/// `usb-present` is `0x00` for `None` and `0x01` for `Some`, and the length-prefixed `uuid` field
/// is only emitted when present — together they make `None` and `Some("")` distinct.
pub fn keyslot_aad(slot: &Keyslot) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 64 + slot.salt.len());
    out.extend_from_slice(AAD_DOMAIN);
    out.push(factor_byte(slot.factor));
    push_kdf(&mut out, &slot.kdf);
    push_len_prefixed(&mut out, &slot.salt);
    match &slot.usb_partition_uuid {
        Some(uuid) => {
            out.push(0x01);
            push_len_prefixed(&mut out, uuid.as_bytes());
        }
        None => {
            out.push(0x00);
        }
    }
    out.extend_from_slice(&slot.dek_generation.to_be_bytes());
    out.extend_from_slice(&slot.id.to_be_bytes());
    out
}

/// DEK wrapped under a KEK; the AEAD tag is the correctness oracle (no separate verifier).
/// Returns `(nonce24, ct||tag)`.
///
/// A fresh 24-byte nonce is drawn from the OS CSPRNG per call (research §AEAD); the 192-bit nonce
/// space makes random nonces safe against birthday-bound reuse. The `Kek` is consumed by value and
/// zeroized on drop (OI-7).
pub fn wrap_dek(kek: Kek, dek: &Dek, aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek.0));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let wrapped = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &dek.0,
                aad,
            },
        )
        // Encryption of a fixed 32-byte plaintext with a valid key cannot fail; a panic here is a
        // genuine library invariant violation, not an operator-facing error.
        .expect("XChaCha20Poly1305 encryption of the 32-byte DEK must not fail");
    (nonce.to_vec(), wrapped)
    // `kek` drops here -> zeroized.
}

/// Consumes the KEK (OI-7); `None` on tag failure (the presented factor is wrong, or the
/// nonce/ciphertext/AAD was tampered). The recovered 32-byte plaintext is returned as a `Dek`.
pub fn unwrap_dek(kek: Kek, nonce: &[u8], wrapped: &[u8], aad: &[u8]) -> Option<Dek> {
    // A malformed nonce length cannot authenticate; reject before touching the cipher.
    if nonce.len() != 24 {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek.0));
    let xnonce = XNonce::from_slice(nonce);
    let mut pt = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: wrapped,
                aad,
            },
        )
        .ok()?; // Poly1305 tag mismatch -> None (the sole correctness oracle).

    // The DEK must be exactly 32 bytes; anything else is a corrupt/foreign envelope.
    if pt.len() != 32 {
        pt.zeroize();
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&pt);
    pt.zeroize(); // wipe the heap plaintext; the [u8;32] now lives only inside Dek.
    Some(Dek(key))
    // `kek` drops here -> zeroized.
}

/// HKDF-SHA256, info = `b"env-ctl/v1/kek/usb"` (research §2). The keyfile is the IKM and the slot's
/// `salt` is the HKDF salt; `expand` produces exactly 32 bytes of KEK.
pub fn kek_from_usb(keyfile: &Zeroizing<Vec<u8>>, salt: &[u8]) -> Kek {
    let hk = Hkdf::<Sha256>::new(Some(salt), keyfile.as_slice());
    let mut kek = [0u8; 32];
    hk.expand(USB_KEK_INFO, &mut kek)
        // expand only errors if the requested length exceeds 255*HashLen (8160 bytes); 32 is far
        // below that, so this is infallible.
        .expect("HKDF-SHA256 expand to 32 bytes is infallible");
    Kek(kek)
}

/// Argon2id (Algorithm::Argon2id, Version::V0x13) with the given params (research §1/§3).
///
/// HARD-FAILS (panics) if the params fall below the downgrade floor on either cost dimension:
/// `p.m_kib < ARGON2_M_KIB_FLOOR` or `p.t_cost < ARGON2_T_COST_FLOOR`. A header that requests a
/// sub-floor cost is an attacker-forceable downgrade and must never be honored (FS-S13). The caller
/// MUST validate slot params against the floor before unlock; this panic is the last-resort guard.
/// The actual params are also bound into the slot AAD (`keyslot_aad`), so this assert is a
/// freshness/downgrade check, not the only protection.
///
/// # Panics
/// - if `p.m_kib < ARGON2_M_KIB_FLOOR` (memory downgrade guard).
/// - if `p.t_cost < ARGON2_T_COST_FLOOR` (iteration downgrade guard).
/// - if the params are otherwise rejected by `argon2::Params::new` (e.g. `p_lanes == 0`), which
///   would only happen on a corrupt/hostile header.
pub fn kek_from_passphrase(pp: &Zeroizing<Vec<u8>>, salt: &[u8], p: Argon2Params) -> Kek {
    assert!(
        p.m_kib >= ARGON2_M_KIB_FLOOR,
        "argon2 m_kib {} is below the {} KiB floor (FS-S13 downgrade guard)",
        p.m_kib,
        ARGON2_M_KIB_FLOOR
    );
    assert!(
        p.t_cost >= ARGON2_T_COST_FLOOR,
        "argon2 t_cost {} is below the {} iteration floor (FS-S13 downgrade guard)",
        p.t_cost,
        ARGON2_T_COST_FLOOR
    );

    let params = Params::new(p.m_kib, p.t_cost, p.p_lanes, Some(32))
        .expect("argon2 params rejected (corrupt/hostile keyslot header)");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Wrap the derived bytes in Zeroizing so any early return / unwind wipes the KEK material; the
    // final value is copied into `Kek` (itself ZeroizeOnDrop) before the scratch buffer drops.
    let mut kek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pp.as_slice(), salt, kek.as_mut())
        // With validated params + a 32-byte output this only fails on an internal allocation error;
        // surfacing it as a panic is acceptable for a local single-operator vault.
        .expect("argon2id hash_password_into failed");
    Kek(*kek)
}

/// Vault header MAC over the keyslot set + issuance floor (OI-8); recomputed on unlock, refuse on
/// drift.
///
/// BLAKE3 keyed_hash is a 256-bit MAC. The key is derived from the unlocked DEK via BLAKE3's own
/// `derive_key` (domain-separated context), so the MAC is unforgeable without the DEK and cannot be
/// confused with any other BLAKE3 use. The message is a canonical, length-prefixed encoding of
/// every slot's identity + KDF + envelope material, followed by the count and the issuance floor —
/// so adding, removing, reordering, or mutating a slot, or regressing the floor, all change the MAC.
pub fn header_mac(dek: &Dek, slots: &[Keyslot], issuance_floor_ms: i64) -> Vec<u8> {
    let key = blake3::derive_key(
        std::str::from_utf8(HEADER_MAC_KEY_INFO).expect("static ascii context"),
        &dek.0,
    );

    let mut msg = Vec::with_capacity(HEADER_MAC_DOMAIN.len() + 16 + slots.len() * 64);
    msg.extend_from_slice(HEADER_MAC_DOMAIN);
    // Slot count up front so a truncated/extended set changes the MAC even before per-slot bytes.
    msg.extend_from_slice(&(slots.len() as u64).to_be_bytes());
    for slot in slots {
        // Reuse the AAD canonical encoding for the KDF/identity fields, then add the remaining
        // header fields (label, enabled, nonce, wrapped DEK) that the AAD intentionally omits.
        let aad = keyslot_aad(slot);
        push_len_prefixed(&mut msg, &aad);
        push_len_prefixed(&mut msg, slot.label.as_bytes());
        msg.push(slot.enabled as u8);
        push_len_prefixed(&mut msg, &slot.wrap_nonce);
        push_len_prefixed(&mut msg, &slot.wrapped_dek);
    }
    msg.extend_from_slice(&issuance_floor_ms.to_be_bytes());

    blake3::keyed_hash(&key, &msg).as_bytes().to_vec()
}

/// Constant-time verification of a stored header MAC against the recomputed one (OI-8): recompute
/// `header_mac(dek, slots, issuance_floor_ms)` and compare it to `stored_mac` **in constant time**.
/// Returns `true` iff they match.
///
/// The stored MAC is DEK-keyed, so a byte-by-byte `==`/`Vec::eq` would be a timing oracle on the
/// tag; we compare with `subtle::ConstantTimeEq`, exactly as `broker::token::verify_bearer` does.
/// `subtle`'s slice `ct_eq` short-circuits on a length mismatch (returns `Choice::from(0)` before
/// touching the contents), which is not a secret-dependent leak here because a well-formed MAC is
/// always 32 bytes (`stored_mac.len()` is the public stored length); the explicit `len_ok` gate is
/// kept as defense-in-depth so the result does not rely on `ct_eq`'s internal length handling.
pub fn verify_header_mac(
    dek: &Dek,
    slots: &[Keyslot],
    issuance_floor_ms: i64,
    stored_mac: &[u8],
) -> bool {
    use subtle::ConstantTimeEq;
    let computed = header_mac(dek, slots, issuance_floor_ms); // always 32 bytes
    let len_ok: u8 = (stored_mac.len() == computed.len()) as u8;
    let mac_eq: u8 = computed.as_slice().ct_eq(stored_mac).unwrap_u8();
    (len_ok & mac_eq) == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    // ---- fixtures ------------------------------------------------------------------------------

    fn sample_slot() -> Keyslot {
        Keyslot {
            id: 7,
            factor: Factor::Passphrase,
            label: "primary".to_string(),
            kdf: Kdf::Argon2id(Argon2Params::default()),
            salt: vec![0x11; 16],
            usb_partition_uuid: None,
            wrap_nonce: vec![],
            wrapped_dek: vec![],
            dek_generation: 1,
            enabled: true,
        }
    }

    fn usb_slot() -> Keyslot {
        Keyslot {
            id: 8,
            factor: Factor::Usb,
            label: "yubi".to_string(),
            kdf: Kdf::HkdfSha256,
            salt: vec![0x22; 32],
            usb_partition_uuid: Some("1234-ABCD".to_string()),
            wrap_nonce: vec![],
            wrapped_dek: vec![],
            dek_generation: 1,
            enabled: true,
        }
    }

    fn fixed_dek() -> Dek {
        Dek([0xAB; 32])
    }

    fn fixed_kek() -> Kek {
        Kek([0xCD; 32])
    }

    // ---- wrap / unwrap round-trip -------------------------------------------------------------

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let aad = keyslot_aad(&sample_slot());
        let (nonce, wrapped) = wrap_dek(fixed_kek(), &fixed_dek(), &aad);

        assert_eq!(nonce.len(), 24, "XChaCha20 nonce is 24 bytes");
        // ct(32) + Poly1305 tag(16) = 48 bytes.
        assert_eq!(wrapped.len(), 48);

        let out = unwrap_dek(fixed_kek(), &nonce, &wrapped, &aad).expect("round-trip must unwrap");
        assert!(bool::from(out.0.ct_eq(&fixed_dek().0)), "recovered DEK matches");
    }

    #[test]
    fn distinct_wraps_use_distinct_nonces() {
        let aad = keyslot_aad(&sample_slot());
        let (n1, c1) = wrap_dek(fixed_kek(), &fixed_dek(), &aad);
        let (n2, c2) = wrap_dek(fixed_kek(), &fixed_dek(), &aad);
        // Random per-call nonce => different nonce and different ciphertext for the same plaintext.
        assert_ne!(n1, n2, "nonces must never be reused");
        assert_ne!(c1, c2, "same DEK under fresh nonce yields different ciphertext");
    }

    // ---- wrong KEK rejected -------------------------------------------------------------------

    #[test]
    fn unwrap_with_wrong_kek_returns_none() {
        let aad = keyslot_aad(&sample_slot());
        let (nonce, wrapped) = wrap_dek(fixed_kek(), &fixed_dek(), &aad);

        let wrong = Kek([0x00; 32]);
        assert!(
            unwrap_dek(wrong, &nonce, &wrapped, &aad).is_none(),
            "a wrong KEK must fail the Poly1305 tag"
        );
    }

    // ---- tampered AAD rejected ----------------------------------------------------------------

    #[test]
    fn tampered_aad_returns_none() {
        let slot = sample_slot();
        let aad = keyslot_aad(&slot);
        let (nonce, wrapped) = wrap_dek(fixed_kek(), &fixed_dek(), &aad);

        // Flip an identity field -> a different canonical AAD -> tag mismatch.
        let mut tampered = slot.clone();
        tampered.id = 9;
        let aad2 = keyslot_aad(&tampered);
        assert_ne!(aad, aad2, "changing id must change the AAD");
        assert!(
            unwrap_dek(fixed_kek(), &nonce, &wrapped, &aad2).is_none(),
            "AAD that doesn't match the wrap must fail the tag"
        );

        // Mutating a single AAD byte directly also fails.
        let mut raw = aad.clone();
        raw[0] ^= 0x01;
        assert!(
            unwrap_dek(fixed_kek(), &nonce, &wrapped, &raw).is_none(),
            "any AAD bit-flip must fail the tag"
        );
    }

    #[test]
    fn tampered_ciphertext_and_nonce_return_none() {
        let aad = keyslot_aad(&sample_slot());
        let (nonce, wrapped) = wrap_dek(fixed_kek(), &fixed_dek(), &aad);

        let mut ct = wrapped.clone();
        ct[0] ^= 0x01;
        assert!(unwrap_dek(fixed_kek(), &nonce, &ct, &aad).is_none());

        let mut n = nonce.clone();
        n[0] ^= 0x01;
        assert!(unwrap_dek(fixed_kek(), &n, &wrapped, &aad).is_none());

        // Wrong-length nonce is rejected up front.
        assert!(unwrap_dek(fixed_kek(), &nonce[..23], &wrapped, &aad).is_none());
    }

    // ---- KDFs ---------------------------------------------------------------------------------

    #[test]
    fn usb_kek_is_deterministic_and_domain_separated() {
        let keyfile = Zeroizing::new(vec![0x42u8; 64]);
        let salt = [0x01u8; 32];
        let a = kek_from_usb(&keyfile, &salt);
        let b = kek_from_usb(&keyfile, &salt);
        assert!(bool::from(a.0.ct_eq(&b.0)), "HKDF is deterministic");

        // A different salt yields a different KEK.
        let c = kek_from_usb(&keyfile, &[0x02u8; 32]);
        assert!(!bool::from(a.0.ct_eq(&c.0)), "salt must change the KEK");
    }

    #[test]
    fn usb_kek_known_answer() {
        // KAT: HKDF-SHA256(salt=0x00*32, ikm=0x00*32).expand("env-ctl/v1/kek/usb", 32).
        // Locks the info string + extract/expand wiring so a future refactor can't silently change
        // the derived KEK (which would orphan every existing USB keyslot).
        let keyfile = Zeroizing::new(vec![0x00u8; 32]);
        let salt = [0x00u8; 32];
        let kek = kek_from_usb(&keyfile, &salt);

        // Recompute the expected value independently from the public hkdf API.
        let hk = Hkdf::<Sha256>::new(Some(&salt), &[0u8; 32]);
        let mut expected = [0u8; 32];
        hk.expand(b"env-ctl/v1/kek/usb", &mut expected).unwrap();
        assert!(bool::from(kek.0.ct_eq(&expected)));
    }

    #[test]
    fn argon2_below_floor_is_rejected() {
        // Exactly one below the floor must panic (the downgrade guard).
        let pp = Zeroizing::new(b"correct horse battery staple".to_vec());
        let salt = [0x07u8; 16];
        let weak = Argon2Params {
            m_kib: ARGON2_M_KIB_FLOOR - 1,
            t_cost: 1,
            p_lanes: 1,
        };
        let r = std::panic::catch_unwind(|| {
            let _ = kek_from_passphrase(&pp, &salt, weak);
        });
        assert!(r.is_err(), "sub-floor m_kib must hard-fail");
    }

    #[test]
    fn argon2_at_floor_round_trips_through_wrap() {
        // At the floor it must succeed; use the minimum permitted cost to keep the test fast
        // (~256 MiB, t = ARGON2_T_COST_FLOOR, p = 1).
        let pp = Zeroizing::new(b"correct horse battery staple".to_vec());
        let salt = [0x07u8; 16];
        let params = Argon2Params {
            m_kib: ARGON2_M_KIB_FLOOR,
            t_cost: ARGON2_T_COST_FLOOR,
            p_lanes: 1,
        };
        let slot = Keyslot {
            kdf: Kdf::Argon2id(params),
            salt: salt.to_vec(),
            ..sample_slot()
        };
        let aad = keyslot_aad(&slot);

        let kek1 = kek_from_passphrase(&pp, &salt, params);
        let (nonce, wrapped) = wrap_dek(kek1, &fixed_dek(), &aad);

        // Same passphrase + salt + params re-derives the same KEK and unwraps the DEK.
        let kek2 = kek_from_passphrase(&pp, &salt, params);
        let out = unwrap_dek(kek2, &nonce, &wrapped, &aad).expect("passphrase round-trip");
        assert!(bool::from(out.0.ct_eq(&fixed_dek().0)));

        // A wrong passphrase derives a different KEK and fails the tag.
        let bad = kek_from_passphrase(&Zeroizing::new(b"wrong".to_vec()), &salt, params);
        assert!(unwrap_dek(bad, &nonce, &wrapped, &aad).is_none());
    }

    // ---- header MAC ---------------------------------------------------------------------------

    #[test]
    fn header_mac_changes_when_slot_added_or_removed() {
        let dek = fixed_dek();
        let floor = 1_700_000_000_000i64;

        let one = vec![sample_slot()];
        let two = vec![sample_slot(), usb_slot()];

        let mac1 = header_mac(&dek, &one, floor);
        let mac2 = header_mac(&dek, &two, floor);
        assert_eq!(mac1.len(), 32, "BLAKE3 keyed_hash is 32 bytes");
        assert_ne!(mac1, mac2, "adding a slot must change the MAC");

        // Removing the slot we added returns to the original MAC (set is canonical, not nonce-y).
        let mac1_again = header_mac(&dek, &one, floor);
        assert_eq!(mac1, mac1_again, "MAC is deterministic over the same set");
    }

    #[test]
    fn header_mac_changes_on_floor_and_slot_mutation_and_reorder() {
        let dek = fixed_dek();
        let slots = vec![sample_slot(), usb_slot()];
        let base = header_mac(&dek, &slots, 1_000);

        // Floor regression / change.
        assert_ne!(base, header_mac(&dek, &slots, 999), "issuance floor binds");

        // Per-slot mutation (label is covered by header_mac but not by the AAD).
        let mut mutated = slots.clone();
        mutated[0].label = "renamed".to_string();
        assert_ne!(base, header_mac(&dek, &mutated, 1_000), "slot mutation binds");

        // Reorder: the canonical encoding is order-sensitive by design.
        let reordered = vec![slots[1].clone(), slots[0].clone()];
        assert_ne!(base, header_mac(&dek, &reordered, 1_000), "order binds");

        // A different DEK yields a different MAC (key separation).
        let other_dek = Dek([0x01; 32]);
        assert_ne!(base, header_mac(&other_dek, &slots, 1_000), "DEK keys the MAC");
    }

    // ---- AAD canonical encoding ---------------------------------------------------------------

    #[test]
    fn aad_distinguishes_none_from_empty_uuid() {
        // None and Some("") must not collide (the present/absent discriminator handles this).
        let mut none_slot = usb_slot();
        none_slot.usb_partition_uuid = None;
        let mut empty_slot = usb_slot();
        empty_slot.usb_partition_uuid = Some(String::new());
        assert_ne!(keyslot_aad(&none_slot), keyslot_aad(&empty_slot));
    }

    #[test]
    fn aad_distinguishes_salt_boundary_shifts() {
        // Length-prefixing means a byte moved across the salt/uuid boundary changes the AAD,
        // i.e. no two distinct (salt, uuid) splits canonicalize to the same bytes.
        let mut a = sample_slot();
        a.salt = vec![0xAA, 0xBB];
        a.usb_partition_uuid = Some("CC".to_string());
        let mut b = sample_slot();
        b.salt = vec![0xAA];
        b.usb_partition_uuid = Some("BBCC".to_string());
        assert_ne!(keyslot_aad(&a), keyslot_aad(&b));
    }

    #[test]
    fn aad_binds_argon2_params() {
        // Two slots identical except for Argon2 m_kib must produce different AADs (a downgrade
        // attempt would otherwise unwrap under the original tag).
        let mut strong = sample_slot();
        strong.kdf = Kdf::Argon2id(Argon2Params::default());
        let mut weak = sample_slot();
        weak.kdf = Kdf::Argon2id(Argon2Params {
            m_kib: ARGON2_M_KIB_FLOOR,
            t_cost: 4,
            p_lanes: 4,
        });
        assert_ne!(keyslot_aad(&strong), keyslot_aad(&weak));
    }
}
