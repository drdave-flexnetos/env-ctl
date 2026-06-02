//! LUKS-style dual-KEK keyslots: the DEK is wrapped under both a USB-keyfile KEK and a
//! passphrase KEK, so the one vault opens via EITHER factor. Keys are zeroized in RAM and never
//! serialized.
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
    /// Opt-in true 2FA (both factors required to unwrap) (CF-3).
    RequireBoth,
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

/// Binds all KDF-determining + identity fields, fixed-width canonical (HF-3).
pub fn keyslot_aad(_slot: &Keyslot) -> Vec<u8> {
    todo!()
}
/// DEK wrapped under a KEK; the AEAD tag is the correctness oracle (no separate verifier).
/// Returns `(nonce24, ct||tag)`.
pub fn wrap_dek(_kek: Kek, _dek: &Dek, _aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    todo!()
}
/// Consumes the KEK (OI-7); `None` on tag failure (the presented factor is wrong).
pub fn unwrap_dek(_kek: Kek, _nonce: &[u8], _wrapped: &[u8], _aad: &[u8]) -> Option<Dek> {
    todo!()
}
/// HKDF-SHA256, info = `b"env-ctl/v1/kek/usb"`.
pub fn kek_from_usb(_keyfile: &Zeroizing<Vec<u8>>, _salt: &[u8]) -> Kek {
    todo!()
}
/// Argon2id (version 0x13) with the given params.
pub fn kek_from_passphrase(_pp: &Zeroizing<Vec<u8>>, _salt: &[u8], _p: Argon2Params) -> Kek {
    todo!()
}
/// Vault header MAC over the keyslot set + issuance floor (OI-8); recomputed on unlock, refuse on
/// drift.
pub fn header_mac(_dek: &Dek, _slots: &[Keyslot], _issuance_floor_ms: i64) -> Vec<u8> {
    todo!()
}
