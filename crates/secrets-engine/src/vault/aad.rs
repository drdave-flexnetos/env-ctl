//! Fixed-width canonical AAD, recomputed at decrypt time and NEVER stored (HF-2). Binding the
//! record's table, row id, version, and DEK generation into the AEAD AAD makes a ciphertext
//! un-relocatable to another row/version/generation.
#[repr(u8)]
pub enum TableTag {
    SecretVersion = 1,
    CaKey = 2,
    Cert = 3,
    HmacKey = 4,
}

/// Canonical AAD bytes for one record. Fixed-width, big-endian, tag-prefixed.
pub fn record_aad(_tag: TableTag, _row_id: u64, _version: u64, _dek_generation: u64) -> Vec<u8> {
    todo!()
}
