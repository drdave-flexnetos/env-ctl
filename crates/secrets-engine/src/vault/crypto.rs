//! Per-record AEAD seal/open (XChaCha20-Poly1305, 24-byte random nonce, AAD-bound). Pure-Rust;
//! lands in Phase 1. Phase-0 bodies are placeholders so no crypto API is pinned prematurely.
use crate::keyslot::Dek;

/// Seal plaintext under the DEK with the given canonical AAD. Returns `(nonce24, ct||tag)`.
pub fn seal(_dek: &Dek, _aad: &[u8], _plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    todo!()
}

/// Open a sealed record. `None` on tag failure (tamper / wrong key / wrong AAD).
pub fn open(_dek: &Dek, _aad: &[u8], _nonce: &[u8], _ct_tag: &[u8]) -> Option<Vec<u8>> {
    todo!()
}
