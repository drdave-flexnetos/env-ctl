//! Bearer verification. Bearers are stored only as a keyed MAC; verification is constant-time
//! (`subtle`) to avoid a timing oracle on the token id.
/// Returns true iff `presented` MACs (under `hmac_key`) to `stored_mac`, compared in constant time.
pub fn verify_bearer(_hmac_key: &[u8; 32], _presented: &str, _stored_mac: &[u8]) -> bool {
    todo!()
}
