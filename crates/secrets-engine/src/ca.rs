//! Local CA + leaf issuance (rcgen-backed, feature `mitm-ca`). The CA private key is stored
//! ENCRYPTED in the vault and is only usable while the vault is unlocked; `Engine::lock` zeroizes
//! the in-RAM issuer. MITM leaf certs are minted in-RAM by the relay-gated proxy resolver ONLY for
//! a host that an active USB-gated relay actively covers — never via the operator `ca issue` path
//! (CF-5). Phase-0 is a placeholder so the engine compiles with or without `mitm-ca`.
pub struct LocalCa;

impl LocalCa {
    pub fn is_initialized(&self) -> bool {
        todo!()
    }
}
