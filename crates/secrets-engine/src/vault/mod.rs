//! The vault: a locked/unlocked state machine over an encrypted-at-rest `Store`. The DEK lives in
//! RAM only while `Unlocked`; `lock()` zeroizes it.
pub mod aad;
pub mod crypto;
pub mod store;

pub use store::{InMemStore, Store};

/// Vault state. `Unlocked` holds the live DEK (zeroized on drop / on `lock`).
pub enum Vault {
    Locked,
    Unlocked { dek: crate::keyslot::Dek },
}

impl Vault {
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Vault::Unlocked { .. })
    }
}
