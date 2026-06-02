//! The vault: a locked/unlocked state machine over an encrypted-at-rest `Store`. The DEK lives in
//! RAM only while `Unlocked`; `lock()` zeroizes it.
pub mod aad;
pub mod audit;
pub mod crypto;
pub mod store;

pub use store::{
    BearerRow, CertRow, InMemStore, RelayPolicyRow, RemoteClient, SecretRow, Store,
};

/// Vault state. `Unlocked` holds the live DEK (zeroized on drop / on `lock`).
pub enum Vault {
    Locked,
    Unlocked { dek: crate::keyslot::Dek },
}

impl Vault {
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Vault::Unlocked { .. })
    }

    /// Borrow the live DEK while `Unlocked`, else `None`. Keeps the DEK owned by the `Vault` (it
    /// is `ZeroizeOnDrop`, so it must never be moved out — only borrowed).
    pub fn dek(&self) -> Option<&crate::keyslot::Dek> {
        match self {
            Vault::Unlocked { dek } => Some(dek),
            Vault::Locked => None,
        }
    }
}
