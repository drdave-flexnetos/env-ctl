//! Typed errors for SETUP-TIME failures only (envctl discipline). A refused operation is NOT an
//! `Err` — it is a `GuardRefused` event + a `Refused` audit outcome.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("vault db error in {path}: {source}")]
    Db {
        path: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("vault is locked")]
    Locked,
    /// Single generic message — never reveals which keyslot failed (OI-17).
    #[error("unlock failed")]
    UnlockFailed,
    #[error("relay issuance refused: USB keyfile possession not proven (rotation gating)")]
    UsbAbsent,
    #[error("unknown relay '{0}'")]
    UnknownRelay(String),
    #[error("runtime dir not found or not 0700: {0}")]
    RuntimeDir(String),
    #[error("mlockall failed; refusing to start (FS-S4)")]
    MlockFailed,
    #[error("vault header MAC mismatch: keyslot set tampered (FS-S13)")]
    HeaderMacMismatch,
    #[error("CA not initialized")]
    NoCa,
    #[error("audit chain broken at seq {0}")]
    AuditChainBroken(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultState {
    Uninitialized,
    Locked,
    LockedNeedPassphrase,
    Unlocked,
    Error,
}
