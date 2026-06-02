//! Storage backend behind a `Store` trait (OI-1). libSQL was REOPENED because the `libsql` crate
//! bundles a C SQLite (`libsql-ffi`), which violates the pure-Rust / no-C tenet; the no-C CI gate
//! (`! cargo tree | grep libsql-ffi`) must pass. Phase 0 ships only `InMemStore`; the chosen
//! pure-Rust durable backend lands in Phase 1.
#[cfg(not(feature = "inmem-store"))]
compile_error!("select a store backend feature (`inmem-store`, or the OI-1-ruled pure-Rust backend)");

use crate::event::AuditRecord;

/// The vault's persistence surface. Encryption happens ABOVE this trait — a `Store` only ever
/// sees ciphertext + non-secret metadata. The durable, hash-chained audit log is committed here
/// before security RPCs return (HF-14).
pub trait Store: Send + Sync {
    fn get_meta(&self, k: &str) -> anyhow::Result<Option<String>>;
    fn put_meta(&self, k: &str, v: &str) -> anyhow::Result<()>;
    fn append_audit(&self, rec: &AuditRecord) -> anyhow::Result<i64>;
    fn verify_audit_chain(&self) -> anyhow::Result<()>;
    // secrets / keyslots / relay / ca CRUD — full set in Phase 1.
}

/// RAM-only backend for tests/CI (the envctl `DryRunRunner` analogue). Holds nothing durable.
pub struct InMemStore;

impl Store for InMemStore {
    fn get_meta(&self, _k: &str) -> anyhow::Result<Option<String>> {
        todo!()
    }
    fn put_meta(&self, _k: &str, _v: &str) -> anyhow::Result<()> {
        todo!()
    }
    fn append_audit(&self, _rec: &AuditRecord) -> anyhow::Result<i64> {
        todo!()
    }
    fn verify_audit_chain(&self) -> anyhow::Result<()> {
        todo!()
    }
}
