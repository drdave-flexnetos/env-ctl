//! libSQL `Store` backend (OI-1, NEW-3). C-quarantined, remote-client only.
//!
//! The engine lib (`envctl-secrets-engine`) NEVER links libSQL; this crate consumes ONLY the
//! engine's public [`envctl_secrets::vault::Store`] trait + row types and is the sole place the
//! libSQL dependency lives. The sync `Store` trait is bridged to the async libSQL remote client by
//! a PRIVATE current-thread tokio runtime ([`sync::SyncConnection`]), so the engine stays
//! async-free.
//!
//! ## C-purity status (OI-1 RESOLVED (a)) — see README.md
//!
//! The literal gate (`libsql-ffi|libsql-sys|sqlite3-sys`) PASSES for
//! `libsql { default-features = false, features = ["remote"] }` — the C-SQLite `core` path is NOT
//! pulled, so NO C *library* is linked. The `remote` feature does pull `libsql-sqlite3-parser`,
//! whose `build.rs` runs `cc` on `lemon.c` to CODEGEN the SQL grammar as Rust (build-time only;
//! nothing C is linked). That build-time `cc` is ACCEPTED under decision (a): it is already
//! mandatory for the engine via ring + blake3. The upheld tenet is "no C *library* in the trust
//! boundary," and this crate is now a `[workspace.members]` entry, gated by `ci/gates/no-c.sh`
//! (Gate 3a). Engine default store stays `inmem-store`; secretd runtime-selects this backend via
//! config (Phase 1 DONE; see `docs/ops/08-secretd-store-config.md`).

#![deny(unsafe_code)]

pub mod error;
pub mod health;
pub mod schema;
pub mod serial;
pub mod store;
pub mod sync;

pub use error::{Error, Result};
pub use health::StoreHealth;
pub use store::{LibSqlStore, LibSqlStoreBuilder};

/// Compiled-in wiring flags (mirrors the DESIGN's lib.rs surface).
pub const FEATURE_REMOTE: bool = cfg!(feature = "remote");
pub const FEATURE_EMBEDDED: bool = cfg!(feature = "embedded");

#[cfg(all(feature = "remote", feature = "embedded"))]
compile_error!("select only one of `remote` or `embedded`");

#[cfg(not(any(feature = "remote", feature = "embedded")))]
compile_error!("select a libSQL wiring feature (`remote` or `embedded`)");

#[cfg(test)]
mod tests;
