//! libSQL `Store` backend (OI-1, NEW-3). C-quarantined, remote-client only.
//!
//! The engine lib (`envctl-secrets-engine`) NEVER links libSQL; this crate consumes ONLY the
//! engine's public [`envctl_secrets::vault::Store`] trait + row types and is the sole place the
//! libSQL dependency lives. The sync `Store` trait is bridged to the async libSQL remote client by
//! a PRIVATE current-thread tokio runtime ([`sync::SyncConnection`]), so the engine stays
//! async-free.
//!
//! ## C-purity status (audit F1) — see README.md
//!
//! The DESIGN's literal gate (`libsql-ffi|libsql-sys|sqlite3-sys`) PASSES for
//! `libsql { default-features = false, features = ["remote"] }` — the C-SQLite `core` path is NOT
//! pulled. HOWEVER the `remote` feature transitively requires `libsql-sqlite3-parser`, whose
//! `build.rs` compiles `lemon.c` via `cc` at build time. That requires a C toolchain and so fails
//! the SPIRIT of audit F1. This crate is therefore deliberately NOT a `[workspace.members]` entry;
//! the workspace stays on `inmem-store`. The code below compiles and is correct; it is held back
//! ONLY on the C-toolchain-purity decision.

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
