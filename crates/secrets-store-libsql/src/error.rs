//! Store-specific error types. These map libSQL/runtime failures into a small, typed surface; the
//! public `Store` trait methods return `anyhow::Result`, so these convert into `anyhow::Error` at
//! the boundary (via `#[from]`-style `impl From`).

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// The current-thread tokio runtime could not be constructed.
    RuntimeCreation(String),
    /// `Builder::new_remote(..).build()` / `connect()` failed.
    Connect(String),
    /// A `SELECT`/`query` failed at the libSQL layer.
    QueryFailed(String),
    /// An `INSERT`/`UPDATE`/`execute` failed at the libSQL layer.
    ExecuteFailed(String),
    /// A `BEGIN`/`COMMIT`/`ROLLBACK` boundary failed.
    TransactionFailed(String),
    /// A row could not be decoded into its domain type (`serial` module).
    SerializationError(String),
    /// The DEK-keyed/unkeyed audit chain broke at this seq (mirrors the engine's
    /// `EngineError::AuditChainBroken`).
    AuditChainBroken(i64),
    /// `put_secret` was handed a `row_id` that was never reserved, or a non-monotonic version.
    Contract(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RuntimeCreation(e) => write!(f, "tokio runtime creation failed: {e}"),
            Error::Connect(e) => write!(f, "libSQL remote connect failed: {e}"),
            Error::QueryFailed(e) => write!(f, "libSQL query failed: {e}"),
            Error::ExecuteFailed(e) => write!(f, "libSQL execute failed: {e}"),
            Error::TransactionFailed(e) => write!(f, "libSQL transaction failed: {e}"),
            Error::SerializationError(e) => write!(f, "row deserialization failed: {e}"),
            Error::AuditChainBroken(seq) => write!(f, "audit chain broken at seq {seq}"),
            Error::Contract(e) => write!(f, "store contract violation: {e}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
