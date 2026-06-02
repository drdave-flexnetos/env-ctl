//! Store health probe. The daemon gates startup on this: the remote store must be reachable, the
//! schema present, and (in production) the connection durable.

/// Snapshot of a libSQL store's health, returned by `LibSqlStore::health`.
#[derive(Debug, Clone)]
pub struct StoreHealth {
    /// Writes wait for sqld disk fsync (`PRAGMA synchronous=FULL` set at init + a confirmed
    /// `fsync_barrier`). Required before the store is allowed to serve security RPCs (HF-14).
    pub durable: bool,
    /// `meta.schema_version` as read back from the store (0 if absent / not initialized).
    pub schema_version: u32,
    /// Which wiring is compiled in: `"remote"` (pure HTTP/Hrana) or `"embedded"` (C-SQLite).
    pub profile: &'static str,
}

impl StoreHealth {
    /// A store is healthy iff it is durable AND a schema has been provisioned.
    pub fn is_healthy(&self) -> bool {
        self.durable && self.schema_version > 0
    }
}
