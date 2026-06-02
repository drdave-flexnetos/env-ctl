//! Store health probe: the remote store is reachable and the schema is provisioned. (`secretd`
//! proves both as a side effect of opening the store — `LibSqlStoreBuilder::build` connects and runs
//! the schema batch, so a dead/unschemaed sqld fails startup; `health()` is the explicit probe.)

/// Snapshot of a libSQL store's health, returned by `LibSqlStore::health`.
#[derive(Debug, Clone)]
pub struct StoreHealth {
    /// True if the store is reachable and the server APPLIED the prior statement — a `SELECT 1`
    /// `fsync_barrier` round-trip on the (sequential) Hrana stream. Durability is sqld SERVER-side
    /// (WAL, durable by default); the client does NOT set or verify a disk fsync (Hrana rejects
    /// `PRAGMA synchronous=FULL`). The barrier confirms server application before success (HF-14).
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
