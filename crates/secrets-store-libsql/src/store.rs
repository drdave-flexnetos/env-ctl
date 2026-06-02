//! `LibSqlStore`: the libSQL-backed implementation of [`envctl_secrets::vault::Store`].
//!
//! The engine's `Store` trait is sync; every method here drives the async libSQL remote client via
//! the private current-thread runtime in [`crate::sync::SyncConnection`]. Encryption happens ABOVE
//! this trait — the store only ever moves ciphertext + non-secret metadata. The audit chain math
//! is the engine's single source of truth (`envctl_secrets::vault::audit`), so this backend can
//! never disagree with `InMemStore` on the chain (HF-14).

use envctl_secrets::event::AuditRecord;
use envctl_secrets::keyslot::Keyslot;
use envctl_secrets::vault::{audit, BearerRow, CertRow, RelayPolicyRow, SecretRow, Store};
use libsql::Value;

use crate::error::Error;
use crate::health::StoreHealth;
use crate::schema;
use crate::serial;
use crate::sync::SyncConnection;

/// Builder for [`LibSqlStore`]: collects the remote URL + auth token, opens the connection, and
/// provisions the schema. Durability is server-side (see [`LibSqlStoreBuilder::build`]).
pub struct LibSqlStoreBuilder {
    url: String,
    auth_token: String,
}

impl LibSqlStoreBuilder {
    pub fn new(url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            auth_token: auth_token.into(),
        }
    }

    /// Open the remote DB and provision the schema. Returns a ready store.
    ///
    /// Durability is the SERVER's responsibility for the remote backend: sqld persists each write to
    /// its WAL (durable by default), and [`LibSqlStore::fsync_barrier`] (a `SELECT 1` round-trip
    /// after each write) confirms the prior statement was applied by the server before success is
    /// reported (HF-14). A client-side `PRAGMA synchronous=FULL` is deliberately NOT issued: Hrana
    /// rejects `PRAGMA` as an "unsupported statement", and the client cannot set the server's sync
    /// mode regardless.
    pub fn build(self) -> anyhow::Result<LibSqlStore> {
        let conn = SyncConnection::open_remote(&self.url, &self.auth_token)?;
        // Provision the schema as a Hrana batch (idempotent DDL; no explicit BEGIN/COMMIT — see DDL).
        conn.runtime().block_on(async {
            let c = conn.conn();
            c.execute_batch(schema::DDL)
                .await
                .map_err(|e| Error::ExecuteFailed(e.to_string()))
        })?;
        Ok(LibSqlStore {
            conn,
            append_lock: std::sync::Mutex::new(()),
        })
    }
}

/// libSQL remote-backed `Store`. Holds one [`SyncConnection`] (its own runtime + connection),
/// shared behind an `Arc` by the engine; all methods take `&self`.
pub struct LibSqlStore {
    conn: SyncConnection,
    /// Serializes `append_audit` within this process. The engine audits under only a READ lock, so
    /// two concurrent RPCs (each on its own `spawn_blocking` thread) could otherwise both read tail
    /// `seq=N`, both seal `N+1`, and the second INSERT would lose to the `seq` PRIMARY KEY — cleanly
    /// erroring but DROPPING that security event's row. `InMemStore` holds a Mutex across link+push;
    /// this is the libSQL analogue (here the read->insert window is a network RTT, so the race is
    /// wider). Held across read-tail + insert so the chain `seq` can never be computed from a stale tail.
    append_lock: std::sync::Mutex<()>,
}

impl LibSqlStore {
    /// Confirm durability with a dummy round-trip (the `fsync_barrier`, HF-14). Audit appends call
    /// this before returning so an `Allowed` is never reported before the row is durable.
    pub fn fsync_barrier(&self) -> anyhow::Result<()> {
        let _ = self
            .conn
            .query_one(schema::FSYNC_BARRIER_PROBE, Vec::new())?;
        Ok(())
    }

    /// Health probe: reachable + schema provisioned + durable.
    pub fn health(&self) -> anyhow::Result<StoreHealth> {
        let durable = self.fsync_barrier().is_ok();
        let schema_version = self
            .get_meta("schema_version")?
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        Ok(StoreHealth {
            durable,
            schema_version,
            profile: if cfg!(feature = "embedded") {
                "embedded"
            } else {
                "remote"
            },
        })
    }
}

impl Store for LibSqlStore {
    // ---- meta KV ----

    fn get_meta(&self, k: &str) -> anyhow::Result<Option<String>> {
        let row = self
            .conn
            .query_one(schema::GET_META, vec![Value::Text(k.to_string())])?;
        match row {
            Some(r) => Ok(Some(
                r.get::<String>(0)
                    .map_err(|e| Error::SerializationError(format!("meta.v: {e}")))?,
            )),
            None => Ok(None),
        }
    }

    fn put_meta(&self, k: &str, v: &str) -> anyhow::Result<()> {
        self.conn.execute(
            schema::PUT_META,
            vec![Value::Text(k.to_string()), Value::Text(v.to_string())],
        )?;
        self.fsync_barrier()?;
        Ok(())
    }

    // ---- secrets ----

    fn reserve_secret_row_id(&self) -> anyhow::Result<i64> {
        // Atomic bump-and-read under one transaction so two concurrent reservations can never read
        // the same next_id (the reserve/assign TOCTOU the trait contract forbids). Via run_retry so a
        // Hrana stream-expiry reconnects + retries; a stream-expiry means the txn never committed, so
        // a redo is safe (at worst an id is skipped — ids need only be unique + monotonic, gaps OK).
        let id = self.conn.run_retry(|conn, rt| {
            rt.block_on(async {
                let txn = conn
                    .transaction()
                    .await
                    .map_err(|e| Error::TransactionFailed(e.to_string()))?;
                txn.execute(schema::INCREMENT_ROW_ID_COUNTER, ())
                    .await
                    .map_err(|e| Error::ExecuteFailed(e.to_string()))?;
                let mut rows = txn
                    .query(schema::GET_NEXT_ROW_ID, ())
                    .await
                    .map_err(|e| Error::QueryFailed(e.to_string()))?;
                let row = rows
                    .next()
                    .await
                    .map_err(|e| Error::QueryFailed(e.to_string()))?
                    .ok_or_else(|| Error::QueryFailed("row_id_counter row missing".into()))?;
                let id = row
                    .get::<i64>(0)
                    .map_err(|e| Error::SerializationError(format!("next_id: {e}")))?;
                txn.commit()
                    .await
                    .map_err(|e| Error::TransactionFailed(e.to_string()))?;
                Ok::<i64, Error>(id)
            })
        })?;
        Ok(id)
    }

    fn put_secret(&self, row: SecretRow) -> anyhow::Result<i64> {
        // Contract checks (mirror InMemStore): row_id must have been reserved (1..=next_id) and not
        // collide, and version must be max+1 for the name (M-1 monotonicity). All under ONE txn so
        // the read-validate-insert is atomic.
        // Via run_retry so a Hrana stream-expiry reconnects + retries. In the (extremely rare) case a
        // commit succeeded but its ack was lost to an expiry, the retry hits the collision/version
        // check and returns a clean Contract error rather than double-inserting.
        let row_id = self.conn.run_retry(|conn, rt| {
            rt.block_on(async {
            let txn = conn
                .transaction()
                .await
                .map_err(|e| Error::TransactionFailed(e.to_string()))?;

            // next reserved high-water mark
            let next_id = {
                let mut rows = txn
                    .query(schema::GET_NEXT_ROW_ID, ())
                    .await
                    .map_err(|e| Error::QueryFailed(e.to_string()))?;
                rows.next()
                    .await
                    .map_err(|e| Error::QueryFailed(e.to_string()))?
                    .ok_or_else(|| Error::QueryFailed("row_id_counter row missing".into()))?
                    .get::<i64>(0)
                    .map_err(|e| Error::SerializationError(format!("next_id: {e}")))?
            };
            if row.row_id <= 0 || row.row_id > next_id {
                return Err(Error::Contract(format!(
                    "put_secret row_id {} was not reserved (max reserved {})",
                    row.row_id, next_id
                )));
            }

            // collision check
            let collides = txn
                .query(schema::SECRET_ROW_ID_EXISTS, vec![Value::Integer(row.row_id)])
                .await
                .map_err(|e| Error::QueryFailed(e.to_string()))?
                .next()
                .await
                .map_err(|e| Error::QueryFailed(e.to_string()))?
                .is_some();
            if collides {
                return Err(Error::Contract(format!(
                    "put_secret row_id {} collides with an existing row",
                    row.row_id
                )));
            }

            // version monotonicity
            let max_version = {
                let mut rows = txn
                    .query(schema::MAX_SECRET_VERSION, vec![Value::Text(row.name.clone())])
                    .await
                    .map_err(|e| Error::QueryFailed(e.to_string()))?;
                rows.next()
                    .await
                    .map_err(|e| Error::QueryFailed(e.to_string()))?
                    .ok_or_else(|| Error::QueryFailed("MAX(version) returned no row".into()))?
                    .get::<i64>(0)
                    .map_err(|e| Error::SerializationError(format!("max_version: {e}")))?
            };
            let expected = (max_version as u32) + 1;
            if row.version != expected {
                return Err(Error::Contract(format!(
                    "put_secret version {} for {:?} violates monotonicity (expected {})",
                    row.version, row.name, expected
                )));
            }

            txn.execute(schema::INSERT_SECRET_VERSION, serial::bind_secret_row(&row))
                .await
                .map_err(|e| Error::ExecuteFailed(e.to_string()))?;
            txn.commit()
                .await
                .map_err(|e| Error::TransactionFailed(e.to_string()))?;
            Ok::<i64, Error>(row.row_id)
            })
        })?;
        self.fsync_barrier()?;
        Ok(row_id)
    }

    fn get_secret_latest(&self, name: &str) -> anyhow::Result<Option<SecretRow>> {
        let row = self
            .conn
            .query_one(schema::GET_SECRET_LATEST, vec![Value::Text(name.to_string())])?;
        match row {
            Some(r) => Ok(Some(serial::deserialize_secret_row(&r)?)),
            None => Ok(None),
        }
    }

    fn get_secret_version(&self, name: &str, version: u32) -> anyhow::Result<Option<SecretRow>> {
        let row = self.conn.query_one(
            schema::GET_SECRET_VERSION,
            vec![Value::Text(name.to_string()), Value::Integer(version as i64)],
        )?;
        match row {
            Some(r) => Ok(Some(serial::deserialize_secret_row(&r)?)),
            None => Ok(None),
        }
    }

    fn max_secret_version(&self, name: &str) -> anyhow::Result<u32> {
        let row = self
            .conn
            .query_one(schema::MAX_SECRET_VERSION, vec![Value::Text(name.to_string())])?;
        match row {
            Some(r) => Ok(r
                .get::<i64>(0)
                .map_err(|e| Error::SerializationError(format!("max_version: {e}")))?
                as u32),
            None => Ok(0),
        }
    }

    fn list_secret_names(&self) -> anyhow::Result<Vec<String>> {
        let rows = self.conn.query_all(schema::LIST_SECRET_NAMES, Vec::new())?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(
                r.get::<String>(0)
                    .map_err(|e| Error::SerializationError(format!("secret.name: {e}")))?,
            );
        }
        Ok(out)
    }

    fn list_secret_versions(&self, name: &str) -> anyhow::Result<Vec<u32>> {
        let rows = self
            .conn
            .query_all(schema::LIST_SECRET_VERSIONS, vec![Value::Text(name.to_string())])?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(
                r.get::<i64>(0)
                    .map_err(|e| Error::SerializationError(format!("secret.version: {e}")))?
                    as u32,
            );
        }
        Ok(out)
    }

    // ---- keyslots ----

    fn save_keyslot(&self, slot: &Keyslot) -> anyhow::Result<()> {
        self.conn.execute(schema::SAVE_KEYSLOT, serial::bind_keyslot(slot)?)?;
        self.fsync_barrier()?;
        Ok(())
    }

    fn load_keyslots(&self) -> anyhow::Result<Vec<Keyslot>> {
        let rows = self.conn.query_all(schema::LOAD_KEYSLOTS, Vec::new())?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(serial::deserialize_keyslot(r)?);
        }
        Ok(out)
    }

    fn load_keyslot(&self, id: i64) -> anyhow::Result<Option<Keyslot>> {
        let row = self.conn.query_one(schema::LOAD_KEYSLOT, vec![Value::Integer(id)])?;
        match row {
            Some(r) => Ok(Some(serial::deserialize_keyslot(&r)?)),
            None => Ok(None),
        }
    }

    // ---- audit (hash-chained, durable append-only) ----

    fn append_audit(&self, rec: &AuditRecord) -> anyhow::Result<i64> {
        // Serialize appenders in-process (the InMemStore-atomicity analogue): hold the lock across
        // read-tail + insert so two concurrent appends can't seal the same `seq` from a stale tail
        // and drop a row. Each store call still routes through run_retry (reconnect-on-expiry); the
        // `SELECT 1` fsync_barrier confirms the server APPLIED the insert (durability is server-side).
        let _guard = self.append_lock.lock().expect("append_lock poisoned");
        let tail = self.last_audit()?;
        let sealed = audit::link_row(tail.as_ref(), rec.clone());
        let seq = sealed.seq;
        self.conn
            .execute(schema::APPEND_AUDIT, serial::bind_audit_record(&sealed)?)?;
        self.fsync_barrier()?;
        Ok(seq)
    }

    fn verify_audit_chain(&self) -> anyhow::Result<()> {
        let rows = self.conn.query_all(schema::ALL_AUDIT_ASC, Vec::new())?;
        let mut chain = Vec::with_capacity(rows.len());
        for r in &rows {
            chain.push(serial::deserialize_audit_record(r)?);
        }
        audit::verify_chain(&chain).map_err(|seq| Error::AuditChainBroken(seq).into())
    }

    fn last_audit(&self) -> anyhow::Result<Option<AuditRecord>> {
        let row = self.conn.query_one(schema::LAST_AUDIT, Vec::new())?;
        match row {
            Some(r) => Ok(Some(serial::deserialize_audit_record(&r)?)),
            None => Ok(None),
        }
    }

    fn query_audit(&self, since_seq: i64, limit: usize) -> anyhow::Result<Vec<AuditRecord>> {
        let rows = self.conn.query_all(
            schema::QUERY_AUDIT,
            vec![Value::Integer(since_seq), Value::Integer(limit as i64)],
        )?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(serial::deserialize_audit_record(r)?);
        }
        Ok(out)
    }

    // ---- relay policies ----

    fn save_relay_policy(&self, row: RelayPolicyRow) -> anyhow::Result<i64> {
        // Upsert by relay_id, reusing the existing id (so live bearers' policy_id is never orphaned).
        // id == 0 => assign: reuse existing, else max+1.
        let existing = self
            .conn
            .query_one(schema::SELECT_RELAY_ID_BY_NAME, vec![Value::Text(row.policy.relay_id.clone())])?;
        let existing_id = match existing {
            Some(r) => Some(
                r.get::<i64>(0)
                    .map_err(|e| Error::SerializationError(format!("relay.id: {e}")))?,
            ),
            None => None,
        };
        let id = if row.id != 0 {
            row.id
        } else if let Some(eid) = existing_id {
            eid
        } else {
            let max = self
                .conn
                .query_one(schema::SELECT_RELAY_MAX_ID, Vec::new())?
                .map(|r| r.get::<i64>(0).unwrap_or(0))
                .unwrap_or(0);
            max + 1
        };
        self.conn
            .execute(schema::UPSERT_RELAY_POLICY, serial::bind_relay_policy(id, &row)?)?;
        self.fsync_barrier()?;
        Ok(id)
    }

    fn load_relay_policy(&self, relay_id: &str) -> anyhow::Result<Option<RelayPolicyRow>> {
        let row = self
            .conn
            .query_one(schema::LOAD_RELAY_POLICY, vec![Value::Text(relay_id.to_string())])?;
        match row {
            Some(r) => Ok(Some(serial::deserialize_relay_policy(&r)?)),
            None => Ok(None),
        }
    }

    fn list_relay_policies(&self) -> anyhow::Result<Vec<RelayPolicyRow>> {
        let rows = self.conn.query_all(schema::LIST_RELAY_POLICIES, Vec::new())?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(serial::deserialize_relay_policy(r)?);
        }
        Ok(out)
    }

    // ---- relay bearers ----

    fn save_bearer(&self, row: BearerRow) -> anyhow::Result<()> {
        self.conn.execute(schema::SAVE_BEARER, serial::bind_bearer_row(&row))?;
        self.fsync_barrier()?;
        Ok(())
    }

    fn load_bearer(&self, token_id: &str) -> anyhow::Result<Option<BearerRow>> {
        let row = self
            .conn
            .query_one(schema::LOAD_BEARER, vec![Value::Text(token_id.to_string())])?;
        match row {
            Some(r) => Ok(Some(serial::deserialize_bearer_row(&r)?)),
            None => Ok(None),
        }
    }

    fn list_bearers_for_relay(&self, relay_id: &str) -> anyhow::Result<Vec<BearerRow>> {
        let rows = self
            .conn
            .query_all(schema::LIST_BEARERS_FOR_RELAY, vec![Value::Text(relay_id.to_string())])?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(serial::deserialize_bearer_row(r)?);
        }
        Ok(out)
    }

    fn revoke_bearers_for_relay(&self, relay_id: &str) -> anyhow::Result<u32> {
        let n = self
            .conn
            .execute(schema::REVOKE_BEARERS_FOR_RELAY, vec![Value::Text(relay_id.to_string())])?;
        self.fsync_barrier()?;
        Ok(n as u32)
    }

    // ---- ca / certs ----

    fn save_cert(&self, row: CertRow) -> anyhow::Result<()> {
        self.conn.execute(schema::SAVE_CERT, serial::bind_cert_row(&row))?;
        self.fsync_barrier()?;
        Ok(())
    }

    fn load_cert(&self, serial_str: &str) -> anyhow::Result<Option<CertRow>> {
        let row = self
            .conn
            .query_one(schema::LOAD_CERT, vec![Value::Text(serial_str.to_string())])?;
        match row {
            Some(r) => Ok(Some(serial::deserialize_cert_row(&r)?)),
            None => Ok(None),
        }
    }

    fn list_certs(&self) -> anyhow::Result<Vec<CertRow>> {
        let rows = self.conn.query_all(schema::LIST_CERTS, Vec::new())?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(serial::deserialize_cert_row(r)?);
        }
        Ok(out)
    }
}
