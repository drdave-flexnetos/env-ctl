//! Storage backend behind a `Store` trait. OI-1 RESOLVED = libSQL (NEW-3, see docs/SERVER-MODE.md):
//! its server/replica/sync serves remote clients. libSQL + its bundled C SQLite (`libsql-ffi`) are
//! QUARANTINED in `crates/secrets-store-libsql`, consumed ONLY by secretd behind THIS trait — the
//! engine lib NEVER links libSQL, so the per-crate no-C gate
//! (`! cargo tree -p envctl-secrets-engine | grep libsql-ffi`) stays green. Encryption happens ABOVE
//! this trait (ciphertext + non-secret metadata only). Phase 1b ships a real RAM-backed
//! `InMemStore`; the libSQL backend lands later behind the IDENTICAL trait, C-isolated.
//!
//! ## Encryption-agnostic
//!
//! A `Store` only ever sees ciphertext + non-secret metadata — never the DEK, the plaintext, or an
//! unlock key. `SecretRow` carries the XChaCha20 nonce + `ct||tag` and the identity fields
//! (`row_id`/`version`/`dek_generation`) the engine uses to reconstruct the canonical `record_aad`
//! at open time (the AAD is NEVER stored — HF-2). The durable, hash-chained audit log is committed
//! here BEFORE security RPCs return (HF-14): `append_audit` links + pushes synchronously.
#[cfg(not(feature = "inmem-store"))]
compile_error!("select a store backend feature (`inmem-store`, or the OI-1-ruled pure-Rust backend)");

use crate::event::AuditRecord;
use crate::keyslot::Keyslot;
use serde::{Deserialize, Serialize};

use super::audit;

/// One stored, sealed secret version. Ciphertext + non-secret metadata ONLY (no DEK, no
/// plaintext). `row_id`/`version`/`dek_generation` reconstruct the canonical `record_aad` at open
/// time (NEVER stored — HF-2). `nonce`+`ct_tag` are the `vault::crypto::seal` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretRow {
    pub row_id: i64, // stable per (name,version); feeds record_aad
    pub name: String,
    pub version: u32,
    pub provider: crate::broker::Provider,
    pub note: String,
    pub broker_only: bool,
    pub dek_generation: i64,
    pub nonce: Vec<u8>,  // 24-byte XChaCha20 nonce
    pub ct_tag: Vec<u8>, // ct||Poly1305 tag
    pub created_ts: String, // RFC3339, from Clock
}

/// Minimal relay row (stub surface for 1b; real fields filled in Phase 4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayPolicyRow {
    pub id: i64,
    pub policy: crate::broker::RelayPolicy,
}

/// A persisted relay bearer. Only the keyed `mac` (over the wire string) AND the keyed `row_mac`
/// (over the security-critical metadata) authenticate this row — the raw bearer is NEVER stored.
///
/// `mac` binds the opaque wire string; `row_mac` (a DEK-keyed `blake3::keyed_hash` over
/// `bearer_row_mac_message`) binds every field `decide` trusts (`revoked`, `expires_at_ms`,
/// `issued_at_ms`, `issued_boottime_ms`, `policy_id`, `client_uid`, `client_pid`). Without it a
/// store-level attacker could flip `revoked`, raise the expiry, rewrite the peer binding, or repoint
/// `policy_id` and still pass the wire MAC (which never sees those fields) — reaching `Allow`. The
/// engine recomputes `row_mac` on every legitimate write (mint AND revoke, DEK live) and re-verifies
/// it before the pure decision; a tamper fails closed (treated as `UnknownBearer`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BearerRow {
    pub token_id: String,
    pub policy_id: i64,
    pub mac: Vec<u8>,
    pub expires_at_ms: i64,
    pub issued_at_ms: i64,
    /// `CLOCK_BOOTTIME` snapshot (ms) captured at mint — the monotonic anchor that fences a
    /// wall-clock rollback resurrecting an expired/within-window bearer (OI-6). Bound into `row_mac`.
    pub issued_boottime_ms: i64,
    pub client_uid: Option<u32>,
    pub client_pid: Option<u32>,
    /// Remote binding (Phase 8, F15): the registered remote client this bearer is bound to, and the
    /// DPoP public-key thumbprint (RFC 7638) it must prove possession of. `None` for a local uid/pid
    /// bearer. A bearer is REMOTE iff `client_id.is_some()` (the planes are mutually exclusive). BOTH
    /// are bound into `row_mac` via the plane-tagged `bearer_row_mac_message` (F12), so a store-level
    /// tamper that adds/swaps them — or flips a local row to remote — fails the row MAC, closed.
    pub client_id: Option<String>,
    pub dpop_jkt: Option<[u8; 32]>,
    pub revoked: bool,
    /// DEK-keyed MAC over `bearer_row_mac_message(..)` of the fields above. Authenticates the
    /// clear-text row state so a store-level tamper cannot forge an `Allow`.
    pub row_mac: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertRow {
    pub serial: String,
    pub cn: String,
    pub not_after: String,
    pub der: Vec<u8>,
}

/// A registered remote client (Phase 8, F15): the principal a remote bearer can be bound to. The
/// edge authenticates a presented `client_id` against this registry (enabled + the registered DPoP
/// key) before a swap. `hardware_bound` records whether the operator attested a NON-extractable key
/// store (OI-SM-5 / audit F20): `false` means the binding is bearer-only — replay-BOUNDED by
/// scope/TTL, not replay-PREVENTED — and swaps should be tagged accordingly. The registry holds NO
/// secret (the jkt is a public-key thumbprint), so it is non-secret metadata like the other rows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteClient {
    pub client_id: String,
    /// RFC 7638 JWK SHA-256 thumbprint of the client's registered DPoP public key.
    pub dpop_jkt: [u8; 32],
    pub enabled: bool,
    pub hardware_bound: bool,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

/// The vault's persistence surface. Encryption happens ABOVE this trait — a `Store` only ever
/// sees ciphertext + non-secret metadata. All methods take `&self` (interior mutability) so the
/// engine can hold a `Box<dyn Store>` shared behind an `Arc` without an outer lock per call.
pub trait Store: Send + Sync {
    // ---- meta KV (real) ----
    fn get_meta(&self, k: &str) -> anyhow::Result<Option<String>>;
    fn put_meta(&self, k: &str, v: &str) -> anyhow::Result<()>;

    // ---- secrets (real CRUD; ciphertext only) ----
    /// Atomically allocate and return the `row_id` the NEXT `put_secret` must carry. The store is
    /// the sole authority for `row_id`s: the engine seals the record AAD against THIS id, then
    /// inserts a row whose `row_id` equals it (see `put_secret`). Reserving under the store's own
    /// lock removes the reserve/assign TOCTOU that previously let two concurrent puts seal against
    /// the same id while the store handed out two distinct ids — which permanently de-authenticated
    /// the loser's ciphertext (AAD/row_id divergence). Monotonic, strictly increasing.
    fn reserve_secret_row_id(&self) -> anyhow::Result<i64>;
    /// Insert a new sealed version. `row.row_id` MUST be a value previously handed out by
    /// `reserve_secret_row_id` (the engine sealed the AAD against it); the store persists it
    /// VERBATIM and returns it. Implementations MUST reject (`Err`) a `row_id` that was never
    /// reserved or that collides with an existing row, so a divergent id can never be stored under
    /// an AAD it does not match. `row.version` must be the NEXT version for `row.name` (engine
    /// computes it under the same critical section). Durable before return.
    fn put_secret(&self, row: SecretRow) -> anyhow::Result<i64>;
    /// Latest enabled version for `name`, or `None`.
    fn get_secret_latest(&self, name: &str) -> anyhow::Result<Option<SecretRow>>;
    /// A specific version.
    fn get_secret_version(&self, name: &str, version: u32) -> anyhow::Result<Option<SecretRow>>;
    /// Highest version number currently stored for `name` (0 if none) — lets the engine pick `v+1`.
    fn max_secret_version(&self, name: &str) -> anyhow::Result<u32>;
    fn list_secret_names(&self) -> anyhow::Result<Vec<String>>;
    fn list_secret_versions(&self, name: &str) -> anyhow::Result<Vec<u32>>;

    // ---- keyslots (real CRUD) ----
    fn save_keyslot(&self, slot: &Keyslot) -> anyhow::Result<()>; // upsert by slot.id
    fn load_keyslots(&self) -> anyhow::Result<Vec<Keyslot>>; // canonical ascending id order
    fn load_keyslot(&self, id: i64) -> anyhow::Result<Option<Keyslot>>;

    // ---- audit (real, hash-chained) ----
    /// Append a row DURABLY before return (HF-14). Returns the assigned `seq`.
    fn append_audit(&self, rec: &AuditRecord) -> anyhow::Result<i64>;
    fn verify_audit_chain(&self) -> anyhow::Result<()>;
    /// Tail of the chain for prev_hash linkage; `None` => genesis.
    fn last_audit(&self) -> anyhow::Result<Option<AuditRecord>>;
    fn query_audit(&self, since_seq: i64, limit: usize) -> anyhow::Result<Vec<AuditRecord>>;

    // ---- relay policies + bearers (minimal stubs in 1b: empty/no-op ok) ----
    fn save_relay_policy(&self, _row: RelayPolicyRow) -> anyhow::Result<i64> {
        Ok(0)
    }
    fn load_relay_policy(&self, _relay_id: &str) -> anyhow::Result<Option<RelayPolicyRow>> {
        Ok(None)
    }
    fn list_relay_policies(&self) -> anyhow::Result<Vec<RelayPolicyRow>> {
        Ok(Vec::new())
    }
    fn save_bearer(&self, _row: BearerRow) -> anyhow::Result<()> {
        Ok(())
    }
    fn load_bearer(&self, _token_id: &str) -> anyhow::Result<Option<BearerRow>> {
        Ok(None)
    }
    /// Every bearer (revoked or not) hanging off `relay_id`'s policy. Used by the dry-run revoke to
    /// count what WOULD be revoked without mutating. Default-empty for stub backends.
    fn list_bearers_for_relay(&self, _relay_id: &str) -> anyhow::Result<Vec<BearerRow>> {
        Ok(Vec::new())
    }
    /// WARNING: this flips `revoked` WITHOUT recomputing the DEK-keyed `row_mac`, so a bearer revoked
    /// via this method will FAIL its row-MAC verify on the next swap (denied as `UnknownBearer` —
    /// fail-closed, and a revoked bearer denies anyway). The engine therefore does NOT use it for the
    /// authoritative revoke: `relay_revoke` reseals each bearer's row MAC individually (DEK live). A
    /// future caller wanting a relay-wide revoke MUST reseal the row MAC of every flipped row, or the
    /// rows become unauthenticated.
    fn revoke_bearers_for_relay(&self, _relay_id: &str) -> anyhow::Result<u32> {
        Ok(0)
    }

    // ---- remote clients (Phase 8, F15; minimal stubs in 1b) ----
    /// Upsert a registered remote client by `client_id`.
    fn save_remote_client(&self, _row: RemoteClient) -> anyhow::Result<()> {
        Ok(())
    }
    fn load_remote_client(&self, _client_id: &str) -> anyhow::Result<Option<RemoteClient>> {
        Ok(None)
    }
    fn list_remote_clients(&self) -> anyhow::Result<Vec<RemoteClient>> {
        Ok(Vec::new())
    }
    /// Mark a client revoked (set `revoked_at_ms`, `enabled=false`). Returns true iff it existed.
    fn revoke_remote_client(&self, _client_id: &str, _now_ms: i64) -> anyhow::Result<bool> {
        Ok(false)
    }

    // ---- ca / certs (minimal stubs in 1b) ----
    fn save_cert(&self, _row: CertRow) -> anyhow::Result<()> {
        Ok(())
    }
    fn load_cert(&self, _serial: &str) -> anyhow::Result<Option<CertRow>> {
        Ok(None)
    }
    fn list_certs(&self) -> anyhow::Result<Vec<CertRow>> {
        Ok(Vec::new())
    }
}

/// RAM-only backend for tests/CI (the envctl `DryRunRunner` analogue). Holds nothing durable
/// across process restarts, but is fully functional in-process: secrets, keyslots and the
/// hash-chained audit log all live behind one `Mutex` (std only — no dep added). `append_audit`
/// links + pushes synchronously while holding the lock, so a row is committed before the call
/// returns (HF-14).
pub struct InMemStore {
    inner: std::sync::Mutex<InMemData>,
}

#[derive(Default)]
struct InMemData {
    meta: std::collections::BTreeMap<String, String>,
    secrets: Vec<SecretRow>, // append-only; latest = max version per name
    keyslots: std::collections::BTreeMap<i64, Keyslot>,
    audit: Vec<AuditRecord>, // ordered by seq, 1-based
    next_secret_row_id: i64, // high-water mark of reserved row_ids (monotonic)
    relays: Vec<RelayPolicyRow>,
    bearers: Vec<BearerRow>,
    remote_clients: Vec<RemoteClient>,
    certs: Vec<CertRow>,
}

impl InMemStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(InMemData::default()),
        }
    }
}

impl Default for InMemStore {
    fn default() -> Self {
        Self::new()
    }
}

/// A poisoned `Mutex` means another thread panicked mid-mutation — the in-RAM store may be torn,
/// so surface it as a setup-time error rather than `unwrap()`-panicking the caller.
fn lock_poisoned() -> anyhow::Error {
    anyhow::anyhow!("in-memory store mutex poisoned")
}

impl Store for InMemStore {
    fn get_meta(&self, k: &str) -> anyhow::Result<Option<String>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.meta.get(k).cloned())
    }

    fn put_meta(&self, k: &str, v: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        g.meta.insert(k.to_string(), v.to_string());
        Ok(())
    }

    fn reserve_secret_row_id(&self) -> anyhow::Result<i64> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        // Atomically bump + return the high-water mark under the store's own lock. The engine seals
        // the AAD against exactly this id and then inserts a row carrying it (HF-2 binding).
        g.next_secret_row_id += 1;
        Ok(g.next_secret_row_id)
    }

    fn put_secret(&self, row: SecretRow) -> anyhow::Result<i64> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        // The store is authoritative for row_ids and persists the engine-sealed id VERBATIM (the
        // record AAD is bound to it). Reject any id that was never reserved or that collides with an
        // existing row, so a divergent id can never be stored under an AAD it does not match.
        if row.row_id <= 0 || row.row_id > g.next_secret_row_id {
            anyhow::bail!(
                "put_secret row_id {} was not reserved via reserve_secret_row_id (max reserved {})",
                row.row_id,
                g.next_secret_row_id
            );
        }
        if g.secrets.iter().any(|r| r.row_id == row.row_id) {
            anyhow::bail!("put_secret row_id {} collides with an existing row", row.row_id);
        }
        // M-1: version-monotonicity. Codify the store contract (the engine computes
        // `version = max_secret_version + 1` under the write lock): the next version for `row.name`
        // MUST be `max+1` (or 1 when there is none). A hostile/buggy store-caller that skips, repeats,
        // or rewinds a version is rejected at WRITE time (earlier, observable) instead of producing a
        // row that later fails its AEAD open (the AAD is bound to `version`) as a silent open-time DoS.
        let expected_version = g
            .secrets
            .iter()
            .filter(|r| r.name == row.name)
            .map(|r| r.version)
            .max()
            .map_or(1, |m| m + 1);
        if row.version != expected_version {
            anyhow::bail!(
                "put_secret version {} for {:?} violates monotonicity (expected {})",
                row.version,
                row.name,
                expected_version
            );
        }
        let row_id = row.row_id;
        g.secrets.push(row);
        Ok(row_id)
    }

    fn get_secret_latest(&self, name: &str) -> anyhow::Result<Option<SecretRow>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g
            .secrets
            .iter()
            .filter(|r| r.name == name)
            .max_by_key(|r| r.version)
            .cloned())
    }

    fn get_secret_version(&self, name: &str, version: u32) -> anyhow::Result<Option<SecretRow>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g
            .secrets
            .iter()
            .find(|r| r.name == name && r.version == version)
            .cloned())
    }

    fn max_secret_version(&self, name: &str) -> anyhow::Result<u32> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g
            .secrets
            .iter()
            .filter(|r| r.name == name)
            .map(|r| r.version)
            .max()
            .unwrap_or(0))
    }

    fn list_secret_names(&self) -> anyhow::Result<Vec<String>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let mut names: Vec<String> = g.secrets.iter().map(|r| r.name.clone()).collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn list_secret_versions(&self, name: &str) -> anyhow::Result<Vec<u32>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let mut vs: Vec<u32> = g
            .secrets
            .iter()
            .filter(|r| r.name == name)
            .map(|r| r.version)
            .collect();
        vs.sort_unstable();
        Ok(vs)
    }

    fn save_keyslot(&self, slot: &Keyslot) -> anyhow::Result<()> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        g.keyslots.insert(slot.id, slot.clone());
        Ok(())
    }

    fn load_keyslots(&self) -> anyhow::Result<Vec<Keyslot>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        // BTreeMap iterates by ascending key, so this is canonical ascending id order.
        Ok(g.keyslots.values().cloned().collect())
    }

    fn load_keyslot(&self, id: i64) -> anyhow::Result<Option<Keyslot>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.keyslots.get(&id).cloned())
    }

    fn append_audit(&self, rec: &AuditRecord) -> anyhow::Result<i64> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        // Link against the current tail and push synchronously while holding the lock so the row
        // is durable-before-return (HF-14). The chain math lives in `audit`, the single source of
        // truth both backends funnel through.
        let sealed = audit::link_row(g.audit.last(), rec.clone());
        let seq = sealed.seq;
        g.audit.push(sealed);
        Ok(seq)
    }

    fn verify_audit_chain(&self) -> anyhow::Result<()> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        audit::verify_chain(&g.audit)
            .map_err(|seq| crate::error::EngineError::AuditChainBroken(seq).into())
    }

    fn last_audit(&self) -> anyhow::Result<Option<AuditRecord>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.audit.last().cloned())
    }

    fn query_audit(&self, since_seq: i64, limit: usize) -> anyhow::Result<Vec<AuditRecord>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g
            .audit
            .iter()
            .filter(|r| r.seq > since_seq)
            .take(limit)
            .cloned()
            .collect())
    }

    fn save_relay_policy(&self, row: RelayPolicyRow) -> anyhow::Result<i64> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        // Upsert by relay_id. Re-minting a Named relay MUST reuse the SAME row id (the bearer
        // linkage key) — its live bearers carry that policy_id, so reassigning it would orphan them.
        // An `id == 0` caller asks the store to assign: reuse the existing id on upsert, else mint a
        // fresh monotonic id (max existing + 1, so an upsert can never collide with a live id).
        let existing_id = g
            .relays
            .iter()
            .find(|r| r.policy.relay_id == row.policy.relay_id)
            .map(|r| r.id);
        let id = if row.id != 0 {
            row.id
        } else if let Some(eid) = existing_id {
            eid
        } else {
            g.relays.iter().map(|r| r.id).max().unwrap_or(0) + 1
        };
        if let Some(existing) = g
            .relays
            .iter_mut()
            .find(|r| r.policy.relay_id == row.policy.relay_id)
        {
            *existing = RelayPolicyRow { id, ..row };
        } else {
            g.relays.push(RelayPolicyRow { id, ..row });
        }
        Ok(id)
    }

    fn load_relay_policy(&self, relay_id: &str) -> anyhow::Result<Option<RelayPolicyRow>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g
            .relays
            .iter()
            .find(|r| r.policy.relay_id == relay_id)
            .cloned())
    }

    fn list_relay_policies(&self) -> anyhow::Result<Vec<RelayPolicyRow>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.relays.clone())
    }

    fn save_bearer(&self, row: BearerRow) -> anyhow::Result<()> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        if let Some(existing) = g.bearers.iter_mut().find(|b| b.token_id == row.token_id) {
            *existing = row;
        } else {
            g.bearers.push(row);
        }
        Ok(())
    }

    fn load_bearer(&self, token_id: &str) -> anyhow::Result<Option<BearerRow>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.bearers.iter().find(|b| b.token_id == token_id).cloned())
    }

    fn list_bearers_for_relay(&self, relay_id: &str) -> anyhow::Result<Vec<BearerRow>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let Some(policy_id) = g
            .relays
            .iter()
            .find(|r| r.policy.relay_id == relay_id)
            .map(|r| r.id)
        else {
            return Ok(Vec::new());
        };
        Ok(g
            .bearers
            .iter()
            .filter(|b| b.policy_id == policy_id)
            .cloned()
            .collect())
    }

    fn revoke_bearers_for_relay(&self, relay_id: &str) -> anyhow::Result<u32> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        // Map relay_id -> policy_id, then flip every matching, not-yet-revoked bearer.
        let policy_id = g
            .relays
            .iter()
            .find(|r| r.policy.relay_id == relay_id)
            .map(|r| r.id);
        let Some(policy_id) = policy_id else {
            return Ok(0);
        };
        let mut n = 0u32;
        for b in g.bearers.iter_mut() {
            if b.policy_id == policy_id && !b.revoked {
                b.revoked = true;
                n += 1;
            }
        }
        Ok(n)
    }

    fn save_remote_client(&self, row: RemoteClient) -> anyhow::Result<()> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        if let Some(existing) = g
            .remote_clients
            .iter_mut()
            .find(|c| c.client_id == row.client_id)
        {
            *existing = row;
        } else {
            g.remote_clients.push(row);
        }
        Ok(())
    }

    fn load_remote_client(&self, client_id: &str) -> anyhow::Result<Option<RemoteClient>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g
            .remote_clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned())
    }

    fn list_remote_clients(&self) -> anyhow::Result<Vec<RemoteClient>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.remote_clients.clone())
    }

    fn revoke_remote_client(&self, client_id: &str, now_ms: i64) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        if let Some(c) = g
            .remote_clients
            .iter_mut()
            .find(|c| c.client_id == client_id)
        {
            c.enabled = false;
            c.revoked_at_ms = Some(now_ms);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn save_cert(&self, row: CertRow) -> anyhow::Result<()> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        if let Some(existing) = g.certs.iter_mut().find(|c| c.serial == row.serial) {
            *existing = row;
        } else {
            g.certs.push(row);
        }
        Ok(())
    }

    fn load_cert(&self, serial: &str) -> anyhow::Result<Option<CertRow>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.certs.iter().find(|c| c.serial == serial).cloned())
    }

    fn list_certs(&self) -> anyhow::Result<Vec<CertRow>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(g.certs.clone())
    }
}

/// Test / diagnostic helpers. These are NOT `#[cfg(test)]` because integration tests (which
/// compile the crate without the `test` cfg) need them; they only mutate/inspect the in-RAM audit
/// log and are harmless on the RAM-only backend. The libSQL backend does not expose them.
impl InMemStore {
    /// Flip one byte of the `subject` of the row at `seq` WITHOUT recomputing `row_hash`, so
    /// `verify_audit_chain` will detect the tamper at that seq. Used by the test that proves the
    /// chain catches a mutated middle row.
    pub fn tamper_audit_subject(&self, seq: i64) {
        let mut g = self.inner.lock().expect("audit tamper lock");
        if let Some(row) = g.audit.iter_mut().find(|r| r.seq == seq) {
            row.subject = Some(match row.subject.take() {
                Some(s) => format!("{s}!tampered"),
                None => "tampered".to_string(),
            });
        }
    }

    /// Snapshot the current audit chain (for assertions on seq / prev_hash linkage).
    pub fn audit_rows(&self) -> Vec<AuditRecord> {
        let g = self.inner.lock().expect("audit snapshot lock");
        g.audit.clone()
    }

    /// Drop the last `n` rows of the audit chain WITHOUT touching anything else, modeling a
    /// store-level attacker (or a crash) that truncates the tail. The remaining rows still form a
    /// valid unkeyed chain (seq 1..=k, linked), so only the DEK-keyed anchor can catch this. Used
    /// by the tail-truncation regression test.
    pub fn truncate_audit_tail(&self, n: usize) {
        let mut g = self.inner.lock().expect("audit truncate lock");
        let keep = g.audit.len().saturating_sub(n);
        g.audit.truncate(keep);
    }

    /// Overwrite a meta value, modeling a store-level tamper of a non-secret header field (e.g.
    /// `vault.dek_generation`). Used by the dek_generation-binding regression test.
    pub fn tamper_meta(&self, k: &str, v: &str) {
        let mut g = self.inner.lock().expect("meta tamper lock");
        g.meta.insert(k.to_string(), v.to_string());
    }

    /// Mutate a stored `BearerRow` IN PLACE without recomputing its DEK-keyed `row_mac`, modeling a
    /// store-level attacker who edits the clear-text bearer metadata (un-revoke, extend expiry,
    /// rewrite the peer binding, repoint the policy_id). The row-MAC verify on the swap path must
    /// reject this as `UnknownBearer`. Used by the bearer-row authenticity regression test.
    pub fn tamper_bearer(&self, token_id: &str, edit: impl FnOnce(&mut BearerRow)) {
        let mut g = self.inner.lock().expect("bearer tamper lock");
        if let Some(b) = g.bearers.iter_mut().find(|b| b.token_id == token_id) {
            edit(b);
        }
    }
}
