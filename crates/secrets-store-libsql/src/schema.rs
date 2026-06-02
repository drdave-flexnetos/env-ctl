//! Canonical SQL: the DDL that provisions the logical schema and every PRE-DEFINED, parameterized
//! statement the `store` module executes. There is NO dynamic SQL anywhere in this crate — user/row
//! input is ALWAYS bound to `?` placeholders, never concatenated into a query string (forbidden
//! pattern #1).

// --------------------------------------------------------------------------------------------
// DDL — provisioned at init via libSQL `execute_batch` (a Hrana batch). The Store only ever sees
// ciphertext + non-secret metadata, so no column holds plaintext or a DEK. Schema is intentionally
// a SUBSET of the full DESIGN model sufficient for the Phase-0/1b Store surface (meta, secrets,
// keyslots, audit, relays, bearers, certs); relay/bearer/cert tables back the engine's default-stub
// methods.
//
// NO explicit `BEGIN;`/`COMMIT;`: Hrana (the remote protocol) rejects transaction-control statements
// as "unsupported statement". Every statement here is idempotent (CREATE TABLE IF NOT EXISTS /
// INSERT OR IGNORE), so running them as a plain batch is safe to repeat on every startup.
// --------------------------------------------------------------------------------------------
pub const DDL: &str = "\
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS row_id_counter (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  next_id INTEGER NOT NULL
);
INSERT OR IGNORE INTO row_id_counter(id, next_id) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS secrets (
  row_id         INTEGER PRIMARY KEY,
  name           TEXT NOT NULL,
  version        INTEGER NOT NULL,
  provider       TEXT NOT NULL,
  note           TEXT NOT NULL,
  broker_only    INTEGER NOT NULL,
  dek_generation INTEGER NOT NULL,
  nonce          BLOB NOT NULL,
  ct_tag         BLOB NOT NULL,
  created_ts     TEXT NOT NULL,
  UNIQUE(name, version)
);
CREATE TABLE IF NOT EXISTS keyslots (
  id                  INTEGER PRIMARY KEY,
  factor              TEXT NOT NULL,
  label               TEXT NOT NULL,
  kdf_json            TEXT NOT NULL,
  salt                BLOB NOT NULL,
  usb_partition_uuid  TEXT,
  wrap_nonce          BLOB NOT NULL,
  wrapped_dek         BLOB NOT NULL,
  dek_generation      INTEGER NOT NULL,
  enabled             INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  seq        INTEGER PRIMARY KEY,
  ts         TEXT NOT NULL,
  actor_uid  INTEGER,
  event_type TEXT NOT NULL,
  subject    TEXT,
  detail     TEXT NOT NULL,
  outcome    TEXT NOT NULL,
  prev_hash  BLOB NOT NULL,
  row_hash   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS relay_policies (
  id          INTEGER PRIMARY KEY,
  relay_id    TEXT NOT NULL UNIQUE,
  policy_json TEXT NOT NULL,
  enabled     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS relay_bearers (
  token_id           TEXT PRIMARY KEY,
  policy_id          INTEGER NOT NULL,
  mac                BLOB NOT NULL,
  expires_at_ms      INTEGER NOT NULL,
  issued_at_ms       INTEGER NOT NULL,
  issued_boottime_ms INTEGER NOT NULL,
  client_uid         INTEGER,
  client_pid         INTEGER,
  revoked            INTEGER NOT NULL,
  row_mac            BLOB NOT NULL,
  client_id          TEXT,
  dpop_jkt           BLOB,
  CHECK ((client_uid IS NOT NULL) OR (client_id IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS remote_clients (
  client_id      TEXT PRIMARY KEY,
  dpop_jkt       BLOB NOT NULL,
  enabled        INTEGER NOT NULL,
  hardware_bound INTEGER NOT NULL,
  created_at_ms  INTEGER NOT NULL,
  revoked_at_ms  INTEGER
);
CREATE TABLE IF NOT EXISTS certs (
  serial     TEXT PRIMARY KEY,
  cn         TEXT NOT NULL,
  not_after  TEXT NOT NULL,
  der        BLOB NOT NULL
);";

/// Dummy round-trip that confirms the connection is live + durable (the `fsync_barrier`).
pub const FSYNC_BARRIER_PROBE: &str = "SELECT 1";

// ---- meta KV ----
pub const GET_META: &str = "SELECT v FROM meta WHERE k = ?";
pub const PUT_META: &str = "INSERT OR REPLACE INTO meta(k, v) VALUES(?, ?)";

// ---- row_id reservation (sole row_id authority; no TOCTOU) ----
pub const INCREMENT_ROW_ID_COUNTER: &str =
    "UPDATE row_id_counter SET next_id = next_id + 1 WHERE id = 1";
pub const GET_NEXT_ROW_ID: &str = "SELECT next_id FROM row_id_counter WHERE id = 1";

// ---- secrets ----
pub const MAX_SECRET_VERSION: &str =
    "SELECT COALESCE(MAX(version), 0) FROM secrets WHERE name = ?";
pub const SECRET_ROW_ID_EXISTS: &str = "SELECT 1 FROM secrets WHERE row_id = ?";
pub const INSERT_SECRET_VERSION: &str = "\
INSERT INTO secrets(row_id, name, version, provider, note, broker_only, dek_generation, nonce, ct_tag, created_ts) \
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
/// Column order MUST match `serial::deserialize_secret_row` (0..=8).
pub const SELECT_SECRET_COLS: &str =
    "row_id, name, version, provider, note, broker_only, dek_generation, nonce, ct_tag, created_ts";
pub const GET_SECRET_LATEST: &str = "\
SELECT row_id, name, version, provider, note, broker_only, dek_generation, nonce, ct_tag, created_ts \
FROM secrets WHERE name = ? ORDER BY version DESC LIMIT 1";
pub const GET_SECRET_VERSION: &str = "\
SELECT row_id, name, version, provider, note, broker_only, dek_generation, nonce, ct_tag, created_ts \
FROM secrets WHERE name = ? AND version = ?";
pub const LIST_SECRET_NAMES: &str = "SELECT DISTINCT name FROM secrets ORDER BY name";
pub const LIST_SECRET_VERSIONS: &str =
    "SELECT version FROM secrets WHERE name = ? ORDER BY version";

// ---- keyslots ----
pub const SAVE_KEYSLOT: &str = "\
INSERT OR REPLACE INTO keyslots(id, factor, label, kdf_json, salt, usb_partition_uuid, wrap_nonce, wrapped_dek, dek_generation, enabled) \
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
/// Column order MUST match `serial::deserialize_keyslot` (0..=8).
pub const LOAD_KEYSLOTS: &str = "\
SELECT id, factor, label, kdf_json, salt, usb_partition_uuid, wrap_nonce, wrapped_dek, dek_generation \
FROM keyslots WHERE enabled = 1 ORDER BY id ASC";
pub const LOAD_KEYSLOT: &str = "\
SELECT id, factor, label, kdf_json, salt, usb_partition_uuid, wrap_nonce, wrapped_dek, dek_generation \
FROM keyslots WHERE id = ?";

// ---- audit (hash-chained, durable append-only) ----
pub const APPEND_AUDIT: &str = "\
INSERT INTO audit_log(seq, ts, actor_uid, event_type, subject, detail, outcome, prev_hash, row_hash) \
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)";
/// Column order MUST match `serial::deserialize_audit_record` (0..=8).
pub const SELECT_AUDIT_COLS: &str =
    "seq, ts, actor_uid, event_type, subject, detail, outcome, prev_hash, row_hash";
pub const LAST_AUDIT: &str = "\
SELECT seq, ts, actor_uid, event_type, subject, detail, outcome, prev_hash, row_hash \
FROM audit_log ORDER BY seq DESC LIMIT 1";
pub const ALL_AUDIT_ASC: &str = "\
SELECT seq, ts, actor_uid, event_type, subject, detail, outcome, prev_hash, row_hash \
FROM audit_log ORDER BY seq ASC";
pub const QUERY_AUDIT: &str = "\
SELECT seq, ts, actor_uid, event_type, subject, detail, outcome, prev_hash, row_hash \
FROM audit_log WHERE seq > ? ORDER BY seq ASC LIMIT ?";

// ---- relay policies ----
pub const SELECT_RELAY_MAX_ID: &str = "SELECT COALESCE(MAX(id), 0) FROM relay_policies";
pub const SELECT_RELAY_ID_BY_NAME: &str =
    "SELECT id FROM relay_policies WHERE relay_id = ?";
pub const UPSERT_RELAY_POLICY: &str = "\
INSERT INTO relay_policies(id, relay_id, policy_json, enabled) VALUES(?, ?, ?, ?) \
ON CONFLICT(relay_id) DO UPDATE SET policy_json = excluded.policy_json, enabled = excluded.enabled";
pub const LOAD_RELAY_POLICY: &str =
    "SELECT id, policy_json FROM relay_policies WHERE relay_id = ?";
pub const LIST_RELAY_POLICIES: &str =
    "SELECT id, policy_json FROM relay_policies WHERE enabled = 1 ORDER BY id";

// ---- relay bearers ----
// Column order (incl. the F15 remote-binding cols 10/11) MUST match `serial::{bind,deserialize}_bearer_row`.
pub const SAVE_BEARER: &str = "\
INSERT OR REPLACE INTO relay_bearers(token_id, policy_id, mac, expires_at_ms, issued_at_ms, issued_boottime_ms, client_uid, client_pid, revoked, row_mac, client_id, dpop_jkt) \
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
/// Column order MUST match `serial::deserialize_bearer_row` (0..=11).
pub const SELECT_BEARER_COLS: &str =
    "token_id, policy_id, mac, expires_at_ms, issued_at_ms, issued_boottime_ms, client_uid, client_pid, revoked, row_mac, client_id, dpop_jkt";
pub const LOAD_BEARER: &str = "\
SELECT token_id, policy_id, mac, expires_at_ms, issued_at_ms, issued_boottime_ms, client_uid, client_pid, revoked, row_mac, client_id, dpop_jkt \
FROM relay_bearers WHERE token_id = ?";
pub const LIST_BEARERS_FOR_RELAY: &str = "\
SELECT token_id, policy_id, mac, expires_at_ms, issued_at_ms, issued_boottime_ms, client_uid, client_pid, revoked, row_mac, client_id, dpop_jkt \
FROM relay_bearers WHERE policy_id = (SELECT id FROM relay_policies WHERE relay_id = ?)";
pub const REVOKE_BEARERS_FOR_RELAY: &str = "\
UPDATE relay_bearers SET revoked = 1 \
WHERE revoked = 0 AND policy_id = (SELECT id FROM relay_policies WHERE relay_id = ?)";

// ---- remote clients (Phase 8, F15) ----
pub const SAVE_REMOTE_CLIENT: &str = "\
INSERT OR REPLACE INTO remote_clients(client_id, dpop_jkt, enabled, hardware_bound, created_at_ms, revoked_at_ms) \
VALUES(?, ?, ?, ?, ?, ?)";
/// Column order MUST match `serial::deserialize_remote_client` (0..=5).
pub const LOAD_REMOTE_CLIENT: &str = "\
SELECT client_id, dpop_jkt, enabled, hardware_bound, created_at_ms, revoked_at_ms \
FROM remote_clients WHERE client_id = ?";
pub const LIST_REMOTE_CLIENTS: &str = "\
SELECT client_id, dpop_jkt, enabled, hardware_bound, created_at_ms, revoked_at_ms \
FROM remote_clients ORDER BY client_id";
pub const REVOKE_REMOTE_CLIENT: &str =
    "UPDATE remote_clients SET enabled = 0, revoked_at_ms = ? WHERE client_id = ?";

// ---- certs ----
pub const SAVE_CERT: &str =
    "INSERT OR REPLACE INTO certs(serial, cn, not_after, der) VALUES(?, ?, ?, ?)";
pub const LOAD_CERT: &str = "SELECT serial, cn, not_after, der FROM certs WHERE serial = ?";
pub const LIST_CERTS: &str = "SELECT serial, cn, not_after, der FROM certs ORDER BY not_after";
