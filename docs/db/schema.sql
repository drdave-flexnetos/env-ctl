-- env-ctl vault schema — CANONICAL LOGICAL MODEL.
--
-- REVIEW FIX (CF-1 / OI-1): libSQL was VERIFIED to bundle C SQLite (libsql-ffi/bundled/src/sqlite3.c),
-- which violates locked decisions 1 & 3 ("NO C deps"). This file is the canonical *logical* schema.
-- The execution backend is an OPEN ITEM awaiting an operator ruling: (a) a pure-Rust embedded store
-- (e.g. redb) expressing these tables as typed keyspaces; or (b) an explicit no-C waiver to keep SQL.
-- All BLOB bodies are app-encrypted (XChaCha20-Poly1305) regardless of backend.
--
-- If SQL is ruled: PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON.
-- All BLOB bodies are app-encrypted; NO plaintext secret, NO DEK, NO unlock key, NO hmac_key on disk.
-- file: ~/.local/share/env-ctl/vault.db  (dir 0700, file 0600)
--
-- AAD discipline (REVIEW FIX HF-2): AEAD AAD is a fixed-width canonical encoding RECOMPUTED at decrypt
-- time from each row's trusted identity columns; it is NEVER read from a stored column. The old
-- per-row `aad_tag` mirror columns are DROPPED to remove the relocation footgun.

-- ---- key/value config + crypto state; single-row invariants enforced by id-guards in code ----
-- Includes the DEK-authenticated header MAC (REVIEW FIX OI-8) over the keyslot set + KDF params, and
-- the monotonic issuance_floor_ms (REVIEW FIX OI-6) cross-checked against CLOCK_BOOTTIME on unlock.
CREATE TABLE meta (
  k TEXT PRIMARY KEY,          -- 'schema_version','vault_id','active_dek_generation','audit_head',
                               -- 'issuance_floor_ms','last_seen_ms','header_mac','rotation_in_progress','created_at'
  v TEXT NOT NULL
);

-- ---- hmac_key for keyed-BLAKE3 bearer hashing (REVIEW FIX OI-9): sealed under the DEK, stable across
-- ---- DEK rotation (re-wrapped, not re-derived) so live bearers survive a rotation ----
CREATE TABLE hmac_key (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  dek_generation     INTEGER NOT NULL REFERENCES dek_generation(generation),
  nonce              BLOB NOT NULL,            -- 24B XChaCha20 nonce
  ciphertext         BLOB NOT NULL,            -- AEAD(DEK, 32B hmac_key, aad=identity-bound)
  created_at         TEXT NOT NULL,
  rewrapped_at       TEXT NOT NULL
);

-- ---- LUKS-style keyslots: each row WRAPS the active DEK under one unlock factor's KEK ----
-- keyslot_aad (REVIEW FIX HF-3) binds factor/kdf/argon2-params/salt/UUID/generation/slot-id, so a
-- tampered param/salt/UUID yields a wrong KEK or AAD mismatch -> fail-closed. argon2 params are also
-- covered by the meta.header_mac, so a silent downgrade is detected on unlock (FS-S13).
CREATE TABLE keyslots (
  id                 INTEGER PRIMARY KEY,
  factor             TEXT NOT NULL,            -- 'passphrase' | 'usb_keyfile' | 'require_both'
  label              TEXT NOT NULL,            -- 'primary-passphrase' | 'usb:PARTUUID=...'
  kdf                TEXT NOT NULL,            -- 'argon2id' | 'hkdf_sha256'
  kdf_salt           BLOB NOT NULL,            -- 32B CSPRNG salt (never zero, never shared) (HF-5/OI low)
  argon2_m_kib       INTEGER,                  -- e.g. 1048576 (1 GiB); NULL for hkdf. Enforced >= floor in code.
  argon2_t_cost      INTEGER,                  -- e.g. 4
  argon2_p_lanes     INTEGER,                  -- e.g. 4
  argon2_version     INTEGER,                  -- 0x13 pinned; NULL for hkdf (Argon2::new explicit, never default)
  usb_partition_uuid TEXT,                     -- GPT PARTUUID (NOT filesystem UUID) of the USB device; NULL for passphrase
  wrap_nonce         BLOB NOT NULL,            -- 24B XChaCha20 nonce for the DEK-wrap AEAD
  wrapped_dek        BLOB NOT NULL,            -- AEAD(KEK, DEK, aad=keyslot_aad): ciphertext||16B tag
  dek_generation     INTEGER NOT NULL REFERENCES dek_generation(generation),
  enabled            INTEGER NOT NULL DEFAULT 1,
  created_at         TEXT NOT NULL,
  rewrapped_at       TEXT NOT NULL,
  UNIQUE(factor, label)
);

-- ---- DEK generation registry (rotation history). Exactly one row has tombstoned_at IS NULL = active ----
-- DEK rotation (REVIEW FIX HF-1) is FULL re-encryption: under one atomic, resumable txn
-- (meta.rotation_in_progress) every ciphertext row is decrypted with the old DEK and re-sealed with
-- the new DEK (fresh nonce, AAD bound to the new generation); only then is the old generation
-- tombstoned and the old DEK dropped. It is NOT a keyslot-only rewrite.
CREATE TABLE dek_generation (
  generation    INTEGER PRIMARY KEY,           -- monotonic; meta.active_dek_generation points here
  created_at    TEXT NOT NULL,
  tombstoned_at TEXT,                          -- set when superseded by rotation
  reason        TEXT                           -- 'init'|'scheduled-rotation'|'compromise'|'passphrase-change'
);

-- ---- logical secret (the stable handle clients reference); body lives in secret_versions ----
CREATE TABLE secrets (
  id              INTEGER PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,        -- 'anthropic/api-key','github/pat','ssh/id_ed25519'
  kind            TEXT NOT NULL,               -- 'api_token'|'ssh_key'|'gpg_key'|'password'|'generic'
  provider        TEXT,                        -- 'anthropic'|'openai'|'github'|'generic'|NULL
  broker_only     INTEGER NOT NULL DEFAULT 0,  -- REVIEW FIX (OI-2): if 1, `secret get --reveal` is REFUSED (FS-S14)
  current_version INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  rotation_due_at TEXT,                        -- optional rotation hint (keys pillar)
  deleted_at      TEXT                         -- soft-delete; body re-encrypted on rotation until purged
);

-- ---- immutable version history; each row is one app-encrypted body envelope ----
-- NO aad_tag column (REVIEW FIX HF-2 footgun): AAD is recomputed from (table_tag, secret_id, version,
-- dek_generation) at decrypt time, never stored.
CREATE TABLE secret_versions (
  secret_id      INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version        INTEGER NOT NULL,             -- 1,2,3...
  dek_generation INTEGER NOT NULL REFERENCES dek_generation(generation),
  nonce          BLOB NOT NULL,                -- 24B per-record XChaCha20 nonce from OsRng (unique)
  ciphertext     BLOB NOT NULL,                -- AEAD(DEK, plaintext, aad=canonical-identity): body||16B tag
  body_len       INTEGER NOT NULL,             -- plaintext length (quota; not secret)
  created_at     TEXT NOT NULL,
  PRIMARY KEY (secret_id, version)
);
CREATE INDEX idx_sv_generation ON secret_versions(dek_generation);

-- ---- named long-lived broker POLICIES (claude-main, gh-ci). Wire bearers are minted UNDER these ----
CREATE TABLE relay_policies (
  id                 INTEGER PRIMARY KEY,
  name               TEXT NOT NULL UNIQUE,     -- 'claude-main','gh-ci'
  secret_id          INTEGER NOT NULL REFERENCES secrets(id),  -- the REAL key this relay maps to
  provider           TEXT NOT NULL,            -- 'anthropic'|'openai'|'github'|'generic'
  data_plane_mode    TEXT NOT NULL,            -- 'base_url'|'mitm_proxy'|'native_subtoken'
  upstream_base      TEXT,                     -- REVIEW FIX (HF-11): validated against the provider's canonical host allowlist at swap
  host_allowlist     TEXT NOT NULL,            -- JSON array of allowed hosts (default-deny if empty)
  path_allowlist     TEXT NOT NULL,            -- JSON array of path prefixes
  method_allowlist   TEXT NOT NULL,            -- JSON array: ['GET','POST',...]
  policy_ttl_secs    INTEGER NOT NULL,         -- named lifetime (1y/90d); the POLICY ttl
  rate_limit_per_min INTEGER,                  -- NULL = unlimited
  quota_budget       INTEGER,                  -- total requests/units; NULL = unlimited
  quota_used         INTEGER NOT NULL DEFAULT 0,
  usb_gated          INTEGER NOT NULL DEFAULT 1, -- issuance/renewal/swap require USB keyfile possession
  enabled            INTEGER NOT NULL DEFAULT 1,
  revoked_at         TEXT,
  created_at         TEXT NOT NULL,
  ephemeral          INTEGER NOT NULL DEFAULT 0  -- 1 = one-off policy created by `env-ctl run`
);

-- ---- minted wire bearers (<=24h). Store ONLY the keyed-BLAKE3 hash; raw bearer never persists ----
-- token_id is an INDEPENDENT random 96-bit id (REVIEW FIX OI-21), decoupled from bearer_hash, to
-- avoid mint-collision DoS and bearer->token_id derivability. A 24h ceiling CHECK (REVIEW FIX HF-15)
-- backs the in-code clamp. Bearer-level revoked_at supports single-bearer revocation (OI-10).
CREATE TABLE relay_bearers (
  id                   INTEGER PRIMARY KEY,
  policy_id            INTEGER NOT NULL REFERENCES relay_policies(id) ON DELETE CASCADE,
  token_id             TEXT NOT NULL UNIQUE,   -- random 96-bit hex; non-secret lookup key (bounded-retry on collision)
  bearer_hash          BLOB NOT NULL,          -- keyed-BLAKE3(hmac_key, raw_bearer), 32B; constant-time compared
  client_label         TEXT,                   -- which process/pid/profile got it (audit)
  client_uid           INTEGER,                -- SO_PEERCRED uid at mint (peer binding, HF-8)
  client_pid           INTEGER,                -- bound child pid for `env-ctl run` ephemerals (HF-8)
  issued_at            TEXT NOT NULL,
  issued_at_ms         INTEGER NOT NULL,       -- monotonic floor check (clock-rollback defense, OI-6)
  expires_at           TEXT NOT NULL,
  expires_at_ms        INTEGER NOT NULL,
  last_used_at         TEXT,
  last_used_at_ms      INTEGER,                -- monotonic-use check: now must be >= last_used_at_ms (OI-6)
  use_count            INTEGER NOT NULL DEFAULT 0,
  bytes_out            INTEGER NOT NULL DEFAULT 0,
  revoked_at           TEXT,                   -- bearer-level revocation (OI-10)
  usb_present_at_issue INTEGER NOT NULL,       -- provenance: was USB possession proven when minted
  CHECK (expires_at_ms <= issued_at_ms + 86400000)   -- REVIEW FIX (HF-15): hard 24h ceiling (FS-S3)
);
CREATE INDEX idx_bearer_policy ON relay_bearers(policy_id);
CREATE INDEX idx_bearer_expiry ON relay_bearers(expires_at_ms);

-- ---- tamper-evident, hash-chained audit log (append-only by discipline; written DURABLY) ----
-- REVIEW FIX (HF-14): security-relevant outcomes are committed here synchronously before the RPC
-- returns; the cosmetic SecretEvent stream is separate and best-effort. subject carries token_id for
-- relay_swap rows (REVIEW FIX OI-11) so each swap joins to exactly one bearer.
CREATE TABLE audit_log (
  seq        INTEGER PRIMARY KEY,              -- dense, monotonic; the chain index
  ts         TEXT NOT NULL,
  actor_uid  INTEGER,                          -- SO_PEERCRED uid of the control-plane caller
  event_type TEXT NOT NULL,                    -- 'unlock','secret_read','relay_mint','relay_swap','dek_rotate','revoke','leaf_mint',...
  subject    TEXT,                             -- secret name / policy name / token_id / sni
  detail     TEXT,                             -- JSON; NEVER contains plaintext secret material
  outcome    TEXT NOT NULL,                    -- 'ok'|'refused'|'failed'
  prev_hash  BLOB NOT NULL,                    -- row_hash of seq-1 (zeroes for seq=1)
  row_hash   BLOB NOT NULL                     -- BLAKE3(canonical(seq,ts,actor_uid,event_type,subject,detail,outcome) || prev_hash)
);

-- ---- local CA: public cert in clear, CA private key app-encrypted under the DEK ----
-- CA validity is SHORT (<=90d, auto-renewed) per REVIEW FIX OI-13; key re-sealed on DEK rotation.
-- NO key_aad_tag column (REVIEW FIX): AAD recomputed from (table_tag, ca_key.id, label, dek_generation).
CREATE TABLE ca_key (
  id                 INTEGER PRIMARY KEY,
  label              TEXT NOT NULL UNIQUE,     -- 'env-ctl-local-ca'
  cert_pem           TEXT NOT NULL,            -- PUBLIC cert, clear (for trust-store wiring)
  key_dek_generation INTEGER NOT NULL REFERENCES dek_generation(generation),
  key_nonce          BLOB NOT NULL,
  key_ciphertext     BLOB NOT NULL,            -- AEAD(DEK, PKCS#8 DER of CA key, aad=identity-bound)
  fingerprint_sha256 TEXT NOT NULL,
  name_constraints   TEXT,                     -- JSON permitted dNSName set = exact relay host_allow union (HF-9)
  not_before         TEXT NOT NULL,
  not_after          TEXT NOT NULL,
  created_at         TEXT NOT NULL
);

-- ---- issued leaf/mTLS certs; private key app-encrypted, public cert clear, revocation tracked ----
-- REVIEW FIX (CF-5/OI-19): usage='mitm_leaf' rows REQUIRE a non-NULL relay_id covering every SAN, and
-- MITM leaf private keys are NOT persisted (minted in-RAM, die with the cache). Only operator-issued
-- control-plane leaves persist their key_ciphertext.
CREATE TABLE certs (
  id                 INTEGER PRIMARY KEY,
  ca_id              INTEGER NOT NULL REFERENCES ca_key(id),
  serial             TEXT NOT NULL UNIQUE,     -- hex serial for CRL/audit
  subject_cn         TEXT NOT NULL,
  san                TEXT,                     -- JSON array of SANs
  usage              TEXT NOT NULL,            -- 'mitm_leaf'|'control_plane_server'|'control_plane_client'
  relay_id           INTEGER REFERENCES relay_policies(id),  -- NOT NULL required for usage='mitm_leaf' (enforced in code)
  cert_pem           TEXT NOT NULL,            -- PUBLIC, clear
  key_dek_generation INTEGER REFERENCES dek_generation(generation), -- NULL for mitm_leaf (key not persisted)
  key_nonce          BLOB,                     -- NULL for mitm_leaf
  key_ciphertext     BLOB,                     -- AEAD(DEK, leaf private key PEM, aad); NULL for mitm_leaf
  not_before         TEXT NOT NULL,
  not_after          TEXT NOT NULL,            -- mitm_leaf: <= min(now+24h, covering relay validity) (CF-5)
  revoked_at         TEXT,
  created_at         TEXT NOT NULL,
  CHECK (usage <> 'mitm_leaf' OR relay_id IS NOT NULL)   -- no orphan interception certs (FS-S6)
);
CREATE INDEX idx_certs_relay ON certs(relay_id);
