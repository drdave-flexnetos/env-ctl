//! Row (de)serialization: `libsql::Row` -> engine domain types, and domain values -> the
//! `Vec<libsql::Value>` bound into parameterized statements. Ciphertext in, ciphertext out — this
//! module NEVER sees plaintext or a DEK; it only moves opaque blobs + non-secret metadata.
//!
//! Column indices below MUST stay in lock-step with the `SELECT ...` column lists in `schema`.
//! `libsql::Row::get::<T>(i32)` does the NULL / numeric / blob coercion; we map any failure to
//! `Error::SerializationError`.

use envctl_secrets::event::{AuditOutcome, AuditRecord};
use envctl_secrets::keyslot::{Kdf, Keyslot};
use envctl_secrets::vault::{BearerRow, CertRow, RelayPolicyRow, SecretRow};
use envctl_secrets::{Factor, Provider, RelayPolicy};
use libsql::{Row, Value};

use crate::error::{Error, Result};

fn ser<E: std::fmt::Display>(ctx: &str, e: E) -> Error {
    Error::SerializationError(format!("{ctx}: {e}"))
}

fn get_i64(row: &Row, idx: i32, ctx: &str) -> Result<i64> {
    row.get::<i64>(idx).map_err(|e| ser(ctx, e))
}

fn get_string(row: &Row, idx: i32, ctx: &str) -> Result<String> {
    row.get::<String>(idx).map_err(|e| ser(ctx, e))
}

fn get_blob(row: &Row, idx: i32, ctx: &str) -> Result<Vec<u8>> {
    row.get::<Vec<u8>>(idx).map_err(|e| ser(ctx, e))
}

/// A column that is `INTEGER` or SQL `NULL` -> `Option<i64>`. `get_value` lets us branch on the
/// stored type without a decode error on NULL.
fn get_opt_i64(row: &Row, idx: i32, ctx: &str) -> Result<Option<i64>> {
    match row.get_value(idx).map_err(|e| ser(ctx, e))? {
        Value::Null => Ok(None),
        Value::Integer(i) => Ok(Some(i)),
        other => Err(ser(ctx, format!("expected INTEGER/NULL, got {other:?}"))),
    }
}

/// A column that is `TEXT` or SQL `NULL` -> `Option<String>`.
fn get_opt_string(row: &Row, idx: i32, ctx: &str) -> Result<Option<String>> {
    match row.get_value(idx).map_err(|e| ser(ctx, e))? {
        Value::Null => Ok(None),
        Value::Text(s) => Ok(Some(s)),
        other => Err(ser(ctx, format!("expected TEXT/NULL, got {other:?}"))),
    }
}

// ---- enum <-> wire-string helpers (serde snake_case is the canonical wire form) ----

fn provider_to_str(p: Provider) -> &'static str {
    match p {
        Provider::Anthropic => "anthropic",
        Provider::Openai => "openai",
        Provider::Github => "github",
        Provider::Generic => "generic",
    }
}

fn provider_from_str(s: &str) -> Result<Provider> {
    match s {
        "anthropic" => Ok(Provider::Anthropic),
        "openai" => Ok(Provider::Openai),
        "github" => Ok(Provider::Github),
        "generic" => Ok(Provider::Generic),
        other => Err(ser("provider", format!("unknown provider {other:?}"))),
    }
}

fn factor_to_str(f: Factor) -> &'static str {
    match f {
        Factor::Usb => "usb",
        Factor::Passphrase => "passphrase",
    }
}

fn factor_from_str(s: &str) -> Result<Factor> {
    match s {
        "usb" => Ok(Factor::Usb),
        "passphrase" => Ok(Factor::Passphrase),
        other => Err(ser("factor", format!("unknown factor {other:?}"))),
    }
}

fn outcome_to_str(o: AuditOutcome) -> &'static str {
    match o {
        AuditOutcome::Ok => "ok",
        AuditOutcome::Refused => "refused",
        AuditOutcome::Failed => "failed",
    }
}

fn outcome_from_str(s: &str) -> Result<AuditOutcome> {
    match s {
        "ok" => Ok(AuditOutcome::Ok),
        "refused" => Ok(AuditOutcome::Refused),
        "failed" => Ok(AuditOutcome::Failed),
        other => Err(ser("outcome", format!("unknown outcome {other:?}"))),
    }
}

// =====================================================================================
// SecretRow
// =====================================================================================

/// Positional params for `schema::INSERT_SECRET_VERSION` (same order as the column list).
pub fn bind_secret_row(row: &SecretRow) -> Vec<Value> {
    vec![
        Value::Integer(row.row_id),
        Value::Text(row.name.clone()),
        Value::Integer(row.version as i64),
        Value::Text(provider_to_str(row.provider).to_string()),
        Value::Text(row.note.clone()),
        Value::Integer(row.broker_only as i64),
        Value::Integer(row.dek_generation),
        Value::Blob(row.nonce.clone()),
        Value::Blob(row.ct_tag.clone()),
        Value::Text(row.created_ts.clone()),
    ]
}

/// Cols: 0 row_id, 1 name, 2 version, 3 provider, 4 note, 5 broker_only, 6 dek_generation,
/// 7 nonce, 8 ct_tag, 9 created_ts.
pub fn deserialize_secret_row(row: &Row) -> Result<SecretRow> {
    Ok(SecretRow {
        row_id: get_i64(row, 0, "secret.row_id")?,
        name: get_string(row, 1, "secret.name")?,
        version: get_i64(row, 2, "secret.version")? as u32,
        provider: provider_from_str(&get_string(row, 3, "secret.provider")?)?,
        note: get_string(row, 4, "secret.note")?,
        broker_only: get_i64(row, 5, "secret.broker_only")? != 0,
        dek_generation: get_i64(row, 6, "secret.dek_generation")?,
        nonce: get_blob(row, 7, "secret.nonce")?,
        ct_tag: get_blob(row, 8, "secret.ct_tag")?,
        created_ts: get_string(row, 9, "secret.created_ts")?,
    })
}

// =====================================================================================
// Keyslot  (kdf serialized as JSON to keep the column count fixed across KDF kinds)
// =====================================================================================

/// Positional params for `schema::SAVE_KEYSLOT`.
pub fn bind_keyslot(slot: &Keyslot) -> Result<Vec<Value>> {
    let kdf_json = serde_json::to_string(&slot.kdf).map_err(|e| ser("keyslot.kdf", e))?;
    Ok(vec![
        Value::Integer(slot.id),
        Value::Text(factor_to_str(slot.factor).to_string()),
        Value::Text(slot.label.clone()),
        Value::Text(kdf_json),
        Value::Blob(slot.salt.clone()),
        match &slot.usb_partition_uuid {
            Some(u) => Value::Text(u.clone()),
            None => Value::Null,
        },
        Value::Blob(slot.wrap_nonce.clone()),
        Value::Blob(slot.wrapped_dek.clone()),
        Value::Integer(slot.dek_generation),
        Value::Integer(slot.enabled as i64),
    ])
}

/// Cols: 0 id, 1 factor, 2 label, 3 kdf_json, 4 salt, 5 usb_partition_uuid, 6 wrap_nonce,
/// 7 wrapped_dek, 8 dek_generation. `enabled` is implied `true` (the SELECTs filter `enabled = 1`).
pub fn deserialize_keyslot(row: &Row) -> Result<Keyslot> {
    let kdf: Kdf =
        serde_json::from_str(&get_string(row, 3, "keyslot.kdf_json")?).map_err(|e| ser("keyslot.kdf", e))?;
    Ok(Keyslot {
        id: get_i64(row, 0, "keyslot.id")?,
        factor: factor_from_str(&get_string(row, 1, "keyslot.factor")?)?,
        label: get_string(row, 2, "keyslot.label")?,
        kdf,
        salt: get_blob(row, 4, "keyslot.salt")?,
        usb_partition_uuid: get_opt_string(row, 5, "keyslot.usb_partition_uuid")?,
        wrap_nonce: get_blob(row, 6, "keyslot.wrap_nonce")?,
        wrapped_dek: get_blob(row, 7, "keyslot.wrapped_dek")?,
        dek_generation: get_i64(row, 8, "keyslot.dek_generation")?,
        enabled: true,
    })
}

// =====================================================================================
// AuditRecord  (detail stored as its canonical JSON text — the engine's chain math re-serializes
// it identically, so the stored text and the hashed bytes never drift)
// =====================================================================================

/// Positional params for `schema::APPEND_AUDIT`. `rec` MUST already be sealed (`seq`/`prev_hash`/
/// `row_hash` set by `audit::link_row`).
pub fn bind_audit_record(rec: &AuditRecord) -> Result<Vec<Value>> {
    let detail_json = serde_json::to_string(&rec.detail).map_err(|e| ser("audit.detail", e))?;
    Ok(vec![
        Value::Integer(rec.seq),
        Value::Text(rec.ts.clone()),
        match rec.actor_uid {
            Some(uid) => Value::Integer(uid as i64),
            None => Value::Null,
        },
        Value::Text(rec.event_type.clone()),
        match &rec.subject {
            Some(s) => Value::Text(s.clone()),
            None => Value::Null,
        },
        Value::Text(detail_json),
        Value::Text(outcome_to_str(rec.outcome).to_string()),
        Value::Blob(rec.prev_hash.clone()),
        Value::Blob(rec.row_hash.clone()),
    ])
}

/// Cols: 0 seq, 1 ts, 2 actor_uid, 3 event_type, 4 subject, 5 detail, 6 outcome, 7 prev_hash,
/// 8 row_hash.
pub fn deserialize_audit_record(row: &Row) -> Result<AuditRecord> {
    let detail: serde_json::Value =
        serde_json::from_str(&get_string(row, 5, "audit.detail")?).map_err(|e| ser("audit.detail", e))?;
    Ok(AuditRecord {
        seq: get_i64(row, 0, "audit.seq")?,
        ts: get_string(row, 1, "audit.ts")?,
        actor_uid: get_opt_i64(row, 2, "audit.actor_uid")?.map(|u| u as u32),
        event_type: get_string(row, 3, "audit.event_type")?,
        subject: get_opt_string(row, 4, "audit.subject")?,
        detail,
        outcome: outcome_from_str(&get_string(row, 6, "audit.outcome")?)?,
        prev_hash: get_blob(row, 7, "audit.prev_hash")?,
        row_hash: get_blob(row, 8, "audit.row_hash")?,
    })
}

// =====================================================================================
// RelayPolicyRow  (the whole RelayPolicy serialized as JSON; the engine treats it opaquely here)
// =====================================================================================

/// `(id, relay_id, policy_json, enabled)` for `schema::UPSERT_RELAY_POLICY`.
pub fn bind_relay_policy(id: i64, row: &RelayPolicyRow) -> Result<Vec<Value>> {
    let policy_json = serde_json::to_string(&row.policy).map_err(|e| ser("relay.policy", e))?;
    Ok(vec![
        Value::Integer(id),
        Value::Text(row.policy.relay_id.clone()),
        Value::Text(policy_json),
        Value::Integer(row.policy.enabled as i64),
    ])
}

/// Cols: 0 id, 1 policy_json.
pub fn deserialize_relay_policy(row: &Row) -> Result<RelayPolicyRow> {
    let policy: RelayPolicy =
        serde_json::from_str(&get_string(row, 1, "relay.policy_json")?).map_err(|e| ser("relay.policy", e))?;
    Ok(RelayPolicyRow {
        id: get_i64(row, 0, "relay.id")?,
        policy,
    })
}

// =====================================================================================
// BearerRow
// =====================================================================================

/// Positional params for `schema::SAVE_BEARER`.
pub fn bind_bearer_row(row: &BearerRow) -> Vec<Value> {
    vec![
        Value::Text(row.token_id.clone()),
        Value::Integer(row.policy_id),
        Value::Blob(row.mac.clone()),
        Value::Integer(row.expires_at_ms),
        Value::Integer(row.issued_at_ms),
        Value::Integer(row.issued_boottime_ms),
        match row.client_uid {
            Some(u) => Value::Integer(u as i64),
            None => Value::Null,
        },
        match row.client_pid {
            Some(p) => Value::Integer(p as i64),
            None => Value::Null,
        },
        Value::Integer(row.revoked as i64),
        Value::Blob(row.row_mac.clone()),
    ]
}

/// Cols: 0 token_id, 1 policy_id, 2 mac, 3 expires_at_ms, 4 issued_at_ms, 5 issued_boottime_ms,
/// 6 client_uid, 7 client_pid, 8 revoked, 9 row_mac.
pub fn deserialize_bearer_row(row: &Row) -> Result<BearerRow> {
    Ok(BearerRow {
        token_id: get_string(row, 0, "bearer.token_id")?,
        policy_id: get_i64(row, 1, "bearer.policy_id")?,
        mac: get_blob(row, 2, "bearer.mac")?,
        expires_at_ms: get_i64(row, 3, "bearer.expires_at_ms")?,
        issued_at_ms: get_i64(row, 4, "bearer.issued_at_ms")?,
        issued_boottime_ms: get_i64(row, 5, "bearer.issued_boottime_ms")?,
        client_uid: get_opt_i64(row, 6, "bearer.client_uid")?.map(|u| u as u32),
        client_pid: get_opt_i64(row, 7, "bearer.client_pid")?.map(|p| p as u32),
        revoked: get_i64(row, 8, "bearer.revoked")? != 0,
        row_mac: get_blob(row, 9, "bearer.row_mac")?,
    })
}

// =====================================================================================
// CertRow
// =====================================================================================

/// Positional params for `schema::SAVE_CERT`.
pub fn bind_cert_row(row: &CertRow) -> Vec<Value> {
    vec![
        Value::Text(row.serial.clone()),
        Value::Text(row.cn.clone()),
        Value::Text(row.not_after.clone()),
        Value::Blob(row.der.clone()),
    ]
}

/// Cols: 0 serial, 1 cn, 2 not_after, 3 der.
pub fn deserialize_cert_row(row: &Row) -> Result<CertRow> {
    Ok(CertRow {
        serial: get_string(row, 0, "cert.serial")?,
        cn: get_string(row, 1, "cert.cn")?,
        not_after: get_string(row, 2, "cert.not_after")?,
        der: get_blob(row, 3, "cert.der")?,
    })
}
