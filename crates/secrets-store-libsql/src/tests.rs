//! Offline unit tests — NO running sqld required. These cover the pure, deterministic pieces of
//! the crate: parameter-binding shape (domain type -> `Vec<libsql::Value>`), error `Display`, and
//! the wiring-flag invariants. Row DESERIALIZATION needs a real `libsql::Row` (its constructor is
//! crate-private), so it is exercised by the `#[ignore]`d integration tests against a live sqld.

use crate::error::Error;
use crate::serial;
use envctl_secrets::event::{AuditOutcome, AuditRecord};
use envctl_secrets::keyslot::{Argon2Params, Factor, Kdf, Keyslot};
use envctl_secrets::vault::{BearerRow, CertRow, SecretRow};
use envctl_secrets::Provider;
use libsql::Value;
use serde_json::json;

fn sample_secret() -> SecretRow {
    SecretRow {
        row_id: 7,
        name: "API_KEY".into(),
        version: 3,
        provider: Provider::Anthropic,
        note: "n".into(),
        broker_only: true,
        dek_generation: 2,
        nonce: vec![0xAA; 24],
        ct_tag: vec![0xBB; 48],
        created_ts: "2026-06-02T00:00:00Z".into(),
    }
}

#[test]
fn bind_secret_row_shape_and_types() {
    let v = serial::bind_secret_row(&sample_secret());
    assert_eq!(v.len(), 10, "10 columns must be bound");
    assert!(matches!(v[0], Value::Integer(7)));
    assert!(matches!(&v[1], Value::Text(s) if s == "API_KEY"));
    assert!(matches!(v[2], Value::Integer(3)));
    assert!(matches!(&v[3], Value::Text(s) if s == "anthropic"));
    // broker_only true -> 1
    assert!(matches!(v[5], Value::Integer(1)));
    // nonce + ct_tag are blobs of the right length
    assert!(matches!(&v[7], Value::Blob(b) if b.len() == 24));
    assert!(matches!(&v[8], Value::Blob(b) if b.len() == 48));
}

#[test]
fn bind_keyslot_serializes_kdf_to_json_and_handles_null_uuid() {
    let slot = Keyslot {
        id: 1,
        factor: Factor::Passphrase,
        label: "pass".into(),
        kdf: Kdf::Argon2id(Argon2Params::default()),
        salt: vec![1, 2, 3],
        usb_partition_uuid: None,
        wrap_nonce: vec![9; 24],
        wrapped_dek: vec![8; 48],
        dek_generation: 1,
        enabled: true,
    };
    let v = serial::bind_keyslot(&slot).expect("bind");
    assert_eq!(v.len(), 10);
    assert!(matches!(&v[1], Value::Text(s) if s == "passphrase"));
    // kdf JSON round-trips back to the same Kdf
    let kdf_json = match &v[3] {
        Value::Text(s) => s.clone(),
        other => panic!("kdf col not text: {other:?}"),
    };
    let kdf: Kdf = serde_json::from_str(&kdf_json).expect("kdf json");
    assert!(matches!(kdf, Kdf::Argon2id(_)));
    // NULL uuid
    assert!(matches!(v[5], Value::Null));
}

#[test]
fn bind_keyslot_usb_uuid_present() {
    let slot = Keyslot {
        id: 2,
        factor: Factor::Usb,
        label: "usb".into(),
        kdf: Kdf::HkdfSha256,
        salt: vec![0; 32],
        usb_partition_uuid: Some("abc-uuid".into()),
        wrap_nonce: vec![0; 24],
        wrapped_dek: vec![0; 48],
        dek_generation: 1,
        enabled: true,
    };
    let v = serial::bind_keyslot(&slot).expect("bind");
    assert!(matches!(&v[1], Value::Text(s) if s == "usb"));
    assert!(matches!(&v[5], Value::Text(s) if s == "abc-uuid"));
}

#[test]
fn bind_audit_record_outcome_and_null_actor() {
    let rec = AuditRecord {
        seq: 1,
        ts: "2026-06-02T00:00:00Z".into(),
        actor_uid: None,
        event_type: "unlock".into(),
        subject: Some("vault".into()),
        detail: json!({"k": "v"}),
        outcome: AuditOutcome::Refused,
        prev_hash: vec![1; 32],
        row_hash: vec![2; 32],
    };
    let v = serial::bind_audit_record(&rec).expect("bind");
    assert_eq!(v.len(), 9);
    assert!(matches!(v[0], Value::Integer(1)));
    assert!(matches!(v[2], Value::Null), "absent actor_uid -> NULL");
    assert!(matches!(&v[4], Value::Text(s) if s == "vault"));
    // detail serialized to compact JSON text
    assert!(matches!(&v[5], Value::Text(s) if s.contains("\"k\"")));
    assert!(matches!(&v[6], Value::Text(s) if s == "refused"));
    assert!(matches!(&v[7], Value::Blob(b) if b.len() == 32));
}

#[test]
fn bind_bearer_row_null_peer_fields() {
    let row = BearerRow {
        token_id: "tok".into(),
        policy_id: 5,
        mac: vec![1; 32],
        expires_at_ms: 100,
        issued_at_ms: 50,
        issued_boottime_ms: 10,
        client_uid: None,
        client_pid: Some(4242),
        revoked: false,
        row_mac: vec![2; 32],
    };
    let v = serial::bind_bearer_row(&row);
    assert_eq!(v.len(), 10);
    assert!(matches!(&v[0], Value::Text(s) if s == "tok"));
    assert!(matches!(v[6], Value::Null), "absent client_uid -> NULL");
    assert!(matches!(v[7], Value::Integer(4242)));
    assert!(matches!(v[8], Value::Integer(0)), "revoked false -> 0");
}

#[test]
fn bind_cert_row_shape() {
    let row = CertRow {
        serial: "DEADBEEF".into(),
        cn: "leaf.local".into(),
        not_after: "2027-01-01T00:00:00Z".into(),
        der: vec![0xCA; 16],
    };
    let v = serial::bind_cert_row(&row);
    assert_eq!(v.len(), 4);
    assert!(matches!(&v[0], Value::Text(s) if s == "DEADBEEF"));
    assert!(matches!(&v[3], Value::Blob(b) if b.len() == 16));
}

#[test]
fn error_display_is_descriptive() {
    assert!(Error::AuditChainBroken(42).to_string().contains("42"));
    assert!(Error::QueryFailed("boom".into()).to_string().contains("boom"));
    assert!(Error::Contract("bad".into()).to_string().contains("bad"));
}

#[test]
fn error_converts_into_anyhow() {
    let f = || -> anyhow::Result<()> { Err(Error::Connect("x".into()))?; Ok(()) };
    let e = f().unwrap_err();
    assert!(e.to_string().contains("connect"));
}

#[test]
fn wiring_flags_default_to_remote() {
    // Read through `std::hint::black_box` so the lint doesn't fold these compile-time `cfg!`
    // constants into a const assertion (clippy::assertions_on_constants). The default build must
    // enable exactly `remote` and not `embedded`.
    assert_eq!(
        (std::hint::black_box(crate::FEATURE_REMOTE), std::hint::black_box(crate::FEATURE_EMBEDDED)),
        (true, false),
    );
}
