//! Integration tests for the libSQL remote `Store` backend.
//!
//! These require a RUNNING sqld reachable over HTTP. They are `#[ignore]`d by default so the crate
//! test suite stays runnable in CI without a server.
//!
//! ## How to run
//!
//! 1. Start a loopback sqld (open auth is fine for the test; NEVER in production):
//!    ```sh
//!    sqld --http-listen-addr 127.0.0.1:8080
//!    # or via Docker:
//!    # docker run -p 8080:8080 ghcr.io/tursodatabase/libsql-server:latest
//!    ```
//! 2. Point the tests at it and run the ignored set:
//!    ```sh
//!    LIBSQL_TEST_URL=http://127.0.0.1:8080 LIBSQL_TEST_AUTH= \
//!      cargo test -p envctl-secrets-store-libsql --features remote -- --ignored --nocapture
//!    ```
//!    (If you configured `--auth-jwt-key-file`, set `LIBSQL_TEST_AUTH` to a valid JWT.)
//!
//! Each test provisions a fresh schema; run against a throwaway database.

use envctl_secrets::event::{AuditOutcome, AuditRecord};
use envctl_secrets::keyslot::{Argon2Params, Factor, Kdf, Keyslot};
use envctl_secrets::vault::{SecretRow, Store};
use envctl_secrets::Provider;
use envctl_secrets_store_libsql::LibSqlStoreBuilder;
use serde_json::json;

fn store() -> envctl_secrets_store_libsql::LibSqlStore {
    let url = std::env::var("LIBSQL_TEST_URL").expect("set LIBSQL_TEST_URL to a running sqld");
    let auth = std::env::var("LIBSQL_TEST_AUTH").unwrap_or_default();
    LibSqlStoreBuilder::new(url, auth).build().expect("open store")
}

#[test]
#[ignore = "requires a running sqld; see module docs for how to run"]
fn meta_roundtrip() {
    let s = store();
    // Use a key NO other test writes (the suite shares one sqld DB; `schema_version` is also set by
    // `health_reports_durable_after_init`, so asserting it pristine here is order-dependent). The
    // suite expects a fresh throwaway DB per run; this key keeps meta_roundtrip order-independent.
    let key = "meta_roundtrip_probe";
    assert_eq!(s.get_meta(key).unwrap(), None);
    s.put_meta(key, "1").unwrap();
    assert_eq!(s.get_meta(key).unwrap().as_deref(), Some("1"));
    // INSERT OR REPLACE overwrites in place.
    s.put_meta(key, "2").unwrap();
    assert_eq!(s.get_meta(key).unwrap().as_deref(), Some("2"));
}

#[test]
#[ignore = "requires a running sqld; see module docs for how to run"]
fn reserve_and_put_secret_monotonic() {
    let s = store();
    let id1 = s.reserve_secret_row_id().unwrap();
    let id2 = s.reserve_secret_row_id().unwrap();
    assert!(id2 > id1, "row ids are strictly increasing");

    let row = SecretRow {
        row_id: id1,
        name: "API_KEY".into(),
        version: 1,
        provider: Provider::Anthropic,
        note: String::new(),
        broker_only: false,
        dek_generation: 1,
        nonce: vec![0xAA; 24],
        ct_tag: vec![0xBB; 48],
        created_ts: "2026-06-02T00:00:00Z".into(),
    };
    assert_eq!(s.put_secret(row.clone()).unwrap(), id1);
    assert_eq!(s.max_secret_version("API_KEY").unwrap(), 1);
    let got = s.get_secret_latest("API_KEY").unwrap().unwrap();
    assert_eq!(got.ct_tag, vec![0xBB; 48]);

    // a non-monotonic version is rejected at write time (M-1)
    let mut bad = row;
    bad.row_id = id2;
    bad.version = 3; // expected 2
    assert!(s.put_secret(bad).is_err());
}

#[test]
#[ignore = "requires a running sqld; see module docs for how to run"]
fn keyslot_roundtrip_and_order() {
    let s = store();
    for id in [2_i64, 1] {
        s.save_keyslot(&Keyslot {
            id,
            factor: Factor::Passphrase,
            label: format!("slot{id}"),
            kdf: Kdf::Argon2id(Argon2Params::default()),
            salt: vec![id as u8; 32],
            usb_partition_uuid: None,
            wrap_nonce: vec![0; 24],
            wrapped_dek: vec![0; 48],
            dek_generation: 1,
            enabled: true,
        })
        .unwrap();
    }
    let slots = s.load_keyslots().unwrap();
    assert_eq!(slots.len(), 2);
    assert!(slots[0].id < slots[1].id, "canonical ascending id order");
}

#[test]
#[ignore = "requires a running sqld; see module docs for how to run"]
fn audit_append_is_durable_and_chain_verifies() {
    let s = store();
    let mk = |et: &str| AuditRecord {
        seq: 0,
        ts: "2026-06-02T00:00:00Z".into(),
        actor_uid: Some(1000),
        event_type: et.into(),
        subject: Some("subj".into()),
        detail: json!({"e": et}),
        outcome: AuditOutcome::Ok,
        prev_hash: Vec::new(),
        row_hash: Vec::new(),
    };
    let s1 = s.append_audit(&mk("unlock")).unwrap();
    let s2 = s.append_audit(&mk("secret_read")).unwrap();
    assert_eq!((s1, s2), (1, 2), "seq is dense, 1-based (HF-14 durable append)");
    s.verify_audit_chain().expect("freshly appended chain verifies");

    let tail = s.last_audit().unwrap().unwrap();
    assert_eq!(tail.seq, 2);
    let page = s.query_audit(0, 10).unwrap();
    assert_eq!(page.len(), 2);
}

#[test]
#[ignore = "requires a running sqld; see module docs for how to run"]
fn health_reports_durable_after_init() {
    let s = store();
    s.put_meta("schema_version", "1").unwrap();
    let h = s.health().unwrap();
    assert!(h.durable, "a confirmed server-applied barrier => durable");
    assert_eq!(h.schema_version, 1);
    assert!(h.is_healthy());
}
