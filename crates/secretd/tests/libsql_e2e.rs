//! Phase-1 wiring e2e: the engine on the DURABLE libSQL store (OI-1 (a)).
//!
//! `#[ignore]`d — requires a running loopback sqld AND a FRESH database (it calls `init_vault`). Run:
//! ```sh
//! rm -rf /tmp/sqld-data && sqld --http-listen-addr 127.0.0.1:8080 -d /tmp/sqld-data &
//! LIBSQL_TEST_URL=http://127.0.0.1:8080 LIBSQL_TEST_AUTH= \
//!   cargo test -p envctl-secretd --test libsql_e2e -- --ignored --nocapture
//! ```
//!
//! Proves the actual Phase-1 deliverable: `Engine::open_with_store` on libSQL does init/unlock/put/get
//! AND the secret + vault survive ACROSS ENGINE INSTANCES (a fresh engine on the SAME sqld DB unlocks
//! the persisted vault and reads the secret) — the whole point of the durable backend vs `InMemStore`.

use envctl_secrets::keyslot::Argon2Params;
use envctl_secrets::paths::Paths;
use envctl_secrets::{Engine, EventSink, Provider, SecretMeta, Unlock};
use envctl_secrets_store_libsql::LibSqlStoreBuilder;
use zeroize::Zeroizing;

fn test_target() -> Option<(String, String)> {
    let url = std::env::var("LIBSQL_TEST_URL").ok()?;
    let auth = std::env::var("LIBSQL_TEST_AUTH").unwrap_or_default();
    Some((url, auth))
}

/// Build a fresh engine on the libSQL store at `url`. Each instance gets its own tempdir `Paths`
/// (the vault state lives in libSQL, NOT on the filesystem — that is what makes the durability test
/// meaningful). Built on the current (sync) thread: no ambient reactor, so the store's `block_on` is
/// safe (mirrors secretd's off-reactor construction).
fn engine_on_libsql(url: &str, auth: &str, root: &str) -> Engine {
    let store = LibSqlStoreBuilder::new(url.to_string(), auth.to_string())
        .build()
        .expect("open libSQL store");
    let paths = Paths::under(std::env::temp_dir().join(root));
    Engine::open_with_store(paths, Box::new(store)).expect("open engine on libSQL store")
}

const PASSPHRASE: &str = "correct horse battery staple libsql e2e";
const SECRET_VALUE: &[u8] = b"sk-ant-durable-value";

#[test]
#[ignore = "requires a running loopback sqld + a fresh DB; see module docs"]
fn engine_over_libsql_put_get_and_durability() {
    let Some((url, auth)) = test_target() else {
        eprintln!("LIBSQL_TEST_URL unset; skipping");
        return;
    };

    // ---- instance 1: init a passphrase-only vault, unlock, put + read back a secret ----
    {
        let engine = engine_on_libsql(&url, &auth, "envctl-libsql-e2e-1");
        let sink = EventSink::null();
        engine
            .init_vault(
                Zeroizing::new(PASSPHRASE.to_string()),
                None, // passphrase-only vault (no USB slot)
                None,
                Argon2Params::default(),
                &sink,
            )
            .expect("init_vault on libSQL");
        engine
            .unlock(
                Unlock::Passphrase(Zeroizing::new(PASSPHRASE.to_string())),
                &sink,
            )
            .expect("unlock");
        engine
            .secret_put(
                SecretMeta {
                    name: "DURABLE_KEY".into(),
                    provider: Provider::Anthropic,
                    note: "phase-1 libSQL durability".into(),
                    broker_only: false,
                },
                Zeroizing::new(SECRET_VALUE.to_vec()),
                &sink,
            )
            .expect("secret_put");
        let got = engine
            .secret_get("DURABLE_KEY", true, true, &sink)
            .expect("secret_get reveal (same instance)");
        assert_eq!(&got[..], SECRET_VALUE, "same-instance read must match");
    }

    // ---- instance 2: a FRESH engine on the SAME sqld DB unlocks + reads the persisted secret ----
    {
        let engine = engine_on_libsql(&url, &auth, "envctl-libsql-e2e-2");
        let sink = EventSink::null();
        // No init: the vault already exists in libSQL. Unlock the PERSISTED keyslots, read the secret.
        engine
            .unlock(
                Unlock::Passphrase(Zeroizing::new(PASSPHRASE.to_string())),
                &sink,
            )
            .expect("unlock a fresh engine against the persisted vault");
        let got = engine
            .secret_get("DURABLE_KEY", true, true, &sink)
            .expect("secret_get from the persisted store");
        assert_eq!(
            &got[..], SECRET_VALUE,
            "the secret MUST survive across engine instances via libSQL (durability)"
        );
    }
}
