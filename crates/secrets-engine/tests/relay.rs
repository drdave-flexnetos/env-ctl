//! Phase-4 relay/broker acceptance tests, driven through the PUBLIC `Engine` API via `with_seams`
//! plus a real `InMemStore` and fake `Clock`/`UsbProbe`/`Upstream`. The single async method
//! (`relay_swap`) is driven with `futures_executor::block_on` (pure Rust; no tokio in the engine).
//!
//! These prove, end to end:
//!
//! - `relay_mint` clamps a 1-year request to <=24h and refuses on an absent USB gate (durable
//!   `Refused` row + `GuardRefused` event, no bearer row written);
//! - the raw bearer / secret NEVER leak into any emitted event nor any audit row (only token_id);
//! - the `Allow` path delivers the REAL key to `Upstream::send` ONLY, and the key never appears in
//!   any event/audit/return;
//! - `Deny` / forged / expired / revoked swaps NEVER reach the upstream (captured slot stays None)
//!   and write a `relay_swapped allowed:false` Refused audit row.
//!
//! The pure decide() truth table (every DenyReason + Allow) is asserted in
//! `broker/decide.rs #[cfg(test)]`, since decide is never entered for `UnknownBearer`.
use std::sync::{Arc, Mutex};

use envctl_secrets::broker::{Method, Provider, RelayKind, RelayPolicy, SwapMode};
use envctl_secrets::keyslot::{Argon2Params, ARGON2_M_KIB_FLOOR, ARGON2_T_COST_FLOOR};
use envctl_secrets::paths::Paths;
use envctl_secrets::seam::{Clock, NoMint, UpstreamError, UsbProbe};
use envctl_secrets::vault::{InMemStore, Store};
use envctl_secrets::{
    DenyReason, EgressReq, EgressResp, Engine, EngineError, EventSink, SecretEvent, SecretMeta,
    SwapOutcome, Unlock, Upstream, MAX_BEARER_TTL_SECS,
};
use futures_executor::block_on;
use zeroize::Zeroizing;

// ---- fakes -----------------------------------------------------------------------------------

/// A clock whose wall time is a shared, settable epoch-millis cell (boottime mirrors it). Lets the
/// tests pin T0, advance past a bearer's expiry, etc.
#[derive(Clone)]
struct FakeClock(Arc<Mutex<i64>>);
impl FakeClock {
    fn new(ms: i64) -> Self {
        FakeClock(Arc::new(Mutex::new(ms)))
    }
    fn set(&self, ms: i64) {
        *self.0.lock().unwrap() = ms;
    }
}
impl Clock for FakeClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        let ms = *self.0.lock().unwrap();
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms).expect("valid epoch ms")
    }
    fn boottime_ms(&self) -> i64 {
        *self.0.lock().unwrap()
    }
}

/// A clock with INDEPENDENT wall + monotonic cells, so a test can rewind the wall clock WITHOUT
/// rewinding `boottime` (which a real attacker also cannot do). Drives the OI-6 rollback fence.
#[derive(Clone)]
struct SplitClock {
    wall: Arc<Mutex<i64>>,
    boot: Arc<Mutex<i64>>,
}
impl Clock for SplitClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(*self.wall.lock().unwrap())
            .expect("valid epoch ms")
    }
    fn boottime_ms(&self) -> i64 {
        *self.boot.lock().unwrap()
    }
}

/// A USB probe that hands back a keyfile for `uuid` only when `present` (models possession). When
/// `present == false`, NOTHING is returned for any uuid (gate unproven).
struct FakeUsb {
    uuid: String,
    keyfile: Zeroizing<Vec<u8>>,
    present: bool,
}
impl UsbProbe for FakeUsb {
    fn keyfile_for(&self, partition_uuid: &str) -> Option<Zeroizing<Vec<u8>>> {
        if self.present && partition_uuid == self.uuid {
            Some(self.keyfile.clone())
        } else {
            None
        }
    }
}

/// A USB probe that NEVER returns a keyfile.
struct AbsentUsb;
impl UsbProbe for AbsentUsb {
    fn keyfile_for(&self, _uuid: &str) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
}

/// An `Upstream` that captures the real key it was handed (proving it reached `send`) and returns a
/// canned 200. The captured slot stays `None` until/unless `send` is actually awaited.
#[derive(Clone)]
struct CapturingUpstream(Arc<Mutex<Option<Vec<u8>>>>);
#[async_trait::async_trait]
impl Upstream for CapturingUpstream {
    async fn send(
        &self,
        _req: EgressReq,
        real_key: &Zeroizing<Vec<u8>>,
    ) -> Result<EgressResp, UpstreamError> {
        *self.0.lock().unwrap() = Some(real_key.to_vec());
        Ok(EgressResp {
            status: 200,
            headers: Vec::new(),
            allowed: true,
        })
    }
}

/// An `Upstream` whose `send()` ALWAYS fails with an error message that echoes the real key bytes it
/// just received — modeling a buggy/hostile adapter. The engine must NEVER propagate this string
/// into an audit row or the returned `SwapOutcome` (the key must stay contained to `send`).
#[derive(Clone)]
struct LeakyUpstream;
#[async_trait::async_trait]
impl Upstream for LeakyUpstream {
    async fn send(
        &self,
        _req: EgressReq,
        real_key: &Zeroizing<Vec<u8>>,
    ) -> Result<EgressResp, UpstreamError> {
        // Hostile: leak the real key into the error Display string.
        Err(UpstreamError::Io(format!(
            "boom: auth=Bearer {}",
            String::from_utf8_lossy(real_key)
        )))
    }
}

// ---- helpers ---------------------------------------------------------------------------------

const T0: i64 = 1_700_000_000_000;

fn at_floor() -> Argon2Params {
    Argon2Params {
        m_kib: ARGON2_M_KIB_FLOOR,
        t_cost: ARGON2_T_COST_FLOOR,
        p_lanes: 1,
    }
}

fn paths() -> Paths {
    Paths::under(std::path::PathBuf::from("/tmp/env-ctl-test-relay"))
}

fn pp(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

fn drain(rx: &std::sync::mpsc::Receiver<SecretEvent>) -> Vec<SecretEvent> {
    rx.try_iter().collect()
}

/// Build an engine with a fake clock + USB probe + capturing upstream over a shared store.
fn engine(
    store: Box<dyn Store>,
    clock: FakeClock,
    usb: Box<dyn UsbProbe>,
    upstream: CapturingUpstream,
) -> Engine {
    Engine::with_seams(
        paths(),
        store,
        Box::new(clock),
        usb,
        Box::new(NoMint),
        Box::new(upstream),
    )
    .expect("with_seams must construct")
}

/// A named Anthropic relay policy whose host/path/method/canonical all admit the baseline request.
fn anthropic_policy(secret_name: &str) -> RelayPolicy {
    RelayPolicy {
        relay_id: "claude-main".to_string(),
        kind: RelayKind::Named,
        provider: Provider::Anthropic,
        secret_name: secret_name.to_string(),
        swap: SwapMode::BaseUrlRepoint {
            upstream_base: "https://api.anthropic.com".to_string(),
        },
        host_allow: vec!["api.anthropic.com".to_string()],
        path_allow: vec!["/v1/".to_string()],
        method_allow: vec![Method::Post],
        policy_ttl_secs: 31_536_000, // 1y
        rate_per_min: Some(600),
        quota_total_requests: Some(1_000_000),
        quota_total_bytes: Some(1_000_000_000),
        enabled: true,
        revoked: false,
    }
}

fn post_req(peer_uid: Option<u32>) -> EgressReq {
    EgressReq {
        method: Method::Post,
        host: "api.anthropic.com".to_string(),
        path: "/v1/messages".to_string(),
        headers: Vec::new(),
        bytes_out: 64,
        peer_uid,
        peer_pid: None,
    }
}

/// True if `needle` appears in any emitted SecretEvent (serialized to JSON) — used to prove the raw
/// bearer / real key NEVER leak into the event stream.
fn events_contain(events: &[SecretEvent], needle: &str) -> bool {
    events.iter().any(|e| {
        serde_json::to_string(e)
            .map(|s| s.contains(needle))
            .unwrap_or(false)
    })
}

/// True if `needle` appears in any audit row's serialized detail OR subject.
fn audit_contains(store: &InMemStore, needle: &str) -> bool {
    store.audit_rows().iter().any(|r| {
        let detail = serde_json::to_string(&r.detail).unwrap_or_default();
        detail.contains(needle)
            || r.subject.as_deref().map(|s| s.contains(needle)).unwrap_or(false)
    })
}

/// A `Store` forwarding to a shared `Arc<InMemStore>` so the test can keep the concrete handle for
/// `audit_rows()` while the engine owns a `Box<dyn Store>`.
struct SharedStore(Arc<InMemStore>);
impl Store for SharedStore {
    fn get_meta(&self, k: &str) -> anyhow::Result<Option<String>> {
        self.0.get_meta(k)
    }
    fn put_meta(&self, k: &str, v: &str) -> anyhow::Result<()> {
        self.0.put_meta(k, v)
    }
    fn reserve_secret_row_id(&self) -> anyhow::Result<i64> {
        self.0.reserve_secret_row_id()
    }
    fn put_secret(&self, row: envctl_secrets::vault::SecretRow) -> anyhow::Result<i64> {
        self.0.put_secret(row)
    }
    fn get_secret_latest(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<envctl_secrets::vault::SecretRow>> {
        self.0.get_secret_latest(name)
    }
    fn get_secret_version(
        &self,
        name: &str,
        version: u32,
    ) -> anyhow::Result<Option<envctl_secrets::vault::SecretRow>> {
        self.0.get_secret_version(name, version)
    }
    fn max_secret_version(&self, name: &str) -> anyhow::Result<u32> {
        self.0.max_secret_version(name)
    }
    fn list_secret_names(&self) -> anyhow::Result<Vec<String>> {
        self.0.list_secret_names()
    }
    fn list_secret_versions(&self, name: &str) -> anyhow::Result<Vec<u32>> {
        self.0.list_secret_versions(name)
    }
    fn save_keyslot(&self, slot: &envctl_secrets::keyslot::Keyslot) -> anyhow::Result<()> {
        self.0.save_keyslot(slot)
    }
    fn load_keyslots(&self) -> anyhow::Result<Vec<envctl_secrets::keyslot::Keyslot>> {
        self.0.load_keyslots()
    }
    fn load_keyslot(&self, id: i64) -> anyhow::Result<Option<envctl_secrets::keyslot::Keyslot>> {
        self.0.load_keyslot(id)
    }
    fn append_audit(&self, rec: &envctl_secrets::AuditRecord) -> anyhow::Result<i64> {
        self.0.append_audit(rec)
    }
    fn verify_audit_chain(&self) -> anyhow::Result<()> {
        self.0.verify_audit_chain()
    }
    fn last_audit(&self) -> anyhow::Result<Option<envctl_secrets::AuditRecord>> {
        self.0.last_audit()
    }
    fn query_audit(
        &self,
        since_seq: i64,
        limit: usize,
    ) -> anyhow::Result<Vec<envctl_secrets::AuditRecord>> {
        self.0.query_audit(since_seq, limit)
    }
    // relay/bearer surface forwards too, so the engine's relay path drives the REAL InMemStore.
    fn save_relay_policy(
        &self,
        row: envctl_secrets::vault::RelayPolicyRow,
    ) -> anyhow::Result<i64> {
        self.0.save_relay_policy(row)
    }
    fn load_relay_policy(
        &self,
        relay_id: &str,
    ) -> anyhow::Result<Option<envctl_secrets::vault::RelayPolicyRow>> {
        self.0.load_relay_policy(relay_id)
    }
    fn list_relay_policies(&self) -> anyhow::Result<Vec<envctl_secrets::vault::RelayPolicyRow>> {
        self.0.list_relay_policies()
    }
    fn save_bearer(&self, row: envctl_secrets::vault::BearerRow) -> anyhow::Result<()> {
        self.0.save_bearer(row)
    }
    fn load_bearer(
        &self,
        token_id: &str,
    ) -> anyhow::Result<Option<envctl_secrets::vault::BearerRow>> {
        self.0.load_bearer(token_id)
    }
    fn list_bearers_for_relay(
        &self,
        relay_id: &str,
    ) -> anyhow::Result<Vec<envctl_secrets::vault::BearerRow>> {
        self.0.list_bearers_for_relay(relay_id)
    }
    fn revoke_bearers_for_relay(&self, relay_id: &str) -> anyhow::Result<u32> {
        self.0.revoke_bearers_for_relay(relay_id)
    }
    fn save_remote_client(
        &self,
        row: envctl_secrets::vault::RemoteClient,
    ) -> anyhow::Result<()> {
        self.0.save_remote_client(row)
    }
    fn load_remote_client(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Option<envctl_secrets::vault::RemoteClient>> {
        self.0.load_remote_client(client_id)
    }
    fn list_remote_clients(&self) -> anyhow::Result<Vec<envctl_secrets::vault::RemoteClient>> {
        self.0.list_remote_clients()
    }
    fn revoke_remote_client(&self, client_id: &str, now_ms: i64) -> anyhow::Result<bool> {
        self.0.revoke_remote_client(client_id, now_ms)
    }
}

// ---- B. relay_mint clamp + USB gate ----------------------------------------------------------

/// A 1-year request is clamped to <=24h; the raw bearer / secret never leak into events or audit.
#[test]
fn relay_mint_clamps_one_year_to_24h_and_never_leaks_raw() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    // Passphrase-only vault => no USB keyslot => the USB gate is vacuously satisfied for mint.
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("mint-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("mint-pass")), &sink).unwrap();
    let _ = drain(&rx);

    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 31_536_000, Some(1000), None, &sink)
        .expect("mint must succeed");

    // The wire bearer is namespaced and clamped to <=24h.
    assert!(bearer.raw.starts_with("evrelay_"), "bearer must carry the evrelay_ prefix");
    assert!(bearer.raw.starts_with(&format!("evrelay_{}_", bearer.token_id)));

    // The stored bearer row's lifetime is clamped to the 24h ceiling.
    let row = inmem.load_bearer(&bearer.token_id).unwrap().expect("bearer row persisted");
    assert!(
        row.expires_at_ms - row.issued_at_ms <= MAX_BEARER_TTL_SECS * 1000,
        "a 1-year request must clamp to <=24h: got {} ms",
        row.expires_at_ms - row.issued_at_ms
    );
    assert_eq!(row.issued_at_ms, T0, "issued at the fake clock's T0");
    assert!(!row.revoked);
    assert_eq!(row.client_uid, Some(1000), "peer-bound to the minting uid");

    // The raw bearer + the secret half NEVER appear in any event or audit row — only the token_id.
    let raw = bearer.raw.to_string();
    let secret = raw
        .strip_prefix(&format!("evrelay_{}_", bearer.token_id))
        .expect("raw has the expected shape")
        .to_string();
    let ev = drain(&rx);
    assert!(!events_contain(&ev, &raw), "raw bearer must not leak into events");
    assert!(!events_contain(&ev, &secret), "bearer secret must not leak into events");
    assert!(!audit_contains(&inmem, &raw), "raw bearer must not leak into audit rows");
    assert!(!audit_contains(&inmem, &secret), "bearer secret must not leak into audit rows");
    // The public token_id IS present (traceability).
    assert!(audit_contains(&inmem, &bearer.token_id), "token_id must be audited");
    assert!(
        ev.iter().any(|e| matches!(e, SecretEvent::RelayMinted { relay, .. } if relay == "claude-main")),
        "a RelayMinted event must be emitted"
    );
}

/// An absent USB gate refuses the mint: typed `UsbAbsent` Err + durable Refused row + GuardRefused
/// event + NO bearer row written.
#[test]
fn relay_mint_refuses_when_usb_absent() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let keyfile = Zeroizing::new(vec![0xA5u8; 64]);

    // Build a USB-enrolled vault (so a USB keyslot exists => the gate is live), then present an
    // ABSENT probe at mint time.
    let store_for_init = Box::new(SharedStore(inmem.clone())) as Box<dyn Store>;
    let eng_init = engine(
        store_for_init,
        clock.clone(),
        Box::new(FakeUsb {
            uuid: "1234-ABCD".to_string(),
            keyfile: keyfile.clone(),
            present: true,
        }),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng_init
        .init_vault(
            pp("usb-pass"),
            Some("1234-ABCD".to_string()),
            Some(keyfile.clone()),
            at_floor(),
            &sink,
        )
        .unwrap();
    eng_init.unlock(Unlock::Passphrase(pp("usb-pass")), &sink).unwrap();
    let _ = drain(&rx);

    // A second engine over the SAME store whose probe NO LONGER possesses the keyfile.
    let eng_absent = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    eng_absent.unlock(Unlock::Passphrase(pp("usb-pass")), &sink).unwrap();
    let _ = drain(&rx);

    // `Bearer` deliberately does NOT implement Debug (it holds the raw secret), so we cannot
    // `expect_err` it; match on the Result directly.
    let res = eng_absent.relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink);
    let err = match res {
        Ok(_) => panic!("an absent USB gate must refuse the mint"),
        Err(e) => e,
    };
    assert!(
        matches!(err.downcast_ref::<EngineError>(), Some(EngineError::UsbAbsent)),
        "expected UsbAbsent, got {err:?}"
    );

    let ev = drain(&rx);
    assert!(
        ev.iter().any(|e| matches!(
            e,
            SecretEvent::GuardRefused { subject, .. } if subject == "claude-main"
        )),
        "a GuardRefused event must be emitted on the USB-absent refusal"
    );
    assert!(
        inmem.audit_rows().iter().any(|r| {
            r.event_type == "relay_mint"
                && r.outcome == envctl_secrets::event::AuditOutcome::Refused
        }),
        "a durable Refused relay_mint audit row must exist"
    );
    // No bearer row was written.
    assert!(
        inmem.load_bearer("anything").unwrap().is_none()
            && inmem.list_bearers_for_relay("claude-main").unwrap().is_empty(),
        "no BearerRow may be written on a refused mint"
    );
}

// ---- C. relay_swap: Allow reaches the upstream WITH THE REAL KEY ------------------------------

/// The Allow path hands the REAL key to `Upstream::send` ONLY, and that key never appears in any
/// event, audit row, or the returned value.
#[test]
fn relay_swap_allow_delivers_real_key_only_to_upstream() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("swap-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("swap-pass")), &sink).unwrap();

    // Put the REAL broker-only secret.
    const REAL: &[u8] = b"sk-REAL-DEADBEEF";
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(REAL.to_vec()),
        &sink,
    )
    .unwrap();

    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    let _ = drain(&rx);

    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    match outcome {
        SwapOutcome::Allowed(resp) => {
            assert_eq!(resp.status, 200);
            assert!(resp.allowed);
        }
        other => panic!("expected Allowed, got {:?}", outcome_kind(&other)),
    }

    // The real key reached Upstream::send EXACTLY.
    assert_eq!(
        cap.0.lock().unwrap().as_deref(),
        Some(REAL),
        "the real key must reach Upstream::send"
    );

    // ...and NEVER leaked into events or audit.
    let ev = drain(&rx);
    let real_str = String::from_utf8(REAL.to_vec()).unwrap();
    assert!(!events_contain(&ev, &real_str), "real key must not leak into events");
    assert!(!audit_contains(&inmem, &real_str), "real key must not leak into audit rows");
    assert!(
        ev.iter().any(|e| matches!(
            e,
            SecretEvent::RelaySwapped { allowed: true, token_id, .. } if *token_id == bearer.token_id
        )),
        "a RelaySwapped{{allowed:true}} event must be emitted carrying only the token_id"
    );
}

/// Phase-8 F15/F12: `register_remote_client` + `relay_mint_remote` bind a bearer to a client_id +
/// DPoP jkt (NOT a uid/pid), persist them, authenticate them in the row MAC, and `decide()` denies
/// that remote bearer when it is presented over the LOCAL egress path (cross-kind).
#[test]
fn relay_mint_remote_binds_client_and_cross_kind_denied_locally() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("remote-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("remote-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-REMOTE".to_vec()),
        &sink,
    )
    .unwrap();

    let jkt = [0x42u8; 32];

    // An UNKNOWN remote client cannot be minted against (default-deny).
    assert!(
        eng.relay_mint_remote(anthropic_policy("anthropic_key"), 3600, "phone".to_string(), jkt, &sink)
            .is_err(),
        "minting against an unregistered client must refuse"
    );

    // Register, then mint binds the bearer to (client_id, jkt).
    eng.register_remote_client("phone".to_string(), jkt, false, &sink)
        .expect("register remote client");
    let bearer = eng
        .relay_mint_remote(anthropic_policy("anthropic_key"), 3600, "phone".to_string(), jkt, &sink)
        .expect("remote mint");
    let _ = drain(&rx);

    // The persisted row carries the remote binding (F15) and NO local uid/pid.
    let row = inmem.load_bearer(&bearer.token_id).unwrap().expect("bearer row persisted");
    assert_eq!(row.client_id.as_deref(), Some("phone"));
    assert_eq!(row.dpop_jkt, Some(jkt));
    assert_eq!(row.client_uid, None);
    assert_eq!(row.client_pid, None);

    // A jkt that does not match the registration is refused at mint (proof-of-possession binding).
    assert!(
        eng.relay_mint_remote(anthropic_policy("anthropic_key"), 3600, "phone".to_string(), [0x99u8; 32], &sink)
            .is_err(),
        "minting with a jkt != the registered key must refuse"
    );

    // Presenting the REMOTE bearer over the LOCAL egress path (req.remote == None) is DENIED
    // cross-kind. Reaching CrossKindPresentation (NOT UnknownBearer) proves the row MAC over
    // client_id/dpop_jkt verified; the real key is never fetched.
    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    match outcome {
        SwapOutcome::Denied(DenyReason::CrossKindPresentation) => {}
        other => panic!("expected Denied(CrossKindPresentation), got {:?}", outcome_kind(&other)),
    }
    assert!(
        cap.0.lock().unwrap().is_none(),
        "the real key must NOT be fetched for a cross-kind deny"
    );
}

/// A mint with NO principal at all (local uid AND pid both None, no remote client) is refused, so
/// the InMemStore and the libSQL CHECK can never disagree on a both-null bearer (fail-closed).
#[test]
fn relay_mint_both_null_principal_refused() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, _rx) = EventSink::channel();
    eng.init_vault(pp("nul"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("nul")), &sink).unwrap();

    assert!(
        eng.relay_mint(anthropic_policy("anthropic_key"), 3600, None, None, &sink)
            .is_err(),
        "a both-null-principal mint must be refused"
    );
    assert!(
        inmem.list_bearers_for_relay("claude-main").unwrap().is_empty(),
        "no bearer is persisted on a refused mint"
    );
}

/// A Deny (wrong method) never fetches the key and never reaches the upstream; a Refused
/// `relay_swapped` audit row is written.
#[test]
fn relay_swap_deny_never_reaches_upstream() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("deny-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("deny-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    let _ = drain(&rx);

    // GET is not in method_allow => MethodNotAllowed.
    let mut req = post_req(Some(1000));
    req.method = Method::Get;
    let outcome = block_on(eng.relay_swap(&bearer.raw, &req, &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::MethodNotAllowed)),
        "expected Denied(MethodNotAllowed), got {:?}",
        outcome_kind(&outcome)
    );
    assert!(
        cap.0.lock().unwrap().is_none(),
        "send must NEVER be awaited on a Deny: captured key slot stays None"
    );
    let ev = drain(&rx);
    assert!(
        ev.iter().any(|e| matches!(
            e,
            SecretEvent::RelaySwapped { allowed: false, .. }
        )),
        "a RelaySwapped{{allowed:false}} event must be emitted"
    );
    assert!(
        inmem.audit_rows().iter().any(|r| {
            r.event_type == "relay_swapped"
                && r.outcome == envctl_secrets::event::AuditOutcome::Refused
        }),
        "a Refused relay_swapped audit row must exist"
    );
}

/// A forged bearer (real token_id, wrong secret) verifies false => UnknownBearer; the upstream is
/// never reached.
#[test]
fn relay_swap_forged_bearer_is_unknown() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("forge-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("forge-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    let _ = drain(&rx);

    // Forge: real token_id, attacker-chosen secret => MAC verify fails.
    let forged = format!("evrelay_{}_{}", bearer.token_id, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let outcome = block_on(eng.relay_swap(&forged, &post_req(Some(1000)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::UnknownBearer)),
        "a forged secret must be UnknownBearer, got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "forged bearer must not reach the upstream");

    // A totally malformed bearer is also UnknownBearer.
    let outcome2 = block_on(eng.relay_swap("not-our-bearer", &post_req(Some(1000)), &sink));
    assert!(matches!(outcome2, SwapOutcome::Denied(DenyReason::UnknownBearer)));
    assert!(cap.0.lock().unwrap().is_none());
}

/// Advancing the clock past `expires_at` yields BearerExpired; the upstream is never reached.
#[test]
fn relay_swap_expired_bearer_is_denied() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("exp-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("exp-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    // Mint with a 1h TTL, then jump the clock 2h forward.
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    let _ = drain(&rx);

    clock.set(T0 + 2 * 3_600_000); // +2h
    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::BearerExpired)),
        "expected BearerExpired, got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "expired bearer must not reach the upstream");
}

/// Revoking a bearer (apply) then swapping yields BearerRevoked; the upstream is never reached.
#[test]
fn relay_swap_revoked_bearer_is_denied() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("rev-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("rev-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");

    // Dry-run revoke first => count 1, no mutation.
    assert_eq!(
        eng.relay_revoke_bearer(&bearer.token_id, false, &sink).unwrap(),
        1,
        "dry-run reports the would-flip count"
    );
    // Apply.
    assert_eq!(
        eng.relay_revoke_bearer(&bearer.token_id, true, &sink).unwrap(),
        1,
        "apply flips exactly one bearer"
    );
    // Re-revoke is a no-op (already revoked => 0).
    assert_eq!(eng.relay_revoke_bearer(&bearer.token_id, true, &sink).unwrap(), 0);
    let _ = drain(&rx);

    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::BearerRevoked)),
        "expected BearerRevoked, got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "revoked bearer must not reach the upstream");
}

/// `relay_revoke` (whole relay) fails closed: apply revokes the policy + every live bearer; a
/// subsequent swap is denied (Revoked). Dry-run reports the count without mutating.
#[test]
fn relay_revoke_whole_relay_fails_closed() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("relayrev-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("relayrev-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    // Two live bearers off the same named relay.
    let b1 = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint b1");
    let _b2 = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint b2");
    let _ = drain(&rx);

    // Dry-run: 2 would be revoked, no mutation.
    assert_eq!(eng.relay_revoke("claude-main", false, &sink).unwrap(), 2);
    // Apply: both flip.
    assert_eq!(eng.relay_revoke("claude-main", true, &sink).unwrap(), 2);
    let _ = drain(&rx);

    // A swap against a now-revoked relay is denied. The policy.revoked flag fires before the
    // bearer-revoked check, so the reason is Revoked.
    let outcome = block_on(eng.relay_swap(&b1.raw, &post_req(Some(1000)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::Revoked)),
        "expected Revoked, got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "a revoked relay must not reach the upstream");
}

/// A peer-bound bearer presented by a different uid is denied (PeerMismatch); never reaches send.
#[test]
fn relay_swap_peer_mismatch_is_denied() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("peer-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("peer-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    let _ = drain(&rx);

    // Present from uid 1001 (bearer is bound to 1000).
    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1001)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::PeerMismatch)),
        "expected PeerMismatch, got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none());
}

/// A swap against a LOCKED vault is `InternalRefused` (never a send), so an internal error can't
/// fail-open into delivering the key.
#[test]
fn relay_swap_locked_vault_is_internal_refused() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock.clone(),
        Box::new(AbsentUsb),
        cap.clone(),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("locked-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("locked-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    eng.lock(&sink).unwrap();
    let _ = drain(&rx);

    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::InternalRefused(_)),
        "a locked vault must be InternalRefused, got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "a locked vault must not reach the upstream");
}

// ---- D. regression tests for the finalize-broker hardening -----------------------------------

/// Build an engine with an arbitrary `Upstream` impl (so a test can inject the leaky sender).
fn engine_with_upstream(
    store: Box<dyn Store>,
    clock: FakeClock,
    usb: Box<dyn UsbProbe>,
    upstream: Box<dyn Upstream>,
) -> Engine {
    Engine::with_seams(paths(), store, Box::new(clock), usb, Box::new(NoMint), upstream)
        .expect("with_seams must construct")
}

/// Set up an unlocked, USB-free vault with the REAL secret + a fresh bearer; return (engine, inmem,
/// sink, rx, bearer). Shared scaffolding for the tamper tests.
fn minted_engine(
    pass: &str,
    cap: CapturingUpstream,
) -> (
    Engine,
    Arc<InMemStore>,
    EventSink,
    std::sync::mpsc::Receiver<SecretEvent>,
    envctl_secrets::broker::Bearer,
) {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let eng = engine(
        Box::new(SharedStore(inmem.clone())),
        clock,
        Box::new(AbsentUsb),
        cap,
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp(pass), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp(pass)), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    let _ = drain(&rx);
    (eng, inmem, sink, rx, bearer)
}

/// CRITICAL: a store-level attacker who un-revokes a revoked bearer (flips `revoked:true->false`
/// in the clear) cannot forge an Allow — the DEK-keyed row MAC no longer matches, so the swap is
/// `UnknownBearer` and the key never reaches the upstream.
#[test]
fn relay_swap_tampered_unrevoke_is_unknown_bearer() {
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let (eng, inmem, sink, _rx, bearer) = minted_engine("tamper-rev", cap.clone());

    // Legitimately revoke the bearer (engine re-MACs the row over revoked=true).
    assert_eq!(eng.relay_revoke_bearer(&bearer.token_id, true, &sink).unwrap(), 1);

    // Store-level tamper: flip revoked back to false WITHOUT touching the row_mac.
    inmem.tamper_bearer(&bearer.token_id, |b| b.revoked = false);

    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::UnknownBearer)),
        "an un-revoke tamper must be UnknownBearer (row MAC mismatch), got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "tampered bearer must not reach the upstream");
}

/// CRITICAL: raising `expires_at_ms` on an expired bearer (to resurrect it) does not forge an Allow
/// — the row MAC binds expiry, so the tamper is UnknownBearer.
#[test]
fn relay_swap_tampered_expiry_is_unknown_bearer() {
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let (eng, inmem, sink, _rx, bearer) = minted_engine("tamper-exp", cap.clone());

    // Push the expiry far into the future WITHOUT re-MACing.
    inmem.tamper_bearer(&bearer.token_id, |b| b.expires_at_ms += 100 * 24 * 3_600_000);

    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::UnknownBearer)),
        "an expiry tamper must be UnknownBearer (row MAC mismatch), got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "tampered bearer must not reach the upstream");
}

/// CRITICAL: rewriting the peer binding (`client_uid`) to match a different caller does not forge an
/// Allow — the row MAC binds the peer ids, so the tamper is UnknownBearer (caught before the peer
/// check even runs).
#[test]
fn relay_swap_tampered_peer_binding_is_unknown_bearer() {
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let (eng, inmem, sink, _rx, bearer) = minted_engine("tamper-peer", cap.clone());

    // Rebind the bearer to uid 1001 in the clear (without re-MACing) and present it from 1001.
    inmem.tamper_bearer(&bearer.token_id, |b| b.client_uid = Some(1001));

    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1001)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::UnknownBearer)),
        "a peer-binding tamper must be UnknownBearer (row MAC mismatch), got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "tampered bearer must not reach the upstream");
}

/// HIGH (OI-6): a wall-clock rollback that lands BACK INSIDE the still-valid window cannot resurrect
/// the relay window — the monotonic boottime anchor catches the wall/monotonic divergence. Here the
/// boottime advances 30 min past mint while the wall clock is rewound to T0, a divergence beyond the
/// skew => the swap is Denied (not Allowed) and the key never reaches the upstream.
#[test]
fn relay_swap_wall_rollback_within_window_is_denied_by_boottime() {
    let inmem = Arc::new(InMemStore::new());
    // Independent wall + boottime cells so we can rewind the wall WITHOUT rewinding monotonic time.
    let wall = Arc::new(Mutex::new(T0));
    let boot = Arc::new(Mutex::new(0i64));
    let clock = SplitClock {
        wall: wall.clone(),
        boot: boot.clone(),
    };
    let cap = CapturingUpstream(Arc::new(Mutex::new(None)));
    let eng = Engine::with_seams(
        paths(),
        Box::new(SharedStore(inmem.clone())),
        Box::new(clock),
        Box::new(AbsentUsb),
        Box::new(NoMint),
        Box::new(cap.clone()),
    )
    .expect("with_seams");

    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("rollback-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("rollback-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"sk-REAL-DEADBEEF".to_vec()),
        &sink,
    )
    .unwrap();
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    let _ = drain(&rx);

    // Monotonic time advances 30 min (within the 1h TTL); wall clock is rewound back to T0.
    *boot.lock().unwrap() = 30 * 60 * 1000;
    *wall.lock().unwrap() = T0; // unchanged wall, but mint saw wall=T0 too => wall delta 0
    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    assert!(
        matches!(outcome, SwapOutcome::Denied(DenyReason::ClockRollback)),
        "a wall/monotonic divergence must be ClockRollback, got {:?}",
        outcome_kind(&outcome)
    );
    assert!(cap.0.lock().unwrap().is_none(), "a rolled-back clock must not reach the upstream");
}

/// MEDIUM: a hostile upstream that echoes the real key into its error string must NOT leak it — the
/// key appears in neither the audit rows nor the returned `SwapOutcome`.
#[test]
fn relay_swap_upstream_error_does_not_leak_real_key() {
    let inmem = Arc::new(InMemStore::new());
    let clock = FakeClock::new(T0);
    let eng = engine_with_upstream(
        Box::new(SharedStore(inmem.clone())),
        clock,
        Box::new(AbsentUsb),
        Box::new(LeakyUpstream),
    );
    let (sink, rx) = EventSink::channel();
    eng.init_vault(pp("leak-pass"), None, None, at_floor(), &sink).unwrap();
    eng.unlock(Unlock::Passphrase(pp("leak-pass")), &sink).unwrap();
    const REAL: &[u8] = b"sk-REAL-DEADBEEF";
    eng.secret_put(
        SecretMeta {
            name: "anthropic_key".to_string(),
            provider: Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(REAL.to_vec()),
        &sink,
    )
    .unwrap();
    let bearer = eng
        .relay_mint(anthropic_policy("anthropic_key"), 3600, Some(1000), None, &sink)
        .expect("mint");
    let _ = drain(&rx);

    let outcome = block_on(eng.relay_swap(&bearer.raw, &post_req(Some(1000)), &sink));
    let real_str = String::from_utf8(REAL.to_vec()).unwrap();
    // The outcome is a refusal whose message is a fixed, key-free label.
    match &outcome {
        SwapOutcome::InternalRefused(m) => {
            assert!(!m.contains(&real_str), "the real key must not appear in the returned outcome");
            assert!(m.contains("upstream send failed"), "fixed key-free label expected, got {m}");
        }
        other => panic!("expected InternalRefused, got {:?}", outcome_kind(other)),
    }
    // ...and never in any emitted event or durable audit row.
    let ev = drain(&rx);
    assert!(!events_contain(&ev, &real_str), "real key must not leak into events");
    assert!(!audit_contains(&inmem, &real_str), "real key must not leak into audit rows");
}

/// Tiny helper to name an outcome variant in panic messages without printing the response body.
fn outcome_kind(o: &SwapOutcome) -> String {
    match o {
        SwapOutcome::Allowed(r) => format!("Allowed(status={})", r.status),
        SwapOutcome::Denied(reason) => format!("Denied({reason:?})"),
        SwapOutcome::InternalRefused(m) => format!("InternalRefused({m})"),
    }
}
