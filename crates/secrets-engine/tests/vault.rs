//! Phase-1b acceptance tests: the functional vault driven through the PUBLIC `Engine` API via
//! `with_seams` + a real `InMemStore` + fake seams. We assert emitted `SecretEvent`s, the durable
//! hash-chained audit log, and `EngineError` semantics. `tests/phase0.rs` is UNTOUCHED and must
//! keep passing alongside this file.
//!
//! Argon2id is run at-floor (`m_kib = ARGON2_M_KIB_FLOOR`, `t_cost = ARGON2_T_COST_FLOOR`,
//! `p_lanes = 1`, ~256 MiB) — the same cost the keyslot unit test
//! `argon2_at_floor_round_trips_through_wrap` already pays, so these stay tolerable in CI.
use envctl_secrets::keyslot::{Argon2Params, Factor, ARGON2_M_KIB_FLOOR, ARGON2_T_COST_FLOOR};
use envctl_secrets::paths::Paths;
use envctl_secrets::seam::{NoMint, SystemClock, UpstreamError, UsbProbe};
use envctl_secrets::vault::{InMemStore, Store};
use envctl_secrets::{
    EgressReq, EgressResp, Engine, EngineError, SecretEvent, SecretMeta, Unlock, Upstream,
    VaultState,
};
use std::path::PathBuf;
use zeroize::Zeroizing;

// ---- fakes -----------------------------------------------------------------------------------

/// A USB probe that hands back a keyfile ONLY when the requested partition UUID matches (models
/// possession-proof, CF-4 — a UUID match alone is never enough; the keyfile must be obtainable).
struct FakeUsb {
    uuid: String,
    keyfile: Zeroizing<Vec<u8>>,
}
impl UsbProbe for FakeUsb {
    fn keyfile_for(&self, partition_uuid: &str) -> Option<Zeroizing<Vec<u8>>> {
        if partition_uuid == self.uuid {
            Some(self.keyfile.clone())
        } else {
            None
        }
    }
}

/// A USB probe that NEVER returns a keyfile (no USB present / possession unproven).
struct AbsentUsb;
impl UsbProbe for AbsentUsb {
    fn keyfile_for(&self, _partition_uuid: &str) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
}

/// The relay/egress path stays `todo!()` in 1b, so `send` is never reached; this exists only to
/// satisfy the `with_seams` signature.
struct FakeUpstream;
#[async_trait::async_trait]
impl Upstream for FakeUpstream {
    async fn send(
        &self,
        _req: EgressReq,
        _real_key: &Zeroizing<Vec<u8>>,
    ) -> Result<EgressResp, UpstreamError> {
        unreachable!("the relay path is out of scope for Phase 1b");
    }
}

// ---- helpers ---------------------------------------------------------------------------------

fn at_floor_params() -> Argon2Params {
    Argon2Params {
        m_kib: ARGON2_M_KIB_FLOOR,
        t_cost: ARGON2_T_COST_FLOOR,
        p_lanes: 1,
    }
}

fn paths() -> Paths {
    Paths::under(PathBuf::from("/tmp/env-ctl-test-phase1b"))
}

fn pp(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

/// Build an engine over a SHARED store + a USB probe of the caller's choice (so a "second engine
/// over the same store" can present a different probe).
fn engine_with(
    store: Box<dyn Store>,
    usb: Box<dyn UsbProbe>,
) -> Engine {
    Engine::with_seams(
        paths(),
        store,
        Box::new(SystemClock),
        usb,
        Box::new(NoMint),
        Box::new(FakeUpstream),
    )
    .expect("with_seams must construct")
}

/// Drain the event channel into a Vec.
fn drain(rx: &std::sync::mpsc::Receiver<SecretEvent>) -> Vec<SecretEvent> {
    rx.try_iter().collect()
}

/// Count `Audit` rows in a drained event batch whose event_type matches.
fn audit_count(events: &[SecretEvent], event_type: &str) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, SecretEvent::Audit(r) if r.event_type == event_type))
        .count()
}

fn has_event<F: Fn(&SecretEvent) -> bool>(events: &[SecretEvent], pred: F) -> bool {
    events.iter().any(pred)
}

// ---- 1. init + passphrase unlock + put/get round-trip ----------------------------------------

#[test]
fn init_passphrase_unlock_put_get_roundtrip() {
    let store: Box<dyn Store> = Box::new(InMemStore::new());
    let eng = engine_with(store, Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();

    // init
    eng.init_vault(pp("super-secret-pass"), None, None, at_floor_params(), &sink)
        .expect("init_vault must succeed");
    let ev = drain(&rx);
    assert_eq!(audit_count(&ev, "vault_init"), 1, "a vault_init audit row must land");

    // unlock
    let st = eng
        .unlock(Unlock::Passphrase(pp("super-secret-pass")), &sink)
        .expect("unlock must succeed");
    assert_eq!(st, VaultState::Unlocked);
    let ev = drain(&rx);
    assert!(
        has_event(&ev, |e| matches!(
            e,
            SecretEvent::VaultUnlocked { factor: Factor::Passphrase }
        )),
        "VaultUnlocked{{Passphrase}} must be emitted"
    );

    // put v1
    eng.secret_put(
        SecretMeta {
            name: "claude".to_string(),
            provider: envctl_secrets::Provider::Anthropic,
            note: String::new(),
            broker_only: false,
        },
        Zeroizing::new(b"sk-live-xyz".to_vec()),
        &sink,
    )
    .expect("secret_put must succeed");
    let ev = drain(&rx);
    assert!(
        has_event(&ev, |e| matches!(
            e,
            SecretEvent::SecretWritten { name, version: 1 } if name == "claude"
        )),
        "SecretWritten{{claude,v1}} must be emitted"
    );

    // get v1 (reveal + apply)
    let got = eng
        .secret_get("claude", true, true, &sink)
        .expect("secret_get must succeed");
    assert_eq!(got.as_slice(), b"sk-live-xyz");
    let ev = drain(&rx);
    assert!(
        has_event(&ev, |e| matches!(e, SecretEvent::SecretRead { name, .. } if name == "claude")),
        "SecretRead must be emitted"
    );

    // put v2 (latest-wins)
    eng.secret_put(
        SecretMeta {
            name: "claude".to_string(),
            provider: envctl_secrets::Provider::Anthropic,
            note: String::new(),
            broker_only: false,
        },
        Zeroizing::new(b"sk-live-v2".to_vec()),
        &sink,
    )
    .expect("secret_put v2 must succeed");
    let ev = drain(&rx);
    assert!(
        has_event(&ev, |e| matches!(
            e,
            SecretEvent::SecretWritten { name, version: 2 } if name == "claude"
        )),
        "SecretWritten{{claude,v2}} must be emitted"
    );

    let got2 = eng
        .secret_get("claude", true, true, &sink)
        .expect("secret_get v2 must succeed");
    assert_eq!(got2.as_slice(), b"sk-live-v2", "latest-wins returns v2 bytes");
}

// ---- 2. USB keyslot unlock via fake probe ----------------------------------------------------

#[test]
fn usb_keyslot_unlock_via_fake_probe() {
    // Build a dual-KEK vault: passphrase + USB. Persist into a shared in-process store; we re-open
    // a fresh engine over the SAME store to model a daemon restart presenting a different probe.
    let inmem = std::sync::Arc::new(InMemStore::new());
    let keyfile = Zeroizing::new(vec![0xA5u8; 64]);

    // We need the store usable by multiple engines. `with_seams` takes Box<dyn Store>, so wrap an
    // Arc in a thin forwarding adapter so several engines share the one backing store.
    let store_for_init = Box::new(SharedStore(inmem.clone())) as Box<dyn Store>;
    let eng_init = engine_with(
        store_for_init,
        Box::new(FakeUsb {
            uuid: "1234-ABCD".to_string(),
            keyfile: keyfile.clone(),
        }),
    );
    let (sink, rx) = envctl_secrets::EventSink::channel();

    eng_init
        .init_vault(
            pp("dual-factor-pass"),
            Some("1234-ABCD".to_string()),
            Some(keyfile.clone()),
            at_floor_params(),
            &sink,
        )
        .expect("dual-KEK init must succeed");
    let _ = drain(&rx);

    // Unlock via USB on an engine whose probe DOES possess the matching keyfile.
    let eng_usb = engine_with(
        Box::new(SharedStore(inmem.clone())),
        Box::new(FakeUsb {
            uuid: "1234-ABCD".to_string(),
            keyfile: keyfile.clone(),
        }),
    );
    let st = eng_usb.unlock(Unlock::Usb, &sink).expect("USB unlock must succeed");
    assert_eq!(st, VaultState::Unlocked);
    let ev = drain(&rx);
    assert!(
        has_event(&ev, |e| matches!(
            e,
            SecretEvent::VaultUnlocked { factor: Factor::Usb }
        )),
        "VaultUnlocked{{Usb}} must be emitted"
    );

    // Same DEK regardless of factor: put then get round-trips.
    eng_usb
        .secret_put(
            SecretMeta {
                name: "gh".to_string(),
                provider: envctl_secrets::Provider::Github,
                note: String::new(),
                broker_only: false,
            },
            Zeroizing::new(b"ghp_token".to_vec()),
            &sink,
        )
        .expect("put under USB-unlocked vault");
    let got = eng_usb
        .secret_get("gh", true, true, &sink)
        .expect("get under USB-unlocked vault");
    assert_eq!(got.as_slice(), b"ghp_token");
    let _ = drain(&rx);

    // Negative: a fresh engine over the SAME store but with a WRONG UUID (possession unproven)
    // must fail to unlock via USB (CF-4) and emit no VaultUnlocked.
    let eng_wrong = engine_with(
        Box::new(SharedStore(inmem.clone())),
        Box::new(FakeUsb {
            uuid: "WRONG-UUID".to_string(),
            keyfile: keyfile.clone(),
        }),
    );
    let err = eng_wrong
        .unlock(Unlock::Usb, &sink)
        .expect_err("wrong-UUID USB unlock must fail");
    assert!(
        matches!(err.downcast_ref::<EngineError>(), Some(EngineError::UnlockFailed)),
        "expected UnlockFailed, got {err:?}"
    );
    let ev = drain(&rx);
    assert!(
        !has_event(&ev, |e| matches!(e, SecretEvent::VaultUnlocked { .. })),
        "no VaultUnlocked on a failed USB unlock"
    );

    // And an absent probe likewise fails.
    let eng_absent = engine_with(Box::new(SharedStore(inmem.clone())), Box::new(AbsentUsb));
    let err = eng_absent
        .unlock(Unlock::Usb, &sink)
        .expect_err("absent USB unlock must fail");
    assert!(matches!(
        err.downcast_ref::<EngineError>(),
        Some(EngineError::UnlockFailed)
    ));
}

// ---- 3. wrong passphrase fails ---------------------------------------------------------------

#[test]
fn wrong_passphrase_fails() {
    let eng = engine_with(Box::new(InMemStore::new()), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();
    eng.init_vault(pp("the-real-pass"), None, None, at_floor_params(), &sink)
        .expect("init");
    let _ = drain(&rx);

    let err = eng
        .unlock(Unlock::Passphrase(pp("nope")), &sink)
        .expect_err("wrong passphrase must fail");
    assert!(
        matches!(err.downcast_ref::<EngineError>(), Some(EngineError::UnlockFailed)),
        "expected the single generic UnlockFailed (OI-17), got {err:?}"
    );
    // Single generic message.
    assert_eq!(err.to_string(), "unlock failed");

    let ev = drain(&rx);
    assert!(
        !has_event(&ev, |e| matches!(e, SecretEvent::VaultUnlocked { .. })),
        "no VaultUnlocked on wrong passphrase"
    );
    assert!(
        ev.iter().any(|e| matches!(
            e,
            SecretEvent::Audit(r)
                if r.event_type == "vault_unlock"
                    && r.outcome == envctl_secrets::event::AuditOutcome::Failed
        )),
        "a Failed vault_unlock audit row must be appended"
    );
}

// ---- 4. lock zeroizes; subsequent get/put refused; re-unlock recovers ------------------------

#[test]
fn lock_zeroizes_then_get_refused() {
    let eng = engine_with(Box::new(InMemStore::new()), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();
    eng.init_vault(pp("lock-pass"), None, None, at_floor_params(), &sink)
        .unwrap();
    eng.unlock(Unlock::Passphrase(pp("lock-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "claude".to_string(),
            provider: envctl_secrets::Provider::Anthropic,
            note: String::new(),
            broker_only: false,
        },
        Zeroizing::new(b"sk-locked".to_vec()),
        &sink,
    )
    .unwrap();
    let _ = drain(&rx);

    // lock
    eng.lock(&sink).expect("lock must succeed");
    let ev = drain(&rx);
    assert!(
        has_event(&ev, |e| matches!(e, SecretEvent::VaultLocked)),
        "VaultLocked must be emitted"
    );

    // get while locked => Err(Locked)
    let err = eng
        .secret_get("claude", true, true, &sink)
        .expect_err("get while locked must fail");
    assert!(matches!(
        err.downcast_ref::<EngineError>(),
        Some(EngineError::Locked)
    ));

    // put while locked => Err(Locked)
    let err = eng
        .secret_put(
            SecretMeta {
                name: "claude".to_string(),
                provider: envctl_secrets::Provider::Anthropic,
                note: String::new(),
                broker_only: false,
            },
            Zeroizing::new(b"x".to_vec()),
            &sink,
        )
        .expect_err("put while locked must fail");
    assert!(matches!(
        err.downcast_ref::<EngineError>(),
        Some(EngineError::Locked)
    ));

    // re-unlock => persisted ciphertext is intact; only the RAM key was wiped.
    eng.unlock(Unlock::Passphrase(pp("lock-pass")), &sink)
        .expect("re-unlock must succeed");
    let got = eng
        .secret_get("claude", true, true, &sink)
        .expect("get after re-unlock must succeed");
    assert_eq!(got.as_slice(), b"sk-locked");

    // lock is idempotent.
    eng.lock(&sink).unwrap();
    eng.lock(&sink).unwrap();
}

// ---- 5. reveal gate: broker_only + apply -----------------------------------------------------

#[test]
fn reveal_gate_broker_only_and_apply() {
    let eng = engine_with(Box::new(InMemStore::new()), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();
    eng.init_vault(pp("gate-pass"), None, None, at_floor_params(), &sink)
        .unwrap();
    eng.unlock(Unlock::Passphrase(pp("gate-pass")), &sink).unwrap();

    // broker_only secret
    eng.secret_put(
        SecretMeta {
            name: "bonly".to_string(),
            provider: envctl_secrets::Provider::Anthropic,
            note: String::new(),
            broker_only: true,
        },
        Zeroizing::new(b"never-reveal".to_vec()),
        &sink,
    )
    .unwrap();
    // normal secret
    eng.secret_put(
        SecretMeta {
            name: "normal".to_string(),
            provider: envctl_secrets::Provider::Anthropic,
            note: String::new(),
            broker_only: false,
        },
        Zeroizing::new(b"reveal-with-apply".to_vec()),
        &sink,
    )
    .unwrap();
    let _ = drain(&rx);

    // broker_only + reveal + apply => REFUSED (HF-5/OI-2)
    let err = eng
        .secret_get("bonly", true, true, &sink)
        .expect_err("broker-only reveal must be refused");
    assert!(err.to_string().contains("broker-only"));
    let ev = drain(&rx);
    assert!(
        has_event(&ev, |e| matches!(e, SecretEvent::GuardRefused { subject, .. } if subject == "bonly")),
        "GuardRefused must be emitted for the broker-only reveal"
    );
    assert!(
        ev.iter().any(|e| matches!(
            e,
            SecretEvent::Audit(r)
                if r.event_type == "secret_read"
                    && r.outcome == envctl_secrets::event::AuditOutcome::Refused
        )),
        "a Refused secret_read audit row must be appended"
    );

    // normal + reveal + !apply => REFUSED (apply gate)
    let err = eng
        .secret_get("normal", true, false, &sink)
        .expect_err("reveal without apply must be refused");
    assert!(err.to_string().contains("apply"));
    let ev = drain(&rx);
    assert!(
        has_event(&ev, |e| matches!(e, SecretEvent::GuardRefused { subject, .. } if subject == "normal")),
        "GuardRefused must be emitted for the apply gate"
    );

    // normal + reveal=false + apply=false => NOT refused on the apply gate (no reveal requested).
    let out = eng
        .secret_get("normal", false, false, &sink)
        .expect("a non-revealing read must not be refused by the apply gate");
    assert!(
        out.as_slice().is_empty(),
        "a non-revealing read returns no plaintext to the caller"
    );
    let ev = drain(&rx);
    assert!(
        !has_event(&ev, |e| matches!(e, SecretEvent::GuardRefused { .. })),
        "no GuardRefused for a non-revealing read"
    );
    assert!(
        has_event(&ev, |e| matches!(e, SecretEvent::SecretRead { name, .. } if name == "normal")),
        "a SecretRead is still emitted for the non-revealing read"
    );
}

// ---- 6. audit chain verifies + detects tamper ------------------------------------------------

#[test]
fn audit_chain_verifies_and_detects_tamper() {
    // We need the concrete InMemStore both for the engine AND for the test-only tamper hook, so
    // build it via SharedStore and keep an Arc to the concrete type.
    let inmem = std::sync::Arc::new(InMemStore::new());
    let eng = engine_with(Box::new(SharedStore(inmem.clone())), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();

    eng.init_vault(pp("chain-pass"), None, None, at_floor_params(), &sink)
        .unwrap();
    eng.unlock(Unlock::Passphrase(pp("chain-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "a".to_string(),
            provider: envctl_secrets::Provider::Generic,
            note: String::new(),
            broker_only: false,
        },
        Zeroizing::new(b"v1".to_vec()),
        &sink,
    )
    .unwrap();
    eng.secret_put(
        SecretMeta {
            name: "a".to_string(),
            provider: envctl_secrets::Provider::Generic,
            note: String::new(),
            broker_only: false,
        },
        Zeroizing::new(b"v2".to_vec()),
        &sink,
    )
    .unwrap();
    let _ = drain(&rx);

    // The chain verifies, and the rows are contiguous + linked.
    inmem.verify_audit_chain().expect("a clean chain must verify");
    let rows = inmem.audit_rows();
    assert!(rows.len() >= 4, "init + unlock + 2 puts => >= 4 audit rows");
    assert_eq!(
        rows[0].prev_hash,
        envctl_secrets::vault::audit::genesis_hash().to_vec(),
        "row 0 links to genesis"
    );
    for (i, r) in rows.iter().enumerate() {
        assert_eq!(r.seq, (i as i64) + 1, "seq must be 1..=n contiguous");
    }
    for w in rows.windows(2) {
        assert_eq!(w[1].prev_hash, w[0].row_hash, "prev_hash == prior row_hash");
    }

    // Tamper a MIDDLE row's subject without recomputing row_hash => the chain breaks at that seq.
    let target_seq = 2i64;
    inmem.tamper_audit_subject(target_seq);
    let err = inmem
        .verify_audit_chain()
        .expect_err("a tampered chain must not verify");
    assert!(
        matches!(
            err.downcast_ref::<EngineError>(),
            Some(EngineError::AuditChainBroken(seq)) if *seq == target_seq
        ),
        "expected AuditChainBroken({target_seq}), got {err:?}"
    );
}

// ---- 7. audit tail-truncation is detected by the DEK-keyed anchor ----------------------------

#[test]
fn audit_tail_truncation_is_detected() {
    let inmem = std::sync::Arc::new(InMemStore::new());
    let eng = engine_with(Box::new(SharedStore(inmem.clone())), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();

    eng.init_vault(pp("trunc-pass"), None, None, at_floor_params(), &sink)
        .unwrap();
    eng.unlock(Unlock::Passphrase(pp("trunc-pass")), &sink).unwrap();
    for _ in 0..3 {
        eng.secret_put(
            SecretMeta {
                name: "a".to_string(),
                provider: envctl_secrets::Provider::Generic,
                note: String::new(),
                broker_only: false,
            },
            Zeroizing::new(b"v".to_vec()),
            &sink,
        )
        .unwrap();
    }
    let _ = drain(&rx);

    // The unkeyed chain verifies AND the DEK-keyed anchor verifies while unlocked.
    inmem.verify_audit_chain().expect("clean chain verifies");
    eng.verify_audit_anchor(&sink)
        .expect("anchor verifies on a clean chain");

    // Drop the most recent rows (e.g. a refused reveal / failed unlock). The unkeyed chain STILL
    // verifies (it is just shorter), which is exactly the gap the anchor closes.
    let before = inmem.audit_rows().len();
    inmem.truncate_audit_tail(2);
    assert_eq!(inmem.audit_rows().len(), before - 2);
    inmem
        .verify_audit_chain()
        .expect("a truncated chain still passes the UNKEYED verifier (the gap)");

    // The DEK-keyed anchor catches the truncation: the anchored (seq, row_hash) is no longer
    // reproducible from any row in the shortened chain.
    let err = eng
        .verify_audit_anchor(&sink)
        .expect_err("the anchor must detect tail truncation");
    assert!(
        matches!(
            err.downcast_ref::<EngineError>(),
            Some(EngineError::AuditChainBroken(_))
        ),
        "expected AuditChainBroken, got {err:?}"
    );
}

// ---- 8. a tampered dek_generation meta is caught at unlock (not silently defaulted) ----------

#[test]
fn tampered_dek_generation_refuses_unlock() {
    let inmem = std::sync::Arc::new(InMemStore::new());
    let eng = engine_with(Box::new(SharedStore(inmem.clone())), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();

    eng.init_vault(pp("gen-pass"), None, None, at_floor_params(), &sink)
        .unwrap();
    let _ = drain(&rx);

    // Tamper the standalone dek_generation meta scalar (the value secret_put seals AAD against).
    // It is no longer read defensively with unwrap_or(1); a value that disagrees with the
    // header-MAC-authenticated slots' generation must refuse the unlock.
    inmem.tamper_meta("vault.dek_generation", "7");

    let err = eng
        .unlock(Unlock::Passphrase(pp("gen-pass")), &sink)
        .expect_err("a tampered dek_generation must refuse unlock");
    assert!(
        matches!(
            err.downcast_ref::<EngineError>(),
            Some(EngineError::HeaderMacMismatch)
        ),
        "expected HeaderMacMismatch, got {err:?}"
    );
    let ev = drain(&rx);
    assert!(
        !has_event(&ev, |e| matches!(e, SecretEvent::VaultUnlocked { .. })),
        "no VaultUnlocked on a generation-mismatch unlock"
    );
}

// ---- 9. re-unlock with a WRONG passphrase on a live vault is idempotent (state guard) --------

#[test]
fn reunlock_with_wrong_passphrase_leaves_vault_unlocked() {
    let eng = engine_with(Box::new(InMemStore::new()), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();
    eng.init_vault(pp("live-pass"), None, None, at_floor_params(), &sink)
        .unwrap();
    eng.unlock(Unlock::Passphrase(pp("live-pass")), &sink).unwrap();
    eng.secret_put(
        SecretMeta {
            name: "k".to_string(),
            provider: envctl_secrets::Provider::Generic,
            note: String::new(),
            broker_only: false,
        },
        Zeroizing::new(b"value".to_vec()),
        &sink,
    )
    .unwrap();
    let _ = drain(&rx);

    // Re-unlock the ALREADY-unlocked vault with a WRONG passphrase. The state guard short-circuits
    // before any KEK derivation, returning Unlocked idempotently — it must NOT fail (which would
    // mislead a caller into thinking the vault is now unusable) and must NOT grind Argon2.
    let st = eng
        .unlock(Unlock::Passphrase(pp("totally-wrong")), &sink)
        .expect("re-unlock of a live vault is idempotent, not an error");
    assert_eq!(st, VaultState::Unlocked);

    // The live DEK is intact: the secret still round-trips.
    let got = eng
        .secret_get("k", true, true, &sink)
        .expect("the vault is still unlocked after the idempotent re-unlock");
    assert_eq!(got.as_slice(), b"value");
}

// ---- 10. many secret_puts all round-trip (AAD/row_id binding holds; no dead records) ---------

#[test]
fn many_puts_all_round_trip() {
    let eng = engine_with(Box::new(InMemStore::new()), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();
    eng.init_vault(pp("multi-pass"), None, None, at_floor_params(), &sink)
        .unwrap();
    eng.unlock(Unlock::Passphrase(pp("multi-pass")), &sink).unwrap();

    // Distinct names interleaved so row_id and version advance independently — the store is the
    // sole row_id authority and the engine seals the AAD against exactly the reserved id, so every
    // stored row must open (no AAD/row_id divergence, no dead records).
    let names = ["alpha", "beta", "gamma", "delta"];
    for round in 0u8..5 {
        for n in names {
            let body = format!("{n}-secret-{round}");
            eng.secret_put(
                SecretMeta {
                    name: n.to_string(),
                    provider: envctl_secrets::Provider::Generic,
                    note: String::new(),
                    broker_only: false,
                },
                Zeroizing::new(body.into_bytes()),
                &sink,
            )
            .expect("each put must succeed");
        }
    }
    let _ = drain(&rx);

    // Latest of each name opens to its last round's value.
    for n in names {
        let got = eng
            .secret_get(n, true, true, &sink)
            .expect("latest version must open (AAD binding intact)");
        assert_eq!(got.as_slice(), format!("{n}-secret-4").as_bytes());
    }
}

// ---- 11. a HeaderMacMismatch leaves the vault Locked ------------------------------------------

#[test]
fn header_mac_mismatch_leaves_vault_locked() {
    let inmem = std::sync::Arc::new(InMemStore::new());
    let eng = engine_with(Box::new(SharedStore(inmem.clone())), Box::new(AbsentUsb));
    let (sink, rx) = envctl_secrets::EventSink::channel();
    eng.init_vault(pp("mac-pass"), None, None, at_floor_params(), &sink)
        .unwrap();
    let _ = drain(&rx);

    // Corrupt the stored header MAC so verify_header_mac fails after the DEK is recovered.
    inmem.tamper_meta("vault.header_mac", &"00".repeat(32));

    let err = eng
        .unlock(Unlock::Passphrase(pp("mac-pass")), &sink)
        .expect_err("a drifted header MAC must refuse unlock");
    assert!(matches!(
        err.downcast_ref::<EngineError>(),
        Some(EngineError::HeaderMacMismatch)
    ));

    // The vault must remain Locked: a subsequent get returns Locked, NOT a recovered secret.
    let err = eng
        .secret_get("anything", true, true, &sink)
        .expect_err("vault must stay locked after a header-MAC mismatch");
    assert!(matches!(
        err.downcast_ref::<EngineError>(),
        Some(EngineError::Locked)
    ));
}

// ---- shared-store adapter --------------------------------------------------------------------

/// A `Store` that forwards to a shared `Arc<InMemStore>`, so several `Engine`s in one test can
/// drive the SAME backing store (modeling a daemon restart / a second handle). Every method is a
/// thin delegate.
struct SharedStore(std::sync::Arc<InMemStore>);

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
    fn load_keyslot(
        &self,
        id: i64,
    ) -> anyhow::Result<Option<envctl_secrets::keyslot::Keyslot>> {
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
}
