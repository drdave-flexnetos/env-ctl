//! Phase-0 acceptance tests: the scaffold compiles AND the two safety primitives behave.
use envctl_secrets::broker::{clamp_ttl, RelayPolicy, SwapMode, MAX_BEARER_TTL_SECS};
use envctl_secrets::guard::{check_sec_guards, Destructiveness, SecGuard, UnlockContext};
use envctl_secrets::keyslot::{Argon2Params, Kdf};
use envctl_secrets::{EventSink, SecretEvent};
use std::time::SystemTime;

#[test]
fn all_uncertain_context_refuses_every_guard() {
    let ctx = UnlockContext::uncertain(1000, SystemTime::UNIX_EPOCH);
    let guards = [
        SecGuard::UsbPresent { partition_uuid: "x".into() },
        SecGuard::RelayValid { relay_id: "claude-main".into() },
        SecGuard::LeafBackedByRelay { host: "api.anthropic.com".into() },
        SecGuard::PeerIsOwner,
        SecGuard::VaultEncryptedAtRest,
    ];
    for g in guards {
        assert!(
            check_sec_guards(std::slice::from_ref(&g), &ctx).is_some(),
            "fail-closed: an all-uncertain context must refuse {g:?}"
        );
    }
}

#[test]
fn dry_run_unless_apply_refuses_without_apply_and_confirm() {
    let ctx = UnlockContext::uncertain(1000, SystemTime::UNIX_EPOCH);
    // apply=false => dry-run => refuse (CF-8).
    let dry = SecGuard::DryRunUnlessApply {
        apply: false,
        confirm: false,
        destructive: Destructiveness::Destructive,
    };
    assert!(check_sec_guards(&[dry], &ctx).is_some());
    // apply=true but a root-of-trust op without confirm => refuse.
    let no_confirm = SecGuard::DryRunUnlessApply {
        apply: true,
        confirm: false,
        destructive: Destructiveness::RootOfTrust,
    };
    assert!(check_sec_guards(&[no_confirm], &ctx).is_some());
    // apply=true + confirm on a root-of-trust op => pass.
    let ok = SecGuard::DryRunUnlessApply {
        apply: true,
        confirm: true,
        destructive: Destructiveness::RootOfTrust,
    };
    assert!(check_sec_guards(&[ok], &ctx).is_none());
}

#[test]
fn clamp_ttl_never_exceeds_24h_and_refuses_nonpositive() {
    let now = 1_000_000i64;
    // request 1 year, policy 1 year => clamped to the 24h ceiling.
    let exp = clamp_ttl(now, 365 * 24 * 3600, 365 * 24 * 3600).expect("positive ttl");
    assert_eq!(exp - now, MAX_BEARER_TTL_SECS);
    assert!(exp - now <= 86_400);
    // policy shorter than the ceiling wins.
    let exp2 = clamp_ttl(now, 3600, 99_999).expect("positive ttl");
    assert_eq!(exp2 - now, 3600);
    // dead/negative TTL is refused (FS-S3).
    assert!(clamp_ttl(now, 0, 100).is_none());
    assert!(clamp_ttl(now, 100, -5).is_none());
}

#[test]
fn relay_policy_deserializes_from_toml() {
    let toml_src = r#"
        relay_id = "claude-main"
        kind = "named"
        provider = "anthropic"
        secret_name = "claude"
        host_allow = ["api.anthropic.com"]
        path_allow = ["/v1/"]
        method_allow = ["post"]
        policy_ttl_secs = 31536000
        enabled = true
        revoked = false

        [swap]
        mode = "base_url_repoint"
        upstream_base = "https://api.anthropic.com"
    "#;
    let p: RelayPolicy = toml::from_str(toml_src).expect("RelayPolicy must deserialize");
    assert_eq!(p.relay_id, "claude-main");
    assert!(matches!(p.swap, SwapMode::BaseUrlRepoint { .. }));
    // rate_per_min / quota_total are absent => None (serde Option default).
    assert!(p.rate_per_min.is_none());
}

#[test]
fn swap_mode_and_kdf_json_round_trip() {
    let modes = [
        SwapMode::BaseUrlRepoint { upstream_base: "https://api.anthropic.com".into() },
        SwapMode::ProxyMitm,
        SwapMode::NativeSubToken { ttl_secs: 3600 },
    ];
    for m in modes {
        let s = serde_json::to_string(&m).unwrap();
        let back: SwapMode = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }
    let kdfs = [Kdf::Argon2id(Argon2Params::default()), Kdf::HkdfSha256];
    for k in kdfs {
        let s = serde_json::to_string(&k).unwrap();
        let back: Kdf = serde_json::from_str(&s).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn event_sink_emits_and_drains() {
    let (sink, rx) = EventSink::channel();
    sink.emit(SecretEvent::VaultLocked);
    sink.emit(SecretEvent::ChildExited { code: 0 });
    let got: Vec<SecretEvent> = rx.try_iter().collect();
    assert_eq!(got.len(), 2);
    // a null sink never panics and drops events.
    EventSink::null().emit(SecretEvent::VaultLocked);
}
