//! Fail-closed safety guards (the envctl boot-repair discipline, declarative). `check_sec_guards`
//! returns `Some(reason)` to REFUSE and `None` only on an affirmative pass — every uncertain
//! branch refuses, so an all-uncertain context refuses every guard (Phase-0 acceptance test #1).
use std::time::SystemTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destructiveness {
    Additive,
    Destructive,
    RootOfTrust,
}

#[derive(Clone, Debug)]
pub enum SecGuard {
    /// PARTUUID pre-filter + keyfile-possession proof (CF-4).
    UsbPresent { partition_uuid: String },
    /// enabled && !revoked(policy & bearer) && expiry>now && usb-gated.
    RelayValid { relay_id: String },
    /// an active USB-gated relay's allowlist covers the host (per SAN).
    LeafBackedByRelay { host: String },
    PeerIsOwner,
    VaultEncryptedAtRest,
    /// `apply == false` => REFUSE (dry-run default, CF-8). Root-of-trust also needs `confirm`.
    DryRunUnlessApply {
        apply: bool,
        confirm: bool,
        destructive: Destructiveness,
    },
}

#[derive(Clone, Debug)]
pub struct UnlockContext {
    /// PROVEN possession (keyfile unwrapped), not a mere UUID match (CF-4).
    pub usb_keyfile_possessed: bool,
    pub usb_partition_uuid: Option<String>,
    pub usb_absent_since: Option<SystemTime>,
    pub peer_uid: Option<u32>,
    pub owner_uid: u32,
    pub now: SystemTime,
}

impl UnlockContext {
    /// An all-uncertain context: nothing is proven, so every guard must refuse.
    pub fn uncertain(owner_uid: u32, now: SystemTime) -> Self {
        Self {
            usb_keyfile_possessed: false,
            usb_partition_uuid: None,
            usb_absent_since: None,
            peer_uid: None,
            owner_uid,
            now,
        }
    }
}

/// `Some(reason)` => REFUSE; `None` only on an affirmative pass. FAIL-CLOSED: each variant refuses
/// unless the context positively proves the precondition. The Phase-1 engine threads live
/// vault/broker state into the `RelayValid`/`LeafBackedByRelay`/`VaultEncryptedAtRest` checks;
/// in Phase 0 those are unproven and therefore refuse (the safe default).
pub fn check_sec_guards(guards: &[SecGuard], ctx: &UnlockContext) -> Option<String> {
    for g in guards {
        let refusal: Option<String> = match g {
            SecGuard::UsbPresent { .. } => {
                if ctx.usb_keyfile_possessed {
                    None
                } else {
                    Some("USB keyfile possession not proven".to_string())
                }
            }
            SecGuard::RelayValid { relay_id } => {
                Some(format!("relay '{relay_id}' validity not proven"))
            }
            SecGuard::LeafBackedByRelay { host } => {
                Some(format!("no active USB-gated relay covers host '{host}'"))
            }
            SecGuard::PeerIsOwner => match ctx.peer_uid {
                Some(uid) if uid == ctx.owner_uid => None,
                _ => Some("peer is not the owner uid".to_string()),
            },
            SecGuard::VaultEncryptedAtRest => {
                Some("vault encryption-at-rest not verified".to_string())
            }
            SecGuard::DryRunUnlessApply {
                apply,
                confirm,
                destructive,
            } => {
                if !*apply {
                    Some("dry-run: --apply required to mutate".to_string())
                } else if matches!(destructive, Destructiveness::RootOfTrust) && !*confirm {
                    Some("root-of-trust op: --confirm required".to_string())
                } else {
                    None
                }
            }
        };
        if let Some(reason) = refusal {
            return Some(reason);
        }
    }
    None
}
