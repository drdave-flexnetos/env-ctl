//! env-ctl secrets engine: the single shared library. No printing, no UI, no clap.
//!
//! Both the daemon (`secretd`) and any future GUI drive the vault + credential broker through
//! the *identical* `Engine` API below; the CLI (`secretctl`) talks to the daemon over gRPC.
//! Mirrors `envctl_engine`: the engine never prints — it emits a structured `SecretEvent`
//! stream over an `std::sync::mpsc` channel. The engine core is synchronous; only the egress
//! swap path (`Engine::relay_swap` + the `Upstream` seam) is async.
//!
//! Phase 1b makes the vault functional: `init_vault` mints the DEK + enrolls keyslots,
//! `unlock`/`lock` drive the locked/unlocked state machine (the DEK is zeroized on `lock`), and
//! `secret_put`/`secret_get` seal/open per-record ciphertext through the `Store`. Every security
//! op appends a DURABLE, hash-chained audit row BEFORE returning (HF-14) and emits a `SecretEvent`.
//! A refused op is `Ok`-with-a-`GuardRefused`-event + a `Refused` audit row — NOT an `Err`
//! (error.rs discipline). The relay/CA/run paths remain `todo!()` (Phase 4+).
#![allow(dead_code)] // Some scaffold fields/bodies are placeholders until later phases.

pub mod event; // SecretEvent, EventSink (std mpsc), Stream, AuditRecord
pub mod error; // EngineError (thiserror, setup-time only), VaultState
pub mod seam; // Clock, UsbProbe, ProviderMint, Upstream + SystemClock/RealUsbProbe + fakes
pub mod guard; // SecGuard, check_sec_guards, UnlockContext (fail-closed)
pub mod paths; // Paths (XDG, env-ctl-namespaced)
pub mod keyslot; // Keyslot, Kdf, Argon2Params, wrap/unwrap (LUKS-style dual KEK) + header MAC
pub mod vault; // Vault state machine + Store trait + crypto (seal/open) + canonical AAD + audit
pub mod broker; // Broker, RelayPolicy, Bearer, decide(), token verify, clamp_ttl, SwapOutcome
pub mod ca; // LocalCa (feature mitm-ca)
pub mod inject; // ChildEnvPlan, ResolvedInjection, injection_template, run_wrapped

pub use broker::{
    clamp_ttl, Bearer, DenyReason, Method, Provider, RelayDecision, RelayId, RelayKind,
    RelayPolicy, SwapMode, SwapOutcome, MAX_BEARER_TTL_SECS,
};
pub use error::{EngineError, VaultState};
pub use event::{AuditRecord, EventSink, SecretEvent, Stream};
pub use guard::{check_sec_guards, Destructiveness, SecGuard, UnlockContext};
pub use keyslot::{Argon2Params, Factor, Kdf, Keyslot};
pub use seam::{Clock, ProviderMint, RealUsbProbe, SystemClock, Upstream, UsbProbe};

use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

use event::AuditOutcome;
use keyslot::{
    kek_from_passphrase, kek_from_usb, keyslot_aad, verify_header_mac, wrap_dek, Dek,
    ARGON2_M_KIB_FLOOR, ARGON2_T_COST_FLOOR,
};
use vault::aad::{record_aad, TableTag};
use vault::store::{BearerRow, RelayPolicyRow, SecretRow};

use broker::{
    bearer_row_mac_message, broker_hmac_key, broker_row_mac_key, canonical_upstreams, decide,
    mac_bearer, mac_bearer_row, parse_bearer, verify_bearer, verify_bearer_row, CanonRequest,
    VerifiedBearer,
};

// Meta keys for the vault header (non-secret; persisted plaintext through the Store).
const META_HEADER_MAC: &str = "vault.header_mac";
const META_ISSUANCE_FLOOR_MS: &str = "vault.issuance_floor_ms";
const META_DEK_GENERATION: &str = "vault.dek_generation";
/// DEK-keyed anchor over the audit chain TAIL (`max_seq` + tail `row_hash`), rewritten on every
/// successful audit append while the vault is unlocked. The chain itself is unkeyed (its hashes are
/// public), so a store-level attacker could drop trailing rows and re-link a perfectly clean
/// shorter chain that `verify_chain` accepts. This anchor binds the EXPECTED tail to the DEK, so a
/// truncated/rewritten chain is caught by `verify_audit_anchor` (only an unlocked vault can advance
/// it). Domain-separated; see `audit_head_mac`.
const META_AUDIT_HEAD: &str = "vault.audit_head";

/// BLAKE3 `derive_key` context for the audit-head anchor key (DEK-keyed, domain-separated from the
/// header MAC and every other BLAKE3 use in the crate).
const AUDIT_HEAD_KEY_INFO: &str = "env-ctl/v1/audit-head/key";
/// Domain-separation prefix for the audit-head anchor message.
const AUDIT_HEAD_DOMAIN: &[u8] = b"env-ctl/v1/audit-head";

/// Top-level engine handle: owns the vault, the broker, and an optional local CA, plus the
/// `Send + Sync` seams. Cheaply cloneable (`Arc` inside) so it can move into worker tasks.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    paths: paths::Paths,
    vault: RwLock<vault::Vault>, // Locked | Unlocked { dek: Dek }
    broker: RwLock<broker::Broker>,
    ca: RwLock<Option<ca::LocalCa>>,
    store: Box<dyn vault::Store>, // persistence seam; default InMemStore (libSQL slots in later)
    // dyn-dispatched seams; the supertrait `: Send + Sync` keeps Engine Send+Sync.
    clock: Box<dyn Clock>,
    usb: Box<dyn UsbProbe>,
    provider: Box<dyn ProviderMint>,
    upstream: Box<dyn Upstream>, // pins frozen webpki roots in the daemon impl (FS-S7)
    owner_uid: u32,
}

/// Which unlock factor the operator is presenting.
pub enum Unlock {
    Usb,
    Passphrase(Zeroizing<String>),
}

pub struct SecretMeta {
    pub name: String,
    pub provider: Provider,
    pub note: String,
    pub broker_only: bool,
}

/// A canonicalized egress request as seen by the broker (host is the *verified* inner Host).
pub struct EgressReq {
    pub method: Method,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub bytes_out: u64,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<u32>,
}

pub struct EgressResp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub allowed: bool,
}

impl Engine {
    /// Open an engine backed by the real seams (`SystemClock`, `RealUsbProbe`, ...) and the
    /// default RAM-backed `InMemStore`. The libSQL-backed store lands later behind the identical
    /// `Store` trait, so this constructor's shape does not change when it does.
    pub fn open(paths: paths::Paths) -> anyhow::Result<Engine> {
        Self::with_seams(
            paths,
            Box::new(vault::InMemStore::new()),
            Box::new(SystemClock),
            Box::new(RealUsbProbe),
            Box::new(seam::NoMint),
            Box::new(NullUpstream),
        )
    }

    /// Construct an engine with injected seams + store (the `envctl with_runner` analogue, for
    /// tests). `store` is the `DryRunRunner` analogue: pass `InMemStore` for an in-RAM vault.
    pub fn with_seams(
        paths: paths::Paths,
        store: Box<dyn vault::Store>,
        clock: Box<dyn Clock>,
        usb: Box<dyn UsbProbe>,
        provider: Box<dyn ProviderMint>,
        upstream: Box<dyn Upstream>,
    ) -> anyhow::Result<Engine> {
        let owner_uid = current_uid();
        Ok(Engine {
            inner: Arc::new(EngineInner {
                paths,
                vault: RwLock::new(vault::Vault::Locked),
                broker: RwLock::new(broker::Broker::default()),
                ca: RwLock::new(None),
                store,
                clock,
                usb,
                provider,
                upstream,
                owner_uid,
            }),
        })
    }

    /// Initialize a fresh vault: mint a random DEK (OsRng), derive the passphrase KEK
    /// (`kek_from_passphrase`, Argon2id) and — when `usb_keyfile` is `Some` — the USB KEK
    /// (`kek_from_usb`, HKDF), wrap the DEK into one `Keyslot` per factor (`wrap_dek`, AAD =
    /// `keyslot_aad`), persist each slot (`store.save_keyslot`), compute the vault header MAC over
    /// the slot set (`header_mac`, keyed by the DEK) and persist it + the issuance floor under meta
    /// keys (`"vault.header_mac"` hex, `"vault.issuance_floor_ms"`, `"vault.dek_generation" = 1`).
    /// Appends a durable `vault_init` audit row; emits no DEK. Refuses (`Err`) if a vault already
    /// exists (meta `"vault.header_mac"` present) or if `params` are below the Argon2 floors.
    /// Returns to `Locked` state.
    pub fn init_vault(
        &self,
        passphrase: Zeroizing<String>,
        usb_partition_uuid: Option<String>,
        usb_keyfile: Option<Zeroizing<Vec<u8>>>,
        params: keyslot::Argon2Params,
        sink: &EventSink,
    ) -> anyhow::Result<()> {
        let inner = &self.inner;

        // Refuse to clobber an existing vault.
        if inner.store.get_meta(META_HEADER_MAC)?.is_some() {
            anyhow::bail!("vault already initialized (refusing to overwrite)");
        }
        // Validate Argon2 params at-or-above the downgrade floors BEFORE deriving (FS-S13). This is
        // a setup-time refusal (Err), not a runtime guard-refusal.
        if params.m_kib < ARGON2_M_KIB_FLOOR {
            anyhow::bail!(
                "argon2 m_kib {} is below the {} KiB floor",
                params.m_kib,
                ARGON2_M_KIB_FLOOR
            );
        }
        if params.t_cost < ARGON2_T_COST_FLOOR {
            anyhow::bail!(
                "argon2 t_cost {} is below the {} iteration floor",
                params.t_cost,
                ARGON2_T_COST_FLOOR
            );
        }

        let dek_generation: i64 = 1;
        let issuance_floor_ms: i64 = inner.clock.now().timestamp_millis();

        // Mint a fresh random DEK from the OS CSPRNG.
        let dek = mint_dek();

        // Enroll the passphrase keyslot (id = 1). The salt is a fresh 16-byte CSPRNG value.
        let mut slots: Vec<Keyslot> = Vec::new();
        let pp_bytes = Zeroizing::new(passphrase.as_bytes().to_vec());
        let pp_salt = random_bytes(16);
        let mut pp_slot = Keyslot {
            id: 1,
            factor: Factor::Passphrase,
            label: "passphrase".to_string(),
            kdf: Kdf::Argon2id(params),
            salt: pp_salt.clone(),
            usb_partition_uuid: None,
            wrap_nonce: Vec::new(),
            wrapped_dek: Vec::new(),
            dek_generation,
            enabled: true,
        };
        let pp_aad = keyslot_aad(&pp_slot);
        let pp_kek = kek_from_passphrase(&pp_bytes, &pp_slot.salt, params);
        let (pp_nonce, pp_wrapped) = wrap_dek(pp_kek, &dek, &pp_aad);
        pp_slot.wrap_nonce = pp_nonce;
        pp_slot.wrapped_dek = pp_wrapped;
        slots.push(pp_slot);

        // Optional USB keyslot (id = 2). Requires both a UUID (slot identity, OI-5) and the keyfile
        // bytes (the IKM). The keyfile is HKDF IKM only — it is never persisted.
        if let Some(keyfile) = usb_keyfile.as_ref() {
            let uuid = usb_partition_uuid.clone().ok_or_else(|| {
                anyhow::anyhow!("usb keyfile provided without a usb_partition_uuid")
            })?;
            let usb_salt = random_bytes(32);
            let mut usb_slot = Keyslot {
                id: 2,
                factor: Factor::Usb,
                label: "usb".to_string(),
                kdf: Kdf::HkdfSha256,
                salt: usb_salt,
                usb_partition_uuid: Some(uuid),
                wrap_nonce: Vec::new(),
                wrapped_dek: Vec::new(),
                dek_generation,
                enabled: true,
            };
            let usb_aad = keyslot_aad(&usb_slot);
            let usb_kek = kek_from_usb(keyfile, &usb_slot.salt);
            let (usb_nonce, usb_wrapped) = wrap_dek(usb_kek, &dek, &usb_aad);
            usb_slot.wrap_nonce = usb_nonce;
            usb_slot.wrapped_dek = usb_wrapped;
            slots.push(usb_slot);
        }

        // Persist each slot, then the header MAC over the canonical slot set + issuance floor.
        for slot in &slots {
            inner.store.save_keyslot(slot)?;
        }
        let mac = keyslot::header_mac(&dek, &slots, issuance_floor_ms);
        inner.store.put_meta(META_HEADER_MAC, &hex_encode(&mac))?;
        inner
            .store
            .put_meta(META_ISSUANCE_FLOOR_MS, &issuance_floor_ms.to_string())?;
        inner
            .store
            .put_meta(META_DEK_GENERATION, &dek_generation.to_string())?;

        // Durable audit BEFORE returning (HF-14). vault_init carries the slot count, not any key.
        self.audit_ok(
            sink,
            "vault_init",
            None,
            serde_json::json!({ "slots": slots.len(), "dek_generation": dek_generation }),
        )?;
        // Anchor the genesis (`vault_init`) row with the local DEK while it is still alive (the
        // vault is Locked, so the in-`audit` anchor advance was a no-op). This DEK-keys the chain
        // tail from the very first row.
        let (seq, tail_hash) = match inner.store.last_audit()? {
            Some(r) => (r.seq, r.row_hash),
            None => (0i64, Vec::new()),
        };
        inner
            .store
            .put_meta(META_AUDIT_HEAD, &hex_encode(&audit_head_mac(&dek, seq, &tail_hash)))?;

        // The DEK never leaves this function; it is dropped (zeroized) here. The vault stays Locked
        // until an explicit `unlock`.
        drop(dek);
        Ok(())
    }

    pub fn unlock(&self, u: Unlock, sink: &EventSink) -> anyhow::Result<VaultState> {
        let inner = &self.inner;
        // State guard: unlocking an already-unlocked vault is idempotent. We short-circuit BEFORE
        // any KEK derivation/probe so a wrong factor presented to a live vault can never (a) be
        // observed as an error while the vault silently stays unlocked, nor (b) grind a fresh
        // Argon2 derivation against a live DEK. The on-the-wire failure for a locked vault stays
        // the single generic UnlockFailed (no oracle).
        if inner.vault.read().expect("vault lock").is_unlocked() {
            return Ok(VaultState::Unlocked);
        }
        let slots = inner.store.load_keyslots()?;
        let stored_mac = self.load_header_mac()?;
        let issuance_floor_ms = self.load_issuance_floor()?;

        // Per-factor probe: try to unwrap the DEK from each enabled slot of the requested factor.
        // On the FIRST success, verify the header MAC over ALL slots, then commit Unlocked.
        let (want_factor, recovered): (Factor, Option<Dek>) = match &u {
            Unlock::Passphrase(pp) => {
                let pp_bytes = Zeroizing::new(pp.as_bytes().to_vec());
                let mut dek = None;
                for slot in slots.iter().filter(|s| {
                    s.enabled && s.factor == Factor::Passphrase
                }) {
                    // Validate the slot's KDF params against the floors AND the argon2 structural
                    // invariants BEFORE deriving. `kek_from_passphrase` calls `Params::new(..)
                    // .expect(..)`, which PANICS for `p_lanes == 0` (ThreadsTooFew) or `m_kib <
                    // 8 * p_lanes` (MemoryTooLittle). A corrupt/hostile keyslot header must surface
                    // as a clean skip -> generic UnlockFailed, never a panic, so we reject those
                    // here. (The flipped p_lanes is also bound into the slot AAD and would fail the
                    // tag, but the panic would happen before the tag check — so the filter must
                    // reject it first.)
                    let params = match slot.kdf {
                        Kdf::Argon2id(p)
                            if p.m_kib >= ARGON2_M_KIB_FLOOR
                                && p.t_cost >= ARGON2_T_COST_FLOOR
                                && p.p_lanes >= 1
                                && p.m_kib >= p.p_lanes.saturating_mul(8) =>
                        {
                            p
                        }
                        _ => continue, // wrong KDF, sub-floor, or structurally invalid: skip.
                    };
                    let kek = kek_from_passphrase(&pp_bytes, &slot.salt, params);
                    let aad = keyslot_aad(slot);
                    if let Some(d) = keyslot::unwrap_dek(kek, &slot.wrap_nonce, &slot.wrapped_dek, &aad)
                    {
                        dek = Some(d);
                        break;
                    }
                }
                (Factor::Passphrase, dek)
            }
            Unlock::Usb => {
                let mut dek = None;
                for slot in slots.iter().filter(|s| s.enabled && s.factor == Factor::Usb) {
                    // UUID match is NOT possession (CF-4): we must actually obtain the keyfile.
                    let Some(uuid) = slot.usb_partition_uuid.as_deref() else {
                        continue;
                    };
                    let Some(keyfile) = inner.usb.keyfile_for(uuid) else {
                        continue; // keyfile absent => possession unproven => skip.
                    };
                    let kek = kek_from_usb(&keyfile, &slot.salt);
                    let aad = keyslot_aad(slot);
                    if let Some(d) = keyslot::unwrap_dek(kek, &slot.wrap_nonce, &slot.wrapped_dek, &aad)
                    {
                        dek = Some(d);
                        break;
                    }
                }
                (Factor::Usb, dek)
            }
        };

        let dek = match recovered {
            Some(d) => d,
            None => {
                // Single generic message (OI-17); never reveals which slot failed.
                self.audit_failed(sink, "vault_unlock", None, serde_json::json!({}))?;
                return Err(EngineError::UnlockFailed.into());
            }
        };

        // Header MAC: recompute over ALL slots and compare (FS-S13). A mismatch means the keyslot
        // set was tampered; zeroize the dek and refuse.
        if !verify_header_mac(&dek, &slots, issuance_floor_ms, &stored_mac) {
            drop(dek); // ZeroizeOnDrop wipes it.
            self.audit_failed(sink, "vault_unlock", None, serde_json::json!({ "reason": "header_mac" }))?;
            return Err(EngineError::HeaderMacMismatch.into());
        }

        // dek_generation binding: the standalone `META_DEK_GENERATION` scalar is load-bearing for
        // the record AAD (`secret_put` seals against it) but is NOT covered by the header MAC
        // directly. Each keyslot's `dek_generation` IS bound by the MAC (via `keyslot_aad`), so now
        // that the slot set is authenticated we cross-check the meta scalar against the trusted
        // slots. A tampered/cleared meta generation is caught here as HeaderMacMismatch instead of
        // silently mis-binding new records after a future DEK rotation.
        let stored_generation = self.load_dek_generation()?;
        let slot_generation = slots.iter().map(|s| s.dek_generation).max().unwrap_or(1);
        if stored_generation != slot_generation {
            drop(dek);
            self.audit_failed(
                sink,
                "vault_unlock",
                None,
                serde_json::json!({ "reason": "dek_generation" }),
            )?;
            return Err(EngineError::HeaderMacMismatch.into());
        }

        // Audit-chain integrity: verify the unkeyed chain AND the DEK-keyed tail anchor against the
        // live chain (truncation/rewrite detection), using the just-recovered DEK before it is
        // committed into the vault. A broken/truncated chain refuses the unlock.
        if let Err(e) = self.verify_audit_anchor_with(&dek) {
            drop(dek);
            self.audit_failed(
                sink,
                "vault_unlock",
                None,
                serde_json::json!({ "reason": "audit_chain" }),
            )?;
            return Err(e);
        }

        // HF-14 (transactional ordering): append the durable `vault_unlocked` audit row BEFORE
        // committing `Unlocked` into RAM, so a failed audit append can never leave the vault
        // unlocked while `unlock` returns `Err`. If the audit fails the dek is dropped (zeroized)
        // and the vault stays Locked.
        self.audit_ok(
            sink,
            "vault_unlocked",
            None,
            serde_json::json!({ "factor": factor_str(want_factor) }),
        )?;
        {
            let mut v = inner.vault.write().expect("vault lock");
            *v = vault::Vault::Unlocked { dek };
        }
        // Now that the DEK is resident, advance the anchor to cover the just-appended
        // `vault_unlocked` row (it was appended while still Locked, so the in-`audit` advance was a
        // no-op). This leaves the freshly-unlocked vault with a current tail anchor.
        self.advance_audit_anchor_if_unlocked()?;
        sink.emit(SecretEvent::VaultUnlocked { factor: want_factor });
        Ok(VaultState::Unlocked)
    }

    /// Zeroizes the DEK + CA issuer in RAM (the true panic stop). Idempotent when already Locked.
    pub fn lock(&self, sink: &EventSink) -> anyhow::Result<()> {
        {
            let mut v = self.inner.vault.write().expect("vault lock");
            // Replacing Unlocked{dek} with Locked drops the old Dek => ZeroizeOnDrop wipes it.
            *v = vault::Vault::Locked;
        }
        {
            let mut ca = self.inner.ca.write().expect("ca lock");
            *ca = None; // drop the in-RAM CA issuer.
        }
        self.audit_ok(sink, "vault_locked", None, serde_json::json!({}))?;
        sink.emit(SecretEvent::VaultLocked);
        Ok(())
    }

    pub fn secret_put(
        &self,
        m: SecretMeta,
        body: Zeroizing<Vec<u8>>,
        sink: &EventSink,
    ) -> anyhow::Result<()> {
        let inner = &self.inner;
        // Requires Unlocked. We hold the WRITE lock for the whole reserve->seal->put so two
        // concurrent puts cannot interleave: this serializes the `version = max+1` read and the
        // store-side `row_id` reservation against the insert, closing the AAD/row_id divergence (a
        // racing pair could otherwise seal against the same id while the store stored distinct ids,
        // permanently de-authenticating the loser's ciphertext). The write lock also guarantees the
        // DEK can't be zeroized out from under us mid-op.
        let v = inner.vault.write().expect("vault lock");
        let dek = match v.dek() {
            Some(d) => d,
            None => return Err(EngineError::Locked.into()),
        };

        // dek_generation is load-bearing for the AAD binding (a wrong generation de-authenticates
        // the record). It is bound into the header MAC and verified at unlock, so a missing/garbled
        // value here is a setup-time failure, NOT a silent default.
        let dek_generation = self.load_dek_generation()?;
        let version = inner.store.max_secret_version(&m.name)? + 1;
        // The store is the sole authority for row_ids: reserve the id under the store's own lock,
        // seal the AAD against EXACTLY that id, then insert a row carrying it. `put_secret` persists
        // the id verbatim and rejects any id it never reserved, so the stored row_id can never
        // diverge from the id the ciphertext was sealed under (HF-2).
        let row_id = inner.store.reserve_secret_row_id()?;
        let aad = record_aad(
            TableTag::SecretVersion,
            row_id,
            version as i64,
            dek_generation,
        );
        let (nonce, ct_tag) = vault::crypto::seal(dek, &aad, &body);
        let created_ts = inner.clock.now().to_rfc3339();

        let row = SecretRow {
            row_id,
            name: m.name.clone(),
            version,
            provider: m.provider,
            note: m.note,
            broker_only: m.broker_only,
            dek_generation,
            nonce,
            ct_tag,
            created_ts,
        };
        let assigned = inner.store.put_secret(row)?;
        // Hard runtime check (NOT a debug_assert, which compiles out in release): a divergent id
        // must never be allowed to persist an un-openable record.
        if assigned != row_id {
            anyhow::bail!(
                "store assigned row_id {assigned} but the ciphertext was sealed against {row_id}"
            );
        }

        // The dek borrow + body drop happen at end of scope; release the write lock before audit so
        // we never hold a lock across a store write that itself takes a lock.
        drop(v);

        self.audit_ok(
            sink,
            "secret_written",
            Some(m.name.clone()),
            serde_json::json!({ "version": version }),
        )?;
        sink.emit(SecretEvent::SecretWritten {
            name: m.name,
            version,
        });
        Ok(())
    }

    /// `reveal` is apply-gated + audited + refused for `broker_only` secrets (HF-5/OI-2).
    pub fn secret_get(
        &self,
        name: &str,
        reveal: bool,
        apply: bool,
        sink: &EventSink,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let inner = &self.inner;
        let v = inner.vault.read().expect("vault lock");
        let dek = match v.dek() {
            Some(d) => d,
            None => return Err(EngineError::Locked.into()),
        };

        let row = match inner.store.get_secret_latest(name)? {
            Some(r) => r,
            None => {
                drop(v);
                self.audit_failed(
                    sink,
                    "secret_read",
                    Some(name.to_string()),
                    serde_json::json!({ "reason": "not_found" }),
                )?;
                anyhow::bail!("unknown secret '{name}'");
            }
        };

        // Reconstruct the SAME canonical AAD from the row's identity (HF-2) and open.
        let aad = record_aad(
            TableTag::SecretVersion,
            row.row_id,
            row.version as i64,
            row.dek_generation,
        );
        let plaintext = match vault::crypto::open(dek, &aad, &row.nonce, &row.ct_tag) {
            Some(pt) => pt,
            None => {
                // Tamper / corruption: the AEAD tag is the sole correctness oracle.
                drop(v);
                self.audit_failed(
                    sink,
                    "secret_read",
                    Some(name.to_string()),
                    serde_json::json!({ "reason": "tamper", "version": row.version }),
                )?;
                anyhow::bail!("secret '{name}' failed authentication (tampered or corrupt)");
            }
        };
        drop(v); // release the vault read lock; `plaintext` is now owned (Zeroizing).

        // REVEAL GATE (HF-5/OI-2): a broker-only secret never reveals; a reveal is apply-gated.
        if reveal {
            if row.broker_only {
                self.refuse(
                    sink,
                    "secret_read",
                    name,
                    "reveal refused: secret is broker-only",
                )?;
                anyhow::bail!("reveal refused: '{name}' is broker-only");
            }
            if !apply {
                self.refuse(
                    sink,
                    "secret_read",
                    name,
                    "reveal refused: apply not set (dry-run)",
                )?;
                anyhow::bail!("reveal refused: '{name}' requires --apply");
            }
            // Allowed reveal: audit + emit, then return the plaintext verbatim.
            let by_uid = inner.owner_uid;
            self.audit_ok(
                sink,
                "secret_read",
                Some(name.to_string()),
                serde_json::json!({ "version": row.version, "revealed": true }),
            )?;
            sink.emit(SecretEvent::SecretRead {
                name: name.to_string(),
                by_uid,
            });
            return Ok(plaintext);
        }

        // reveal = false: the plaintext is consumed internally (e.g. for injection) and NOT
        // returned to the caller verbatim. We audit the (non-revealing) read and return an empty
        // buffer; the apply gate does NOT apply when no reveal was requested.
        self.audit_ok(
            sink,
            "secret_read",
            Some(name.to_string()),
            serde_json::json!({ "version": row.version, "revealed": false }),
        )?;
        sink.emit(SecretEvent::SecretRead {
            name: name.to_string(),
            by_uid: inner.owner_uid,
        });
        // Drop the plaintext (Zeroizing wipes it) and hand back an empty buffer.
        drop(plaintext);
        Ok(Zeroizing::new(Vec::new()))
    }

    /// USB-possession-gated, `<=24h`, peer-bound.
    ///
    /// Mints a fresh wire bearer (`evrelay_{token_id}_{secret}`) against `spec`, persisting ONLY its
    /// keyed MAC (`BearerRow.mac`); the raw bearer is returned to the caller and NEVER stored,
    /// audited, or emitted. USB possession is proven before any key material is touched (HF-14: the
    /// refusal writes its durable `Refused` row + `GuardRefused` event BEFORE returning). The TTL is
    /// clamped to `<=24h` through the single `clamp_ttl` choke point.
    pub fn relay_mint(
        &self,
        spec: RelayPolicy,
        requested_ttl_secs: i64,
        peer_uid: Option<u32>,
        peer_pid: Option<u32>,
        sink: &EventSink,
    ) -> anyhow::Result<Bearer> {
        let inner = &self.inner;
        let now_ms = inner.clock.now().timestamp_millis();
        // Monotonic anchor captured at mint (OI-6): the rollback fence in `decide` measures elapsed
        // lifetime against THIS, not the rewindable wall clock. It is bound into the row MAC.
        let issued_boottime_ms = inner.clock.boottime_ms();

        // Hold the vault READ lock for the whole mint so the DEK cannot be zeroized out from under
        // us between the gate check and the MAC.
        let v = inner.vault.read().expect("vault lock");
        let dek = match v.dek() {
            Some(d) => d,
            None => return Err(EngineError::Locked.into()),
        };

        // USB-GATE (HF-14): prove possession of the keyfile backing an enabled USB keyslot BEFORE
        // touching any key material. A UUID match alone is not possession (CF-4) — `keyfile_for`
        // must actually return the bytes. Absence is a REFUSAL (durable Refused row + GuardRefused
        // event), then a typed `UsbAbsent` Err; the real key is never derived.
        if !self.usb_possession_proven()? {
            drop(v);
            self.refuse(sink, "relay_mint", &spec.relay_id, "usb possession not proven")?;
            return Err(EngineError::UsbAbsent.into());
        }

        // TTL CLAMP (HF-15): the single choke point min()'s requested vs policy_ttl vs the 24h
        // ceiling (all in SECONDS, where `MAX_BEARER_TTL_SECS` lives) and refuses a dead/negative
        // TTL. `clamp_ttl(now_secs, ...)` returns the absolute expiry in the SAME unit, so we feed it
        // epoch-seconds and convert the result back to the millis the bearer row stores.
        let now_secs = now_ms.div_euclid(1000);
        let expires_at_secs = match clamp_ttl(now_secs, spec.policy_ttl_secs, requested_ttl_secs) {
            Some(e) => e,
            None => {
                drop(v);
                self.refuse(sink, "relay_mint", &spec.relay_id, "ttl clamp refused (non-positive)")?;
                anyhow::bail!("relay_mint refused: clamped TTL is non-positive");
            }
        };
        let expires_at_ms = expires_at_secs.saturating_mul(1000);

        // Resolve / generate the relay_id. Ephemeral relays own a fresh generated id when blank.
        let mut spec = spec;
        if matches!(spec.kind, RelayKind::Ephemeral) && spec.relay_id.is_empty() {
            spec.relay_id = format!("eph_{}", hex_encode(&random_bytes(8)));
        }

        // Persist the policy (upsert by relay_id; the assigned id IS the bearer linkage key).
        let policy_id = inner.store.save_relay_policy(RelayPolicyRow {
            id: 0,
            policy: spec.clone(),
        })?;

        // MINT the raw bearer from the OS CSPRNG. token_id is a public, opaque index (lowercase
        // hex, no separator char); secret is the actual 32-byte authenticator (base64url-no-pad).
        let token_id = hex_encode(&random_bytes(16));
        let secret = b64url_nopad(&random_bytes(32));
        let raw = Zeroizing::new(format!("{}{}_{}", broker::BEARER_PREFIX, token_id, secret));

        // MAC the WHOLE wire string under the DEK-derived bearer key (Zeroizing, dropped at scope
        // end). We persist ONLY the MAC — the raw bearer never touches disk.
        let hmac_key = broker_hmac_key(dek);
        let mac = mac_bearer(&hmac_key, &raw);
        drop(hmac_key);

        // Authenticate the clear-text row metadata with a SEPARATE DEK-keyed MAC (CRITICAL fix). This
        // binds `revoked`/`expires_at_ms`/`issued_at_ms`/`issued_boottime_ms`/`policy_id`/peer ids, so
        // a store-level attacker cannot flip any of them to forge an Allow — the swap path re-verifies
        // this before `decide`, and a tamper fails closed (UnknownBearer).
        let row_mac_key = broker_row_mac_key(dek);
        let row_mac = mac_bearer_row(
            &row_mac_key,
            &bearer_row_mac_message(
                &token_id,
                policy_id,
                expires_at_ms,
                now_ms,
                issued_boottime_ms,
                peer_uid,
                peer_pid,
                false,
            ),
        );
        drop(row_mac_key);

        inner.store.save_bearer(BearerRow {
            token_id: token_id.clone(),
            policy_id,
            mac: mac.to_vec(),
            expires_at_ms,
            issued_at_ms: now_ms,
            issued_boottime_ms,
            client_uid: peer_uid,
            client_pid: peer_pid,
            revoked: false,
            row_mac: row_mac.to_vec(),
        })?;

        // Release the vault lock BEFORE the audit store write (never hold a lock across a store write
        // that takes its own lock).
        drop(v);

        let expires_at = ms_to_rfc3339(expires_at_ms);
        // Durable audit BEFORE return WITHOUT the bearer; only the public token_id appears.
        self.audit_ok(
            sink,
            "relay_minted",
            Some(spec.relay_id.clone()),
            serde_json::json!({
                "token_id": token_id,
                "kind": spec.kind,
                "expires_at_ms": expires_at_ms,
            }),
        )?;
        sink.emit(SecretEvent::RelayMinted {
            relay: spec.relay_id.clone(),
            kind: spec.kind,
            expires_at: expires_at.clone(),
        });

        Ok(Bearer {
            relay_id: spec.relay_id,
            token_id,
            raw,
            expires_at,
        })
    }
    /// Fail-closed; returns the count of bearers/policies flipped (HF-16). When `apply`, the relay
    /// policy is marked `revoked` AND every live bearer hanging off it is revoked; a store error is
    /// an `Err` (the revoke must NOT silently no-op). When `!apply` (dry-run) the count that WOULD be
    /// revoked is returned without mutating. The durable audit row is written BEFORE returning.
    pub fn relay_revoke(
        &self,
        relay_id: &str,
        apply: bool,
        sink: &EventSink,
    ) -> anyhow::Result<u32> {
        let inner = &self.inner;

        if !apply {
            // Dry-run: count the live bearers that WOULD be revoked, mutate nothing.
            let would = inner
                .store
                .list_bearers_for_relay(relay_id)?
                .into_iter()
                .filter(|b| !b.revoked)
                .count() as u32;
            self.audit_ok(
                sink,
                "relay_revoked",
                Some(relay_id.to_string()),
                serde_json::json!({ "apply": false, "would_revoke": would }),
            )?;
            return Ok(would);
        }

        // apply: flip the policy revoked flag, then revoke every live bearer.
        if let Some(mut row) = inner.store.load_relay_policy(relay_id)? {
            row.policy.revoked = true;
            inner.store.save_relay_policy(row)?;
        }
        // Flip + re-MAC every live bearer in the ENGINE (DEK live) rather than via the store-side
        // `revoke_bearers_for_relay`, which would set `revoked` without recomputing the DEK-keyed row
        // MAC and so leave the rows failing their own authenticity check on the next swap. We flip the
        // authenticated `revoked` flag and reseal the row MAC over it, keeping the row valid AND
        // revoked. A locked vault cannot revoke (no DEK) — fail closed with an Err.
        let mut n = 0u32;
        for mut b in inner.store.list_bearers_for_relay(relay_id)? {
            if !b.revoked {
                b.revoked = true;
                self.reseal_bearer_row(&mut b)?;
                inner.store.save_bearer(b)?;
                n += 1;
            }
        }

        self.audit_ok(
            sink,
            "relay_revoked",
            Some(relay_id.to_string()),
            serde_json::json!({ "apply": true, "revoked": n }),
        )?;
        sink.emit(SecretEvent::RelayRevoked {
            relay: relay_id.to_string(),
            reason: "operator revoke".to_string(),
        });
        Ok(n)
    }

    /// Single-bearer revocation (OI-10). When `apply` and the bearer exists and is not already
    /// revoked, flip it and return 1; an already-revoked or unknown bearer returns 0 (fail-closed
    /// count). Dry-run returns the would-flip count (0/1) without mutating. The durable audit row is
    /// written BEFORE returning (HF-14).
    pub fn relay_revoke_bearer(
        &self,
        token_id: &str,
        apply: bool,
        sink: &EventSink,
    ) -> anyhow::Result<u32> {
        let inner = &self.inner;
        let row = inner.store.load_bearer(token_id)?;
        let would_flip = matches!(&row, Some(b) if !b.revoked);

        if !apply {
            self.audit_ok(
                sink,
                "relay_bearer_revoked",
                Some(token_id.to_string()),
                serde_json::json!({ "apply": false, "would_revoke": would_flip as u32 }),
            )?;
            return Ok(would_flip as u32);
        }

        let n = if would_flip {
            let mut b = row.expect("would_flip implies Some");
            b.revoked = true;
            // Re-authenticate the row under the live DEK so the flipped `revoked` is bound into the
            // row MAC (else the swap path's row-MAC verify would reject the legitimately-revoked
            // row as tampered). A locked vault cannot revoke — fail closed with an Err.
            self.reseal_bearer_row(&mut b)?;
            inner.store.save_bearer(b)?;
            1u32
        } else {
            0u32
        };
        self.audit_ok(
            sink,
            "relay_bearer_revoked",
            Some(token_id.to_string()),
            serde_json::json!({ "apply": true, "revoked": n }),
        )?;
        if n == 1 {
            sink.emit(SecretEvent::RelayRevoked {
                relay: token_id.to_string(),
                reason: "bearer revoke".to_string(),
            });
        }
        Ok(n)
    }
    /// Hot path: default-deny by construction — the real key is fetched only inside `Allowed`;
    /// any internal error becomes `InternalRefused` (a durable-audited 403), never `send()` (CF-9).
    ///
    /// The real secret is read from the unlocked vault ONLY inside the `Allow` branch and goes ONLY
    /// to `Upstream::send` — it is NEVER put in a `SecretEvent`, an audit row, an `Err`, or the
    /// return value. A `Deny` (or any internal error) never fetches the key and never reaches the
    /// upstream. All locks are dropped before the `.await` (the real key is moved out as an owned
    /// `Zeroizing<Vec<u8>>`).
    pub async fn relay_swap(
        &self,
        bearer: &str,
        req: &EgressReq,
        sink: &EventSink,
    ) -> SwapOutcome {
        // The whole pre-await body is fallible; funnel any `?` (lock poison / store error) into a
        // durable-audited `InternalRefused` so an internal error can NEVER fail-open into a send.
        match self.relay_swap_prepare(bearer, req, sink) {
            Err(e) => {
                let msg = e.to_string();
                let _ = self.audit_failed(
                    sink,
                    "relay_swapped",
                    None,
                    serde_json::json!({ "reason": "internal", "detail": msg }),
                );
                SwapOutcome::InternalRefused(msg)
            }
            // Deny: already audited + emitted inside prepare; the key was never fetched.
            Ok(Prepared::Deny(reason)) => SwapOutcome::Denied(reason),
            // Allow: prepare already extracted the real key (under the now-released lock) and the
            // matched relay metadata. ONLY NOW do we await the upstream.
            Ok(Prepared::Allow(allow)) => {
                let owned = EgressReq {
                    method: req.method,
                    host: req.host.clone(),
                    path: req.path.clone(),
                    headers: req.headers.clone(),
                    bytes_out: req.bytes_out,
                    peer_uid: req.peer_uid,
                    peer_pid: req.peer_pid,
                };
                // HF-11 send-site fence (belt-and-suspenders): re-assert that the EXACT host about to
                // receive the real key is in the provider's frozen canonical allowlist, immediately
                // before send. `decide` already checked this, but re-checking here against the host
                // carried in `allow` (and `owned.host`) forecloses any divergence if the actual
                // upstream target ever becomes a function of an adapter/base-url rewrite. A miss
                // refuses WITHOUT sending — the key (still in `allow`) is dropped/zeroized.
                if !canonical_upstreams(allow.provider)
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(&owned.host) && h.eq_ignore_ascii_case(&allow.host))
                {
                    let _ = self.audit_failed(
                        sink,
                        "relay_swapped",
                        Some(allow.relay_id.clone()),
                        serde_json::json!({
                            "token_id": allow.token_id,
                            "reason": "upstream_fence",
                            "allowed": false,
                        }),
                    );
                    return SwapOutcome::InternalRefused("upstream host fence".to_string());
                }
                match self.inner.upstream.send(owned, &allow.real_key).await {
                    Ok(resp) => {
                        let _ = self.audit_ok(
                            sink,
                            "relay_swapped",
                            Some(allow.relay_id.clone()),
                            serde_json::json!({
                                "token_id": allow.token_id,
                                "host": req.host,
                                "method": method_str(req.method),
                                "allowed": true,
                            }),
                        );
                        sink.emit(SecretEvent::RelaySwapped {
                            relay: allow.relay_id,
                            host: req.host.clone(),
                            method: method_str(req.method).to_string(),
                            allowed: true,
                            token_id: allow.token_id,
                            client_uid: req.peer_uid.unwrap_or(self.inner.owner_uid),
                            client_label: String::new(),
                        });
                        SwapOutcome::Allowed(resp)
                    }
                    Err(ue) => {
                        // The real key went ONLY to send(); it is dropped (zeroized) with `allow`.
                        // CRITICAL containment: an upstream adapter is the one component that just
                        // received the REAL key. Its error STRING is untrusted — a buggy/hostile
                        // adapter could echo the auth header / key bytes into `ue.to_string()`. We
                        // therefore NEVER propagate the raw error text into the durable audit row or
                        // the caller-visible outcome; we map it to a fixed, key-free DISCRIMINANT
                        // label only, preserving the "never in an audit row / Err / return value"
                        // invariant.
                        let kind = upstream_error_kind(&ue);
                        let _ = self.audit_failed(
                            sink,
                            "relay_swapped",
                            Some(allow.relay_id.clone()),
                            serde_json::json!({
                                "token_id": allow.token_id,
                                "reason": "upstream",
                                "kind": kind,
                            }),
                        );
                        SwapOutcome::InternalRefused(format!("upstream send failed ({kind})"))
                    }
                }
            }
        }
    }

    /// The synchronous, fallible pre-await half of `relay_swap`: parse + verify the bearer, snapshot
    /// the clock/floor/USB gate, run the PURE `decide`, and — only on `Allow` — extract the real key
    /// while still holding the vault read lock, then release every lock before returning so the
    /// caller can `.await` the upstream with no guard held. A `Deny` is audited + emitted here (the
    /// key is never fetched); any `Err` is mapped to `InternalRefused` by the caller.
    fn relay_swap_prepare(
        &self,
        bearer: &str,
        req: &EgressReq,
        sink: &EventSink,
    ) -> anyhow::Result<Prepared> {
        let inner = &self.inner;

        // 1. Parse. A malformed / foreign bearer is UnknownBearer (no store hit, no crypto).
        let Some((token_id, raw)) = parse_bearer(bearer) else {
            return Ok(Prepared::Deny(self.deny_swap(sink, None, None, DenyReason::UnknownBearer)?));
        };

        // 2. Snapshot under the vault READ lock. A poisoned lock fails closed (mapped to
        // InternalRefused by the caller), never a panic that unwinds past the deny funnel.
        let v = inner.vault.read().map_err(|_| anyhow::anyhow!("vault lock poisoned"))?;
        let dek = match v.dek() {
            Some(d) => d,
            // A locked vault returns InternalRefused (never a send) — fail-closed.
            None => anyhow::bail!("vault is locked"),
        };
        let now_ms = inner.clock.now().timestamp_millis();
        let boottime_now_ms = inner.clock.boottime_ms();
        let issuance_floor_ms = self.load_issuance_floor()?;

        // Load the bearer row by the public token_id (O(1)); a miss is UnknownBearer.
        let Some(row) = inner.store.load_bearer(token_id)? else {
            drop(v);
            return Ok(Prepared::Deny(self.deny_swap(sink, None, Some(token_id), DenyReason::UnknownBearer)?));
        };

        // Constant-time MAC verify over the WHOLE wire string. A forged/wrong secret cannot be
        // distinguished from an absent bearer => UnknownBearer (no oracle).
        let hmac_key = broker_hmac_key(dek);
        if !verify_bearer(&hmac_key, raw, &row.mac) {
            drop(hmac_key);
            drop(v);
            return Ok(Prepared::Deny(self.deny_swap(sink, None, Some(token_id), DenyReason::UnknownBearer)?));
        }
        drop(hmac_key);

        // Constant-time verify of the DEK-keyed ROW MAC over the clear-text metadata (CRITICAL fix).
        // This is what stops a store-level attacker from flipping `revoked`, raising `expires_at_ms`,
        // rewriting the peer binding, or repointing `policy_id` to forge an Allow: any such tamper
        // makes the recomputed MAC diverge from the stored one. A mismatch is indistinguishable from
        // an absent/forged bearer => UnknownBearer (no oracle), and the real key is never fetched.
        let row_mac_key = broker_row_mac_key(dek);
        let row_msg = bearer_row_mac_message(
            &row.token_id,
            row.policy_id,
            row.expires_at_ms,
            row.issued_at_ms,
            row.issued_boottime_ms,
            row.client_uid,
            row.client_pid,
            row.revoked,
        );
        if !verify_bearer_row(&row_mac_key, &row_msg, &row.row_mac) {
            drop(row_mac_key);
            drop(v);
            return Ok(Prepared::Deny(self.deny_swap(sink, None, Some(token_id), DenyReason::UnknownBearer)?));
        }
        drop(row_mac_key);

        // Load the matched policy by the bearer's policy_id (the linkage key). A miss, or a policy
        // whose assigned id disagrees with the bearer, is treated as UnknownBearer (never a
        // successful Allow against a mismatched pair).
        let policy_row = match self.find_policy_by_id(row.policy_id)? {
            Some(pr) => pr,
            None => {
                drop(v);
                return Ok(Prepared::Deny(self.deny_swap(sink, None, Some(token_id), DenyReason::UnknownBearer)?));
            }
        };
        let relay_id = policy_row.policy.relay_id.clone();
        let secret_name = policy_row.policy.secret_name.clone();

        // USB possession gate snapshot: absent => the gate is currently unproven.
        let usb_absent_since_ms = if self.usb_possession_proven()? {
            None
        } else {
            Some(now_ms)
        };

        // 3. Bump the broker's ephemeral usage counters (post-bump tallies feed the pure budgets). A
        // poisoned broker lock fails closed (Err -> InternalRefused), never a panic.
        let (total_requests, total_bytes, rate_in_window) = {
            let mut broker = inner
                .broker
                .write()
                .map_err(|_| anyhow::anyhow!("broker lock poisoned"))?;
            broker.bump(&row.token_id, now_ms, req.bytes_out)
        };

        let vb = VerifiedBearer {
            policy_id: row.policy_id,
            token_id: row.token_id.clone(),
            expires_at_ms: row.expires_at_ms,
            issued_at_ms: row.issued_at_ms,
            issued_boottime_ms: row.issued_boottime_ms,
            client_uid: row.client_uid,
            client_pid: row.client_pid,
            revoked: row.revoked,
        };
        let canon = CanonRequest {
            method: req.method,
            host: req.host.clone(),
            sni: trusted_sni_for(&policy_row.policy.swap, req),
            path: req.path.clone(),
            bytes_out: req.bytes_out,
            peer_uid: req.peer_uid,
            peer_pid: req.peer_pid,
            usage_requests: total_requests,
            usage_bytes: total_bytes,
            rate_in_window,
        };

        // 4. The PURE, default-deny decision (expiry fenced against BOTH the wall and monotonic
        // clocks).
        match decide(
            &policy_row.policy,
            &vb,
            &canon,
            now_ms,
            boottime_now_ms,
            usb_absent_since_ms,
            issuance_floor_ms,
        ) {
            RelayDecision::Deny { reason } => {
                drop(v);
                Ok(Prepared::Deny(self.deny_swap(sink, Some(relay_id), Some(token_id), reason)?))
            }
            RelayDecision::Allow => {
                // ONLY NOW fetch the real secret — internal open, reveal=false-internal — producing
                // an owned Zeroizing<Vec<u8>>. We are still holding the vault read lock, so the DEK
                // is live; we extract the key, then drop EVERY lock before returning so the caller
                // can await with no guard held. The real key goes ONLY into the returned `Allow`.
                let real_key = self.open_real_key(dek, &secret_name)?;
                drop(v);
                // Carry the provider + the canonical host so `relay_swap` can re-assert the HF-11
                // upstream-host fence IMMEDIATELY before send (belt-and-suspenders: decide() already
                // checked it, but the send-site gate forecloses any future divergence between the
                // host decide saw and the host actually sent).
                Ok(Prepared::Allow(AllowPrepared {
                    relay_id,
                    token_id: row.token_id,
                    provider: policy_row.policy.provider,
                    host: req.host.clone(),
                    real_key,
                }))
            }
        }
    }

    /// Open the real secret for an Allowed swap, reconstructing the canonical record AAD exactly as
    /// `secret_get` does. Returns the plaintext as an owned `Zeroizing<Vec<u8>>` — this is the ONLY
    /// place the real key materializes on the swap path, and it flows ONLY to `Upstream::send`.
    fn open_real_key(
        &self,
        dek: &keyslot::Dek,
        secret_name: &str,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let row = self
            .inner
            .store
            .get_secret_latest(secret_name)?
            .ok_or_else(|| anyhow::anyhow!("relay secret '{secret_name}' not found"))?;
        let aad = record_aad(
            TableTag::SecretVersion,
            row.row_id,
            row.version as i64,
            row.dek_generation,
        );
        vault::crypto::open(dek, &aad, &row.nonce, &row.ct_tag)
            .ok_or_else(|| anyhow::anyhow!("relay secret '{secret_name}' failed authentication"))
    }

    /// Find a relay policy row by its assigned id (the bearer linkage key). Linear scan of the
    /// policy set; the store has no id index in 1b/Phase 4 InMem.
    fn find_policy_by_id(&self, policy_id: i64) -> anyhow::Result<Option<RelayPolicyRow>> {
        Ok(self
            .inner
            .store
            .list_relay_policies()?
            .into_iter()
            .find(|r| r.id == policy_id))
    }

    /// Recompute the DEK-keyed row MAC over a bearer row's CURRENT (security-critical) fields and
    /// write it back into `row.row_mac`. Called on every legitimate row mutation (mint reseals
    /// inline; revoke reseals here) so the persisted row always carries a MAC that matches its
    /// clear-text state. Requires the vault unlocked (`Err(Locked)` otherwise — a locked vault can
    /// neither mint nor revoke, fail-closed).
    fn reseal_bearer_row(&self, row: &mut BearerRow) -> anyhow::Result<()> {
        let v = self.inner.vault.read().map_err(|_| anyhow::anyhow!("vault lock poisoned"))?;
        let dek = match v.dek() {
            Some(d) => d,
            None => return Err(EngineError::Locked.into()),
        };
        let row_mac_key = broker_row_mac_key(dek);
        row.row_mac = mac_bearer_row(
            &row_mac_key,
            &bearer_row_mac_message(
                &row.token_id,
                row.policy_id,
                row.expires_at_ms,
                row.issued_at_ms,
                row.issued_boottime_ms,
                row.client_uid,
                row.client_pid,
                row.revoked,
            ),
        )
        .to_vec();
        drop(row_mac_key);
        Ok(())
    }

    /// Whether USB possession is currently PROVEN: some enabled USB keyslot's keyfile is obtainable
    /// (a UUID match alone is not possession, CF-4). When the vault has NO USB keyslot enrolled, the
    /// gate is vacuously satisfied (a passphrase-only vault is not USB-gated).
    fn usb_possession_proven(&self) -> anyhow::Result<bool> {
        let slots = self.inner.store.load_keyslots()?;
        let usb_slots: Vec<_> = slots
            .iter()
            .filter(|s| s.enabled && s.factor == Factor::Usb)
            .collect();
        if usb_slots.is_empty() {
            return Ok(true);
        }
        for s in usb_slots {
            if let Some(uuid) = s.usb_partition_uuid.as_deref() {
                if self.inner.usb.keyfile_for(uuid).is_some() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Audit + emit a denied swap (the real key is NEVER fetched on this branch) and return the
    /// reason so the caller can wrap it in `SwapOutcome::Denied`.
    fn deny_swap(
        &self,
        sink: &EventSink,
        relay_id: Option<String>,
        token_id: Option<&str>,
        reason: DenyReason,
    ) -> anyhow::Result<DenyReason> {
        let reason_str = serde_json::to_value(reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| format!("{reason:?}"));
        self.audit(
            sink,
            "relay_swapped",
            relay_id.clone(),
            serde_json::json!({
                "token_id": token_id,
                "reason": reason_str,
                "allowed": false,
            }),
            AuditOutcome::Refused,
        )?;
        sink.emit(SecretEvent::RelaySwapped {
            relay: relay_id.unwrap_or_default(),
            host: String::new(),
            method: String::new(),
            allowed: false,
            token_id: token_id.unwrap_or("").to_string(),
            client_uid: self.inner.owner_uid,
            client_label: String::new(),
        });
        Ok(reason)
    }
    /// Operator-issued NON-MITM leaves only; REFUSES `usage = mitm_leaf` (CF-5).
    pub fn ca_issue(
        &self,
        _cn: &str,
        _sans: &[String],
        _usage: &str,
        _sink: &EventSink,
    ) -> anyhow::Result<String> {
        todo!()
    }
    pub fn run_child(
        &self,
        _plan: inject::ChildEnvPlan,
        _argv: Vec<String>,
        _sink: &EventSink,
    ) -> anyhow::Result<i32> {
        todo!()
    }

    // ---- internal helpers ---------------------------------------------------------------------

    /// Build + persist a durable `Ok` audit row, then mirror it onto the (cosmetic) event channel.
    fn audit_ok(
        &self,
        sink: &EventSink,
        event_type: &str,
        subject: Option<String>,
        detail: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.audit(sink, event_type, subject, detail, AuditOutcome::Ok)
    }

    fn audit_failed(
        &self,
        sink: &EventSink,
        event_type: &str,
        subject: Option<String>,
        detail: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.audit(sink, event_type, subject, detail, AuditOutcome::Failed)
    }

    /// Emit a `GuardRefused` event + a durable `Refused` audit row (the engine's refusal discipline:
    /// a refused op is NOT an `Err` at the audit/event layer — the caller decides whether to map it
    /// to an `Err`/empty per its gate).
    fn refuse(
        &self,
        sink: &EventSink,
        event_type: &str,
        subject: &str,
        reason: &str,
    ) -> anyhow::Result<()> {
        self.audit(
            sink,
            event_type,
            Some(subject.to_string()),
            serde_json::json!({ "reason": reason }),
            AuditOutcome::Refused,
        )?;
        sink.emit(SecretEvent::GuardRefused {
            subject: subject.to_string(),
            reason: reason.to_string(),
        });
        Ok(())
    }

    fn audit(
        &self,
        sink: &EventSink,
        event_type: &str,
        subject: Option<String>,
        detail: serde_json::Value,
        outcome: AuditOutcome,
    ) -> anyhow::Result<()> {
        let ts = self.inner.clock.now().to_rfc3339();
        let actor_uid = Some(self.inner.owner_uid);
        let rec = vault::audit::new_row(ts, actor_uid, event_type, subject, detail, outcome);
        // Durable BEFORE return (HF-14): the store links + pushes synchronously.
        let seq = self.inner.store.append_audit(&rec)?;
        // Advance the DEK-keyed tail anchor when the vault is unlocked, so a store-level attacker
        // who later drops trailing rows (e.g. a refused reveal) cannot re-link a clean shorter
        // chain that `verify_chain` would accept — the anchor's `(seq, row_hash)` no longer match.
        // Rows written while LOCKED (init-before-unlock, failed unlock, lock) are not DEK-anchorable
        // at append time; they are covered by the unkeyed chain linkage forward from the anchored
        // row. Best-effort under a read lock; a failure to read the tail is non-fatal to the op.
        self.advance_audit_anchor_if_unlocked()?;
        // Mirror onto the cosmetic event channel with the sealed seq (best-effort).
        let mut mirrored = rec;
        mirrored.seq = seq;
        sink.emit(SecretEvent::Audit(mirrored));
        Ok(())
    }

    /// If the vault is unlocked, recompute + persist the DEK-keyed anchor over the CURRENT chain
    /// tail. No-op when locked (no resident DEK to key the anchor with).
    fn advance_audit_anchor_if_unlocked(&self) -> anyhow::Result<()> {
        let v = self.inner.vault.read().expect("vault lock");
        let Some(dek) = v.dek() else {
            return Ok(());
        };
        let (seq, tail_hash) = match self.inner.store.last_audit()? {
            Some(r) => (r.seq, r.row_hash),
            None => (0i64, Vec::new()),
        };
        let mac = audit_head_mac(dek, seq, &tail_hash);
        self.inner.store.put_meta(META_AUDIT_HEAD, &hex_encode(&mac))?;
        Ok(())
    }

    /// Verify the DEK-keyed audit anchor against the live chain (truncation/rewrite detection).
    /// Requires the vault to be unlocked (the anchor is DEK-keyed). See `verify_audit_anchor_with`
    /// for the verification rule. Returns `Err(EngineError::AuditChainBroken)` on any mismatch.
    pub fn verify_audit_anchor(&self, _sink: &EventSink) -> anyhow::Result<()> {
        let v = self.inner.vault.read().expect("vault lock");
        let dek = match v.dek() {
            Some(d) => d,
            None => return Err(EngineError::Locked.into()),
        };
        self.verify_audit_anchor_with(dek)
    }

    /// Verify the DEK-keyed audit anchor against the live chain using an explicit DEK (so it can be
    /// driven from `unlock` with the just-recovered DEK, before it is committed into the vault).
    ///
    /// Rule: the unkeyed `verify_chain` must pass (partial-mutation tamper-evidence) AND the stored
    /// anchor MAC must be reproducible from SOME `(seq, row_hash)` present in the live chain.
    /// Because the MAC binds the seq, truncating the chain below the anchored seq removes the only
    /// row that reproduces the anchor (caught), and rewriting any covered row changes its row_hash
    /// (caught). Rows appended while LOCKED after the anchor (e.g. a failed unlock) sit above the
    /// anchored seq and are covered only by the forward unkeyed linkage — the documented limit.
    fn verify_audit_anchor_with(&self, dek: &Dek) -> anyhow::Result<()> {
        use subtle::ConstantTimeEq;
        // The chain itself must verify first (partial-mutation tamper-evidence).
        self.inner.store.verify_audit_chain()?;

        let Some(stored_hex) = self.inner.store.get_meta(META_AUDIT_HEAD)? else {
            // No anchor was ever written (only ever logged while locked); the unkeyed chain still
            // verified above, so there is nothing to anchor against.
            return Ok(());
        };
        let stored_mac = hex_decode(&stored_hex).ok_or(EngineError::AuditChainBroken(0))?;

        let rows = self.inner.store.query_audit(0, usize::MAX)?;
        let matched = if rows.is_empty() {
            // Empty-chain anchor (seq 0).
            bool::from(audit_head_mac(dek, 0, &[]).as_slice().ct_eq(&stored_mac))
        } else {
            rows.iter().any(|r| {
                bool::from(audit_head_mac(dek, r.seq, &r.row_hash).as_slice().ct_eq(&stored_mac))
            })
        };
        if !matched {
            // The anchored tail is not reproducible from any row in the live chain => the chain was
            // truncated below the anchor, or a covered row was rewritten.
            return Err(EngineError::AuditChainBroken(0).into());
        }
        Ok(())
    }

    fn load_header_mac(&self) -> anyhow::Result<Vec<u8>> {
        let hexed = self
            .inner
            .store
            .get_meta(META_HEADER_MAC)?
            .ok_or(EngineError::UnlockFailed)?;
        hex_decode(&hexed).ok_or_else(|| EngineError::UnlockFailed.into())
    }

    fn load_issuance_floor(&self) -> anyhow::Result<i64> {
        let s = self
            .inner
            .store
            .get_meta(META_ISSUANCE_FLOOR_MS)?
            .ok_or(EngineError::UnlockFailed)?;
        s.parse::<i64>()
            .map_err(|_| EngineError::UnlockFailed.into())
    }

    /// Load the DEK generation, which is load-bearing for the record AAD binding. The value is
    /// bound into the header MAC (verified at unlock), so a missing or garbled meta value here is a
    /// setup-time failure — NOT a silent `unwrap_or(1)` default, which would convert a
    /// tamper/corruption signal into records sealed under the wrong generation.
    fn load_dek_generation(&self) -> anyhow::Result<i64> {
        let s = self
            .inner
            .store
            .get_meta(META_DEK_GENERATION)?
            .ok_or_else(|| anyhow::anyhow!("dek_generation missing"))?;
        s.parse::<i64>()
            .map_err(|_| anyhow::anyhow!("dek_generation is not a valid integer"))
    }
}

/// The result of `relay_swap_prepare`: either a (already-audited) deny, or an allow carrying the
/// extracted real key + the metadata `relay_swap` needs to audit/emit the successful send. The real
/// key lives here only until `send()` consumes it; `Zeroizing` wipes it on drop.
enum Prepared {
    Deny(DenyReason),
    Allow(AllowPrepared),
}

struct AllowPrepared {
    relay_id: String,
    token_id: String,
    /// Provider + the exact host that will be sent — carried so `relay_swap` can re-assert the HF-11
    /// canonical-upstream fence at the send site (not solely inside `decide`).
    provider: Provider,
    host: String,
    /// The real secret — flows ONLY to `Upstream::send`; never audited/emitted/returned.
    real_key: Zeroizing<Vec<u8>>,
}

/// Decide the SNI value `decide` binds against the verified inner Host (HF-9), per swap mode.
///
/// SECURITY NOTE (anti-fronting): the `sni` value here is read from a request header, which is
/// CLIENT-CONTROLLED — a malicious client can set it to match its Host (or omit it) to no-op the
/// check. So it is NOT a security control in modes where the engine does not observe the real TLS
/// SNI. We therefore split by `SwapMode`:
///
///   * `ProxyMitm` — the relay terminates TLS, so a genuine TLS-observed SNI is REQUIRED to enforce
///     anti-fronting. Until the proxy plumbs the observed SNI as a trusted field (Phase-4+), we fail
///     CLOSED: synthesize a sentinel SNI that can never equal the inner Host, so `decide` returns
///     `SniHostMismatch` rather than silently trusting the client header.
///   * everything else — there is no TLS termination at the relay, so there is nothing for the
///     engine to observe; we return `None` (the check is a documented no-op) instead of pretending a
///     client-supplied header is a real SNI.
fn trusted_sni_for(swap: &SwapMode, _req: &EgressReq) -> Option<String> {
    match swap {
        // Fail closed: a sentinel that cannot match any real host (the leading byte is illegal in a
        // DNS name), forcing SniHostMismatch until a trusted, TLS-observed SNI is plumbed in.
        SwapMode::ProxyMitm => Some("\u{0}untrusted-sni-not-observed".to_string()),
        _ => None,
    }
}

/// A fixed, key-free label for an `UpstreamError` DISCRIMINANT — never its `Display` string (which
/// is adapter-controlled and could echo the real key). Used for the audit row + the refused outcome.
fn upstream_error_kind(e: &seam::UpstreamError) -> &'static str {
    match e {
        seam::UpstreamError::Io(_) => "io",
        seam::UpstreamError::HostNotAllowed(_) => "host_not_allowed",
    }
}

fn method_str(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
        Method::Connect => "CONNECT",
        Method::Options => "OPTIONS",
    }
}

/// Format epoch-millis as an RFC3339 UTC string for the bearer's `expires_at` (cosmetic; the
/// authoritative deadline is the stored `expires_at_ms`).
fn ms_to_rfc3339(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(0).unwrap())
        .to_rfc3339()
}

/// base64url, no padding (RFC 4648 §5). Used for the bearer secret (the actual authenticator). Pure
/// table-driven encode — no extra dependency.
fn b64url_nopad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Read the effective owner uid (the real uid the daemon runs as). Falls back to 0 on platforms
/// without `getuid` exposed through `rustix` — the engine never prints, so a best-effort value is
/// acceptable for the audit `actor_uid` and `SecretRead.by_uid`.
fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Mint a fresh 32-byte DEK from the OS CSPRNG (getrandom-backed; the engine's nonce/key policy
/// mandates OsRng, OI-16). The scratch array is wrapped in `Zeroizing` so an early unwind wipes it
/// before the bytes are moved into the `Dek` (itself `ZeroizeOnDrop`).
fn mint_dek() -> Dek {
    let mut buf = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(buf.as_mut()).expect("OS CSPRNG must produce 32 bytes for the DEK");
    Dek(*buf)
}

/// Fresh CSPRNG bytes (salts). `getrandom` is the OS CSPRNG; salts are non-secret but must be
/// unpredictable per slot so two slots never share a KDF salt.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("OS CSPRNG must produce salt bytes");
    v
}

/// DEK-keyed MAC over the audit chain tail `(seq, tail_row_hash)` — the durable anchor that makes
/// tail-truncation/rewrite detectable (the unkeyed chain alone is only tamper-EVIDENT against
/// partial mutation). BLAKE3 `keyed_hash` is a 256-bit MAC; the key is derived from the DEK via
/// BLAKE3 `derive_key` (domain-separated context) so the anchor is unforgeable without the unlocked
/// DEK and cannot be confused with the header MAC. `tail_row_hash` is the empty slice for an empty
/// chain (`seq == 0`).
fn audit_head_mac(dek: &Dek, seq: i64, tail_row_hash: &[u8]) -> Vec<u8> {
    let key = blake3::derive_key(AUDIT_HEAD_KEY_INFO, &dek.0);
    let mut msg = Vec::with_capacity(AUDIT_HEAD_DOMAIN.len() + 8 + tail_row_hash.len());
    msg.extend_from_slice(AUDIT_HEAD_DOMAIN);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(tail_row_hash);
    blake3::keyed_hash(&key, &msg).as_bytes().to_vec()
}

/// Lowercase hex (no separators) — for the non-secret header MAC stored in meta.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Decode lowercase/uppercase hex with no separators; `None` on any malformed input.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn factor_str(f: Factor) -> &'static str {
    match f {
        Factor::Usb => "usb",
        Factor::Passphrase => "passphrase",
    }
}

/// A do-nothing `Upstream` for `Engine::open` until the daemon wires the real (webpki-pinned)
/// sender. The 1b vault path never reaches `send()` (the relay path stays `todo!()`).
struct NullUpstream;

#[async_trait::async_trait]
impl Upstream for NullUpstream {
    async fn send(
        &self,
        _req: EgressReq,
        _real_key: &Zeroizing<Vec<u8>>,
    ) -> Result<EgressResp, seam::UpstreamError> {
        Err(seam::UpstreamError::Io("upstream not wired".to_string()))
    }
}
