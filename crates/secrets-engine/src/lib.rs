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
use vault::store::SecretRow;

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
                broker: RwLock::new(broker::Broker),
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
    pub fn relay_mint(
        &self,
        _spec: RelayPolicy,
        _requested_ttl_secs: i64,
        _peer_uid: Option<u32>,
        _peer_pid: Option<u32>,
        _sink: &EventSink,
    ) -> anyhow::Result<Bearer> {
        todo!()
    }
    /// Fail-closed; returns the count of bearers/policies flipped (HF-16).
    pub fn relay_revoke(
        &self,
        _relay_id: &str,
        _apply: bool,
        _sink: &EventSink,
    ) -> anyhow::Result<u32> {
        todo!()
    }
    /// Single-bearer revocation (OI-10).
    pub fn relay_revoke_bearer(
        &self,
        _token_id: &str,
        _apply: bool,
        _sink: &EventSink,
    ) -> anyhow::Result<u32> {
        todo!()
    }
    /// Hot path: default-deny by construction — the real key is fetched only inside `Allowed`;
    /// any internal error becomes `InternalRefused` (a durable-audited 403), never `send()` (CF-9).
    pub async fn relay_swap(
        &self,
        _bearer: &str,
        _req: &EgressReq,
        _sink: &EventSink,
    ) -> SwapOutcome {
        todo!()
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
