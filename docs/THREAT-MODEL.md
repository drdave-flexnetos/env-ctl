# env-ctl — Threat Model

**Status:** Reconciled + adversarial-review-hardened · STRIDE-style, grounded in the 12 locked operator decisions
**Idiom:** mirrors envctl's `REQ-SAFE-*` / `FS-*` vocabulary; no `--force` bypasses any guard.

## 1. Trust boundaries

**TCB = the `secretd` daemon address space** — the ONLY place the plaintext DEK and real upstream API keys exist, zeroized on drop, protected by `mlockall(MCL_CURRENT|MCL_FUTURE)` + raised `RLIMIT_MEMLOCK` + `MADV_DONTDUMP` + `RLIMIT_CORE=0` (daemon refuses to start if `mlockall` fails). Every boundary crossing out of it carries only AEAD ciphertext or a <=24h peer-bound relay bearer:

| Crossing | Carries |
|---|---|
| daemon -> store (vault.db) | AEAD ciphertext + metadata only; keyslot set + KDF params under a DEK header MAC |
| daemon -> backup / stolen disk | same ciphertext; DEK wrapped under USB-KEK and passphrase-KEK |
| daemon -> child process (`env-ctl run`) | relay bearer + base-URL/proxy env; never the real key |
| daemon -> real upstream | real key, TLS verified against a FROZEN bundled-Mozilla (webpki-roots) store — never the local CA, never the OS store |
| daemon -> data-plane client | peer-bound relay bearer (<=24h), validated per request against its policy |
| control client -> daemon | gRPC/UDS, authz by `SO_PEERCRED` uid == owner |

## 2. STRIDE x adversary -> mitigation (each grounded in a locked decision)

| # | Adversary | STRIDE | Mitigation (locked decision) |
|---|---|---|---|
| A1 | Local non-owner process/uid | Spoofing/EoP | Control plane UDS 0700/0600 + `SO_PEERCRED` reject uid != owner; no TCP control listener; data proxy loopback-only + peer-bound bearer; DB is ciphertext at rest [8,12,3] |
| A2 | Malware in the OWNER's session | EoP/Info | Runs as owner -> can call control plane, but blast radius bounded by the relay model: each bearer <=24h, host/path/method-allowlisted, quota-capped, peer-bound, durably audited; the real key never leaves the daemon and only egresses to the provider's canonical upstream; pulling the USB stops new egress within a short grace and drains all relays within 24h. **Bounded, not prevented** [5,6] |
| A3 | Accidental git commit | Info | Real keys never enter a `.env`/child env/repo; vault file is ciphertext; daemon stores under `~/.local/share` (0700), outside repos [9,3,12] |
| A4 | Stolen disk / backup | Info | App-layer XChaCha20-Poly1305 per record; DEK wrapped under argon2id/HKDF keyslots; unlock key never on disk, zeroized in RAM; **no SQLCipher and (per OI-1 ruling) no C SQLite weak-default surface** [3,4] |
| A5 | Stolen USB key | Spoofing the auto-unlock factor | USB is ONE keyslot; the vault still needs the box; operator can revoke the USB slot + rekey the DEK; the keyfile CONTENT is the secret (not the UUID). On removable vfat/exfat the `0400` mode is advisory — physical possession is the boundary (see A11) [4,11] |
| A6 | Network MITM of REAL upstream | Tampering/Spoofing | Upstream egress verifies TLS against FROZEN bundled-Mozilla roots; the local CA AND the OS store are REFUSED for upstream verification; optional native scoped sub-tokens limit a MITM'd key's reach [10,5] |
| A7 | Compromised client holding a relay token | Info/EoP | Bearer <=24h, enabled/revoked (policy- AND bearer-level), allowlist + rate/quota, peer-bound, checked per request; revoke flips the policy or the single bearer; USB-absent stops renewal AND new egress (grace); every request durably audited [5,6] |
| A8 | Malicious/forged relay POLICY row (owner-session) | Tampering/Info | `relay_swap` refuses egress to any upstream outside the provider's canonical host allowlist, so a repointed `upstream_base` cannot exfiltrate the real key to an attacker host even with a valid public cert [5] |
| A9 | SNI/Host confusion by a compromised MITM client | Spoofing/EoP | Canonical host = the verified inner HTTP Host after decryption; SNI≠Host is refused; `decide()` runs per request on the inner host [10,5] |
| A10 | Replay of a harvested plain-HTTP bearer (BaseUrlRepoint) | Spoofing | Bearer peer-bound at mint (uid/pid); ephemerals pid-scoped to the `run` child; mismatched peer denied; honest residual: same-uid replay is bounded by allowlist+quota+short-TTL, not bearer secrecy [5,6] |
| A11 | Local read of the mounted USB keyfile | Info | Keyfile is the secret; on vfat/exfat `0400` is meaningless, so any same-session process can copy it while mounted. Mitigation: document physical-possession boundary, warn on mode-bit-ignoring FS, optional TPM-sealed/per-install salt so a bare copy is insufficient; keyfile is read into `Zeroizing`, never to a temp file [4,11] |
| A12 | Attacker-forced passphrase-fallback downgrade | EoP/Info | The two factors are an OR (1-of-2), so overall strength == the WEAKER factor == the passphrase's argon2id work against an offline attacker with `vault.db`. Mitigation: enforce passphrase entropy at enroll; argon2id m=1GiB,t=4,p=4; optional require-both keyslot. **This is a downgrade the attacker can force, stated plainly — not 2FA** [4] |

## 3. Affirmative safety requirements (REQ-SEC-*, mirror REQ-SAFE-*)

- **REQ-SEC-1 (dry-run by default, encoded on the WIRE):** every destructive RPC carries a positively-phrased `apply` (proto3 default `false` == dry-run, the safe state) plus `confirm` for root-of-trust ops; vault rekey/destroy, relay revoke-all, CA rotate-root/revoke, trust-store unwire, and `secret get --reveal` all require `apply=true`; root-of-trust destruction needs `apply && confirm`. No `--force` bypasses any REQ-SEC-*.
- **REQ-SEC-2 (resolve-once, no TOCTOU):** an `UnlockContext` resolves USB possession + peer uid ONCE per op; guards read from it, never re-resolve mid-op.
- **REQ-SEC-3 (resolve + PROVE USB possession):** `UsbPresent` uses the PARTUUID as a pre-filter, then proves possession of the keyfile cryptographically (keyfile unwraps the USB keyslot or matches a vault-resident keyed MAC); any failure => refuse (no renewal, no leaf).
- **REQ-SEC-4 (fail-closed guards):** `UsbPresent`/`RelayValid`/`LeafBackedByRelay`/`PeerIsOwner` return a refusal when they cannot PROVE the precondition (UUID unreadable, keyfile absent, clock skew, missing policy, peercred unavailable). Never silently pass.
- **REQ-SEC-5 (relay TTL ceiling, single choke point):** every minted bearer has `expiry <= now+24h` via the sole `clamp_ttl` path (saturating arithmetic; `<=0` or out-of-range TTL refused); a named relay is a policy, the wire bearer is always <=24h; renewal AND new egress require USB possession (re-checked at swap with a short grace). Accept-side re-asserts the ceiling.
- **REQ-SEC-6 (real key isolation):** the real key exists only in the daemon TCB, zeroized on drop; never enters a child env, the DB plaintext, the client-facing wire, shell history, git, OR an upstream outside the provider's canonical host allowlist. `secret get --reveal` is the single audited, apply-gated exception (refused for broker-only secrets).
- **REQ-SEC-7 (CA leaf minting is relay-scoped AND USB-gated):** a MITM leaf is minted ONLY inside the relay-gated resolver for a host actively intercepted for a currently-valid USB-gated relay whose allowlist covers it, `not_after <= min(now+24h, relay validity)`; the general `ca issue` REFUSES `usage='mitm_leaf'`. Otherwise refuse.
- **REQ-SEC-8 (back up before clobber + reversible wiring):** every trust-store edit is resolve -> re-verify -> timestamped backup -> apply; per-tool child-only env wiring self-reverts; the system bundle is written ONLY to an owned discrete file and reverted by deleting that file + regenerating, fingerprint-verified — the monolithic bundle is never hand-edited.
- **REQ-SEC-9 (never touch user DATA):** KeePassXC DBs, original `~/.ssh` keys, browser profiles, and any non-env-ctl store are never read-destructively or written; interop is opt-in import only.

## 4. Forbidden states (FS-S*, extend FS-1..8)

| ID | Must never happen |
|---|---|
| FS-S1 | A real upstream key appears in a child env, argv, shell history, or any file outside the encrypted vault. |
| FS-S2 | The vault (secret bodies) is written to disk unencrypted, or with a key derived by anything other than the argon2id/HKDF keyslots. |
| FS-S3 | A relay bearer is issued or accepted with `expiry > now+24h`. |
| FS-S4 | The unlock/DEK key is written to persistent storage, or left un-zeroized after the operation that needed it; or the daemon runs without `mlockall`+`RLIMIT_CORE=0`. |
| FS-S5 | USB absent (beyond the grace window) yet a relay is renewed/issued, a NEW egress swap succeeds, OR a long-lived bearer keeps working past 24h. |
| FS-S6 | A CA leaf is minted for a host NOT actively intercepted for a currently-valid USB-gated relay (an orphan interception cert), including via the general `ca issue` verb. |
| FS-S7 | The broker's REAL upstream call trusts the local CA, the OS system store, or any non-frozen-webpki root for upstream TLS verification; or accepts an upstream host outside the provider's canonical allowlist. |
| FS-S8 | A control-plane request from uid != owner is served (SO_PEERCRED check skipped/failed-open). |
| FS-S9 | A guard that cannot prove its precondition (UUID/keyfile unreadable, peercred unavailable, clock/policy unverifiable) silently allows the op. |
| FS-S10 | A destructive verb runs without `apply` (including an omitted/default-zero proto request being treated as apply), or root-of-trust destruction without `confirm`. |
| FS-S11 | A trust-store file is overwritten without a prior timestamped backup, or a revert removes content other than the exact owned anchor (for the system bundle: any edit to the monolithic bundle other than via owned-file delete + regenerate). |
| FS-S12 | A `--force` flag bypasses any REQ-SEC-* guard. |
| FS-S13 | A passphrase keyslot is unwrapped with argon2 params below the enforced floor, or a silently-added/downgraded keyslot passes unlock without header-MAC drift detection. |
| FS-S14 | `secret get --reveal` returns plaintext without `apply` + audit, or reveals a broker-only secret. |
| FS-S15 | A walk-up `.env-ctl` profile from an untrusted ancestor auto-attaches a NAMED relay without explicit confirmation. |

## 5. Residual risks (stated plainly, not mistaken for containment)

- **A2/A12 are bounded, not prevented.** `SO_PEERCRED` gives uid; owner-session malware passes it and can force the passphrase-fallback (1-of-2) downgrade. The mitigation is blast-radius reduction (24h peer-bound relays, allowlists, durable audit, USB-pull grace drain, entropy-enforced passphrase) + an optional require-both keyslot, not prevention.
- **MITM trust-store breadth** is the largest new attack surface; bounded by REQ-SEC-7 (relay-scoped + USB-gated leaves, no persisted MITM keys) + REQ-SEC-8 (reversible per-tool, child-only wiring; owned-file-only system bundle). NameConstraints is defense-in-depth only (enforcement on user-added roots varies across clients).
- **USB partition-UUID is a convenience selector, not a security boundary** — the keyfile CONTENT is the secret, and presence-gating now PROVES possession of that content. The UUID check only stops accidental wrong-stick auto-unlock.
- **USB keyfile confidentiality on removable media** (A11): `0400` is advisory on vfat/exfat; physical possession is the real boundary.
- **Clock rollback** by owner-session malware could extend a bearer; mitigated by a monotonic issuance floor + `last_seen_ms` high-water + `CLOCK_BOOTTIME` cross-check + eager expiry purge. The floor lives in the owner-writable DB, so it is effective vs accidental skew + external disk attackers, NOT vs owner-session malware (honest A2 framing).
- **Zeroize is best-effort** vs swap/coredumps; mitigated by `mlockall` + `RLIMIT_CORE=0` + `MADV_DONTDUMP` + fixed-capacity buffers; the argon2 1 GiB arena and tonic/hyper internal receive buffers for the passphrase/secret cannot be fully zeroized — documented residuals (encrypted/no swap recommended at install).
- **Native sub-token mint** depends on provider APIs that can change/rate-limit; OPTIONAL best-effort — a provider change degrades to relay-proxy mode, never fails the whole broker closed.
- **At-rest backend (OI-1):** locked decision 3's "libSQL/SQLite" + "NO C deps" are mutually exclusive (libSQL bundles C SQLite, VERIFIED); A4/FS-S2's "no C weak-default surface" holds only under the pure-Rust backend ruling.

## 6. Fail-closed guard engine (Phase 0 signatures)

```rust
/// Some(reason) => REFUSE (-> OpStatus::Refused + SecretEvent::GuardRefused). None only on affirmative pass.
pub enum SecGuard {
    UsbPresent { partition_uuid: String },   // PARTUUID pre-filter + cryptographic keyfile-possession proof
    RelayValid { relay_id: String },         // enabled && !revoked(policy & bearer) && expiry>now && usb-possession-gated
    LeafBackedByRelay { host: String },      // an active, USB-gated relay's allowlist covers host (per SAN)
    PeerIsOwner,                             // SO_PEERCRED uid == owner uid
    VaultEncryptedAtRest,                    // store opens as AEAD ciphertext, never plaintext
    DryRunUnlessApply { apply: bool, confirm: bool, destructive: Destructiveness }, // apply==false (proto default) => refuse
}
pub fn check_sec_guards(guards: &[SecGuard], ctx: &UnlockContext) -> Option<String>;
pub struct UnlockContext {
    pub usb_keyfile_possessed: bool,         // PROVEN possession, not mere UUID match
    pub usb_partition_uuid: Option<String>,  // resolved selector (pre-filter only)
    pub usb_absent_since: Option<std::time::SystemTime>, // drives the swap-time grace window
    pub peer_uid: Option<u32>,
    pub owner_uid: u32,
    pub now: std::time::SystemTime,
}
```
