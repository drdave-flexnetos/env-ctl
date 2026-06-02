# env-ctl — Phase-1 Crypto + Vault Security Audit

**Target:** committed, building code (54 tests green) under `crates/secrets-engine/src/`
(`vault/crypto.rs`, `vault/aad.rs`, `keyslot.rs`, `vault/audit.rs`, `vault/store.rs`, `lib.rs`, `guard.rs`).
**Cross-references:** `docs/THREAT-MODEL.md` (FS-S*/REQ-SEC-*), `docs/DESIGN-NOTES.md` (HF-*/CF-*/OI-*),
`docs/research/{01,02,13}`.
**Method:** 8 lens reports deduplicated + reconciled against the source. Every escalated finding was
re-derived from the code; two lens findings were **downgraded as false positives / over-rated** after
line-level verification (called out below). Adversary assumed: a determined local attacker with
store/disk/backup write access, malformed/adversarial stored bytes, and owner-session malware (A2/A12).

---

## 1. Executive verdict

**The Phase-1 at-rest cryptography and keyslot design are sound and fit for a secrets vault.** The
confidentiality and key-integrity core is correct, well-tested, and conservative:

- **AEAD (`crypto.rs`)** — XChaCha20-Poly1305 with a fresh 24-byte `OsRng` nonce per seal, full
  16-byte Poly1305 tag (never truncated), canonical fixed-width AAD authenticated on both seal and
  open, decrypt as the sole correctness oracle, nonce-length validated before use, plaintext returned
  in `Zeroizing`. A CFRG draft KAT pins the wiring. No defects.
- **Keyslots / KDF (`keyslot.rs`)** — Argon2id at a 256 MiB / t≥3 / p≥1 floor enforced at THREE
  layers (init-time `Err`, unlock-time pre-filter that also blocks the `Params::new` panic, and AAD
  binding so a silent param swap fails the tag); HKDF-SHA256 with a versioned domain-separated `info`
  for the 64-byte-CSPRNG USB keyfile; DEK-keyed BLAKE3 header MAC over the canonical slot set + issuance
  floor, verified constant-time on every unlock. The 1-of-2 OR semantics are stated honestly (the
  `RequireBoth` "2FA" branch was deliberately severed, CF-3). No defects.
- **Key material in RAM** — `Dek`/`Kek` are `ZeroizeOnDrop`, never `Serialize`, never leave the
  `RwLock`-protected `Vault`, zeroized on `lock()`/drop; passphrase + recovered plaintext wrapped in
  `Zeroizing`. No key escape found.
- **Store boundary** — the `Store` only ever sees ciphertext + non-secret metadata; the DEK/plaintext
  never cross it. A lying store breaks decryption (DoS) but cannot breach confidentiality (AEAD tag).
  The row_id reserve→seal→insert TOCTOU (HF-2) is correctly closed under the vault write lock.
- **State machine + gating** — idempotent unlock short-circuit before any KDF work (no factor-oracle
  timing leak, OI-17), generic `UnlockFailed`, reveal gate apply-gated + broker-only-refused (FS-S14),
  durable audit appended before every security RPC returns (HF-14), dry-run encoded as wire
  `apply=false` (FS-S10), `PeerIsOwner` SO_PEERCRED equality (FS-S8). The relay/CA/run paths are
  correctly `todo!()` and refused by the all-uncertain guard context (out of Phase-1 scope).

**One real defect** keeps the audit-log integrity sub-system from fully meeting its own durable
truncation-detection promise: `verify_audit_anchor_with` accepts the stored anchor MAC if it matches
**any** row in the live chain rather than binding a **monotonic** tail. An attacker who controls the
store **and** holds a previously-valid `vault.audit_head` snapshot (stolen disk/backup — in scope) can
truncate recent audit rows and replay the stale anchor to pass verification. This **does not** touch
secret confidentiality, the DEK, or AEAD integrity; it weakens tamper-evidence of **recent audit
history**. It is a genuine HIGH defect in a security mechanism, not a confidentiality break — so the
crypto+vault core is sound, but **this finding is on the must-fix-before-sign-off list** because it
defeats a guarantee the code and `META_AUDIT_HEAD` doc-comment explicitly advertise.

**Verdict: SOUND for at-rest confidentiality and key handling; CONDITIONALLY sound for audit
integrity — sign off Phase-1 only after H-1 is fixed (or the residual is formally accepted and
documented in the threat model).**

---

## 2. Findings (severity-sorted)

| # | Sev | Title | Location | Impact | Fix | Conf |
|---|-----|-------|----------|--------|-----|------|
| H-1 | **High** | Audit anchor verifies against ANY row, not a monotonic tail → stale-anchor replay defeats truncation detection | `lib.rs:817-825` (`verify_audit_anchor_with`); advance at `lib.rs:770-782`; doc `lib.rs:53-59` | Store-write attacker holding a prior `vault.audit_head` snapshot truncates recent rows (failed unlocks, locks, reads) and rewrites the anchor to a previously-valid value; `verify_chain` passes (shorter clean chain) and the replayed anchor still matches a surviving row → truncation undetected, evidence silently dropped. Confidentiality/DEK/AEAD unaffected. | Bind a **monotonic issuance counter** into the anchor: `audit_head_mac(dek, issuance_id, max_seq, tail_hash)` with `issuance_id` persisted + strictly increasing per advance; reject any anchor whose counter/seq is below the stored high-water. Matching `rows.last()` alone is **insufficient** (the replayed A5 equals the tail anchor of a truncated-to-5 chain). Add a regression test that truncates AND rewrites the anchor to a captured earlier value. | High |
| M-1 | Medium | `Store::put_secret` does not enforce the documented version-monotonicity contract | `store.rs:207-225`; contract `store.rs:85-91` | A hostile/buggy `Store` can persist a row with a wrong/duplicate `(name, version)`. The engine sealed the AAD against the version it computed, so a mismatch fails the AEAD tag at open → DoS (un-openable record), not a confidentiality breach. The contract boundary is implicit rather than codified. | In `put_secret`, assert `row.version == max_version(row.name) + 1` (and `== 1` when none exists); `bail!` otherwise. Defense-in-depth + earlier, observable failure. | Medium |
| M-2 | Medium | Audit anchor advance lags the true tail under concurrency / crash | `lib.rs:741-766`, `770-782` | `advance_audit_anchor_if_unlocked` runs after `append_audit` under a separate read lock; a concurrent append, or a crash between append and advance, leaves the persisted anchor behind the real tail. Not exploitable (the unkeyed chain covers the gap), but the "anchor binds the exact tail at each append" promise is soft. | Either hold the vault write lock across append+advance, or fold the advance into `append_audit` under the store lock. For a single-operator local vault this is acceptable as a documented residual; pairs naturally with the H-1 monotonic-counter fix. | Medium |
| L-1 | Low | Rows appended while LOCKED are unanchored (init / failed-unlock / lock) — drop-above-anchor gap | `lib.rs:741-766` (comment 754-760), `796-804` | Rows written while Locked sit above the last DEK-anchored seq and are covered only by forward unkeyed linkage; a store attacker can drop them and re-link a clean shorter chain. **Documented limit**, and partially subsumed by H-1's counter fix (a monotonic seq high-water also catches this). Honest A2 residual. | Accept + document under THREAT-MODEL A2, OR record locked-time security events under a passphrase/USB-KEK secondary anchor, OR re-emit a DEK-anchored marker immediately post-unlock. | Medium |
| L-2 | Low | `RwLock`/`Mutex` `.expect()` poison panics | `lib.rs:300,428,442,447,468,540,771,788`; store `*.expect()` in test helpers | A thread panic while holding the vault lock poisons it; subsequent ops panic. Single-operator daemon → not attacker-controlled today; a future multi-threaded service could make it a DoS vector. | Acceptable for the single-operator model; if it goes multi-threaded, recover via `into_inner()` or use a non-poisoning lock. Document the single-writer assumption. | Medium |
| L-3 | Low | `push_len_prefixed` length cast is `debug_assert!` only (audit + keyslot canonical encoding) | `audit.rs:53-60`; `keyslot.rs:129-136` | In release the `u32` length cast silently wraps for a ≥4 GiB field, which would (theoretically) break canonical injectivity of the hash chain / AAD. Unreachable in practice (real fields are tiny: salts, UUIDs, 48-byte wrapped DEK, small JSON). Hardening nit, not a live defect. | Promote to an unconditional `assert!`/checked cast, or impose a sane max-field length and return an error. | Low |
| L-4 | Low | `derive_key`/`keyed_hash` MAC intermediates not wrapped in `Zeroizing` | `lib.rs:899,904` (`audit_head_mac`); `keyslot.rs:305-308,326` (`header_mac`) | The BLAKE3 `Hash` temporaries (derived MAC key + 32-byte MAC output) are short-lived and the OUTPUT is a non-secret MAC persisted in plaintext. The derived *key* is a brief uncleared intermediate. Hygiene departure from the crate's zero-once-done norm, not a leak. | Optional: scope-zeroize the derived key or add a comment that the MAC output is intentionally non-secret. | High |
| I-1 | Info | `dek_generation` floor/upper-bound not range-checked beyond the slot cross-check | `lib.rs:390-401,477,857-865` | A malformed meta `dek_generation` (e.g. 0) is caught at unlock by the `stored == max(slot_generation)` cross-check (HeaderMacMismatch) and any record mis-seal fails AEAD at open. Theoretical only. | Optional defense-in-depth: reject `generation < 1`. | Medium |
| I-2 | Info | `secret_put` does not re-assert `dek_generation` against the verified slot set | `lib.rs:477-489` | A store that regresses `META_DEK_GENERATION` between unlock and put could seal a record under a stale generation → that record fails AEAD on future open (DoS, caught late), never a confidentiality break. | Optional: cache the unlock-verified generation in vault state and seal against it (mirror the unlock cross-check) to fail at put-time. | High |
| I-3 | Info | Committing-AEAD decision documented but unresolved | `research/01-aead-at-rest.md:137-138` | XChaCha20-Poly1305 is non-committing; benign under the single-DEK design. Becomes relevant only if multi-key/overlapping-rotation scenarios emerge. | Record the explicit decision in DESIGN-NOTES; re-evaluate if the threat model gains key-multiplicity. | High |
| I-4 | Info | Nonce `to_vec()` allocation / minor comment gaps | `crypto.rs:60,115`; `keyslot.rs:80-83` (`saturating_mul` intent); `store.rs:69-72` (Store contract wording) | Cosmetic. 24-byte nonce heap alloc is negligible; `saturating_mul` rejects out-of-spec `p_lanes` cleanly. | Add clarifying comments only. | High |

### Reconciliation notes — lens claims corrected on verification

- **REJECTED (false positive): "Out-of-bounds panic in `hex_decode`" (lens "Panic-safety", rated HIGH).**
  `lib.rs:919` returns `None` on odd length **before** the loop, so `i` always lands on an even index
  and `len` is even; therefore `i <= len-2` and `bytes[i+1] <= bytes[len-1]` is always in bounds
  (`lib.rs:918-931`). The premise "an odd-length string that passes the modulo check" is impossible.
  **No defect.** (Tightening the loop to `i + 1 < bytes.len()` is harmless but unnecessary.)
- **DOWNGRADED: audit-anchor replay rated CRITICAL by the "Audit chain" lens → reconciled to HIGH (H-1).**
  The attack is real and correctly identified, but it does not breach secret confidentiality, expose
  the DEK, or forge a valid ciphertext/MAC (the anchor remains unforgeable without the DEK — the
  attacker only *replays* a value the vault itself once emitted). It degrades audit-trail
  truncation-evidence for recent history under a store+snapshot attacker. Genuine defect, must-fix —
  but HIGH, not CRITICAL.
- **DOWNGRADED: `push_len_prefixed` truncation rated MEDIUM → reconciled to LOW (L-3).** Requires a
  ≥4 GiB single canonical field, unreachable with the actual data; release-only `debug_assert` is the
  only gap.

---

## 3. Per-invariant conformance

| Invariant | Status | Evidence |
|---|---|---|
| **FS-S1** real key never in child env/argv/file | N/A (Phase-4) | `run_child`/inject are `todo!()` (`lib.rs:685-691`); correctly unproven |
| **FS-S2** vault bodies never plaintext / only argon2id-HKDF-derived | **UPHELD** | per-record XChaCha20-Poly1305 (`crypto.rs`); DEK wrapped under argon2id + HKDF keyslots only (`keyslot.rs`); store sees ciphertext only (`store.rs`) |
| **FS-S3** bearer expiry ≤ now+24h | N/A (Phase-4) | broker/relay `todo!()` |
| **FS-S4** DEK never persisted / always zeroized | **UPHELD** | `Dek` ZeroizeOnDrop, not `Serialize`; minted+wrapped+dropped in `init_vault` (`lib.rs:204,289`); `lock()` replaces with `Locked` → wipe (`lib.rs:442-444`); mlockall is daemon-side per threat model |
| **FS-S5** no egress/renewal with USB absent | N/A (Phase-4) | relay path unimplemented; **but** H-1 weakens the *audit-evidence* half of FS-S5's spirit (durable record of locked-time events) — see H-1 |
| **FS-S6 / FS-S7** MITM-leaf scoping / upstream root trust | N/A (Phase-4) | `ca_issue`/relay `todo!()`; `LeafBackedByRelay` refuses in all-uncertain ctx |
| **FS-S8** control-plane uid==owner | **UPHELD** (engine half) | `PeerIsOwner` requires `Some(uid)==owner_uid` (`guard.rs:76-78`); daemon must wire SO_PEERCRED |
| **FS-S9** uncertain guard never silently allows | **UPHELD** | `check_sec_guards` refuses every uncertain branch (`guard.rs:60-101`); phase0 acceptance test |
| **FS-S10** dry-run default / no apply-by-omission | **UPHELD** | `DryRunUnlessApply` refuses `!apply`; proto3 bool defaults false (`guard.rs:83-95`) |
| **FS-S11** trust-store backup-before-clobber | N/A (Phase-4) | not in Phase-1 scope |
| **FS-S12** no `--force` bypass | **UPHELD** | no force path; guards are declarative + fail-closed |
| **FS-S13** no sub-floor / silently-downgraded keyslot | **UPHELD** | floor checked init-time (`lib.rs:185-198`), unlock pre-filter (`lib.rs:324-334`), `kek_from_passphrase` hard-assert (`keyslot.rs:268-279`), AAD-bound params + DEK header MAC (`keyslot.rs`); generation cross-check (`lib.rs:390-401`) |
| **FS-S14** reveal needs apply+audit, refuses broker-only | **UPHELD** | reveal gate (`lib.rs:584-616`): broker-only refused, `!apply` refused, audited on reveal |
| **FS-S15** untrusted-ancestor profile auto-attach | N/A (Phase-4) | not in scope |
| **HF-2** canonical AAD, never stored, reconstructed at open | **UPHELD** | `record_aad` 39-byte fixed-width, const-asserted (`aad.rs:38-43`), reconstructed at open (`lib.rs:561-566`), not serialized |
| **HF-3** keyslot AAD binds KDF/identity; tamper → tag fail | **UPHELD** | `keyslot_aad` length-prefixed, injectivity-tested (`keyslot.rs:166-184`) |
| **HF-5 / OI-2** reveal escape-hatch gated | **UPHELD** | see FS-S14 |
| **HF-14** durable audit before return | **UPHELD** (with M-2/L-1 caveats) | append before commit/return (`lib.rs:421-426,518,605`); anchor freshness is soft under crash/concurrency (M-2) and locked-time rows unanchored (L-1) |
| **OI-8** DEK-keyed header MAC, constant-time | **UPHELD** | `verify_header_mac` uses `subtle::ConstantTimeEq` (`keyslot.rs:339-350`) |
| **OI-16** OsRng-mandated nonces | **UPHELD** | seal + wrap use `generate_nonce(&mut OsRng)`; seeded RNG only under `#[cfg(test)]` |
| **OI-17** single generic unlock failure | **UPHELD** | one `UnlockFailed`; idempotent short-circuit before KDF (`lib.rs:300-302`) |
| **CF-3** no nominal `RequireBoth` 2FA | **UPHELD** | variant severed from unlock machine + warded by comment (`keyslot.rs:46-52`) |
| **Audit truncation/whole-rewrite resistance** (research 13 §"signed head") | **VIOLATED (partial)** | DEK-keyed anchor exists, but its verification is non-monotonic and replayable (H-1); research 13 §1.14/§5 calls for a signed/monotonic head — the monotonic property is not yet met |

---

## 4. Must-fix before Phase-1 sign-off

1. **H-1 — Audit anchor monotonicity.** Bind a strictly-increasing issuance counter (and/or persisted
   `max_seq` high-water) into `audit_head_mac` and reject any anchor at/below the stored high-water;
   matching only `rows.last()` is **not** sufficient. Add a truncate-AND-replay-stale-anchor
   regression test. *(If the operator instead chooses to accept the residual, it must be written into
   THREAT-MODEL.md under A2 as an explicit, signed-off limitation — but the default expectation for a
   secrets vault is to fix it.)*
2. **M-1 — Codify the version-monotonicity contract in `put_secret`** so a hostile/buggy store is
   rejected at write time rather than silently producing un-openable records.

Everything else (M-2, L-1..L-4, I-1..I-4) is hardening / documentation and may be deferred or accepted
as a documented residual. The `hex_decode` HIGH from the panic-safety lens is a **false positive** and
requires no change.
