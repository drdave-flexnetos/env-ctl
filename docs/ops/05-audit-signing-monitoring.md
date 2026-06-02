# env-ctl ops — Ed25519 audit-head signing + log export/monitoring

> **Scope.** A concrete ops/deploy design for adding (a) **Ed25519 signing of the audit chain head** for
> off-box / third-party verifiability, and (b) **audit-log export + monitoring/alerting** (journald +
> NDJSON + SIEM) to the *exact* env-ctl system described in this repo's design docs. Targets the
> shipping topology: one central `secretd` on the dual-RTX-5090 box, libSQL vault via loopback `sqld`,
> relay-bearers-only HTTPS edge for remote thin clients (incl. the Telegram cloud agent), local UDS +
> `SO_PEERCRED` control plane, USB-PARTUUID unlock default, VPS deferred.
>
> **Status:** RESEARCH-INFORMED DESIGN · sourced against the live ecosystem (June 2026) and
> cross-referenced against this repo's code + design docs. Claims that could not be independently
> confirmed are flagged **[UNVERIFIED]**. **READ-ONLY** — no code in this repo was changed to produce
> this doc.
>
> **Phase fit.** Chain core lands in **Phase 1** (`docs/ROADMAP.md`, "Vault core"). Ed25519 head-signing
> is a **Phase 1–4 additive layer** (it rides on the CA/DEK key machinery from Phase 1/4). Export +
> alerting is a **Phase 5 daemon** concern (`secretd` owns tracing, the on-disk log, and the network
> edge). The merge into `envctl` is **Phase 7**.

---

## 0. What is actually already true in this repo (ground truth, not aspiration)

Before adding anything, pin down what exists so the design is additive, not duplicative. Verified by
reading the source/docs in this repo:

- **The hash chain is real, not a stub.** `crates/secrets-engine/src/vault/audit.rs` implements
  `canonical_row`, `row_hash`, `link_row`, `verify_chain`, `genesis_hash` with full unit tests
  (tamper/reorder/delete/insert all break at the right `seq`). This is the single source of truth both
  the `InMemStore` and the future libSQL store funnel through.
- **The chain hash order is `blake3(prev_hash ‖ canonical_row(rec))`.** The code does
  `h.update(prev_hash); h.update(&canonical_row(rec))` (`audit.rs:113-118`). `canonical_row` itself
  prepends a 20-byte domain prefix `b"env-ctl/v1/audit-row"` and length-prefixes every field.
  - **DOC/CODE DRIFT to fix (not blocking this design):** `docs/db/schema.sql:168` comments the order
    as `BLAKE3(canonical(...) ‖ prev_hash)` — the *reverse* of the code. And `schema.sql:167` says
    `prev_hash` is "zeroes for seq=1", but the code uses a **domain-separated `genesis_hash()`**
    (`blake3(b"env-ctl/v1/audit-genesis")`), explicitly *not* all-zero. The code is authoritative; the
    schema comments should be corrected to match. Any off-box verifier MUST follow the code order.
- **Whole-rewrite / truncation defense already exists, and it is NOT Ed25519.** Per the module header in
  `audit.rs:13-17` and `docs/db/schema.sql:25`, the engine keeps a **DEK-keyed tail anchor**
  `meta.audit_head` (and `Engine::verify_audit_anchor`) binding the expected `(max_seq, tail_row_hash)`
  to the unlocked DEK; only an unlocked vault can advance it. The plain hash chain is, by design, only
  tamper-evident against *partial* mutation. **So the gap Ed25519 fills is specifically off-box /
  third-party verifiability** (a verifier who does NOT hold the DEK), not "the only rewrite defense" —
  do not oversell it.
- **Ed25519 is already in the system.** The remote relay edge uses **DPoP (RFC 9449) with per-client
  Ed25519 keys**, recording each client's JWK thumbprint `jkt` (`docs/SERVER-MODE.md:108-118`). So an
  Ed25519 verify/sign surface and a key-thumbprint discipline already exist to mirror.
- **Crypto backend is `ring`, explicitly NOT `aws-lc-rs`** (`docs/ROADMAP.md` Phase 0: "pinned to the
  **ring** crypto backend (no aws-lc-rs)"; CI gate `! cargo tree -i aws-lc-sys`). Any signing crate
  added MUST NOT pull `aws-lc-sys`.
- **Durable-before-RPC is the law (HF-14 / FS-S26).** Security outcomes are committed to `audit_log`
  synchronously before the RPC returns (`docs/DESIGN-NOTES.md:55`); the `SecretEvent` mpsc stream is
  cosmetic/best-effort (`DESIGN-NOTES.md:69`). On the remote edge, **FS-S26**: "a remote swap returns
  Allowed before its audit row is durably committed" is forbidden (`SERVER-MODE.md:219`).
- **The on-disk log home already exists.** `~/.local/state/env-ctl/` (0700) holds `secretd.log` and the
  **operator-box-local audit mirror / `audit_head` second home** (`docs/ARCHITECTURE.md:126`,
  `SERVER-MODE.md:219`). NDJSON export belongs here — it is an extension of an existing artifact, not a
  new directory.
- **The engine is sync + non-printing; the daemon owns I/O.** `tracing-subscriber` is owned by `secretd`
  (`ROADMAP.md` Phase 5). Therefore **journald/NDJSON/SIEM/alert wiring lives entirely in `secretd`**,
  behind a `Store`-trait-style seam — never in `envctl-secrets-engine` (which must stay pure-Rust with
  no tokio/tonic/hyper, per the Phase 0 dep gate).

**Net:** the chain is done; the anchor (DEK-keyed, on-box) is done. This doc adds an **off-box trust
anchor (Ed25519 head signature + published pubkey)** and the **operational plumbing** (export +
monitoring + alerting) — both additive, both fail-closed.

---

## 1. Threat model alignment (why each piece exists)

Mapped to `docs/THREAT-MODEL.md`. The design is honest about what signing does and does not buy.

| Threat (THREAT-MODEL §2/§5) | What audit signing + monitoring contributes |
|---|---|
| **A2 / A12 — owner-session malware (bounded, not prevented)** | Signing does NOT prevent it: malware running as owner can drive an *unlocked* daemon to write/sign new genuine rows, or (worst case) rotate the signing key and re-sign. The contribution is **blast-radius visibility**: every `relay_swap`/`secret_read`/`relay_mint` is durably audited (existing) AND **exported off-box in near-real-time** (new), so an external SIEM holds an append-only copy the local attacker cannot retroactively suppress. **Honest framing kept** — defense-in-depth, not containment. |
| **A4 — stolen disk / backup** | The `audit_log` table is ciphertext-adjacent metadata; the chain hashes are public. A thief cannot forge a *partial* edit (chain breaks) and cannot advance `meta.audit_head` (DEK-keyed) — **and now** cannot produce a head that verifies against the **published Ed25519 public key** without the (DEK-sealed) private key. |
| **A8 — forged relay policy row (owner-session)** | Egress is already host-allowlist-bounded. Monitoring adds an alert when a `relay_swap` targets, or a policy is edited toward, a host outside the canonical provider allowlist. |
| **External auditor / regulator** (not an adversary, a *requirement*) | The DEK-keyed anchor is *unverifiable off-box* (verifier would need the DEK == the secret). **Ed25519 head signing is the enabler**: publish the pubkey, an air-gapped verifier confirms the head without any ability to forge (RFC 8032 asymmetry). Optional RFC 3161 TSA adds trusted-time witness for SEC Rule 17a-4-style acceptance. |
| **FS-S26 — remote swap Allowed before durable audit** | The NDJSON/journald export MUST hang off the *same* commit path as the durable row (after commit, before/at RPC return for the durable sink; the SIEM forward may lag). Export lag must NEVER gate `Allow`, and a missing export must NEVER fail a swap *open*. |
| **FS-S4 / zeroize residuals** | The Ed25519 **private** signing key is key material: sealed under the DEK at rest, in-RAM only while unlocked, `Zeroizing`, dropped/zeroized on lock and on USB-pull (mirrors the in-RAM CA `Issuer`, `ROADMAP.md` Phase 4). |
| **FS-S9 — fail-closed guards** | A head signature that does not verify on unlock => **refuse to unlock / refuse egress**, identical posture to a broken chain. Never "verify failed, continue." |

**Two hard rules carried from the threat model into this design:**
1. **No new network surface.** Adding signing/monitoring MUST NOT add a listener. The listener
   self-check (`SERVER-MODE.md:91`) refuses to start unless exactly one non-loopback listener (the
   relay edge) exists. SIEM/alert egress is **outbound from `secretd`** (or a sidecar reads the NDJSON
   file) — never an inbound port.
2. **No `aws-lc-sys`, exactly one `rustls`, zero libSQL in the engine.** Any crate added for signing or
   export is checked against the existing Phase 0/7 `cargo tree` gates.

---

## 2. Ed25519 audit-head signing — recommended design

### 2.1 Design decision: key custody = the DEK, rotation = per DEK-generation

Three custody options were considered; the recommendation is **(C)**:

| Option | Pro | Con | Verdict |
|---|---|---|---|
| (A) Rotate signing key on **every USB unlock** | Maximum forward-security granularity | High churn; an old head signed under key *gen N* becomes unverifiable once key *gen N+1* is the only published key unless every historical pubkey is retained; complicates the off-box verifier | Rejected — churn vs. benefit poor for a single-operator vault |
| (B) One **long-lived** signing key | Simplest verifier | No forward security; one key compromise re-signs all history | Rejected — defeats the point |
| **(C) One signing key per `dek_generation`, sealed under that DEK, all historical pubkeys retained & published** | Reuses the **existing** DEK-rotation machinery (full re-encryption under one resumable txn, `schema.sql:65-75`); rotation reasons already enumerated (`init`/`scheduled-rotation`/`compromise`/`passphrase-change`); forward security at the natural compromise boundary; verifier walks a short pubkey history | **RECOMMENDED** |

Rationale: env-ctl **already** rotates the DEK as full re-encryption and already re-seals the CA key and
the HMAC key on rotation (`schema.sql:30-39, 171-186`). Binding the audit signing key to
`dek_generation` means: (1) zero new rotation orchestration, (2) a `reason='compromise'` rotation
*also* rotates the audit signing key (correct — you want a fresh signing key after compromise), and
(3) the verifier needs only the small, published set of per-generation pubkeys.

### 2.2 What gets signed

Sign the **anchor tuple**, not raw rows (the chain already protects rows). The signed message binds the
head to the vault identity and the DEK generation so a head cannot be replayed across vaults/generations:

```text
AUDIT_HEAD_DOMAIN  = b"env-ctl/v1/audit-head"          // 21 bytes, distinct from audit-row/genesis
msg = AUDIT_HEAD_DOMAIN
    || vault_id (16B)                                  // meta.vault_id, binds to THIS vault
    || dek_generation : u32be                          // binds to the signing key's generation
    || max_seq : i64be                                 // the head sequence number
    || tail_row_hash (32B)                             // verify_chain's last row_hash
    || head_ts_ms : u64be                              // monotonic; cross-checked vs issuance_floor_ms
sig = Ed25519_sign(audit_sign_sk[gen], msg)            // 64 bytes, RFC 8032 pure EdDSA (no pre-hash)
```

Use **pure Ed25519 over the raw `msg`** (RFC 8032 — Ed25519 internally hashes with SHA-512; do NOT add an
outer BLAKE3 pre-hash, that would be Ed25519ph/a non-standard variant and complicates external
verifiers). [RFC 8032 §5.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1).

> **Correction vs. an earlier draft:** an outer `blake3(msg)` then `sign_digest(...)` was floated. Don't.
> Standard `SigningKey::sign(&msg)` over the canonical byte string is what every off-box `ed25519-dalek`
> / OpenSSL / `ssh-keygen -Y verify` verifier expects.

### 2.3 Schema additions (libSQL store crate only; engine stays store-agnostic)

Add one table; reuse `meta` for the *current* head pointer. DDL written in the repo's existing style
(`docs/db/schema.sql`); enforced append-only **by discipline** like `audit_log` (no UPDATE/DELETE).

```sql
-- ---- per-DEK-generation Ed25519 key for signing the audit chain head (off-box verifiability) ----
-- Private key sealed under the DEK exactly like ca_key (AAD recomputed from table_tag+id+gen, never
-- stored). Public key is CLEAR and PUBLISHED off-box. Rotated WITH the DEK (full re-encryption txn).
CREATE TABLE audit_sign_key (
  id                 INTEGER PRIMARY KEY,
  dek_generation     INTEGER NOT NULL REFERENCES dek_generation(generation),
  public_key         BLOB NOT NULL,            -- 32B Ed25519 public key, CLEAR (published)
  key_nonce          BLOB NOT NULL,            -- 24B XChaCha20 nonce
  key_ciphertext     BLOB NOT NULL,            -- AEAD(DEK, 32B Ed25519 seed/private, aad=identity-bound)
  jkt                TEXT NOT NULL,            -- base64url(SHA-256(JWK)) thumbprint, mirrors DPoP jkt discipline
  created_at         TEXT NOT NULL,
  superseded_at      TEXT,                     -- set when a newer dek_generation supersedes it
  UNIQUE(dek_generation)
);

-- The CURRENT signed head lives in meta (single source of truth, same row family as audit_head):
--   meta.k = 'audit_head'      -> existing: JSON {max_seq, tail_row_hash} (DEK-keyed anchor)
--   meta.k = 'audit_head_sig'  -> NEW: JSON {dek_generation, max_seq, tail_row_hash, head_ts_ms, sig}
-- audit_head_sig is advanced in the SAME txn that advances audit_head (one atomic head update).
```

Notes:
- The **private key is the 32-byte Ed25519 seed**, AEAD-sealed under the DEK with the same
  identity-binding AAD pattern the CA key uses (`schema.sql:173` "AAD recomputed from
  (table_tag, id, label, dek_generation)"). No `key_aad_tag` column — AAD is recomputed, never stored,
  matching the repo's HF-2 discipline.
- `jkt` mirrors the DPoP thumbprint format so the audit pubkey and the remote-client pubkeys use one
  canonical identifier scheme, and one off-box tool can print/verify both.
- On `dek_generation` rotation: the full-re-encryption txn (already resumable via
  `meta.rotation_in_progress`) re-seals `audit_sign_key.key_ciphertext` for the **surviving** rows under
  the new DEK *and* mints a new `audit_sign_key` row for the new generation, marks the old
  `superseded_at`, and re-signs the current head with the new key. Old pubkeys are retained (never
  deleted) so historical heads stay verifiable.

### 2.4 Engine API additions (sync, pure-Rust, in `envctl-secrets-engine`)

Keep the engine sync and non-printing. Add to the audit module / a sibling:

```rust
// crates/secrets-engine/src/vault/audit_sign.rs  (proposed)
const AUDIT_HEAD_DOMAIN: &[u8] = b"env-ctl/v1/audit-head";

/// Build the canonical head message (see §2.2). Pure, no I/O.
pub fn head_message(vault_id: &[u8; 16], dek_gen: u32, max_seq: i64,
                    tail_row_hash: &[u8; 32], head_ts_ms: u64) -> Vec<u8> { /* ... */ }

/// Sign the head with the in-RAM (DEK-unsealed) signing key. Called inside the durable head update.
pub fn sign_head(sk: &ed25519_dalek::SigningKey, msg: &[u8]) -> [u8; 64] {
    sk.sign(msg).to_bytes()           // RFC 8032 pure EdDSA, no pre-hash
}

/// Off-box-equivalent verify: given the published pubkey for `dek_gen`, the head tuple, and the sig.
/// Returns Ok(()) only on an affirmative pass — every error path is a REFUSAL (FS-S9).
pub fn verify_head(pk: &ed25519_dalek::VerifyingKey, msg: &[u8], sig: &[u8; 64])
    -> Result<(), AuditHeadError> { /* strict; constant-time not required (public data) */ }
```

`SigningKey`/`VerifyingKey` come from **`ed25519-dalek` 2.x** ([docs.rs/ed25519-dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/)).
Hold the in-RAM `SigningKey` in a `Zeroizing` wrapper; `ed25519-dalek` 2.x integrates `zeroize`
(enable the `zeroize` feature) — [crates.io/crates/ed25519-dalek](https://crates.io/crates/ed25519-dalek).

### 2.5 Unlock + write flow (fail-closed)

On **unlock** (after USB-possession + DEK unseal, before the vault is usable):
1. `verify_chain(rows)` — existing; `Err(seq)` => refuse (existing).
2. Verify `meta.audit_head` (DEK-keyed anchor) matches the chain tail — existing.
3. **NEW:** unseal `audit_sign_key.key_ciphertext` for the active `dek_generation`; load the in-RAM
   `SigningKey` (`Zeroizing`).
4. **NEW:** recompute `head_message(...)` from the tail; `verify_head(pk, msg, sig)` against
   `meta.audit_head_sig`. Any mismatch => `GuardRefused{reason:"audit_head_signature_invalid"}` and
   **refuse to enter the unlocked state** (FS-S9 posture).

On every **durable audit append** (the HF-14 path, same txn):
1. `link_row(prev, rec)` -> sealed row -> persist (existing).
2. Advance `meta.audit_head` (existing DEK-keyed anchor).
3. **NEW:** `sign_head(...)` over the new tail; write `meta.audit_head_sig` **in the same txn**. The head
   signature is part of the durable commit — it cannot lag the row (consistent with HF-14 / FS-S26).

On **lock / USB-pull (after grace):** zeroize the in-RAM `SigningKey` along with the DEK and the CA
`Issuer` (existing zeroize choreography, `ROADMAP.md` Phase 2/4).

### 2.6 Backward compatibility / migration

First unlock after the Phase-1+ upgrade, for a vault with no `audit_sign_key` row:
1. Load + `verify_chain` as-is (no signature yet to verify).
2. Mint an `audit_sign_key` row for the active `dek_generation` (Ed25519 keygen from `OsRng`).
3. Sign the current tail; write `meta.audit_head_sig`.
4. Subsequent unlocks verify normally. No historical rows are rewritten; the chain is untouched.

> **[UNVERIFIED]** that no in-flight code already reserves `meta.k='audit_head_sig'` — grep before
> implementing. As of this doc only `audit_head` is referenced (`schema.sql:25`).

### 2.7 Off-box verification tool (operator-facing)

Ship a tiny verifier as an `envctl` subcommand (or a standalone bin) usable on an **air-gapped machine**:

```bash
# Operator exports (over the control plane, USB-gated, read-only) a verification bundle:
#   audit.ndjson            (the exported chain, §3)
#   audit-pubkeys.json      ([{dek_generation, public_key_b64, jkt, created_at, superseded_at}, ...])
#   audit-heads.json        ([{dek_generation, max_seq, tail_row_hash, head_ts_ms, sig_b64}, ...])
#
# On the air-gapped box (no DEK, no vault, no network):
envctl audit verify --chain audit.ndjson --pubkeys audit-pubkeys.json --heads audit-heads.json
#   -> recomputes verify_chain() over the NDJSON
#   -> for each head, picks the pubkey for its dek_generation and checks the Ed25519 sig
#   -> FAILS LOUDLY (nonzero exit) on any chain break, seq gap, or bad signature
```

The verifier reproduces **the code's** hash order (`prev_hash ‖ canonical_row`) and the §2.2 head
message — publish both byte layouts in `docs/` so a third party can re-implement the verifier in any
language (the canonical encoding is already fully specified in `audit.rs:62-109`).

---

## 3. Audit-log export (journald + NDJSON) — recommended design

All in `secretd` (Phase 5), behind a seam so the engine stays I/O-free. Export hangs off the **durable
commit path** (after the audit row + head sig commit), so the exported record is exactly the committed
one.

### 3.1 Sink 1 — systemd journald (structured, via `tracing`)

`secretd` already owns `tracing-subscriber` (ROADMAP Phase 5). Emit one structured event per durable
audit row. The unit runs as a **user service** under `$XDG_RUNTIME_DIR/env-ctl` (control socket) — so use
the user journal.

```rust
// in secretd, on the durable commit path (NOT the cosmetic SecretEvent mpsc):
tracing::info!(
    target: "envctl_audit",
    seq        = rec.seq,
    ts         = %rec.ts,
    event_type = %rec.event_type,
    actor_uid  = rec.actor_uid,
    subject    = rec.subject.as_deref(),
    outcome    = ?rec.outcome,
    row_hash   = %hex::encode(&rec.row_hash),
    head_seq   = head.max_seq,           // current signed head after this commit
    "audit"
);
```

With `tracing-journald` ([docs.rs/tracing-journald](https://docs.rs/tracing-journald/)) fields land as
journald structured fields (uppercased, e.g. `EVENT_TYPE`, `ROW_HASH`):

```bash
# Query the durable audit stream from the user journal:
journalctl --user-unit=env-ctl-secretd.service -t envctl_audit -o json-pretty
# Follow only refusals:
journalctl --user-unit=env-ctl-secretd.service -o json --output-fields=EVENT_TYPE,OUTCOME,SUBJECT -f \
  | jq 'select(.OUTCOME=="Refused")'
```

> **journald structured-field reference:** `journalctl -o json` / `--output-fields` emit/select
> structured fields — [systemd journalctl manpage](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html).
> **[UNVERIFIED]** exact field-name casing produced by `tracing-journald` for nested spans — confirm
> against the installed crate version before writing SIEM parsers against it.

> **Never** put secret material in fields. `audit_log.detail` is already "NEVER contains plaintext secret
> material" (`schema.sql:165`); the exporter must not widen that.

### 3.2 Sink 2 — NDJSON file (SIEM ingestion), in the EXISTING state dir

Append one JSON object per line to the **already-defined** audit mirror home:

- Path: `~/.local/state/env-ctl/audit.ndjson` (dir is 0700, file 0600; matches
  `ARCHITECTURE.md:126` / `SERVER-MODE.md:219`).
- One line per durable row; each line is independently parseable even on truncation.

```json
{"seq":1,"ts":"2026-06-02T14:30:00Z","actor_uid":1000,"event_type":"unlock","subject":null,"outcome":"ok","row_hash":"b1f0...","prev_hash":"e7c9...","head_sig_seq":1}
{"seq":2,"ts":"2026-06-02T14:30:15Z","actor_uid":1000,"event_type":"relay_mint","subject":"tok_9f3a","outcome":"ok","row_hash":"77a2...","prev_hash":"b1f0...","head_sig_seq":2}
{"seq":3,"ts":"2026-06-02T14:31:02Z","actor_uid":1000,"event_type":"relay_swap","subject":"tok_9f3a","outcome":"ok","row_hash":"0c4d...","prev_hash":"77a2...","head_sig_seq":3}
```

- **`subject` carries the `token_id`** for `relay_swap`/`relay_mint` rows (OI-11, `schema.sql:158`), so
  each swap line joins to exactly one bearer — this is the forensic key for monitoring.
- **Rotation:** when `audit.ndjson` exceeds e.g. 100 MiB, rename to
  `audit-YYYYMMDDTHHMMSSZ.ndjson` and gzip; retain N days (operator-configurable). The chain `seq` is
  global and monotonic, so rotated segments still concatenate into one verifiable chain.
- **Write discipline (FS-S26-safe):** the NDJSON write happens **after** the durable DB commit. An
  NDJSON write failure is logged + alerted (`AuditExportFailed`) but **MUST NOT** fail the operation
  open — the authoritative record is the committed `audit_log` row; NDJSON is a derived export.
- **Optional `systemd-journald` -> file is redundant;** prefer emitting to journald AND appending NDJSON
  from the same commit hook (dual-sink), rather than scraping the journal back out, so the NDJSON is
  guaranteed to contain `row_hash`/`prev_hash` for off-box `verify_chain`.

### 3.3 Export seam (lives in `secretd`, not the engine)

```rust
/// secretd-side. Engine calls back into this AFTER the durable audit txn commits.
pub trait AuditExport: Send + Sync {
    /// Best-effort, post-commit. MUST NOT block the RPC return for long and MUST NOT fail it open.
    fn export(&self, rec: &AuditRecord, head: &SignedHead);
}
struct DualSink { ndjson: Arc<Mutex<BufWriter<File>>> /* + journald via tracing */ }
```

The engine emits the durable row (sync); `secretd` wraps the commit and invokes `AuditExport::export`
on the same thread after commit, before sending the gRPC response (so a crash between commit and
response still leaves the durable row — HF-14 — and at worst loses the NDJSON line, which the next
`verify`/reconcile rebuilds from the DB).

---

## 4. Monitoring + alerting — recommended design

### 4.1 Alert rules (evaluated in `secretd` on each durable row)

| Alert | Condition (over the durable stream) | Severity | Action |
|---|---|---|---|
| `UnlockFailed` | `event_type=unlock` && `outcome=refused` | HIGH | journald error + SIEM + operator notify; threshold N/window for brute-force |
| `UsbAbsentDuringSwap` | a `relay_swap` denied with the USB-absent/grace reason (FS-S5) | MEDIUM | notify; expected on intentional USB pull, alert if unexpected |
| `ChainVerifyFailure` | `verify_chain()` returns `Err(seq)` at unlock or on the background sweep | CRITICAL | **refuse unlock / refuse all egress**; page operator |
| `HeadSigInvalid` | `verify_head()` fails at unlock | CRITICAL | **refuse unlock**; page operator |
| `OutOfAllowlistEgressAttempt` | `relay_swap` `outcome=refused` with host-allowlist reason (A8/HF-11) | HIGH | notify; repeated => possible forged-policy attempt |
| `RemoteClientMismatch` | remote swap denied `PeerMismatch`/`RemoteClientUnknown` (DPoP, SERVER-MODE §4.2) | MEDIUM-HIGH | notify; threshold => possible bearer theft / replay |
| `RevealUsed` | `secret_read` via `secret get --reveal` (apply+confirm) | HIGH | always notify — the one audited plaintext exit (REQ-SEC-6) |
| `AuditExportFailed` | NDJSON/journald sink errored post-commit | LOW-MEDIUM | self-heal alert; the DB row is still authoritative |
| `BrokerOnlyEgressBlocked` | a broker-only secret attempted a native-subtoken/reveal exit | CRITICAL | block (already enforced) + page; indicates misconfig or attack |

Rules are **pure check functions** (a `secretd` `AlertRule` seam), invoked synchronously on each durable
row, emitting to journald (`tracing::warn!`/`error!`) and an optional outbound `AlertSink`. **Alert
dispatch is best-effort and MUST NOT gate `Allow`** (same rule as export).

### 4.2 Operator alerting config (no new inbound surface)

```toml
# ~/.config/env-ctl/alerting.toml   (0600)
[alerting]
enabled        = true
min_severity   = "medium"            # info|low|medium|high|critical

[alerting.journald]
enabled        = true                # always-on local sink

[alerting.webhook]                   # OUTBOUND only; never opens a listener
enabled        = true
url            = "https://hooks.example.com/services/XXXX"   # Slack/PagerDuty/generic
timeout_ms     = 3000
# Per THREAT-MODEL: the Telegram bot token and any relay bearer MUST NOT co-locate with secretd
# (SERVER-MODE.md:138). If alerting to Telegram, run it as a SEPARATE process reading audit.ndjson.

[alerting.unlock_failed]
threshold      = 3
window_secs    = 600                 # 3 failed unlocks / 10 min -> escalate
```

### 4.3 SIEM ingestion (the NDJSON file is the contract)

The NDJSON file is a stable, documented contract; point any agent at it. **No env-ctl-side SIEM
plugin** — keep the daemon lean.

**Filebeat (ELK)** — [elastic.co/docs filebeat log input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-log):
```yaml
filebeat.inputs:
  - type: filestream
    id: envctl-audit
    paths: ["/home/*/.local/state/env-ctl/audit.ndjson"]
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
output.elasticsearch:
  hosts: ["https://localhost:9200"]
```

**Vector** (pure-Rust agent, fits the ethos) — [vector.dev docs](https://vector.dev/docs/reference/configuration/sources/file/):
```toml
[sources.envctl_audit]
type = "file"
include = ["/home/*/.local/state/env-ctl/audit.ndjson"]
[transforms.parse]
type = "remap"
inputs = ["envctl_audit"]
source = '. = parse_json!(.message)'
```

**Datadog Agent** — [docs.datadoghq.com log collection](https://docs.datadoghq.com/agent/logs/):
```yaml
logs:
  - type: file
    path: /home/*/.local/state/env-ctl/audit.ndjson
    service: env-ctl
    source: env-ctl-audit
```

**Example detection (Splunk SPL):**
```spl
source="*/.local/state/env-ctl/audit.ndjson" event_type=unlock outcome=refused
| bucket _time span=10m | stats count by _time, actor_uid | where count > 3
```

---

## 5. systemd unit (the shipping deployment)

`envctl install secretd` lays down a **user** service (`ROADMAP.md` Phase 7; `SERVER-MODE.md:246`). The
unit hardening below complements the runtime mlockall/RLIMIT_CORE posture (THREAT-MODEL §1). Place at
`~/.config/systemd/user/env-ctl-secretd.service`:

```ini
[Unit]
Description=env-ctl secretd (credential broker + vault owner)
After=network-online.target
# Hard dependency on the USB keyslot is enforced IN the daemon (refuses to start with no USB keyslot
# on-box, SERVER-MODE.md:246), not by a device unit, so a missing stick fails closed loudly.

[Service]
Type=notify
ExecStart=%h/.local/bin/envctl secretd --foreground
# Hardening (defense-in-depth ON TOP OF mlockall/RLIMIT_CORE=0/MADV_DONTDUMP done in-process):
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/env-ctl %h/.local/state/env-ctl %h/.config/env-ctl %t/env-ctl
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
# mlockall needs the memlock budget (FS-S4); RLIMIT_CORE=0 is also set in-process:
LimitMEMLOCK=infinity
LimitCORE=0
UMask=0077

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now env-ctl-secretd.service
systemctl --user status env-ctl-secretd.service
journalctl --user-unit=env-ctl-secretd.service -t envctl_audit -f
```

> systemd sandboxing directive reference:
> [systemd.exec manpage](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
> **[UNVERIFIED]** that `MemoryDenyWriteExecute=true` is compatible with every dependency `secretd`
> links at runtime (some JITs/TLS stacks trip it) — test on the box; if a dep needs W^X relaxation,
> drop this one directive and document the residual rather than weakening the others.
> **[UNVERIFIED]** the exact installed binary path (`%h/.local/bin/envctl`) — confirm against the
> Phase 7 install layout.

---

## 6. RFC 3161 TSA anchoring (Phase 2+, OPTIONAL, regulated deployments only)

The DEK-keyed anchor + Ed25519 head signature prove integrity and authenticity off-box. An **RFC 3161
Time-Stamp Authority** additionally proves the head existed at a specific time, witnessed by a trusted
third party — strengthening court/regulatory acceptance (the 2022 SEC Rule 17a-4 amendments recognize
cryptographic audit trails: see `docs/research/13-tamper-evident-audit.md:46`).

- **When:** regulated/compliance deployments, low cadence (once/day or per-N-rows).
- **When NOT:** single-operator internal tooling (the default here) — skip it.
- **What to stamp:** the signed head tuple (or a periodic Merkle root over rows since the last anchor),
  not every row (TSA round-trips cost latency and sometimes money).
- **Standard:** [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html); free decentralized alternative
  is [OpenTimestamps](https://opentimestamps.org/) (Bitcoin anchoring, weaker formal acceptance, higher
  latency).

```sql
CREATE TABLE audit_tsa_anchor (
  id            INTEGER PRIMARY KEY,
  seq_start     INTEGER NOT NULL,
  seq_end       INTEGER NOT NULL,
  head_msg_hash BLOB NOT NULL,            -- SHA-256 of the signed head message (TSA-native hash)
  tsa_url       TEXT NOT NULL,
  tsa_token     BLOB NOT NULL,            -- RFC 3161 TimeStampToken, ASN.1 DER
  requested_at  TEXT NOT NULL,
  tsa_gen_time  TEXT                      -- parsed genTime from the token
);
```

- **Pure-Rust caveat:** the RFC 3161 request/response is ASN.1 (CMS/PKCS#7). A pure-Rust path exists via
  `rasn`/`der`/`cms` crates, but **[UNVERIFIED]** that a maintained, pure-Rust RFC-3161-specific crate
  with no C/OpenSSL transitive dep is available at implementation time — **verify against crates.io and
  the `! cargo tree -i aws-lc-sys` / no-openssl-sys gates before adopting.** If only an OpenSSL-backed
  crate exists, TSA must run in a **separate sidecar process**, never linked into `secretd`. The TSA hash
  is SHA-256 (RFC 3161-native); `sha2 = "0.10"` is already a dep (`research/13:54`).

---

## 7. Deployment checklist (this exact system)

**Profile A — on-box (the DEFAULT; dual-RTX-5090 box, USB local):**
1. `envctl install secretd`; enroll USB keyslot (daemon refuses to start on-box with no USB keyslot).
2. Store: `store.profile="embedded"` — embedded `sqld` bound to **loopback only**; `secretd` uses the
   pure-Rust `remote` libSQL client (`SERVER-MODE.md:75,247`). C core isolated in `sqld`.
3. Phase 1 lands the chain + DEK-keyed anchor (already coded in the engine).
4. Add `audit_sign_key` table + `meta.audit_head_sig`; Ed25519 keygen at vault init / first upgraded
   unlock (§2.6); sign head in the durable head-update txn (§2.5).
5. Phase 5: enable journald + NDJSON dual-sink export (§3) and alert rules (§4) in `secretd`.
6. Publish the verification bundle (§2.7) to an off-box/air-gapped location periodically.
7. Point a SIEM agent (Vector/Filebeat/Datadog) at `~/.local/state/env-ctl/audit.ndjson` (§4.3).
8. Configure `~/.config/env-ctl/alerting.toml` (outbound webhook only; Telegram alerting = separate
   process per `SERVER-MODE.md:138`).

**Profile B — VPS (DEFERRED — operator-authorizer protocol open, OI-SM-2/3, `ROADMAP.md` Phase -1 note):**
- At-rest DEK is **passphrase-argon2id only** (USB absent) — a documented structural downgrade
  (THREAT-MODEL A12). Export + signing become *more* important: the operator-box-local audit mirror +
  off-box Ed25519 verification are how a compromised VPS cannot silently hide unauthorized egress.
- `verify_chain` + `verify_head` MUST succeed at boot or the daemon refuses to serve.
- Do not ship until the authorizer protocol is specced.

---

## 8. Dependency verification (June 2026)

| Crate / std | Version | Status | Source |
|---|---|---|---|
| `ed25519-dalek` | 2.x | Pure-Rust EdDSA (RFC 8032); enable `zeroize`; verify it does NOT pull `aws-lc-sys` | [docs.rs/ed25519-dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/) · [crates.io](https://crates.io/crates/ed25519-dalek) |
| `blake3` | 1.5 (repo pin) | Already a dep; chain hash | [crates.io/crates/blake3](https://crates.io/crates/blake3) |
| `sha2` | 0.10 (repo pin) | Already a dep; TSA SHA-256 if used | [crates.io/crates/sha2](https://crates.io/crates/sha2) |
| `serde_json` | 1.0 | Already a dep; NDJSON + canonical detail | [crates.io/crates/serde_json](https://crates.io/crates/serde_json) |
| `zeroize` | 1.x | Already a dep (key material) | repo `Cargo.toml` |
| `hex` | 0.4 | Pure-Rust; `row_hash` display | [crates.io/crates/hex](https://crates.io/crates/hex) |
| `tracing` / `tracing-subscriber` | 0.1 / 0.3 | Daemon-owned (Phase 5) | [crates.io/crates/tracing](https://crates.io/crates/tracing) |
| `tracing-journald` | latest | journald sink | [docs.rs/tracing-journald](https://docs.rs/tracing-journald/) |
| RFC 3161 TSA crate | — | **[UNVERIFIED]** pure-Rust no-C option; sidecar if OpenSSL-only | verify crates.io at impl time |
| `ring` crypto backend | repo-pinned | Backend; **no `aws-lc-rs`/`aws-lc-sys`** | `ROADMAP.md` Phase 0 |

**Gates any addition must still pass (from `ROADMAP.md` Phase 0/7):**
`! cargo tree -i aws-lc-sys` · `! cargo tree | grep -E 'libsql-ffi|sqlite3-sys|openssl-sys'` (in the
engine) · exactly one `rustls` node · `cargo tree -p envctl-secrets-engine` shows no tokio/tonic/hyper
(so signing stays in the pure engine; export/alerting stays in `secretd`).

---

## 9. Open questions (operator / spec decisions)

1. **Signing-key rotation cadence — confirm (C).** Per-`dek_generation` is recommended (§2.1). Accept,
   or require an additional scheduled audit-key rotation independent of DEK rotation? **Recommend:
   per-DEK-generation, plus an explicit `reason='compromise'` path that you already have.**
2. **Schema-comment drift.** Correct `schema.sql:167-168` to match the code (`prev_hash ‖ canonical_row`,
   domain-separated genesis, not zeroes) so any third-party verifier built from the schema is correct.
   Pure doc fix; not in scope to change here (READ-ONLY).
3. **Background chain sweep cadence.** O(n) verify-on-unlock is accepted (`research/13:93`). Do you also
   want a periodic background `verify_chain` + head re-sign while running long-lived? (relevant for the
   always-on box). Unspecified in current docs (open question 2 in `research/13`).
4. **NDJSON rotation/retention.** Size threshold + retention days + whether rotated `.ndjson.gz` segments
   are also covered by a TSA anchor for archival. Unaddressed in Phase 0 docs (`research/13` open Q6).
5. **TSA: needed at all?** Default = no (single-operator). Only if a regulated deployment appears
   (§6). If yes, pick a provider and confirm a no-C pure-Rust client or commit to a sidecar.
6. **Telegram alert delivery.** If the operator wants audit alerts in Telegram, this MUST be a separate
   process reading `audit.ndjson` — never inside `secretd` (THREAT-MODEL / `SERVER-MODE.md:138`: the bot
   token and relay bearers must not co-locate). Confirm the operator accepts the sidecar split.
7. **Export-failure policy.** Confirmed posture: NDJSON/journald failures alert but never fail an op open
   (the DB row is authoritative). Operator to confirm this is acceptable vs. a stricter "halt on export
   failure" stance for high-compliance modes.
8. **`meta.k='audit_head_sig'` collision.** **[UNVERIFIED]** no in-flight code reserves that key — grep
   before implementing.

---

## 10. Summary

env-ctl's audit layer is already sound on-box: a real, tested BLAKE3 hash chain
(`crates/secrets-engine/src/vault/audit.rs`) plus a DEK-keyed tail anchor (`meta.audit_head`) that the
engine advances only while unlocked. The **specific gap** this design closes is **off-box / third-party
verifiability and operational visibility**:

- **Ed25519 head signing** (key per `dek_generation`, sealed under the DEK, all pubkeys published) lets
  an air-gapped auditor verify the head with no ability to forge — the asymmetric anchor the DEK-keyed
  one cannot provide (RFC 8032). Signed in the same durable txn as the head update (HF-14 / FS-S26).
- **Dual-sink export** (journald + NDJSON in the existing `~/.local/state/env-ctl/` mirror) and
  **outbound-only alerting** give a SIEM an append-only off-box copy that owner-session malware cannot
  retroactively suppress — turning A2/A12's "bounded, not prevented" into "bounded *and visible*."
- Everything stays **pure-Rust in the engine, I/O in `secretd`, fail-closed, no new listener, no
  `aws-lc-sys`/libSQL in the engine** — honoring the repo's load-bearing tenets.

RFC 3161 TSA anchoring is the one piece deferred to Phase 2+ and only for regulated deployments.
