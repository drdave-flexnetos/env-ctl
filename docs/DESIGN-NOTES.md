# env-ctl — Design Notes (resolved decisions + cross-dimension reconciliations + review fixes)

**Status:** Reconciled by the lead architect from six dimension designs + the threat-model/roadmap dimension, then hardened by an adversarial review pass. The 12 locked operator decisions are NOT relitigated; conflicts below are RESOLVED. CONFIRMED critical/high review findings are folded into the artifacts; medium/low items are recorded as OPEN ITEMS at the end.

---

## RESOLVED DECISIONS (locked operator choices the whole design is built to)

| # | Locked operator decision | How the design honors it |
|---|---|---|
| 1 | Pure-Rust Cargo workspace, STABLE toolchain, edition 2021, rust-version 1.80, MIT OR Apache-2.0, few mainstream deps, NO web/WebView; mirrors envctl; merges into `envctl/crates/`; engine is a pure non-printing LIBRARY emitting an Event stream. | Four crates `envctl-secrets-{engine,proto}`,`-secretd`,`-secretctl`; engine is sync, never prints, emits `SecretEvent`; async confined to `secretd`. `[workspace.package]` edition/rust-version/license match envctl. **CI gate enforces no C *library* in the trust boundary** (see R9/OI-1 — RESOLVED (a): libSQL `remote` links none; build-time `cc`, already needed by ring+blake3, is accepted). |
| 2 | Mission: local single-operator secrets VAULT + credential BROKER for one Ubuntu 26.04 dual-RTX-5090 box; fills envctl Non-Goal N6. | Whole architecture; TCB = the daemon; broker = the inject model. |
| 3 | libSQL/SQLite store with APP-LAYER encryption — XChaCha20-Poly1305 AEAD per record, key via argon2id; ciphertext + metadata/version/audit tables; NO SQLCipher, NO C deps. | App-layer AEAD per record + argon2id KEK: honored fully. **Internal conflict:** "libSQL/SQLite" AND "NO C deps" cannot both hold — libSQL bundles C SQLite (VERIFIED). Resolution: keep the SQL logical schema as canonical (`db/schema.sql`); the *execution backend* is RESOLVED as OI-1 (a): libSQL's **`remote`** client, which links no C *library* (the `core`/`libsql-ffi` C-SQLite path is never pulled). |
| 4 | USB-skips-passphrase unlock: USB partition-UUID keyfile auto-unlock; passphrase argon2id fallback; one vault openable by EITHER factor (LUKS keyslots wrapping one DEK); keys zeroized in RAM; unlock key never on disk. | LUKS-style dual keyslot (USB-KEK via HKDF, passphrase-KEK via argon2id) wrapping one DEK; `Zeroizing`/`ZeroizeOnDrop`; `mlockall`+`RLIMIT_CORE=0`. **Honestly reframed as 1-of-2, not 2FA** (review C1) with an optional require-both keyslot mode. |
| 5 | Broker = inject model (virtual credit cards): real key never leaves the daemon; per-client RELAY tokens swapped for the real key at egress; three data-plane modes (BaseUrlRepoint, ProxyMitm, NativeSubToken); each relay carries a policy (mapping, host/path+method allowlist, expiry, rate/quota, enabled/revoked); full audit. | `broker/` modules; `decide()` pure default-deny; three `SwapMode`s; real key fetched only inside the Allow branch and pinned to the provider's canonical upstream host set (review fix). |
| 6 | Relay bearers rotate/expire <=24h; issuance/renewal gated on USB presence; named relay = long-lived POLICY, wire bearer always <=24h; ephemeral = one-off, also <=24h; 24h limits blast radius + gives traceability. | `MAX_BEARER_TTL_SECS=86400`; single `clamp_ttl` choke point; USB gating proven by keyfile possession AND re-checked at swap time (review fixes); per-bearer `token_id` in every swap audit row for traceability. |
| 7 | Support BOTH named long-lived relay policies AND ephemeral per-invocation tokens. | `RelayKind::{Named, Ephemeral}`; ephemerals from `env-ctl run`, pid-bound. |
| 8 | gRPC over UDS for CONTROL plane; authz by SO_PEERCRED (uid); relay proxy is the DATA plane (HTTP/HTTPS). | `secretd` tonic-over-`UnixListener` + `SO_PEERCRED` interceptor (uid==owner, fail-closed); hyper/reqwest relay proxy. |
| 9 | `env-ctl run -- <cmd>` exec-wrapper injects relay token + base-URL/proxy into the CHILD ONLY; real key never in child env/history/git; optional per-directory profiles. | `inject.rs` fork/exec; `.env-ctl` profiles (relay names only); fail-closed profile discovery (review fix). |
| 10 | Local CA powers MITM data-plane TLS + optional control-plane mTLS; trust-store wiring per tool and/or system bundle under envctl reversible Wiring discipline. | `ca.rs` (feature `mitm-ca`); per-tool child-only env wiring; system bundle as owned-file-only, `--apply --confirm`, fingerprint-verified revert (review fix FS-S11). |
| 11 | Inherit envctl boot-repair gold standard: fail-closed guards, dry-run by default, back up before clobber, never touch user data, refuse on ambiguity; define forbidden states. | `SecGuard` engine; wire encodes dry-run as the default (review fix); FS-S1..S15. |
| 12 | XDG layout, env-ctl-namespaced; 0700 dirs; runtime socket under XDG_RUNTIME_DIR; crate/package names must not collide with envctl-engine/envctl/envctl-gui. | `paths.rs`; verified collision-free naming (envctl uses `envctl`/`envctl-engine`/`envctl-gui`). |

---

## REVIEW FIXES (what the adversarial pass changed)

The review ran five lenses. CONFIRMED critical/high findings were folded directly into the artifacts; this section summarizes each change. Medium/low items are deferred to OPEN ITEMS.

### Critical fixes applied
- **CF-1 (dep hygiene): libSQL bundles C SQLite.** VERIFIED `libsql-ffi-0.9.30/bundled/src/sqlite3.c` (8.9 MB) compiled by its build.rs — `core` feature pulls it; there is no pure-Rust path. Violates locked decisions 1 & 3 and the design's own CI gate. Fix: `db/schema.sql` is now the canonical *logical* schema; the execution backend is RESOLVED (OI-1 (a)): libSQL **`remote`** only, so `core`/`libsql-ffi` is never linked. Enforced by `ci/gates/no-c.sh` (Gate 3a). (Wording in R9, THREAT-MODEL A4/FS-S2 updated.)
- **CF-2 (dep hygiene): rcgen/rustls default to aws-lc-rs (C/asm).** Contradicts the design's own "ring path" note. Fix: pin `rustls = { default-features=false, features=["ring","logging","std","tls12"] }`, `rcgen = { default-features=false, features=["ring","pem"] }`; daemon installs the ring `CryptoProvider`; CI `! cargo tree -i aws-lc-sys`.
- **CF-3 (key handling): passphrase fallback is attacker-forceable downgrade.** The "2FA" framing is false — it is 1-of-2 and the attacker picks the weaker factor by inducing USB-absent. Fix: state plainly that vault strength == the passphrase keyslot's argon2id work factor against an offline attacker with `vault.db`; enforce passphrase entropy at enroll; keep argon2id m=1GiB,t=4,p=4; add an OPTIONAL require-both keyslot (`KEK=KDF(usb_keyfile || passphrase)`); add THREAT-MODEL A12/FS-S13.
- **CF-4 (key handling): USB-presence gating spoofable via UUID.** PARTUUID is operator-settable; gates keying off mere presence (relay/leaf mint) could be faked to defeat the 24h drain. Fix: `UsbPresent` PROVES keyfile possession cryptographically (must unwrap the USB keyslot or match a vault-resident keyed MAC); UUID is a pre-filter only; `StatusResp.usb_partuuid` removed from the wire.
- **CF-5 (CA/MITM): `ca issue` mints arbitrary unscoped, long-TTL leaves.** A direct owner-callable path to FS-S6/orphan interception certs with no relay backing. Fix: `Certs.Issue`/`ca_issue` refuse `usage='mitm_leaf'`; MITM leaves are mintable ONLY inside the relay-gated proxy resolver, clamped `<=min(now+24h, relay validity)`, with a NOT NULL `relay_id` FK.
- **CF-6 (CA/MITM): upstream root store ambiguity ("SYSTEM/Mozilla").** `reqwest rustls-tls` uses bundled webpki-roots, NOT the OS store; a future native-roots "fix" would silently trust an installed local CA (FS-S7 break). Fix: build the egress client with an explicit `RootCertStore` from `webpki_roots::TLS_SERVER_ROOTS` only; forbid native-roots/`danger_accept_invalid_certs`; reword FS-S7/§4/§6.
- **CF-7 (CA/MITM): system-bundle wiring not reversible under the inherited marker-block model.** `update-ca-certificates` rewrites the monolithic `/etc/ssl/certs/ca-certificates.crt`; there is no marker block to excise. Fix: write the CA ONLY to an owned discrete file, backup the bundle first, revert by deleting only the owned file + regenerating; fingerprint-verified; `--apply --confirm` + default OFF.
- **CF-8 (fail-closed): proto `bool dry_run` inverts the safe default.** proto3 scalars default to `false` on the wire, so an omitting/old/replayed client transmits `dry_run=false` == APPLY. Fix: every destructive RPC uses positively-phrased `bool apply` (default false == dry-run) + `bool confirm`; `DryRunUnlessApply` reads `apply && (!root || confirm)`; Phase-0 conformance test on default-constructed requests.
- **CF-9 (fail-closed): `relay_swap` returns `anyhow::Result` — fail-open risk on the real-key path.** Fix: swap is default-deny by construction (real key fetched only in the `decide()==Allow` branch); any `Err` maps to a durable-audited 403, never a retry/fall-through; a `SwapOutcome` type (`Allowed|Denied|InternalRefused`) is preferred over `anyhow::Result`.

### High fixes applied
- **HF-1 (crypto): DEK rotation contradiction.** Defined explicitly as full O(all-secrets) re-encryption under one atomic, resumable (`rotation_in_progress`) transaction; old DEK dropped only after every row + every keyslot is re-sealed; passphrase rotation is the cheap one-blob rewrite.
- **HF-2 (crypto): AAD raw concatenation is canonicalization-ambiguous.** Fixed-width canonical AAD: `domain || u8(table_tag) || u64be(secret_id) || u64be(version) || u64be(dek_generation)`; collision unit test.
- **HF-3 (crypto): `keyslot_aad` undefined.** Defined to bind factor/kdf-id/argon2 params/salt/UUID/generation/slot-id with fixed-width encoding; negative test that flipping any keyslot metadata byte makes `unwrap_dek` return `None`.
- **HF-4 (key handling): never-key-to-disk vs swap/coredump.** `mlockall(MCL_CURRENT|MCL_FUTURE)` (not just "DEK pages"), raised `RLIMIT_MEMLOCK`, `MADV_DONTDUMP`, `RLIMIT_CORE=0`; fixed-capacity zeroizing buffers for the real key/CA key so realloc never strands plaintext; argon2 arena mlocked or documented as a residual; daemon refuses to start if `mlockall` fails.
- **HF-5 (key handling): proto re-introduces non-zeroized plaintext (`UnlockReq.passphrase`, `GetSecretResp.value`).** Reconcile `secret get --reveal` with FS-S1: default metadata-only, reveal is `--apply`+confirm + audited, broker-only secrets refuse it; zeroize proto-decoded secret/passphrase fields immediately into `Zeroizing`; document tonic/hyper internal buffers as a residual.
- **HF-6 (relay): USB-pull "graceful drain" grants ~24h USB-absent access.** USB possession re-checked at swap time with a short grace; new egress denied past grace; FS-S5 extended.
- **HF-7 (relay): bearer not cryptographically bound to policy/expiry/uid.** Either sign/MAC a structured bearer over `token_id||policy_id||expires_at_ms||client_uid`, or have `decide()` take the verified `Bearer` row by value and assert `row.policy_id==policy.id` + check `client_uid`; decide() table test that a bearer from policy A cannot evaluate against policy B.
- **HF-8 (relay): BaseUrlRepoint bearer over plain HTTP is replayable by any same-uid process.** Peer-bind at swap via `SO_PEERCRED`/per-mint pid nonce; prefer pid-scoped ephemerals for `run`; document plain-HTTP replayability honestly.
- **HF-9 (CA/MITM): NameConstraints presented as a security boundary.** Demoted to defense-in-depth; permitted set = exact union of relay `host_allow`, never wildcard, re-issued on change; real scoping is `LeafBackedByRelay` + child-only trust.
- **HF-10 (CA/MITM): leaf minting not USB-gated.** `UsbPresent` added to the resolver so a USB-pull stops new leaves immediately; pair with `lock` to zeroize the CA Issuer.
- **HF-11 (CA/MITM): real key can egress to an attacker host with a valid public cert.** Provider-bound canonical upstream host allowlist; `relay_swap` refuses out-of-set upstreams.
- **HF-12 (fail-closed): FS-S7 unenforceable at the engine boundary.** Engine owns/asserts the frozen webpki root store passed to the `Upstream` impl; startup guard + integration test that a local-CA chain to upstream is rejected.
- **HF-13 (fail-closed): `ca_issue` unscoped (mirror of CF-5 from the fail-closed lens).** Split operator-issued (non-MITM) vs relay-gated MITM leaf paths.
- **HF-14 (fail-closed): audit on the swap path is lossy.** Security outcomes (swap allow/deny, secret_read, unlock, mint, revoke) are written DURABLY (same txn / synchronous `append_audit`) before the RPC returns; cosmetic events stay best-effort; crash-injection test.
- **HF-15 (fail-closed): no DB-level 24h ceiling + `clamp_ttl` overflow.** SQL/storage `CHECK`, saturating arithmetic, proto-boundary rejection of out-of-range `u64` ttl, accept-side re-assertion in `decide()`.
- **HF-16 (fail-closed): `relay_revoke` is best-effort/ungated returning `()`.** Made fail-closed: durable before returning success, reports the count actually flipped; the true panic stop is `lock` (DEK zeroize, every bearer un-swappable).
- **HF-17 (merge): rustix feature conflict.** Merged row is `["process","net"]` (VERIFIED envctl has only `["process"]`); named Phase-7 action, not a no-op.
- **HF-18 (merge): MSRV unverified, likely-broken at 1.80.** Add a `cargo +1.80.0` CI gate; if 1.80 must hold, pin `idna`/`icu` patch versions (url->idna->icu raised MSRV past 1.80); else raise the shared floor with operator blessing.

---

## Cross-dimension conflict resolutions (lead-architect calls)

### R1 — Crate count & names
FOUR crates: `secrets-engine` (lib `envctl_secrets`), `secrets-proto`, `secretd`, `secretctl`. Vault/keyslot/broker/certs/inject are modules inside `secrets-engine` (shared DEK/store/audit/event vocabulary; crate boundaries there leak the DEK and create circular deps). All package names `envctl-secrets-*`; bins `secretd`/`secretctl`; verified collision-free. (Lib name changed `secrets` -> `envctl_secrets` per the low review nit on namespace genericity.)

### R2 — Sync core vs async
Engine core is SYNC and deterministic (like envctl-engine); only `relay_swap` + the `Upstream` seam are `async fn`. `EventSink` stays **std mpsc** (envctl parity). The daemon bridges the sync `Receiver<SecretEvent>` onto its async gRPC stream — but the tamper-evident audit is NOT on this lossy path (HF-14).

### R3 — One Event enum
ONE `SecretEvent` enum; the proto `Event` is its wire mirror; a CI round-trip conformance test prevents drift.

### R4 — Keyslot KDF
USB slot: HKDF-SHA256 (the keyfile is already 64 B CSPRNG; argon2 on auto-unlock is wrong). Passphrase slot: argon2id `Argon2::new(Algorithm::Argon2id, Version::V0x13, params)` (never `default()`), default `m=1 GiB, t=4, p=4`, params persisted per-slot AND bound into `keyslot_aad` (so a downgrade is detected, HF-3). A param floor is enforced in code (refuse to unwrap a slot below the floor).

### R5 — Bearer hashing
`bearer_hash = keyed-BLAKE3(hmac_key, raw_bearer)` (32 B); `hmac_key` lives only in the unlocked vault, sealed under the DEK (storage row added — see OI-9), stable across DEK rotation (re-wrapped, not re-derived). Lookup by an INDEPENDENT random `token_id` (review low fix — decoupled from `bearer_hash` to avoid a mint-collision DoS and bearer->token_id derivability), then constant-time `subtle` MAC compare. Raw bearers never persist.

### R6 — DEK in RAM type
`Dek(Zeroizing<[u8;32]>)` / `Kek(Zeroizing<[u8;32]>)` (fixed 32-B, `ZeroizeOnDrop`); `Zeroizing<Vec<u8>>` (fixed-capacity) for variable-length real bodies + the CA key. None `Serialize`.

### R7 — rustls/rcgen backend
Pin `rustls = 0.23` AND `rcgen = 0.13` with `default-features = false` on the **ring** path (CF-2); CI: exactly one `rustls` node, ZERO `openssl-sys`/`aws-lc-sys`; reqwest `default-features=false, ["rustls-tls","http2","stream"]`.

### R8 — udev
Partition-UUID poll is authoritative (fail-closed); `udev` is OFF-BY-DEFAULT and only nudges the poller (linking libudev/C would violate no-C if mandatory).

### R9 — Store backend C-dep tension (RESOLVED (a) — see OI-1)
The synthesized design claimed "libSQL pure-Rust path." The `core`/`libsql-ffi` path is indeed C (CF-1, VERIFIED) — so the adopted backend is libSQL's **`remote` client**, which links NO C library (proven by `cargo tree`; enforced by `ci/gates/no-c.sh` Gate 3a). `db/schema.sql` is retained as the canonical logical model. The upheld tenet is "no C *library* in the trust boundary," NOT "no `cc`" — the engine already needs `cc` via ring + blake3, so accepting the build-time toolchain (operator decision (a)) adds no new class of dependency. The `inmem-store` feature (RAM-only) remains the CI test analogue and the engine default.

---

## Departures from envctl, stated plainly
- **tokio/tonic/hyper/rustls/reqwest** expand envctl's small dep set + add an async runtime, confined to `secretd` (+ proto/cli). Justified by locked decisions 8 (gRPC control plane) + 5 (relay proxy).
- **The at-rest store** (libSQL `remote`, OI-1 RESOLVED (a)) is heavier than the few-deps tenet prefers but is the locked storage pillar; mitigated by `default-features=false` minimization + the `inmem-store` test feature + the no-C CI gate (which proves no C *library* is linked).

---

## OPEN ITEMS (medium/low review items + deferred decisions)

| ID | Severity | Item | Disposition |
|---|---|---|---|
| **OI-1** | **RESOLVED (a)** | **At-rest store backend = libSQL `remote` (operator ruling, NEW-3).** The complete `Store` impl in `crates/secrets-store-libsql` is now a `[workspace.members]` entry (builds + 9 offline tests under the unified workspace = 117 total green; 5 sqld integration tests `#[ignore]`d). **Operator chose (a): accept a C build-toolchain.** Verified empirically on this box: the engine ALREADY requires `cc` at build time via **ring** (`cargo tree -i cc` shows ring compiles C/asm for its crypto primitives) **and blake3** (SIMD) — so adopting libSQL adds no new *class* of build dependency. The upheld tenet is **"no C *library* LINKED into the trust boundary"** (no SQLite/OpenSSL/aws-lc), which `cargo tree` PROVES: `default-features=false, features=["remote"]` pulls no `libsql-ffi`/`libsql-sys`/`sqlite3-sys`, no `aws-lc-sys`/`aws-lc-rs`/`openssl-sys`, and exactly ONE ring-only `rustls` (libSQL doesn't even add its own). The `remote` feature's only C is `libsql-sqlite3-parser`'s build-time `lemon.c` codegen, which EMITS Rust and links nothing. Enforced by `ci/gates/no-c.sh` (Gate 3a auto-armed now the crate is a member). Engine default store stays `inmem-store`; **secretd runtime-selects this backend via config (Phase-1 DONE; see `docs/ops/08-secretd-store-config.md`).** Residuals (honest): libSQL `remote` drags in a duplicate-major legacy stack confined to its subtree — `hyper 0.14` (vs the workspace's 1.x), `http 0.2`, `http-body 0.4`, `h2 0.3`, `base64 0.21`, `itertools 0.12`, and a 2nd `prost` major (0.12 via `libsql-hrana`, vs the workspace's 0.13) — all pure-Rust, now linked into **`secretd`** (Phase-1 wiring DONE — the engine/proto/cli still never link it; gate-proven no C library); dup/bloat, not a C/gate violation. Transport: secretd uses a PLAINTEXT loopback connector (libSQL's `tls` feature would add a 2nd rustls 0.22, breaking the single-rustls gate), reconnecting on Hrana `STREAM_EXPIRED` (the idle baton dies during argon2 in `init_vault`); a remote sqld is reached via a loopback TLS terminator (see `docs/ops/08-secretd-store-config.md`). One accepted advisory: **CVE-2025-47736** (`libsql-sqlite3-parser <= 0.13.0` invalid-UTF-8 parser crash, low; no patched release; NOT reachable — the store uses only static SQL with bound `?` params, so no attacker text reaches the parser). | RESOLVED (a). Target remains strict C-toolchain-free (blake3 `pure` + a pure-Rust Hrana client); revisit if a maintained pure-Rust Hrana client lands (CF-1 / the `core` path is still C and still forbidden). |
| OI-2 | medium | `secret get --reveal` is the by-design TCB escape hatch. Gated behind `--apply`+confirm+audit; broker-only secrets refuse it. Open: whether to remove plaintext reveal entirely. | Implement gated; revisit removal in Phase 1. |
| OI-3 | medium | Walk-up `.env-ctl` profile discovery trust. Honor only operator-trusted roots / at-or-below cwd; named-relay attach needs confirmation. Open: exact trusted-root config UX. | Spec in Phase 6. |
| OI-4 | medium | USB-pull auto-relock is now DEFAULT-ON with a drain grace. Open: default grace window length (proposed ~5 min) + interaction with long-running egress. | Tune in Phase 2/3. |
| OI-5 | medium | USB identifier semantics: pin GPT **PARTUUID** (`blkid -o value -s PARTUUID` / sysfs), NOT filesystem UUID (`blkid -U`). Phase-2 acceptance updated to match. | Pin PARTUUID; reject FS-UUID as selector. |
| OI-6 | medium | Clock-rollback hardening beyond the issuance floor: cross-check `CLOCK_BOOTTIME`/audit-chain high-water; refuse acceptance of bearers whose `issued_at_ms` < floor OR `now < last_seen_ms - skew`; eagerly purge expired bearers. The floor is owner-writable, so it is effective only vs accidental skew + external attackers, NOT owner-session malware (honest A2 framing). | Implement in Phase 3. |
| OI-7 | medium | KEK derivation scratch zeroization (argon2 memory arena, hkdf state); consume `Kek` by value in `unwrap_dek` so it is short-lived; pass keyfile/passphrase as `&Zeroizing`. | Implement in Phase 1/2. |
| OI-8 | medium | Keyslot-set tamper detection via DEK-authenticated header MAC over all slots' factor/kdf/params/salt/count + a code-level argon2 param floor; audit every keyslot mutation. | Implement in Phase 1. |
| OI-9 | medium | `hmac_key` storage + rotation: add a sealed row (mirroring `ca_key`), stable across DEK rotation; document that DEK rotation does NOT invalidate live bearers. | Schema row added; test in Phase 3. |
| OI-10 | medium | Per-bearer revocation RPC (`Relay.RevokeBearer{token_id}`) so a single leaked bearer is revocable without killing a shared named policy; `decide()` rejects bearer-level `revoked_at`. | Add RPC in Phase 3. |
| OI-11 | medium | Per-swap traceability: add `token_id` (+ `client_uid`/`client_label`) to `RelaySwapped` event + proto + `audit_log.subject`; CI assertion that a swap row joins to a unique bearer row. | Implement in Phase 3. |
| OI-12 | medium | SNI≠inner-Host enforcement + per-request `decide()` on established MITM connections; decide() table test for SNI!=Host. | Implement in Phase 4. |
| OI-13 | medium | CA validity shortened to <=90d auto-renewed; `ca rotate`/compromise enumerates all touched wiring targets and fails-closed unless the old fingerprint is excised everywhere. | Implement in Phase 4. |
| OI-14 | medium | Feature-matrix hygiene: make `rustls*` engine deps `optional` under `mitm-ca`; `compile_error!` guards for zero/both store backends; add the full build matrix to CI. | Implement in Phase 0/7. |
| OI-15 | medium | Vendor `proto/control.proto` inside `crates/secrets-proto/proto/`, reference via `CARGO_MANIFEST_DIR`, add `include=["proto/**"]`. | Done in SCAFFOLD-SPEC. |
| OI-16 | low | Mandate `OsRng` for ALL nonces in the seal path; forbid seeded RNG behind a non-test cfg; debug-assert no `(dek_generation, nonce)` repeat within a rotation batch. | Implement in Phase 1. |
| OI-17 | low | Generic unlock error (single `UnlockFailed`) across both slots; no early-exit that reveals which slot exists; try every enabled slot. | Implement in Phase 2. |
| OI-18 | low | USB keyfile on vfat/exfat ignores `0400`; document physical-possession-is-the-boundary; warn if the keyfile FS ignores mode bits; consider TPM-sealed/per-install salt so a bare keyfile copy is insufficient. | Document + warn in Phase 2; TPM is a stretch goal. |
| OI-19 | low | Persist NO MITM-leaf private keys (mint in-RAM, die with cache); relay-disable evicts cache AND any persisted rows; only operator service/mTLS leaves persist. | Implement in Phase 4. |
| OI-20 | low | CA in-RAM `Issuer` mlocked + zeroized on lock; test that `lock` drops the Issuer. | Implement in Phase 4. |
| OI-21 | low | `token_id` is an independent random 96-bit id (decoupled from `bearer_hash`) with bounded UNIQUE-collision retry. | Schema/spec reflect this. |
| OI-22 | low | High-sensitivity control ops (reveal, ca rotate, rekey, revoke-all) require an explicit operator unlock interaction rather than reusing a cached DEK silently; rate-limit + loudly audit control mutations (narrows same-uid A2 blast radius, does not prevent it). | Revisit in Phase 5. |
| OI-23 | low | getrandom/rand pinned 0.2/0.8 (consistent now); add to `cargo tree -d` watch list; migrate the pair together when the ecosystem moves to getrandom 0.3/rand 0.9. | Watch only; no change now. |
| OI-24 | low | rust-toolchain.toml stays floating `stable` for dev ergonomics; the 1.80 floor is a separate verified CI gate (`cargo +1.80.0`). | CI gate added (R10/HF-18). |
