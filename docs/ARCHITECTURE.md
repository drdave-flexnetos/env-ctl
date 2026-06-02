# env-ctl — Architecture

**Status:** Design reconciled + adversarial-review-hardened · parallel repo to `envctl`, destined to merge into `envctl/crates/`
**Owner:** Single power-user (dual-RTX-5090 Ubuntu 26.04 box)
**Reconciles:** workspace-engine · data-model-crypto · keymgmt-unlock · broker-relay · certs-ca · api-cli-inject · threat-model-roadmap
**Adversarial pass:** all CONFIRMED critical/high findings folded in below; medium/low recorded as OPEN ITEMS in `DESIGN-NOTES.md`.

> Pure Rust, stable toolchain, edition 2021, `rust-version = 1.80` (verified gate — see DESIGN-NOTES R10), `MIT OR Apache-2.0`. No web / no WebView. One pure engine library that NEVER prints; thin front-ends drive it through a structured `SecretEvent` stream — exactly like `envctl-engine`. A local HTTP relay proxy (data plane) and a gRPC-over-UDS control plane are the only network surfaces, both loopback/UDS only.

---

## 1. Overview

`env-ctl` is the secrets vault + credential broker `envctl` left out (Non-Goal N6). It stores keys/certs/tokens encrypted at rest and hands them to tools as a "virtual credit card": the real long-lived key NEVER leaves the daemon; clients receive short-lived (<=24h) relay bearers that the broker SWAPS for the real key at egress.

The system has **two planes with different trust models** (locked decision 8):

| Plane | Transport | Authz | Who reaches it |
|---|---|---|---|
| **Control** | gRPC over a Unix-domain socket under `$XDG_RUNTIME_DIR/env-ctl/control.sock` (0700 dir, 0600 sock) | `SO_PEERCRED` uid == owner (fail-closed) | the owner only (CLI / `envctl`) |
| **Data** | HTTP/HTTPS relay proxy on loopback | relay bearer validated per-request against its policy + peer-bound at swap time | semi-trusted local clients holding a <=24h bearer |

The **daemon address space is the sole Trusted Computing Base (TCB)**: the plaintext Data-Encryption-Key (DEK) and the real upstream API keys exist in cleartext ONLY there, zeroized on drop, with `mlockall` + `RLIMIT_CORE=0` + `MADV_DONTDUMP` against swap/coredump leakage. Everything crossing a boundary out of it — disk, backup, child env, the wire, git — carries only AEAD ciphertext or a <=24h relay bearer.

## 2. Crate layout (four crates, collision-free with envctl-engine / envctl / envctl-gui)

| Path | Package | Lib/Bin name | Kind | Owns |
|---|---|---|---|---|
| `crates/secrets-engine` | `envctl-secrets-engine` | `envctl_secrets` (lib) | LIB (sync core) | vault, keyslot, broker policy/decide/mint, CA, inject, the `SecretEvent` spine, `EngineError`, the 5 seams. NO tokio-net / tonic / hyper. |
| `crates/secrets-proto` | `envctl-secrets-proto` | `envctl_secrets_proto` (lib) | LIB | tonic/prost control-plane contract; `build.rs` compiles `proto/control.proto` **vendored inside the crate**. |
| `crates/secretd` | `envctl-secretd` | `secretd` (bin) | BIN (async) | wires `Engine` to tokio: UDS gRPC server + `SO_PEERCRED` interceptor + relay HTTPS proxy + MITM listener + audit/tracing sink. The ONLY place tokio/hyper/rustls/reqwest live. |
| `crates/secretctl` | `envctl-secretctl` | `secretctl` (bin) | BIN (async, thin) | tonic UDS client; clap verbs; drains the `SecretEvent` stream / `--json`. Never touches crypto. |

> **Naming (verified collision-free):** envctl's packages are `envctl`, `envctl-engine`, `envctl-gui` (bins `envctl`, `envctl-gui`; lib `envctl_engine`). The new packages `envctl-secrets-engine`/`-proto`/`-secretd`/`-secretctl`, bins `secretd`/`secretctl`, and lib names `envctl_secrets`/`envctl_secrets_proto` collide with none. (Review fix: the engine lib name was changed from the over-generic `secrets` to `envctl_secrets`.)

The vault/keyslot/broker/certs/inject subsystems are **modules inside `secrets-engine`**, not separate crates, because they share one DEK, one store, one audit chain, and one `SecretEvent` vocabulary — splitting them would force the DEK and the seal/open primitives across crate boundaries (a leak surface and a circular-dep magnet: certs needs the vault to encrypt its key; the broker needs certs for MITM; certs needs the broker policy table for the gate).

## 3. The engine spine (mirror of envctl-engine)

`secrets-engine` mirrors `envctl-engine` to the letter, with ONE deliberate departure (the egress seam is `async`; everything else is sync):

```
secrets-engine/src/
  lib.rs        Engine{ inner: Arc<EngineInner> }, Clone, Send+Sync+'static
  event.rs      SecretEvent (one enum, all crates drain it) + EventSink (std mpsc) — EXACT envctl shape
  error.rs      EngineError (thiserror, setup-time ONLY) + VaultState
  seam.rs       Clock, UsbProbe, ProviderMint, Upstream (HookRunner analogues, all Send+Sync)
  guard.rs      SecGuard + check_sec_guards (fail-closed, resolve-once UnlockContext) — mirror of envctl guard.rs
  paths.rs      XDG: ~/.config|.local/share(0700)|.local/state/env-ctl + $XDG_RUNTIME_DIR/env-ctl
  vault/        mod.rs (Vault state machine) + store.rs (backend-abstracted, AEAD records) + crypto.rs (seal/open) + aad.rs (canonical AAD)
  keyslot.rs    LUKS-style dual KEK wrap/unwrap (USB-KEK via HKDF, passphrase-KEK via argon2id) + header MAC
  broker/       mod.rs (Broker handle) + policy.rs + decide.rs (PURE default-deny) + token.rs + adapter.rs
  ca.rs         LocalCa: issue/renew/revoke leaf + MITM certs (feature `mitm-ca`)
  inject.rs     ChildEnvPlan + injection_template table (provider -> env delta) + run_wrapped
```

- **Engine is a pure library that never prints.** Core crypto/policy/decide is sync and deterministic. Only `Engine::relay_swap` (the proxy hot path) and the `Upstream` seam are `async fn`.
- **One `SecretEvent` enum** over `EventSink(std::sync::mpsc::Sender<SecretEvent>)` — the same `channel()`/`null()`/`emit()` API as envctl's `EventSink`. The sync core emits into it; the daemon's async tasks bridge events from a `std` `Receiver` onto the gRPC server-stream. **The cosmetic event stream is best-effort (emit may drop); the tamper-evident `audit_log` is written DURABLY and synchronously before any security-relevant RPC returns (review fix: audit is not on the lossy mpsc path).**
- **Five behavioral seams** (the HookRunner family): `Clock`, `UsbProbe` (partition-UUID resolve + **keyfile-possession proof**, not mere UUID match — review fix), `ProviderMint` (default `Unsupported`), `Upstream` (the one `async` seam; pins upstream roots — see §6).
- **Typed `EngineError` for setup-time failures ONLY.** A denied egress / expired bearer / revoked relay is NOT an `Err` — it is a `RelaySwapped{ allowed: false }` durable-audited event + a 403 `EgressResp`, exactly as a failing hook is `OpStatus::Failed`, not `Err`, in envctl. **The swap path is default-deny by construction (review fix): the real key is fetched ONLY inside the `decide() == Allow` branch; any internal error maps to a 403 + audited deny, never a retry and never a fall-through to `Upstream::send`.**

## 4. Trust boundaries (data leaving the TCB carries only ciphertext or a <=24h peer-bound bearer)

```
daemon -> store (vault.db)   : AEAD ciphertext + metadata only (no plaintext secret, no DEK)
daemon -> backup/stolen disk : same ciphertext; DEK wrapped under USB-KEK and passphrase-KEK keyslots; header MAC over keyslot set
daemon -> child process      : relay bearer + base-URL/proxy env, NEVER the real key (inject.rs)
daemon -> real upstream      : real key, TLS verified against a FROZEN bundled-Mozilla (webpki-roots) store — NEVER the local CA, NEVER the OS store (review fix FS-S7)
daemon -> data-plane client  : peer-bound relay bearer (<=24h), validated per request against its policy
control client -> daemon     : gRPC/UDS, authz by SO_PEERCRED uid == owner
```

## 5. Key hierarchy (3-tier, app-layer, no C/SQLCipher)

1. **Unlock factor -> 32-byte KEK.** USB keyfile (64 B CSPRNG on the partition) -> `KEK_usb = HKDF-SHA256(keyfile, salt32, info=b"env-ctl/v1/kek/usb")` (review fix: fixed domain-separated `info`, 32-B CSPRNG per-slot salt, output length asserted == 32). Passphrase -> `KEK_pp = argon2id(passphrase, salt, params)` built explicitly as `Argon2::new(Algorithm::Argon2id, Version::V0x13, params)` — never `Argon2::default()` (review fix).
2. **LUKS-style keyslot.** Each KEK wraps the SAME 32-byte DEK: `wrapped_dek = XChaCha20-Poly1305(KEK).seal(DEK, aad=keyslot_aad)`. EITHER factor opens ONE vault. The AEAD tag IS the correctness oracle (wrong factor => tag mismatch => no plaintext, no separate verifier). **`keyslot_aad` binds ALL KDF-determining + identity fields (review fix, was undefined): `b"env-ctl/v1/keyslot" || u8(factor) || u8(kdf_id) || u32be(m_kib) || u32be(t_cost) || u32be(p_lanes) || len32(salt)||salt || len32(uuid)||uuid || u64be(dek_generation) || u64be(slot_id)`.** Tampering any param/salt/UUID => different KEK or AAD mismatch => fail-closed.
3. **DEK -> per-record envelope.** Every secret body: fresh 24-byte CSPRNG (`OsRng`) nonce + AAD bound by a **canonical, unambiguous, fixed-width encoding** (review fix; replaces raw concatenation): `b"env-ctl/v1" || u8(table_tag) || u64be(secret_id) || u64be(version) || u64be(dek_generation)`. AAD is **recomputed at decrypt time from the row's trusted identity columns — never read from a stored column** (review fix: the `aad_tag` mirror column is dropped to remove the footgun).

**DEK rotation is full re-encryption (review fix — it is NOT a keyslot-only rewrite):** under one atomic transaction with a `rotation_in_progress` meta flag (resumable on crash), every ciphertext row (`secret_versions`, `ca_key`, `certs`) is decrypted with the OLD DEK and re-sealed with the NEW DEK using a fresh nonce + AAD bound to `new_generation`; then `keyslots.wrapped_dek` is rewritten for every enabled slot, `meta.active_dek_generation` is advanced, the old generation is tombstoned, and only THEN is the old DEK dropped. Cost is O(all secrets) and documented. **Passphrase rotation is the cheap one-blob keyslot rewrite; DEK rotation is the expensive full re-seal.**

All key material (`Dek`, `Kek`, passphrase, keyfile, decrypted CA `Issuer`) lives in `Zeroizing`/`ZeroizeOnDrop` wrappers and is **never** `Serialize`. The keyslot set + KDF params are additionally bound under a **DEK-authenticated vault header MAC**; on unlock the header is recomputed and the unlock refuses on drift (review fix — detects a silently-added or param-downgraded keyslot, a swapped USB UUID, or a rewound issuance floor).

## 6. The three data-plane swap modes (locked decision 5)

| Mode | For | Wire shape | CA needed |
|---|---|---|---|
| `BaseUrlRepoint` | clients honoring a custom base URL (Claude `ANTHROPIC_BASE_URL`, OpenAI `OPENAI_BASE_URL`) | client -> local plain-HTTP endpoint authed by a **peer-bound** bearer -> broker injects real key, re-originates verified TLS to the real upstream | no |
| `ProxyMitm` | hardcoded-host clients (`git`, `gh`, `curl`) | `HTTPS_PROXY` CONNECT + local-CA MITM leaf for the CLIENT->broker hop only | yes (leaf gated on an active relay covering the SNI) |
| `NativeSubToken` | providers that mint scoped sub-creds (GitHub fine-grained PAT / App token, OpenAI project key) | the wire carries a real-but-scoped credential | no |

**Egress invariants (review-hardened):**
- **FS-S7 root pinning:** the broker's real upstream client is built with an EXPLICIT `rustls::RootCertStore` seeded ONLY from `webpki_roots::TLS_SERVER_ROOTS` (frozen bundled Mozilla). It REFUSES the local CA AND refuses the OS system store (immune to a poisoned system bundle if the operator ever ran `ca trust --system-bundle`). `native-tls`, `rustls-tls-native-roots`, and `danger_accept_invalid_certs` are forbidden by CI grep. (Review fix: "SYSTEM/Mozilla roots" was ambiguous and a native-roots "fix" would silently trust an installed local CA.)
- **Upstream host allowlist (review fix):** each provider is bound to a canonical upstream host set in the engine-owned provider table (`Anthropic => {api.anthropic.com}`, `Openai => {api.openai.com}`, `Github => {api.github.com}`). `relay_swap` REFUSES if the resolved upstream host (from `BaseUrlRepoint.upstream_base` or the MITM target) is not in that set — so a malicious policy row cannot repoint egress of the real key to an attacker host that merely holds a valid public cert.
- **Canonical host = inner Host (review fix):** for MITM, `decide()` runs on EVERY request against the verified inner HTTP `Host`/`:authority` after decryption, and the connection is refused on SNI≠Host mismatch — closing the SNI/Host confusion gap.
- **Peer binding (review fix):** for the loopback data plane, the bearer is bound at mint to the client's `SO_PEERCRED` uid/pid (ephemerals tied to the child pid of `env-ctl run`); swaps whose peer does not match are denied. Plain-HTTP `BaseUrlRepoint` bearers are documented as replayable by any same-uid process; the real mitigations are allowlist + quota + short TTL + peer binding, not bearer secrecy.

## 7. 24h rotation + USB gating (locked decisions 6, 7)

- Every minted wire bearer has `expires_at <= now + 24h` (`MAX_BEARER_TTL_SECS = 86400`). A **named relay** (`claude-main` 1y, `gh-ci` 90d) is a long-lived POLICY; the bearer minted under it is always <=24h. An **ephemeral relay** is a one-off minted by `env-ctl run` for a single process, also <=24h.
- **Single TTL choke point (review fix):** `clamp_ttl(now, policy_ttl_secs, requested_ttl_secs) = now + requested.clamp(1, policy_ttl).min(MAX)` using saturating arithmetic; `requested`/`policy` TTL <= 0 is REFUSED (no dead/negative bearers); a `u64` `ttl_secs` exceeding `i64::MAX` is rejected at the proto boundary, never wrapped. This is the ONLY path that computes `expires_at`. A storage `CHECK (expires_at_ms <= issued_at_ms + 86400000)` and an accept-side re-assertion in `decide()` are defense-in-depth.
- **USB gating is keyfile-possession-proven, not UUID-presence (review fix):** `UsbPresent` uses the partition identifier ONLY as a fast pre-filter, then proves possession of the keyfile cryptographically (the keyfile must unwrap the USB keyslot, or match a vault-resident keyed MAC). Mint, renew, **and leaf minting** all require this proof. The enrolled UUID is NOT emitted on the wire (`StatusResp.usb_partuuid` removed — it leaked the gate selector).
- **USB presence is re-checked at SWAP time, not only at mint (review fix FS-S5):** `decide()`/`relay_swap` re-resolve USB possession; once the USB has been absent longer than a short grace window (default ~5 min, configurable), NEW egress is denied with `GateAbsent` while in-flight streamed responses drain. This honors "pull the USB and access stops" without a full 24h tail.
- **USB-pull DEFAULTS to auto-relock (review fix — was default-off):** pulling the enrolled USB zeroizes the DEK (and the in-RAM CA `Issuer`) after a short drain grace; default-off is an explicit opt-out the operator must choose. `lock`/idle-timeout zeroizes on demand. `relay revoke --all` (durable, count-reporting) and `lock` (DEK zeroize, the true panic stop) are the containment actions.

## 8. The local CA (certs-ca, feature `mitm-ca`)

- One CA keypair with **SHORT validity (<=90d, auto-renewed while unlocked — review fix; "long-lived" invited a stolen-DEK signing-oracle window)**; its private key never touches disk in clear — PKCS#8 DER is sealed under the DEK in the `ca_key` table and decrypted into an in-RAM `Zeroizing` rcgen `Issuer` (mlocked, dropped on lock — review fix: CA key gets the same protection class as the DEK) only while unlocked.
- **MITM leaf minting is unreachable except through the relay-gated proxy resolver (review fix — critical).** The general `Engine::ca_issue` / `Certs.Issue` RPC mints ONLY `control_plane_server`/`control_plane_client` leaves and REFUSES `usage='mitm_leaf'`. MITM leaves are minted in-RAM, on demand, ONLY after `check_sec_guards([LeafBackedByRelay{host}, UsbPresent])` passes for every SAN against a resolve-once `UnlockContext`, with `not_after <= min(now+24h, covering relay validity)`. `mitm_leaf` rows carry a NOT NULL `relay_id` FK; **MITM leaf private keys are NOT persisted (review fix)** — they die with the cache entry. No covering relay => `ResolvesServerCert::resolve` returns `None` => handshake fails closed.
- Revocation = relay disable -> cache evict + no re-mint; short TTL replaces CRL/OCSP. **Even on an already-established MITM connection, `decide()` runs per request, so a revoked relay yields 403 immediately regardless of a cached leaf (review fix — the leaf cache is a performance optimization, never an authorization oracle).**
- The CA cert carries X.509 NameConstraints whose **permitted dNSName set is the EXACT union of all relay `host_allow` entries (never a wildcard/`all`) and is re-issued when that union changes (review fix)**. NameConstraints is documented as **defense-in-depth only** (enforcement on user-added roots varies across Go/OpenSSL/Node/rustls); the real scoping is `LeafBackedByRelay` + per-tool child-only trust wiring. Subject is loud: `env-ctl LOCAL MITM CA — DO NOT TRUST GLOBALLY`.
- Trust is wired **per-tool, child-only** (`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`) via `env-ctl run`. The system bundle is an explicit, `--apply --confirm` (RootOfTrust), default-OFF last resort: **the CA is written ONLY to a discrete owned file `/usr/local/share/ca-certificates/env-ctl-local-mitm-ca.crt`, with a timestamped backup of `/etc/ssl/certs/ca-certificates.crt` first, then `update-ca-certificates`; revert deletes ONLY that owned file and re-runs the generator (review fix FS-S11 — the monolithic bundle is never hand-edited; the envctl marker-block model cannot apply to it).** On `ca rotate`/compromise the engine enumerates every wiring target it ever touched and fails-closed unless the OLD CA fingerprint is excised everywhere.

## 9. Auto-inject (`env-ctl run -- <cmd>`, locked decision 9)

A fork/exec wrapper (NOT a sourced shell mutation): it mints a <=24h ephemeral (or named) bearer **bound to the child pid**, asks the daemon for a `ResolvedInjection` (the provider-shaped env delta), clones the parent env, overlays ONLY the injected keys, and `execvp`s the child. The real key never enters the child env, argv, shell history, or git. Per-directory `.env-ctl` TOML profiles (relay NAMES only — never secrets) auto-attach named relays, but **discovery is fail-closed against planted profiles (review fix): only profiles under an operator-trusted root (or at/under cwd, not an ancestor) are honored, and attaching a NAMED (non-ephemeral) relay requires explicit `--profile` or confirmation — the pre-exec emit is a gate, not just an FYI.** `--no-profile` disables discovery.

## 10. Safety (inherited envctl gold standard, locked decision 11)

Fail-closed `SecGuard` engine (Phase 0, real signatures + refusal types, `todo!()` bodies): `UsbPresent`, `RelayValid`, `LeafBackedByRelay`, `PeerIsOwner`, `VaultEncryptedAtRest`, `DryRunUnlessApply`. Resolve-once-per-op `UnlockContext` (no TOCTOU). **The wire encodes the SAFE state as the default (review fix — critical): every destructive RPC carries a positively-phrased `bool apply` (proto3 default `false` == dry-run) plus `bool confirm` for RootOfTrust ops; an all-zero/omitted request is treated as dry-run.** Destructive verbs (rm, rotate, revoke, ca init/rotate, trust apply, rekey, destroy, **`secret get --reveal`** — review fix: reveal is a loud, audited, `--apply`-gated escape hatch, broker-only secrets refuse it) are dry-run by default; root-of-trust destruction also needs `--confirm`. No `--force` bypasses any guard. User data (KeePassXC DBs, `~/.ssh` originals, browser profiles) is never touched. See `THREAT-MODEL.md` for REQ-SEC-1..9 and FS-S1..S15.

## 11. XDG layout (env-ctl-namespaced, sits beside envctl's dirs)

```
~/.config/env-ctl/                      config (profiles defaults, daemon config, trusted-profile-roots allowlist)
~/.local/share/env-ctl/        (0700)   vault.db (0600), ca/ca.pem (0644, public cert), ca/bundles/<tool>.pem
~/.local/state/env-ctl/        (0700)   secretd.log, audit mirror (audit_head second home)
$XDG_RUNTIME_DIR/env-ctl/      (0700)   control.sock (0600), relay-proxy bind config
USB <partition-uuid>:/env-ctl/keyfile  (0400) 64-byte CSPRNG keyfile (mode bits advisory on vfat/exfat — see THREAT-MODEL A5/A11)
```

## 12. Merge into envctl

The four crates drop into `envctl/crates/` verbatim (names verified collision-free). `[workspace.dependencies]` rows are **caret-compatible and re-resolve to one unified lockfile (review fix — they do NOT "merge byte-identical"; envctl's resolved pins differ, e.g. serde 1.0.228 vs 1.0.219).** Two named non-no-op merge actions (review fix):
1. **`rustix` is a feature-set UNION, not unchanged:** the merged row MUST be `rustix = { version = "0.38", features = ["process", "net"] }` (envctl has only `["process"]`; `secretd` needs `net` for `SO_PEERCRED`). Additive, so the GUI/engine still build.
2. The proto file is **vendored inside `crates/secrets-proto/proto/` and referenced via `CARGO_MANIFEST_DIR`** (review fix — the old `../../proto/control.proto` path breaks on merge).

The secrets-only rows (tokio, tonic, prost, tonic-build, tower, hyper, hyper-util, http-body-util, reqwest, chacha20poly1305, argon2, hkdf, sha2, blake3, zeroize, subtle, rand, getrandom, rcgen, rustls, rustls-pemfile, rustls-pki-types, x509-parser, webpki-roots, async-trait, tracing-subscriber, the chosen pure-Rust store) are additive and pulled ONLY by the new crates. CLI verbs fold under `envctl secret|vault|relay|ca|run`; `secretd` ships as a new manifest `SystemdUnit` component so `envctl install secretd` stands it up and `envctl reset secretd` unwinds it via the same guarded Wiring revert. The `SecGuard`/`GuardRefused`/resolve-once-`UnlockContext` idiom is the SAME as `envctl-engine`'s `guard.rs`; REQ-SEC-*/FS-S* sit beside REQ-SAFE-*/FS-1..8.

**Dependency hygiene CI gates (review fixes — critical/high):**
- **NO C deps:** `! cargo tree -i aws-lc-sys` and `! cargo tree | grep -E 'libsql-ffi|sqlite3-sys|openssl-sys'` (libSQL was VERIFIED to bundle C SQLite via `libsql-ffi/bundled/src/sqlite3.c` — the store backend is reopened as an OPEN ITEM requiring an operator ruling; see DESIGN-NOTES R9/OI-1).
- **One rustls, ring backend:** `rustls = { default-features = false, features = ["ring","logging","std","tls12"] }`, `rcgen = { default-features = false, features = ["ring","pem"] }`; daemon installs `rustls::crypto::ring::default_provider()` explicitly.
- **MSRV verified:** a `cargo +1.80.0` gate (not the floating `stable` in rust-toolchain.toml), with `idna`/`icu` patch pins if 1.80 must hold (see DESIGN-NOTES R10).
- **Feature matrix:** engine builds for `{default}`, `{--no-default-features --features inmem-store}`, `{inmem-store,mitm-ca}`; `compile_error!` guards enforce exactly-one store backend.
