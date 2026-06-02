# env-ctl — Server Mode (central daemon + remote relay-only clients)

**Status:** Delta on the reconciled + adversarial-hardened design · refines locked decisions #1/#2/#3/#8 ONLY · does NOT relitigate the 12 locked decisions, REQ-SEC-1..9, or FS-S1..S15
**Scope of this delta:** three operator rulings (NEW-1/2/3) add a central server topology and a remote thin-client data plane; the engine's authorization core is unchanged in shape. CONFIRMED critical/high findings from the server-mode adversarial pass are folded in below; medium/low are recorded as OPEN ITEMS.
**Reads with:** `ARCHITECTURE.md` (two-plane model, §1/§6), `THREAT-MODEL.md` (STRIDE, FS-S*), `DESIGN-NOTES.md` (OI-1), `db/schema.sql`, `research/03` (libSQL bundles C SQLite), `research/12` (remote token binding), `research/15` (VPS gating).

> Discipline preserved throughout: **fail-closed**, **dry-run by default for destructive ops**, **never touch user data**, **refuse on ambiguity**, and **the engine never prints** (it emits the `SecretEvent` stream; the durable `audit_log` is committed before any security RPC returns). Nothing here weakens an existing invariant; everything here is additive and default-deny.

---

## 0. The three operator rulings (NEW-1/2/3) and how this delta honors them

| # | Ruling | How the design honors it |
|---|---|---|
| **NEW-1** (topology) | ONE central `secretd` owns the libSQL vault (on THIS dual-5090 box OR a VPS). Remote THIN clients (Telegram cloud agent, phone, laptop) connect IN. Single source of truth. (Refines #2: single-box → central server + remote relay clients.) | One `secretd` = the sole TCB and sole vault owner. Remote clients are data-plane-only thin clients. §1 adds a THIRD plane (remote relay edge); §2 keeps ONE store, owner-only. |
| **NEW-2** (remote auth) | Remote clients get **RELAY-BEARERS ONLY** over HTTPS. They may USE brokered credentials (≤24h scoped relay) but CANNOT reach the control plane. Control stays LOCAL UDS + `SO_PEERCRED`. **NO remote vault management, ever.** (Refines #8.) | The remote edge routes to exactly ONE engine entry point — `relay_swap` — and shares zero RPC routes with control. Control is UDS-only, proven unreachable over the network by **construction** (separate module/process + CI dependency gate), not merely by a runtime self-check. §3 / §6. |
| **NEW-3** (OI-1 resolved) | OI-1 = **libSQL**. Its server/replica/sync is the required feature; a pure-Rust local-only store (redb) cannot serve remote clients. The bundled C SQLite is an **ACCEPTED, SCOPED waiver**: the `envctl-secrets-engine` LIB stays pure-Rust; libSQL + its C core live ONLY in the store/daemon layer. Prefer a deployment that isolates the C core (embedded on the daemon host, or a remote-HTTP libSQL client to a separate `sqld`). | OI-1 is RESOLVED = libSQL with a scoped C waiver (§2). ALL libSQL crates are quarantined in a NEW `secrets-store-libsql` crate consumed ONLY by `secretd`, behind the unchanged `Store` trait. The blanket no-C CI gate becomes a **per-crate scoped pair** (engine stays green; the store crate carries a documented, bounded waiver). The recommended on-box deployment isolates the C core into a **separate process** (embedded `sqld` on loopback + the pure-Rust `remote` client) so a C bug is not co-resident with the network edge and the secret-handling address space. |

---

## 1. Shape: three planes, ONE TCB

The single TCB is unchanged: it is still exactly the `secretd` address space — the only place the plaintext DEK and real upstream keys exist (zeroized on drop, `mlockall` + `RLIMIT_CORE=0` + `MADV_DONTDUMP`). What changes is WHO can reach it and OVER WHAT. There are now **three planes**, not two:

| Plane | Transport | Authz | Who reaches it | Status |
|---|---|---|---|---|
| **Control** | gRPC over UDS under `$XDG_RUNTIME_DIR/env-ctl/control.sock` (0700 dir, 0600 sock) | `SO_PEERCRED` uid == owner (fail-closed) | the owner only (CLI / `envctl`) | unchanged (locked #8) |
| **Local data** | HTTP/HTTPS relay proxy on loopback | relay bearer validated per-request + `SO_PEERCRED` peer-bound at swap (HF-8) | same-box clients holding a ≤24h bearer | unchanged |
| **Remote relay (NEW)** | public **HTTPS + mTLS-required** edge, **TLS terminated in-process by `secretd`** | a ≤24h relay bearer that is **sender-constrained** (DPoP proof-of-possession, §4) and **client-identity-bound**, validated by the SAME `decide()` default-deny machine | remote thin clients (Telegram cloud agent, phone, laptop) | NEW (this delta) |

The remote relay edge is a **strictly additive front-end** to the EXISTING `decide()` default-deny machine. `decide()` keeps its shape: it takes a verified bearer + a canonical request + the presence-gate marker + the issuance floor and is still pure default-deny. The new actor (remote thin client) can ONLY reach `relay_swap`; it can USE brokered credentials; it can NEVER manage the vault (NEW-2).

**Engine-side footprint of the whole delta is tiny and sync:** one generalized client-binding type, one additive field on `CanonRequest`/`VerifiedBearer`, a few `DenyReason` variants, and the rename of the gate input (§4/§5). All TLS, sockets, DPoP verification, and libSQL live in `secretd` / the new store crate — never in the engine lib.

---

## 2. Central store: libSQL behind the unchanged `Store` trait, C-isolated

NEW-3 resolves OI-1 = **libSQL** (its server/replica/sync is the required remote-serving feature; redb is local-only and cannot serve remote clients) with a **scoped, documented C-SQLite waiver**. The delta enforces one structural rule:

> **The `envctl-secrets-engine` LIB never links libSQL.** It continues to operate strictly ABOVE the `Store` trait: ciphertext + non-secret metadata in, blobs out; AAD recomputed at decrypt from trusted identity columns; durable hash-chained audit. App-layer **XChaCha20-Poly1305 stays authoritative** — the store sees only opaque ciphertext (research/03: `sqld` is "untrusted storage"). libSQL's built-in at-rest encryption is **never** relied upon (it is disabled/unimplemented, issue #1756; enabling it would re-add a C cipher dependency — forbidden).

### 2.1 Crate quarantine (one new crate; engine unchanged)

| Path | Package | Owns | C core? |
|---|---|---|---|
| `crates/secrets-store-libsql` (NEW) | `envctl-secrets-store-libsql` | ALL libSQL: the `Store` impl behind the engine trait. Depends on the engine ONLY for `Store` + `AuditRecord`. | yes — the ONLY crate permitted to link `libsql-ffi` (the scoped waiver lives here) |
| `crates/secrets-engine` | `envctl-secrets-engine` | the trait, the crypto, decide() | **NO** — no-C gate stays green |
| `crates/secretd` | `envctl-secretd` | selects the durable store at runtime via a `StoreProfile`; opt-in features `libsql-store` / `libsql-remote` | links the store crate only when those features are on |

The `Store` trait is the encryption boundary and stays unchanged in spirit; the delta adds only a connection-config seam and two methods (no libSQL types leak into the engine API):

```rust
pub trait Store: Send + Sync {
    fn get_meta(&self, k: &str) -> anyhow::Result<Option<String>>;
    fn put_meta(&self, k: &str, v: &str) -> anyhow::Result<()>;
    fn append_audit(&self, rec: &AuditRecord) -> anyhow::Result<i64>;   // DURABLE before the RPC returns (HF-14)
    fn verify_audit_chain(&self) -> anyhow::Result<()>;
    /// Confirm the last write is durably committed (embedded WAL fsync / remote sqld ack).
    /// Err => caller treats the op as InternalRefused (default-deny), NEVER success (HF-14 across the round-trip).
    fn fsync_barrier(&self) -> anyhow::Result<()>;
    /// Liveness of the durable backend; gates daemon startup (fail-closed).
    fn health(&self) -> anyhow::Result<StoreHealth>;
    // secrets / keyslots / relay / ca / remote_clients CRUD — full set in Phase 1, all ciphertext-in/out.
}
pub struct StoreHealth { pub durable: bool, pub schema_version: u32, pub profile: &'static str }
```

`db/schema.sql` stays the **canonical logical model** for both profiles. `inmem-store` stays the CI/test backend AND the engine default; the libSQL backend is opt-in on `secretd` only. `compile_error!` continues to enforce exactly-one durable backend.

### 2.2 C-isolation: the most important store decision

The team's own research (research/03) is blunt: a memory-safety bug in bundled `sqlite3.c` inside the daemon is a direct vault-compromise vector. Putting an embedded C core **in-process** in a daemon that ALSO terminates the public TLS edge is the **weakest** of the options. Therefore, even on-box, the **recommended** wiring isolates the C core into a **separate process**:

- **Recommended on-box store wiring:** an **embedded `sqld` bound to loopback only (no exposed Hrana/gRPC port to the network)**, and `secretd` talks to it via the **`remote` libSQL client** (`default-features=false, features=["remote"]`, *intended* to be pure-Rust with no `libsql-ffi`). **NOT YET PROVEN (audit F1):** the `secrets-store-libsql` crate does not exist yet and `libsql` is absent from `Cargo.lock`, so this purity is a recommendation, not a verified fact. It MUST be proven by the required CI gate below *before* the store ships; **if `libsql`'s `remote` feature does not yield a C-free graph, switch to the separate `libsql-client` + `libsql-hrana` crates** (the unambiguously pure path). The C core then lives only in the separate `sqld` process, isolated from `secretd`'s key-handling and the network edge. The relay edge speaks the typed engine API; the engine owns all (parameterized) SQL; attacker bytes never reach the SQL parser.
- **Fallback (operator risk-accepted):** embedded libSQL **in-process** in `secretd` (`core`/`replication` features = the 8.9 MB bundled `sqlite3.c`). Permitted only with an explicit, recorded operator risk acceptance (research/03 §3), because the C core is then co-resident with the secret-handling address space. If chosen, the public edge MUST run as a separate process from this `secretd` (§6) so internet bytes and the C core are never in one address space.

CI gate delta (replaces the blanket no-C gate with a scoped pair):
- ENGINE pure-Rust (unchanged): `! cargo tree -p envctl-secrets-engine | grep -E 'libsql-ffi|sqlite3-sys|aws-lc-sys|openssl-sys'`.
- STORE crate scoped waiver — a **REQUIRED CI job** (audit F1), failing the build if violated: `cargo tree -p envctl-secrets-store-libsql --no-default-features --features remote | grep -E 'libsql-ffi|libsql-sys'` MUST find **nothing** (pure-Rust remote client = the recommended wiring). If that gate cannot pass with the `libsql` crate, the store crate MUST use `libsql-client` + `libsql-hrana` instead. The embedded `core` build is the documented, bounded, risk-accepted waiver. The blanket `cargo-deny` `libsql-ffi` ban flips to a `secrets-store-libsql`-scoped allow only when that crate lands and the gate is green.
- `secretctl`/`secrets-proto` MUST stay C-free.

---

## 3. Remote auth: relay-bearers only, control PROVABLY unreachable

NEW-2: remote clients get relay-bearers only over HTTPS; they may USE brokered credentials but CANNOT reach the control plane. This is enforced by **construction**, not by a runtime check alone:

1. **Two separate service objects.** The control gRPC service and the remote relay edge are distinct service objects with **disjoint route tables**. The control service is constructed exclusively on a `UnixListener` (FS-S8); the relay edge exposes ONLY `POST /v1/relay/swap` → `relay_swap`. They are not a multiplexed tonic server.
2. **Module/process isolation, CI-enforced.** The control service types live in a module the edge module NEVER imports; a CI dependency check (a `control-types-not-in-edge` grep, the same pattern as the relay-cert-separation grep) fails the build if the edge references any control service type. **Strongly preferred:** run the public edge as a **separate process** from the control listener (it already must be separate from an in-process embedded C core per §2.2), so an internet-facing memory-safety bug cannot reach the control listener's address space at all.
3. **Startup self-check (defense-in-depth, labeled as such).** `secretd` enumerates listeners and **refuses to start** unless exactly one non-loopback listener exists (the relay HTTPS edge) and the control socket is a UDS under `$XDG_RUNTIME_DIR` with no TCP control bind anywhere (extends FS-S8).
4. **Deploy smoke test (defense-in-depth).** From off-box, every control verb (vault/secret/keyslot/ca/relay-create/unlock/lock) is attempted against the public endpoint and MUST fail; a data-plane swap with a valid client cert + DPoP-bound bearer MUST succeed.

The remote control RPCs that DO exist for managing remote clients (`RegisterRemoteClient`, `RevokeRemoteClient`, `MintRemoteBearer`) are **control-plane only**: UDS + `SO_PEERCRED` + USB-gated + dry-run-by-default (`apply` gate). They are NOT routed on the edge; the remote client receives its bearer **out-of-band** and can call none of them.

---

## 4. RESOLVED — remote bearer binding (C-A), scheme C-A

The original bearer was peer-bound to the local caller uid/pid via `SO_PEERCRED` (HF-8). Remote clients have no local uid/pid. The resolution preserves every HF-8 guarantee with a **single normative binding spec** (the three draft deltas proposed three divergent mechanisms; this is the reconciled, finding-corrected one).

### 4.1 The rejected mechanism, and why

A "presented cert fingerprint == registered fingerprint for this client_id" check (one draft's primary control) adds **zero** replay resistance: a certificate is a **public** value sent in the clear in the handshake, so the equality always holds for a known `client_id`. The only thing that made "useless without the device private key" true was mTLS at the TLS layer — and that guarantee is **lost** if any TLS-terminating reverse proxy sits in front, because RFC5705 exported-keying-material (EKM) is only available to the process that performed the handshake. Both pitfalls are forbidden here.

### 4.2 The normative scheme (C-A): DPoP primary, in-process TLS, mTLS opt-in

Per research/12 (the dedicated research for exactly this problem), **DPoP (RFC 9449) is the primary sender-constraint** because mTLS-bound tokens are broken by the corporate-MITM TLS-inspection scenario env-ctl explicitly TOLERATES (a re-signing appliance presents a different public key, defeating cert binding) — and env-ctl ships a local MITM CA as a first-class feature. The scheme:

1. **The edge terminates inbound TLS/mTLS in-process** (an in-tree hyper + rustls edge). No external TLS-terminating reverse proxy for the relay edge. If a front is wanted purely for DoS absorption it MUST operate at **L4 (TCP passthrough / PROXY protocol)** so the session reaches `secretd` intact. A config where the bearer-validating process cannot compute the channel binding is a **forbidden state** (FS-S20).
2. **Per-client identity = a registered `client_id` + a per-client signing key (DPoP, Ed25519).** At registration (local, USB-gated, control-plane) the daemon records the client's DPoP public-key thumbprint (`jkt`). mTLS client certs (from a SEPARATE remote-clients CA, never the MITM CA) are an **opt-in "hardened mode"** for MITM-free deployments only; the corporate-MITM incompatibility is stated.
3. **Sender-constraint folded into the bearer MAC (extends HF-7):**
   ```
   bearer_mac = keyed-BLAKE3(hmac_key,
       token_id || u64be(policy_id) || u64be(expires_at_ms)
       || u8(kind) || len32(client_id)||client_id || dpop_jkt[32])
   ```
   Each request carries a fresh **DPoP proof** the edge verifies (`typ`/`jwk`/`htm`/`htu`/`iat`, a server-issued nonce for clock drift, and a `jti` replay store server-side). A captured bearer alone is useless without the per-request signing key.
4. **`decide()` adds exactly ONE clause (default-deny preserved):** for a remote bearer, REQUIRE `req.remote == Some` AND `req.remote.client_id == bearer.client_id` AND the DPoP thumbprint matches the registered `jkt` AND the per-request DPoP proof verified at the edge — else `Deny(PeerMismatch | RemoteClientUnknown)`. **Cross-kind never crosses:** a remote bearer presented over loopback (`req.remote == None`), or a local bearer presented remotely, is DENIED.
5. **`source_cidr` is defense-in-depth ONLY**, demoted in the same words as `NameConstraints`/`PARTUUID` ("a fast pre-filter, never the sole control"). It is a near-no-op for a cloud agent whose egress IPs rotate; it MUST NOT be one of the AND-clauses that can stand in for a missing strong binding, and it defaults to "unset = not enforced" for cloud clients to avoid rotation-induced fail-closed outages while still logging the source IP per swap.

### 4.3 Guarantees preserved (mapped to HF-8 / OI-10 / OI-11)

- **≤24h rotation:** the single `clamp_ttl` choke point is unchanged.
- **Scope:** the unchanged host/path/method allowlist.
- **USB-gated issuance:** unchanged (in the default topology the USB is local — §5).
- **Per-client revocation:** `RevokeRemoteClient{client_id}` flips the client row `enabled=0`; the edge consults a **fast-path revocation set at the TLS/DPoP handshake** so a revoked client is dropped BEFORE bearer evaluation. `RevokeBearer{token_id}` still kills a single bearer.
- **Audit traceability:** every remote swap row logs `client_id`, `source_ip`, a session id, and a **non-secret hash of the channel binding** (e.g. `BLAKE3(ekm)` truncated) — never raw EKM, never the bearer, never the real key — so a binding-bypass/replay (same bearer under two session bindings) is detectable.

### 4.4 The Telegram cloud-agent posture, stated honestly (not a footnote)

The flagship NEW-1 actor is a Telegram-hosted cloud agent that typically runs in a shared/multi-tenant runtime where a private key in env/config is extractable. If the agent **cannot** hold a non-exportable (HSM/TPM/enclave-backed) key, the binding for THAT client degrades toward bearer-only — i.e. **replay-bounded-by-scope-and-TTL, NOT replay-prevention**. This is the central security property of the new plane and is treated structurally:

- A per-client `hardware_bound` flag in `remote_clients`. The "useless without the device key" claim is advertised ONLY for clients whose key store is attestably non-exportable.
- For a non-hardware-bound cloud agent: **tightest blast-radius controls** — minimal host/path/method allowlist, low `rate_limit_per_min` and `quota_budget`, TTL well under 24h (minutes, e.g. 15–60 min, forcing frequent re-mint that re-checks USB), mandatory per-request audit.
- **Prefer `NativeSubToken`** for the cloud agent where the provider supports it, so what egresses is itself a scoped, short-lived, independently-revocable provider credential rather than a relay bearer that swaps in the real long-lived key.
- **Push model:** the agent's bearer is minted on-demand per task by the operator box, not held standing, so a leaked credential is already near-expiry.
- research/12 §8: the relay bearer and the Telegram bot token are both passwords and Telegram is an active malware C2 channel; they MUST NEVER co-locate in one process.

### 4.5 Streaming revocation (finding fix)

Remote relay traffic can ride a single long-lived HTTP/2 stream (LLM token streaming is the Telegram use case). "Dead at the next request" is false for a stream held open for minutes. Therefore:
- On `RevokeBearer` / `RevokeRemoteClient` / `lock` / USB-pull, **actively tear down** in-flight streams for that `client_id`/policy — do not merely deny the next request.
- **Re-run `decide()` periodically during a long stream** (every N seconds / N bytes) so a revoke or USB-pull aborts an in-flight stream within the grace window (extends FS-S5 to in-flight remote streams). Cap max stream duration per remote bearer well under the bearer TTL.

---

## 5. RESOLVED — USB-gating vs topology (C-B): default + VPS tradeoff

USB-presence gating is meaningful only where the USB physically is. The resolution is **fail-closed with a recommended default and no silent downgrade**, built on a **single presence-gate abstraction** rather than a parallel gate.

### 5.1 One presence gate, not two

The engine's sole egress gate input is generalized from `usb_absent_since_ms` to **`gate_absent_since_ms`**, fed by a daemon-side `PresenceGate` trait:

```rust
pub enum GateState { Present, AbsentSince(Instant), Unproven }
pub trait PresenceGate: Send + Sync { fn resolve(&self) -> GateState; }
```

`UsbProbe` is one impl (Profile A); the operator-box token verifier is another (Profile B). **`decide()` treats `Unproven` EXACTLY like `AbsentSince(now)`** — immediate deny, no grace. There is no second, unspecified gate bolted beside `decide()`; the VPS factor flows through the same choke point or VPS mode refuses to start. (Phase-0 unit test: a VPS-config `decide()` with no valid presence factor denies, mirroring the all-uncertain `UnlockContext` test.)

### 5.2 Profile A — DEFAULT (recommended): daemon on THIS box

`secretd` runs on the dual-5090 box. The USB is physically local; the embedded `sqld`/vault is loopback-only; **ONLY the relay HTTPS edge is network-exposed**. All existing USB-possession gating (REQ-SEC-3/5, FS-S5, swap-time re-check + drain) is **unchanged byte-for-byte** because the daemon host holds the USB. A remote swap re-checks USB possession on the host exactly like a local swap — pull the USB and remote egress stops within the grace window.

**Two finding-driven tightenings for the remote plane:**
- **Plane-specific grace:** the ~5-min grace was sized for the local-UX "brief USB jiggle mid-command" case; it is mis-sized as a remote security boundary. For the **remote plane the grace is short or zero** — on USB-absent, deny NEW remote egress immediately while local same-box ergonomics keep the existing grace. The remote grace is a **security** parameter, not a UX one.
- **On-box gate must actually be backed by a USB keyslot:** if topology is on-box and NO enabled `usb_keyfile` keyslot exists, the daemon **refuses to start** (or forces every `usb_gated=0` to be an explicit, audited operator choice) — a passphrase-only on-box vault otherwise has the A12 posture (minus the hypervisor risk) while the operator believes they are in the strong default. New FS-S22 (symmetric to the VPS FS-S21).

### 5.3 Profile B — VPS (explicit opt-in, fail-closed, **non-shippable until the authorizer protocol is specified**)

If `secretd` runs on a VPS the USB cannot be there. VPS mode is supported only with an explicit substitute factor and **never silently downgrades**, but the substitute protocol is currently UNSPECIFIED and load-bearing, so VPS mode is **gated as non-shippable** until it is designed and tested (OI-SM-2):

- **Store:** prefer the pure-Rust `remote` libSQL client to a SEPARATE hardened `sqld` (JWT Ed25519 + TLS + pinned cert, **never the open default** — research/03: `sqld` defaults to no auth, no usable at-rest encryption). `sqld` is untrusted ciphertext storage; only app-encrypted blobs reach it; the DEK is never persisted.
- **Substitute gate (split authority):** mint/renew/post-grace swap on the VPS REQUIRE a short-lived, **operator-box-signed presence token** issued over the mTLS remote channel by an `env-ctl authorizer` on the box that holds the USB. The presence token maps into `gate_absent_since_ms` via the `PresenceGate` impl. If the operator box (USB holder) is unreachable, the VPS **drains in-flight and denies new egress** — identical fail-closed semantics to a USB pull. **A VPS deploy with no configured substitute factor fails closed at startup** (FS-S21).
- **Wrapping vs gating are separate roles (finding fix):** a `remote_release` keyslot MAY wrap the DEK for boot unlock, but unwrapping the DEK once at boot does **not** inherit the USB's *continuous* swap-time gate. Continuous gating MUST be the separate, periodically-refreshed presence token. Forbidden state FS-S23: VPS egress succeeds using a DEK unwrapped at boot while no currently-valid presence token exists.
- **Forbidden substitute factors:** a **vTPM has no hardware boundary** on an untrusted hypervisor (it inherits the hypervisor's trust) — **forbidden by default**. SEV-SNP is allowed ONLY if the daemon verifies at startup that the attestation report shows TCB/spec ≥ 1.58 (fail-closed otherwise). Allowed substitutes: the operator-box-signed token, or (AWS-only) a Nitro Enclave + attested KMS. FS-S24 forbids gating DEK release on a vTPM.
- **Trusted time:** the VPS clock is hypervisor-controlled, which defeats the owner-writable monotonic issuance floor and can extend bearer TTLs. VPS mode REQUIRES an **external trusted time source** (e.g. Roughtime / signed time from the operator box) for bearer issuance and acceptance; refuse issuance if trusted time is unavailable (OI-SM-3).

### 5.4 The VPS at-rest tradeoff, stated plainly (the reason VPS is opt-in)

In VPS mode the secrets-at-rest live OFF the operator box as app-encrypted ciphertext on a host the operator does not physically control. With no USB factor present, the keyslot model collapses to the **passphrase keyslot's argon2id work factor** (the A12 1-of-2 downgrade made structural and permanent). The presence-token gate is a **run-time issuance** control; it does **nothing** for a memory-capture adversary — the DEK lives in VPS RAM while unlocked, exposed to hypervisor / cross-VM (VMScape CVE-2025-40300) / cold-boot / chosen-plaintext (Heracles, SEV-SNP pre-1.58) adversaries. The operator-box-token gate is NOT a substitute for the USB's at-rest role. The only postures that keep the DEK off the cloud host are **Profile A** or a **Nitro Enclave + attested KMS**. This is why Profile A is the default and VPS is opt-in with eyes open, behind an explicit, audited operator risk acceptance at install.

---

## 6. RESOLVED — public relay endpoint TLS + hardening (C-C)

The remote relay edge is a NEW network attack surface. Resolution across all four sub-points:

### 6.1 TLS / cert strategy: three disjoint roots, each one job

| Cert/CA | Role | Trust path | Never |
|---|---|---|---|
| **Edge SERVER cert** | secures the inbound remote hop | **PUBLICLY-TRUSTED** (ACME/Let's Encrypt for a VPS FQDN, or an org CA the phone/Telegram agent already trusts). Loaded from `~/.config/env-ctl/relay-tls/{cert.pem,key.pem}` (key 0600). | NEVER the local MITM CA |
| **Remote-clients CA** (hardened mTLS mode only) | the edge's `ClientCertVerifier` trusts ONLY this root | private, env-ctl-owned, app-encrypted under the DEK; signs SHORT-lived client leaves (≤7d, auto-renewed on USB-gated liveness) | NEVER the MITM CA, never the public server cert |
| **MITM CA** | UNCHANGED; signs upstream-interception leaves on the daemon host only | local, loud subject `env-ctl LOCAL MITM CA — DO NOT TRUST GLOBALLY` | NEVER network-served; NEVER presented to remote clients |
| **Upstream egress roots** | UNCHANGED; verify the real upstream | frozen `webpki_roots::TLS_SERVER_ROOTS` only (FS-S7) | never the OS store, never any local CA |

Remote clients trust the edge via the **public PKI** — they install nothing. Mixing the MITM CA into the edge (forcing clients to install it, or chaining the edge cert to it) is a **forbidden state** (FS-S25). The separation is made **structural, not grep-only**: the edge's rustls `ServerConfig` is built from a type that can only be loaded from the `relay-tls` path, and the MITM CA key is a distinct newtype the edge module cannot import (a CI grep that the relay listener module never references the MITM CA path is retained as defense-in-depth). A startup self-check verifies the presented edge cert chains to a **public root** and explicitly NOT to the MITM CA or the remote-clients CA, failing closed otherwise.

### 6.2 Rate-limit / DoS

- **mTLS/DPoP-required before app bytes:** unauthenticated peers are dropped at the handshake, before any crypto / before the C core / before a DB write.
- **Per-source-IP handshake rate limit + per-client-id token buckets + global connection cap + body-size caps + request timeouts** (absorbs slowloris/floods). The **accept-loop DoS class (CVE-2024-47609)** applies to this NEW network listener (it is a network-listener bug, NOT addressed by "control is UDS-only"): pin `tonic ≥ 0.12.3` + a patched hyper line, enforced by `cargo audit` in CI.
- **Authenticated-flood / write-amplification defense:** a compromised client with a valid key can drive high-rate swaps, each hitting `decide()`, the bearer verify, and the **durable audit fsync** (HF-14). Enforce `rate_limit_per_min` and `quota_budget` as **hard pre-`decide()` admission control** (shed before any crypto or DB write); **group-commit** audit writes for high-rate swaps while preserving "durable before response" (the group fsyncs before any batched response returns); cap concurrent in-flight swaps per `client_id` and globally; keep MITM leaf minting rate-limited and cached.

### 6.3 Control-plane unreachability (proven, §3) and C-core exposure

Control unreachability is proven by construction (§3). The libSQL C core is network-facing only via §2.2; the recommended wiring (separate-process `sqld` + pure-Rust `remote` client) keeps the C core out of the edge's address space entirely. The `sqld`/Hrana port is loopback or private-network + mTLS-pinned and is included in the listener self-check allowlist explicitly. The Profile-B operator-box→VPS authorizer link is treated as a **privileged control-adjacent boundary**: mTLS, pinned, its own narrow message schema, rate-limited, audited, and explicitly unable to invoke any vault-management verb (it can only RELEASE issuance, never manage the vault).

### 6.4 Ordering: auth before swap, durable audit before Allowed

The remote-swap order is pinned (reuses CF-9 default-deny-by-construction):
```
edge: mTLS/DPoP verify  →  per-client rate/quota admission  →  decide() == Allow
   →  durable append_audit + fsync_barrier confirmed  →  THEN fetch real key (inside Allow)  →  Upstream::send
```
Any failure before the barrier maps to `InternalRefused` / 403 with a durable deny audit — never a fall-through to `Upstream::send`. For a remote `sqld`, a barrier timeout is a hard fail-closed deny, and the deny itself is durably auditable on a path that does not depend on the same stalled node (the operator-box-local audit mirror under `~/.local/state/env-ctl`). Forbidden state FS-S26: a remote swap returns Allowed before its audit row is durably committed.

### 6.5 Availability coupling (ACME)

A lapsed edge cert breaks all remote clients; on a CGNAT/dynamic-IP home box ACME may be impractical, pressuring operators toward the weaker VPS. **Default mitigation:** a **reverse tunnel from a small public VPS to the on-box daemon** — public TLS terminated **on-box** (so EKM/DPoP binding survives, §4) and forwarded over an authenticated channel — keeping the USB-local Profile A viable WITHOUT exposing the box or moving the vault to the VPS. Monitor cert expiry and **fail closed** (refuse remote clients) on a lapsed cert; there is NO MITM-CA fallback by design (FS-S25).

---

## 7. This-box vs VPS — decision table + deployment steps

### 7.1 Decision table

| Dimension | Profile A — THIS box (DEFAULT, recommended) | Profile B — VPS (opt-in, fail-closed, non-shippable until OI-SM-2) |
|---|---|---|
| Vault / DEK location | on the operator box (physical control) | OFF the operator box (untrusted hypervisor) |
| USB gating | local, **unchanged** (REQ-SEC-3/5, FS-S5) | substituted by operator-box-signed presence token (split authority) |
| At-rest strength | full keyslot model (USB + passphrase) | **passphrase argon2id only** (USB absent) — structural downgrade |
| Memory-capture adversary | bounded to the box the operator controls | DEK in VPS RAM, exposed (VMScape / Heracles / cold-boot) |
| Store C core | separate-process `sqld` on loopback + pure-Rust `remote` client (preferred); in-process embedded = risk-accepted fallback | separate `sqld` node, pure-Rust client on the VPS |
| Network surface | ONLY the relay HTTPS edge | relay HTTPS edge + the `sqld` link + the authorizer link |
| Trusted time | system clock (box) | **external trusted time required** (hypervisor clock untrusted) |
| Reachability | reverse tunnel from a small VPS → on-box daemon (TLS terminated on-box) | direct public FQDN + ACME |
| Recommendation | **use this** | only if reachability truly forces it, with explicit risk acceptance |

### 7.2 Deployment steps

**Profile A (default):**
1. `envctl install secretd` on THIS box (manifest `SystemdUnit`; user service under `$XDG_RUNTIME_DIR`). Insert and enroll the USB keyslot (daemon refuses to start on-box with no USB keyslot — §5.2).
2. Store: `store.profile = "embedded"`; run an embedded `sqld` bound to loopback; `secretd` uses the pure-Rust `remote` client to it. (In-process embedded only with a recorded risk acceptance, and then the edge runs as a separate process.)
3. Edge: provision a PUBLICLY-TRUSTED relay cert (ACME or operator-supplied) into `relay-tls/`. For a home box, default to a **reverse tunnel from a small VPS** terminating public TLS **on-box**.
4. Register each device locally (USB present): `envctl relay register-remote --client-id phone --source-cidr ...` → records the DPoP `jkt` (and, in hardened mode, mints a ≤7d mTLS client leaf from the remote-clients CA). Hand the device its bearer + (hardened mode) cert **out-of-band**.
5. Open ONLY the relay port in the firewall; control via local `secretctl` over UDS. Pull the USB → remote egress stops within the (short, remote-plane) grace; `lock` / `relay revoke --all` are the panic stops for remote too.
6. Run the deploy smoke test (§3): every control verb undialable off-box; a valid DPoP-bound swap succeeds; USB-pull stops remote egress within grace.

**Profile B (VPS, opt-in — blocked until OI-SM-2/3 ship):**
1. Provision a hardened `sqld` node (JWT Ed25519 + TLS + pinned cert, NOT the open default).
2. `secretd --features libsql-remote`, `store.profile = "remote"`, `sync_url`/`auth_jwt`/`tls_pin` set.
3. Configure the substitute gate: `env-ctl authorizer` on the operator box (holds the USB), reachable over mTLS; configure trusted time. No gate configured ⇒ refuses to start (FS-S21).
4. Provision a publicly-trusted edge cert (ACME). Record the explicit operator risk acceptance for the at-rest downgrade (§5.4).
5. All startup self-checks must pass or the daemon refuses to serve.

---

## 8. THREAT-MODEL DELTA

### 8.1 New trust-boundary rows (append to THREAT-MODEL §1)

| Crossing | Carries |
|---|---|
| remote client → relay edge (public TLS, in-process) | publicly-trusted server cert; DPoP-bound (mTLS hardened-mode) ≤24h bearer; rate-limited; channel binding computed in-process |
| `secretd` → embedded/separate `sqld` | loopback or private mTLS-pinned; app-encrypted ciphertext only; `sqld` is untrusted storage |
| operator box (USB) → `secretd`-VPS (Profile B only) | mTLS; short-lived operator-box-signed presence tokens; fail-closed if absent; cannot invoke vault management |

### 8.2 New adversaries (STRIDE; append to THREAT-MODEL §2)

| # | Adversary | STRIDE | Mitigation |
|---|---|---|---|
| A13 | Remote attacker on the public relay edge | Spoofing/EoP | Public TLS + DPoP sender-constraint (mTLS hardened mode); no proof ⇒ rejected at the edge; control has NO network route (proven by construction, §3); only default-deny, scoped, ≤24h egress is reachable [NEW-2] |
| A14 | Stolen remote bearer replayed by another host | Spoofing | Bearer MAC binds `client_id` + DPoP `jkt`; a request without the per-request signing key ⇒ `PeerMismatch`; ≤24h; per-bearer + per-client revocation [C-A] |
| A15 | Fully-compromised remote client (key + bearer) | EoP/Info | Blast radius == that client's relay scope only (allowlist + rate/quota + ≤24h + canonical-upstream-only); `revoke-client` kills it next handshake; in-flight streams torn down (§4.5). **Bounded, not prevented** (mirrors A2) [C-A] |
| A16 | Network flood / slowloris / accept-loop DoS at the edge | DoS | Per-IP handshake limit before mTLS/DPoP; patched `tonic`/`hyper` (CVE-2024-47609); body caps, timeouts, global conn cap; pre-`decide()` admission shedding [C-C] |
| A17 | Attempt to reach vault management over the public endpoint | EoP | Control gRPC binds ONLY a `UnixListener`; edge routes ONLY to `relay_swap`; module/process isolation + CI dependency gate + deploy smoke test [NEW-2] |
| A18 | C SQLite memory-safety bug in a network-facing daemon | Tampering/EoP | Recommended wiring puts the C core in a SEPARATE `sqld` process (pure-Rust `remote` client in `secretd`); typed API, no attacker SQL, app-AEAD'd rows; in-process embedded only with recorded risk acceptance + separate edge process [NEW-3] |
| A19 | VPS-hosted vault: secrets-at-rest + DEK-in-RAM off the operator box | Info | At-rest == passphrase argon2id only (USB absent); DEK in VPS RAM exposed to hypervisor/cross-VM (VMScape)/cold-boot/Heracles; presence-token gate does NOT defend memory capture; stated plainly — the reason VPS is opt-in [C-B] |
| A20 | Telegram cloud agent with an extractable key | Spoofing/Info | If not `hardware_bound`: binding degrades to bearer-only ⇒ tightest scope/quota/short-TTL/push-mint + prefer `NativeSubToken`; bot token and relay bearer never co-located (research/12 §8); the strong-binding claim is gated behind the `hardware_bound` flag [C-A] |

### 8.3 New affirmative requirements (append to THREAT-MODEL §3)

- **REQ-SEC-10 (remote binding fail-closed):** a remote bearer is accepted ONLY if the presented `client_id` + DPoP proof matches the registered binding AND the client row is enabled; any uncertainty (no proof, unknown `client_id`, channel binding uncomputable) ⇒ `Deny(PeerMismatch)`. Cross-kind binding ⇒ Deny. `source_cidr` is defense-in-depth only.
- **REQ-SEC-11 (control plane network-unreachable, provable):** the control gRPC service is constructed only on a `UnixListener`; the edge exposes ONLY the swap route; a CI dependency gate forbids control service types in the edge module; a deploy smoke test confirms every control verb is undialable over the public endpoint.
- **REQ-SEC-12 (remote edge hardening):** the edge terminates TLS in-process (no TLS-terminating front; L4 passthrough only), presents a publicly-trusted cert (never the MITM CA), and enforces per-source rate limits + body caps + timeouts + global conn caps + pre-`decide()` admission control.
- **REQ-SEC-13 (presence-gate unification):** all gating flows through `gate_absent_since_ms` fed by a `PresenceGate`; `Unproven` is treated as `AbsentSince(now)`; VPS mode with no configured substitute factor refuses to start.

### 8.4 New forbidden states (append to THREAT-MODEL §4; unique IDs continuing FS-S15)

| ID | Must never happen |
|---|---|
| FS-S16 | A remote bearer is accepted without a verified DPoP proof (hardened mode: without a verified, registered, non-revoked mTLS client cert) whose binding matches the bearer's `client_id` (anonymous or mismatched remote egress). |
| FS-S17 | Any control-plane verb is dialable over the public/remote endpoint, or a control RPC is registered on any TCP/network listener. |
| FS-S18 | The local MITM CA (or any cert chaining to it) is presented as the public relay edge cert, or a remote client is asked to install the MITM CA. |
| FS-S19 | The relay edge binds a public/non-loopback interface behind a TLS-**terminating** front (binding uncomputable), or accepts a remote request with no sender-constraint proof. |
| FS-S20 | A relay bearer is accepted over a connection whose channel binding could not be computed by the bearer-validating process. |
| FS-S21 | `secretd` runs in VPS mode with no configured substitute presence factor (silent USB-gating downgrade). |
| FS-S22 | `secretd` runs on-box / Profile A with NO enabled `usb_keyfile` keyslot yet serves USB-gated egress (the gate backs nothing). |
| FS-S23 | VPS egress succeeds using a DEK unwrapped at boot while no currently-valid presence token exists. |
| FS-S24 | DEK release is gated on a vTPM whose isolation is hypervisor-backed (no hardware boundary). |
| FS-S25 | The relay edge cert chains to the MITM CA, or a lapsed public edge cert silently falls back to the MITM CA. |
| FS-S26 | A remote swap returns Allowed before its audit row is durably committed (`fsync_barrier` unconfirmed). |

### 8.5 New residual risks (append to THREAT-MODEL §5)

- **A15/A20 are bounded, not prevented** (mirror A2): a fully-compromised remote client acts within its relay scope until revoked; mitigation is blast-radius reduction, not prevention.
- **VPS at-rest (A19):** app-encrypted ciphertext + DEK-in-RAM on an untrusted hypervisor reduces to passphrase strength and is exposed to memory-capture; Profile A avoids this entirely.
- **The scoped C-SQLite waiver (NEW-3)** is real residual surface; the recommended separate-`sqld` wiring bounds it; an in-process embedded build requires a recorded operator risk acceptance and a periodic libSQL CVE watch.

---

## 9. OPEN ITEMS (server-mode; medium/low — to append to DESIGN-NOTES)

| ID | Severity | Item |
|---|---|---|
| OI-SM-1 | medium | DPoP plumbing details: `jti` replay-store sizing/eviction, server-issued nonce lifecycle, clock-drift window; the exact `remote_clients` schema for `jkt` + `hardware_bound`. |
| OI-SM-2 | high (blocks VPS) | Operator-box authorizer protocol (presence-token format/binding/TTL/replay window/outage behavior) + the substitute-factor declaration UX. VPS mode is non-shippable until specified and FS-S21/S23 have passing negative tests. |
| OI-SM-3 | high (blocks VPS) | External trusted-time source for VPS bearer issuance/acceptance (hypervisor clock untrusted; defeats the monotonic floor). |
| OI-SM-4 | medium | Remote-clients CA lifecycle (separate from MITM CA + edge server cert): leaf TTL/rotation (≤7d), revocation-set propagation latency at the handshake. |
| OI-SM-5 | medium | Telegram cloud-agent key custody confirmation: does the runtime offer a non-exportable/process-isolated key store? Sets `hardware_bound`; otherwise the bearer-only degraded posture (§4.4) applies. |
| OI-SM-6 | medium | Reverse-tunnel-from-VPS pattern as the home-box default reachability path; ensure TLS termination stays on-box so DPoP/EKM survives. |
| OI-SM-7 | low | Per-client `source_cidr` UX; documented as defense-in-depth pre-filter only (never sole control), default unset for cloud clients. |
| OI-SM-8 | low | libSQL embedded-replica sync is offline/Last-Push-Wins; if ever used, replicate only NON-secret metadata read-only; revocation/audit are never Last-Push-Wins. |

---

## 10. Phasing (ROADMAP delta)

- **Phase 0 (now):** add the fail-closed surface as compile-present `todo!()` guards — the `RemotePeer`/client-binding type, the new `DenyReason` variants, the `relay_bearers.client_id`/`dpop_jkt` fields, the `gate_absent_since_ms` rename + `PresenceGate` trait, and the listener-enumeration self-check. The safety surface is never deferred (the existing rule). The public edge listener MUST NOT serve until the remote-binding deny path and the self-check are non-`todo!()`.
- **Phase 1:** store work targets the **libSQL backend behind the `Store` trait in the new `secrets-store-libsql` crate** (Profile A; recommended separate-process `sqld` + pure-Rust `remote` client). `inmem-store` remains the CI analogue and the engine default.
- **New Phase 8 — SERVER-MODE (remote relay HTTPS plane):** in-process TLS-terminating edge; DPoP verification + replay store; remote-clients CA (hardened mode); `RemotePeer`/binding wired into `decide()`; the listener self-check + deploy smoke test; the publicly-trusted edge cert; streaming revocation tear-down. **Profile B (VPS) is a gated sub-item, blocked behind OI-SM-2/3** (operator-authorizer protocol + trusted time) — until then Profile A is the only production path and the daemon refuses VPS mode.
