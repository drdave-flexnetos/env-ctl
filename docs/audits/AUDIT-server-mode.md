# env-ctl — SERVER-MODE Design Audit (lead-auditor consolidation)

**Target:** the DESIGN in `docs/SERVER-MODE.md` (central `secretd` + libSQL vault + remote relay-only
thin clients; DPoP-bound bearers; control-plane local-UDS-only; on-box USB-PARTUUID default; VPS
Profile B deferred), cross-referenced with `docs/THREAT-MODEL.md`, `docs/research/{03,12,15}`,
`docs/ops/{01,02,07}`, and the **committed** relay logic in
`crates/secrets-engine/src/broker/decide.rs`.
**Method:** six SERVER-MODE lens reports (remote DPoP binding · control-plane unreachability +
Phase-8 readiness · libSQL C-isolation · public-edge TLS/DoS/cert-separation · USB-gating vs
topology/VPS · threat-model FS-S16–S26 / REQ-SEC-10–13 completeness) deduplicated and re-derived
against source. Adversary assumed: network attacker on the public edge, a compromised/Telegram agent
holding a bearer, a stolen bearer, a TLS-terminating malicious reverse proxy, and a VPS-snapshot
attacker.
**Posture:** READ-ONLY review of a DESIGN before its Phase 6/8 implementation. Ground-truth verified
against the committed `decide()`, `docs/db/schema.sql`, the workspace `Cargo.toml`, `Cargo.lock`, and
the `crates/` tree as of 2026-06-02.

---

## 1. Executive verdict

**The SERVER-MODE design is architecturally SOUND and is NOT yet shippable for Phase 6/8 — by its own
explicit deferral, not by a hidden flaw.** Across all six lenses there is consensus and zero dissent:
the three-plane model (control UDS-only, local data, remote relay edge), the DPoP-primary
sender-constraint (RFC 9449, correctly chosen over mTLS-bound tokens because env-ctl ships a MITM CA),
the fail-closed `PresenceGate` abstraction (`Unproven` treated exactly as `AbsentSince(now)`), the
disjoint-trust-root cert strategy (FS-S25, no MITM-CA fallback), and the honest VPS at-rest downgrade
(A19) are all correct in intent. The design also correctly gates Profile B (VPS) as **non-shippable**
until the operator-box authorizer protocol (OI-SM-2) and trusted time (OI-SM-3) exist.

**Two things separate "sound design" from "shippable":**

1. **ONE genuine CRITICAL that is a design-doc DEFECT, not a deferral:** SERVER-MODE §2.2 (line 75)
   asserts the libSQL `remote` client is *"VERIFIED pure-Rust, no libsql-ffi."* This is **not verified** —
   it is an unproven assertion that masks a supply-chain hazard. The ops doc (`ops/07 §1.1`) correctly
   demands a `cargo tree` gate that does not yet exist in any runnable CI, and `secrets-store-libsql`
   does not yet exist. Until the exact gate below is GREEN, the recommended on-box wiring is
   **risk-accepted, not verified**. This must be corrected in the *design doc's wording* and proven in
   CI before Phase 1.

2. **A cluster of HIGH items that are real but correctly scoped to Phase 8** (remote binding fields
   absent from `decide()`/schema; the in-process TLS+DPoP edge is `todo!()`; streaming revocation
   tear-down unspecified; jti replay-store undefined; the VPS install-time gate; the CVE-2024-47609
   pin is vague). These are execution gaps the design itself names; the risk is that the
   normative `bearer_mac` formula (§4.2) and the committed `decide()` are bridged sloppily at Phase 8
   and a binding-bypass slips through.

**Honest residual — the Telegram key-custody problem cannot be designed away.** SERVER-MODE §4.4 is
commendably candid: a Telegram cloud agent in a shared/multi-tenant runtime where the DPoP private key
is extractable degrades to **bearer-only — replay-bounded by scope/TTL, NOT replay-prevented.** No
amount of protocol work fixes this; it is a property of the deployment surface. The design's mitigation
(the `hardware_bound` flag gating the strong-binding claim, tightest scope/quota/short-TTL, push-mint,
prefer `NativeSubToken`, bot-token-never-co-located) is the correct *blast-radius* response, but
**OI-SM-5 — does the Telegram runtime actually offer a non-exportable key store? — is unresolved**, and
a mis-set `hardware_bound=true` silently over-claims security. This residual is the single most
important thing for the operator to internalize before exposing the Telegram plane: **the flagship
actor is the weakest-bound actor, and that is structural.**

---

## 2. Findings (severity-sorted, deduplicated across the six lenses)

| # | Sev | Title | Location | Impact | Fix | Conf |
|---|-----|-------|----------|--------|-----|------|
| F1 | **CRITICAL** | libSQL `remote` purity is **design-asserted, not cargo-tree-proven** (3 lenses agree) | `SERVER-MODE.md §2.2` lines 75, 175; `ops/07 §1.1` (correctly flags), `Cargo.toml` libsql block; `secrets-store-libsql` absent; `libsql` absent from `Cargo.lock` | The store owns the vault; a default-features misconfig re-adds `libsql-ffi`/`libsql-sys` (8.9 MB `sqlite3.c`) into the secret-handling/edge address space (A18). The "VERIFIED" claim makes a risk-accepted config look proven. | Correct the §2.2 wording from "VERIFIED" to "to be proven by CI gate". Decide crate path (`libsql` `--no-default-features --features remote` vs `libsql-client`+`libsql-hrana`) and land the EXACT gate in §3 below as a **required** job before Phase 1. Until GREEN: risk-accepted, not pure. | high |
| F2 | **CRITICAL** | In-process TLS+DPoP edge is `todo!()`; no edge module exists | `crates/secretd/src/main.rs` (`todo!()`); `SERVER-MODE §4.2` lines 106-118; `ops/07 §1.2` shape-grep expects `crates/secretd/src/edge` which is absent; FS-S20 | No TLS termination, no EKM/channel binding, no DPoP verification, no enforcement of FS-S20. The plane that the whole delta adds does not exist yet. | Phase 8: rustls `ServerConfig` from the `relay-tls` path only (never MITM CA, FS-S25); hyper listener on the public NIC; RFC 9449 proof verify (typ/jwk/htm/htu/iat/nonce/jti). The validating process MUST be the one that computed the binding (FS-S20). Add the `control-types-not-in-edge` grep once the module exists. | high |
| F3 | **HIGH** | Remote binding fields absent from `decide()`/`VerifiedBearer`/`CanonRequest` — REQ-SEC-10/FS-S16 unenforceable (4 lenses agree) | `decide.rs` `VerifiedBearer` (39-49: only `client_uid`/`client_pid`), `CanonRequest` (59-73: no `remote`), DenyReason (17-35), PeerMismatch is local-only (140-149); `SERVER-MODE §4.2` clause 4 | The normative `bearer_mac` formula binds `client_id`+`dpop_jkt[32]`, but no field carries them. `decide()` would treat a remote bearer like a local one; cross-kind presentation (remote-over-loopback / local-over-remote) is not denied. | Phase 8: add `RemotePeer{client_id, dpop_jkt, dpop_verified}`; `CanonRequest.remote: Option<RemotePeer>`; `VerifiedBearer.client_id/dpop_jkt`. New clause after line 149: if `req.remote.is_some()` require `client_id`==bearer + jkt match + proof verified, else if `bearer.client_id.is_some()` and `req.remote.is_none()` deny cross-kind. | high |
| F4 | **HIGH** | Remote `DenyReason` variants missing — audit granularity / forbidden-state distinction lost | `decide.rs` DenyReason enum (17-35); REQ-SEC-10; FS-S16 | All remote failures collapse to `PeerMismatch`; operators cannot distinguish missing-DPoP from unknown-client from revoked-client from jkt-mismatch from replay — defeating the §4.3 audit-traceability goal. | Phase 8: add `RemoteClientUnknown`, `RemoteClientRevoked`, `RemoteNoDPoP` (and optionally `DPoP_VerificationFailed` if any fallback path lets proof failure reach `decide()`; otherwise document that proof failure 401s at the edge and NEVER reaches `decide()`). Test each variant separately. | high |
| F5 | **HIGH** | Streaming revocation tear-down specified but unimplemented; `decide()` is per-request only (3 lenses agree) | `SERVER-MODE §4.5` lines 140-144 (labeled "finding fix"); `decide.rs` (all 17 checks point-in-time); `relay_swap` per-request; no stream/session field, no timer | A revoked/compromised remote client on a long-lived HTTP/2 stream (LLM token streaming — the Telegram use case) keeps egressing after RevokeBearer/RevokeRemoteClient/lock/USB-pull until the stream ends or TTL elapses — defeating revocation and USB-pull as panic stops (extends FS-S5). | Phase 8 (edge/daemon, not the pure `decide()`): track in-flight streams by `(client_id, token_id)`; re-run `decide()` every N s / N bytes; on revoke/lock/USB-pull send RST_STREAM (CANCEL) or 403 + `X-Revoked-At`; cap stream duration well under bearer TTL; audit every abort durably. Recommend concrete N (e.g. ≤10 s for the remote tier). | high |
| F6 | **HIGH** | DPoP `jti` replay-store undefined → DoS + replay-window ambiguity (3 lenses agree; OI-SM-1) | `SERVER-MODE §4.2` line 115, OI-SM-1 line 320; `research/12 §2.2` | Unbounded `jti` store = memory-exhaustion DoS by a flood of unique-`jti` proofs. Undefined eviction = old-`jti` replay window. Undefined nonce strategy + genuine-retry handling = either rejected legitimate retries or accepted replays. | Before Phase 8 ship, specify in DESIGN-NOTES: proof validity window (e.g. 5 min); store = bounded ring/LRU (cap ~10k or proportional to clients×window) with deterministic eviction; nonce strategy (eager round-trip vs lazy on >10 s drift); genuine-retry recovery (new nonce invalidates old jti so the retry is accepted); count jti probes against `rate_per_min`. | high |
| F7 | **HIGH** | VPS Profile B has no install-time gate → silent USB-gating downgrade (FS-S21) | `SERVER-MODE §5.3` lines 171-180; `ops/01 §8` (sketch only); `ops/02 §3` (`enable=false` until Phase 6); FS-S21 line 301 | Operator editing `secrets.toml` to `profile="remote"` without `operator_authorizer_url` silently downgrades to passphrase-only at-rest (A19) and bypasses the substitute presence factor. | Manifest install script (ops/02 §3): if `secrets.toml` has `profile="remote"`, REQUIRE `operator_authorizer_url` configured else FATAL exit 1 (fail-closed). Until OI-SM-2/3 land, gate must be present; any VPS-config merge in CI must also add OI-SM-2/3 or fail (mirror the `enable=false` gate). | high |
| F8 | **HIGH** | VPS operator-box authorizer protocol unspecified — blocks Profile B (OI-SM-2) | `SERVER-MODE §5.3` lines 172-177; OI-SM-2 line 321; FS-S21/S23 | Without token format/binding/TTL/replay-window/outage behavior, a VPS deploy cannot exist; a weak binding invites token-mint from a compromised box or replay. | Design + test: Ed25519-signed token {ts, vps_instance_id, nonce, expiry, replay_nonce}; bound to VPS mTLS cert + per-request server nonce; short TTL (5-15 min forcing re-mint that re-checks USB); replay defense (server nonce/jti); operator-box-unreachable ⇒ drain + deny (fail-closed). Negative tests for FS-S21/S23 must pass before Profile B is shippable. | high |
| F9 | **HIGH** | Wrapping-vs-gating separation not enforced in code (FS-S23) | `SERVER-MODE §5.3` line 177; FS-S23 line 303; `research/15 §2` | A `remote_release` keyslot unwraps the DEK at boot; if the boot-unwrapped DEK is cached and the presence token later goes `Unproven`, egress could continue without a valid presence factor — violating fail-closed. | Phase B: at startup in VPS mode assert PresenceGate not `Unproven` before any swap (FS-S21); on EVERY `relay_swap` re-resolve the gate (never cache the result across swaps); `Unproven` at swap ⇒ deny `GateAbsent`. The vault DEK cache MUST NOT be the relay path's authority. | high |
| F10 | **HIGH** | CVE-2024-47609 fix is named vaguely ("pin tonic ≥0.12.3 + a patched hyper line") | `SERVER-MODE §6.2` line 205; `Cargo.toml` pins `tonic = "0.12"` (not ≥0.12.3) and `hyper = "1.5"` with no patched-line comment | Accept-loop DoS on the NEW network listener (NOT mitigated by "control is UDS-only"); the mitigation is unverifiable at implementation time and the current pins do not encode it. | In `Cargo.toml`: bump to the exact `tonic ≥ 0.12.3` and the named patched `hyper` version, with a comment citing the fix. Add a `cargo audit`/`cargo deny check advisories` CI step that FAILS if CVE-2024-47609 is unresolved. | high |
| F11 | **HIGH** | MSRV 1.80 unverified against the real lockfile (HF-18 / OQ-1) | `ops/07 §2.1` lines 140-145, OQ-1 line 581; `Cargo.toml` `rust-version="1.80"`; box `rustc` is 1.96 | `reqwest 0.12 → url → idna → icu` has historically bumped MSRV past 1.80; a silent transitive bump breaks the declared floor for the secretd dep chain. Engine (pure-Rust, 1.80-OK) is fine; Phase 6 (tokio/hyper/rustls/reqwest) is the risk. | Run `cargo +1.80.0 check --workspace --locked --all-features` as advisory NOW; pin `idna`/`icu` to 1.80-compatible patches or raise the floor with a recorded DESIGN-NOTES decision. Blocker for Phase 6, not Phase 0. | medium |
| F12 | MEDIUM | `bearer_mac` does not encode plane (`u8(kind)` undefined); cross-plane fails only at logic level | `SERVER-MODE §4.2` formula; `token.rs mac_bearer()` (single hmac_key); schema `relay_bearers` (no `kind`/`client_id`/`dpop_jkt`) | A local (uid/pid) bearer presented remotely passes the MAC and is caught only by a `decide()` logic clause, not at the crypto level — weaker defense-in-depth than the stated "cross-kind never crosses". | Add a `kind` ('local'/'remote') column; include `kind` (and the plane's identity fields) in the canonical MAC message, OR domain-separate the hmac_key per kind. Then cross-plane presentation fails at the MAC, not just the clause. | medium |
| F13 | MEDIUM | Channel-binding EKM hash not carried into `CanonRequest` for fail-closed audit | `SERVER-MODE §4.3` line 128; `decide.rs` `CanonRequest` (59-73) | Edge validates EKM before `decide()` (correct), but no field lets `decide()` fail closed if `req.remote.is_some()` yet the binding summary is absent (broken edge); audit cannot log the non-secret binding hash for replay detection. | Phase 8 (optional hardening): add `CanonRequest.channel_binding_summary: Option<[u8;16]>`; if `req.remote.is_some()` and it is `None`, deny. Local requests leave it `None`. | medium |
| F14 | MEDIUM | `PresenceGate` trait not yet introduced; gate is a raw `usb_absent_since_ms` param | `decide.rs` signature (89-97), check 16 (179-181); `SERVER-MODE §5.1` lines 154-161; REQ-SEC-13 | The VPS substitute factor (Phase B) cannot be wired without duplicating `decide()`. This is a Phase-0-scope, behavior-preserving refactor that is a prerequisite for unblocking Phase B. | Phase 0: add `enum GateState{Present,AbsentSince,Unproven}` + `trait PresenceGate` in a `gate.rs`; `decide()` calls `gate.resolve()` and treats `AbsentSince`+`Unproven` as deny (no logic change); ship a `UsbProbe` impl. | medium |
| F15 | MEDIUM | `relay_bearers` schema lacks remote binding columns (`client_id`, `dpop_jkt`, `kind`) | `docs/db/schema.sql relay_bearers` (`client_uid`/`client_pid` only) | When Phase 8 adds remote fields to `VerifiedBearer`, the store cannot persist or MAC-authenticate `client_id`/`dpop_jkt`. | Phase 8 migration: ADD `client_id TEXT UNIQUE` (NULL local), `dpop_jkt BLOB` (32B, NULL local), CHECK `(client_uid IS NOT NULL) OR (client_id IS NOT NULL)`; include both in `bearer_row_mac_message()`. Create a `remote_clients` table (id, client_id PK, enabled, `hardware_bound`, registered_jkt, created_at, revoked_at). | high |
| F16 | MEDIUM | mTLS hardened-mode client-cert lifecycle / revocation-propagation undefined (OI-SM-4) | `SERVER-MODE §4.2` clause 2 lines 111-112, §8.1 line 196, OI-SM-4 line 323 | Leaf issuance/TTL/auto-renewal and revocation-set propagation latency unspecified; a revoked/expired leaf mid-session has undefined enforcement timing. Hardened mode cannot ship until specified. | Specify: USB-gated leaf issuance RPC; ≤7d TTL with auto-renew if <1-2d to expiry; revocation set loaded at startup + on RevokeRemoteClient + polled (≤30 s); reject revoked client at the TLS handshake before bearer verify. State whether the cert subject binds the DPoP jkt or is independent. | medium |
| F17 | MEDIUM | Channel-binding depends on in-process TLS; no runtime guard against a TLS-terminating reverse proxy (FS-S20) | `SERVER-MODE §4.2` clause 1 lines 106-110; FS-S20 line 300; startup self-check §3.3 | If an operator fronts the edge with TLS-terminating nginx, EKM/DPoP binding becomes uncomputable and the bearer MAC degrades to a plain password; the self-check verifies listeners but not that TLS is in-process. | Primarily docs/ops (ops/01 PROMINENT note: TLS termination is in-process BY DESIGN, FS-S20; reverse proxy that terminates TLS is FORBIDDEN; use L4/PROXY-protocol passthrough). Phase 8 optional `--validate-tls-in-process` startup probe that computes a DPoP binding and refuses if it cannot. | medium |
| F18 | MEDIUM | Group-commit audit fsync optimization unspecified — risk to "durable before response" (HF-14/FS-S26) | `SERVER-MODE §6.2` lines 206-207, §6.4 line 219; THREAT-MODEL HF-14 | An unspecified group-commit could let a batched response return before its fsync, or fsync fail after responses were sent, or batch unboundedly under attack — silently breaking FS-S26. | Specify a concrete sketch: batch cap (N=100 or T=100 ms); fsync completes before ANY batched response returns; on fsync failure the whole batch maps to 403 + durable deny (never 200). Unit test: fsync failure mid-batch leaks no 200. | high |
| F19 | MEDIUM | Per-IP / per-client rate-limit layer location undefined; PROXY-protocol source-IP trust ambiguous | `SERVER-MODE §6.2` line 204, §6.5 line 223 | Per-IP handshake limit unquantified and its layer (rustls vs hyper queue vs middleware) unspecified; if a PROXY line is trusted for rate-limiting, an attacker defeats per-IP limits. | Quantify (e.g. 10 handshakes/s/IP, global conn cap 1000) enforced in the accept loop before rustls; rate-limit against the immediate peer (tunnel IP), never the PROXY-forwarded source (use PROXY only for logging). | medium |
| F20 | MEDIUM | Telegram `hardware_bound` UX unspecified; mis-set over-claims binding (OI-SM-5) | `SERVER-MODE §4.4` lines 130-138, OI-SM-5 line 324; A20 | Operator could set `hardware_bound=true` for an extractable-key cloud agent, claiming strong binding while degraded to bearer-only. THE residual (see §1). | Default `hardware_bound=false`; require explicit `--hardware-bound yes` at `register-remote` with confirmation that the key store is non-extractable; audit every non-hardware-bound registration loudly and tag its swaps `bearer-only-binding`; ship an operator checklist for the Telegram runtime. | medium |
| F21 | MEDIUM | ACME renewal lag / emergency fail-closed timing undocumented | `SERVER-MODE §6.5` lines 221-223; FS-S25 | Lapsed-cert fail-closed is stated, but renewal SLA, dual-cert window behavior, and on-box ACME failure during partition are undefined — a sudden lapse hard-breaks all remote clients with no warning. | Specify: ACME renewal starts 30d before expiry; CRITICAL log + fail-closed if renewal still failing 24h before lapse; serve the newer valid cert during overlap; on corrupted/missing cert refuse new TLS. NO MITM-CA fallback (FS-S25). | medium |
| F22 | LOW | Profile A startup self-check for USB keyslot presence is an OR, not enforced (FS-S22) | `SERVER-MODE §5.2` lines 168-169, FS-S22 line 302; `ops/01` (not encoded) | A passphrase-only on-box vault has the A12 posture while the operator believes USB-gating is active; "refuses to start" vs "forces explicit choice" is undecided and not encoded in systemd/secretd. | secretd startup guard: if `profile==on-box` AND no enabled `usb_keyfile` keyslot AND not `--allow-passphrase-only`, refuse with a loud error; audit the override if set. | medium |
| F23 | LOW | Startup self-check does not validate the edge cert's *source*/issuer (FS-S25) | `SERVER-MODE §3` lines 91-92, §6.1 line 200 | The listener self-check validates binding but not that the loaded edge cert chains to a public root and not to the MITM CA; a deployment-time cert swap (symlink to MITM CA) bypasses the §1.2 CI grep. | Startup: verify the edge cert issuer != MITM CA subject AND chains to `webpki_roots::TLS_SERVER_ROOTS`; refuse otherwise. Unit-test rejection of a MITM-signed edge cert. | low |
| F24 | LOW | `source_cidr` schema/enforcement-layer undefined (OI-SM-7) | `SERVER-MODE §4.2` line 120; `relay_policies` (no column) | No `source_cidr` column; pre-filter-vs-in-decide undecided. Demoted to defense-in-depth (correct), but unimplemented. | Add `source_cidr_allow TEXT` (JSON CIDR array, NULL=unrestricted) to `relay_policies`; enforce as edge pre-filter (403 before `decide()`); default unset for cloud clients; log source IP per swap. NEVER a security boundary. | low |
| F25 | LOW | Remote bearer recovery / re-mint UX + out-of-band channel undefined | `SERVER-MODE §7.2` lines 249-250; `research/12 §4.4` | No documented recovery if a bearer is lost before first use; out-of-band delivery channel unstated (plain email is unsafe). | Document `ReMintRemoteBearer` (USB-gated) recovery; require E2E-encrypted out-of-band delivery; log mint events per client_id. | low |
| F26 | INFO | RateLimited / BudgetBytes / quota gating already correctly ENFORCED | `decide.rs` lines 159-176 | No issue — REQ-SEC-5 correctly implemented; pre-`decide()` shedding is a Phase-8 broker optimization, not a `decide()` change. | None. | high |

> **Dedup note:** the remote-binding gap (F3/F4/F15) was reported by four lenses; streaming revocation
> (F5) by four; the libSQL purity claim (F1) by three (control-plane, libSQL-isolation, edge lenses).
> The libSQL-isolation lens additionally raised the **crate-choice decision** (`libsql` vs
> `libsql-client`+`libsql-hrana`) and the **crate-does-not-exist** observation; both are folded into
> F1's fix and the §4 adjudication. No lens finding was downgraded as a false positive — every claim
> was confirmed against source (the local-only `decide()`, the schema, the Cargo pins, the absent
> crate/lockfile entry).

---

## 3. Per-invariant: ENFORCED / NEEDS-CODE / GAP vs the committed `decide()`

The committed `decide.rs` enforces the **baseline local-plane** invariants completely. Every remote
(FS-S16–S26, REQ-SEC-10–13) invariant is absent from code — correctly deferred to Phase 8, but the
table makes the deferral auditable rather than assumed.

| Invariant | Status vs committed `decide()` | Evidence |
|---|---|---|
| **FS-S5** USB-absent stops egress (per-request) | **ENFORCED** | `decide.rs` check 16, lines 179-181 (`usb_absent_since_ms.is_some() ⇒ GateAbsent`) |
| **FS-S5** extended to in-flight remote STREAMS | **GAP** (F5) | No stream context / periodic re-check in `decide.rs` or `relay_swap` |
| HF-8 local peer binding (uid/pid) | **ENFORCED** | `decide.rs` check 11, lines 139-149 |
| OI-6 clock-rollback / monotonic fence | **ENFORCED** | `decide.rs` check 17, lines 182-210 (boottime anchor) |
| REQ-SEC-5 quota/rate | **ENFORCED** | `decide.rs` checks 13-15, lines 156-176 |
| HF-11 canonical-upstream fence | **ENFORCED** | `decide.rs` check 10, lines 133-138 |
| **REQ-SEC-10 / FS-S16** remote bearer binding (client_id + DPoP jkt + proof) | **NEEDS-CODE** (F3) | `VerifiedBearer`/`CanonRequest` have no remote fields; no remote clause |
| REQ-SEC-10 cross-kind denial | **NEEDS-CODE** (F3/F12) | No `kind` field; cross-plane caught (if at all) only at logic level |
| Remote `DenyReason` granularity | **NEEDS-CODE** (F4) | enum lines 17-35: only local `PeerMismatch` |
| §4.3 channel-binding (EKM) audit hash, fail-closed | **NEEDS-CODE** (F13) | no `channel_binding_summary` in `CanonRequest` |
| **REQ-SEC-13** PresenceGate unification (`Unproven`==`AbsentSince(now)`) | **NEEDS-CODE** (F14) | raw `usb_absent_since_ms` param; no trait/enum |
| §4.5 streaming revocation tear-down | **NEEDS-CODE / GAP** (F5) | not in `decide()` (correctly daemon-side) and not specified |
| FS-S26 durable-audit-before-Allowed (single request) | **ENFORCED (by `Store` contract)** | `Store::append_audit` + `fsync_barrier` (engine `store.rs`); HF-14 |
| FS-S26 under group-commit batching | **GAP** (F18) | optimization unspecified; could regress the invariant |
| **REQ-SEC-11 / FS-S17** control unreachable over edge | **ENFORCED BY CONSTRUCTION (not by `decide()`)** | separate service objects + module/CI isolation + startup self-check (SERVER-MODE §3); routing means control RPCs never reach `decide()`. Startup self-check + edge module + CI grep are **NEEDS-CODE** (F2) |
| **FS-S20** channel binding computed by the validating process | **NEEDS-CODE / GAP** (F2/F17) | in-process edge is `todo!()`; no runtime guard against TLS-terminating proxy |
| FS-S21 VPS refuses to start w/o substitute factor | **GAP** (F7) | no install-time gate; ops/01 sketch only |
| FS-S22 on-box w/o USB keyslot refuses | **GAP** (F22) | OR-worded; not encoded in secretd/systemd |
| FS-S23 no boot-unwrap egress w/o presence token | **NEEDS-CODE** (F9) | wrapping-vs-gating separation not enforced |
| FS-S25 edge cert never chains to MITM CA / no fallback | **PARTIAL** | §1.2 CI grep specified (not yet runnable, F2); startup issuer check is **GAP** (F23) |

---

## 4. libSQL C-isolation adjudication (the ops-flagged blocker)

**Verdict: the ops doc is RIGHT and the design doc is WRONG-AS-WORDED.** Three independent lenses
converged on the same defect. The facts, ground-truthed against this checkout:

- `SERVER-MODE.md §2.2` (line 75) states the `libsql` crate with `default-features=false,
  features=["remote"]` is **"VERIFIED pure-Rust, no `libsql-ffi`."** This is an **assertion, not a
  proof.** The `libsql` crate's *default* features pull `core` → `libsql-sys`/`libsql-ffi` (the bundled
  8.9 MB `sqlite3.c`, compiled by its `build.rs`); `remote` alone *can* be pure-Rust, but only in a
  **non-default, fragile** configuration whose purity must be demonstrated by `cargo tree`.
- `ops/07 §1.1` (Gate 3a, lines 63-76) **correctly** specifies the needed gate as a conditional shell
  snippet — but it lives in a design doc, **not in any runnable CI**: there is no `.github/workflows/`
  and no `ci/gates/no-c.sh` in the repo (Phase 0).
- `crates/secrets-store-libsql` **does not exist**, and `libsql` is **absent from `Cargo.lock`**
  (`grep -c 'name = "libsql' Cargo.lock` → 0). So nothing is provably pure-Rust today because nothing
  is wired at all. `cargo-deny` currently bans `libsql-ffi` outright (ops/07 §4.1), which is the right
  Phase-0 posture.
- The crate-choice decision (`libsql` `--features remote` **vs** `libsql-client`+`libsql-hrana`) is
  flagged as an explicit blocker (ops/07 OQ-3 lineage; libSQL-isolation lens) and has **not been made**
  in the design; §2.2 assumes the former without ruling out the latter.

**Required action (do BEFORE Phase 1, as a hard pre-ship gate):**

1. Correct the §2.2 wording: replace *"VERIFIED pure-Rust"* with *"to be PROVEN pure-Rust by the CI
   gate below; risk-accepted until GREEN."*
2. Decide the crate path now and record it in DESIGN-NOTES. Run `cargo tree` on both candidates against
   a throwaway crate to pick whichever the tree proves C-free.
3. When `crates/secrets-store-libsql` lands in Phase 1, the conditional gate must **transition from
   conditional (Phase 0, passes because the crate is absent) to a REQUIRED job** that fails hard if the
   crate exists but the `remote` build links C. Also convert the `cargo-deny` outright `libsql-ffi` ban
   to a `wrappers`-scoped allow limited to that one crate.

**The EXACT required cargo-tree gate (copy verbatim into `ci/gates/no-c.sh` / the required CI job):**

```bash
# Gate 3a (REQUIRED once crates/secrets-store-libsql exists): the RECOMMENDED on-box wiring
# (pure-Rust libSQL `remote` client) MUST contain NO bundled C SQLite. Fail-closed.
cargo tree -p envctl-secrets-store-libsql --no-default-features --features remote 2>/dev/null \
  | grep -E 'libsql-ffi|libsql-sys' \
  && { echo "FAIL: C SQLite (libsql-ffi/libsql-sys) in the remote-client build"; exit 1; } \
  || echo "PASS: remote-client store build is pure-Rust (no libsql-ffi/libsql-sys)"
```

(Gate 3b — the in-process **embedded** build — remains the documented, bounded operator-risk-accepted
waiver: `libsql-ffi` MAY appear, but ONLY under the store crate's subtree, and ONLY with a recorded
risk acceptance, and then the public edge MUST run as a separate process per §2.2/A18.) Until Gate 3a
is GREEN in a runnable required job, the "recommended wiring" is **risk-accepted, not verified pure.**

---

## 5. Resolve-before-Phase-6/8 shortlist (ordered)

**Before Phase 1 (store):**
1. **F1** — correct the §2.2 "VERIFIED" wording; decide the libSQL crate path; land the EXACT Gate-3a
   as a required CI job (and the runnable `no-c.sh`/`shape.sh` + `.github/workflows/ci.yml` they
   presuppose). Flip the `cargo-deny` ban to a wrappers-scoped allow when the crate lands.

**Before Phase 6 (secretd async/network deps):**
2. **F10** — pin the exact `tonic ≥ 0.12.3` + named patched `hyper` for CVE-2024-47609; add the
   `cargo audit`/`deny check advisories` failing step.
3. **F11** — run `cargo +1.80.0 check --workspace --locked --all-features`; pin `idna`/`icu` or raise
   the floor with a recorded decision.
4. **F14** — land the `PresenceGate` trait refactor (Phase-0-scope, behavior-preserving) — it is the
   prerequisite for unblocking Phase B without re-touching `decide()`.

**Before / within Phase 8 (remote relay edge) — must all be done to avoid a binding-bypass:**
5. **F2 + F3 + F4 + F15** — bring up the in-process TLS+DPoP edge AND, in the SAME change, bridge the
   normative `bearer_mac`/§4.2-clause-4 binding into `decide()` (remote fields + cross-kind denial +
   specific DenyReasons) and the schema (`client_id`/`dpop_jkt`/`kind` + `remote_clients`). The edge
   listener MUST NOT serve until the remote-binding deny path and the startup self-check are
   non-`todo!()` (SERVER-MODE §10 Phase 0 rule).
6. **F6** — specify and implement the bounded `jti` replay store (cap + eviction + nonce + retry
   recovery) before the edge serves.
7. **F5** — implement streaming revocation tear-down + periodic `decide()` re-check; cap stream
   duration under TTL.
8. **F18** — pin the group-commit fsync sketch so FS-S26 survives batching; unit-test fsync-fail-mid-batch.
9. **F12, F13, F17, F19, F23** — defense-in-depth hardening (plane-bound MAC, EKM audit field,
   reverse-proxy guard + ops note, per-IP limits + PROXY-source caveat, startup edge-cert issuer check).

**Before Profile B (VPS) is shippable — keep gated as non-shippable until ALL pass:**
10. **F7 + F8 + F9** — install-time fail-closed gate (FS-S21), the operator-box authorizer protocol
    (OI-SM-2) with passing FS-S21/S23 negative tests, and the enforced wrapping-vs-gating separation;
    plus OI-SM-3 trusted time. The A19 VPS-snapshot/at-rest downgrade is a **documented, accepted**
    tradeoff (prefer Profile A or Nitro Enclave + attested KMS), not a fixable gap.

**Operator-residual to internalize (not blocking, but must be communicated):**
11. **F20 / OI-SM-5** — the Telegram key-custody residual: confirm whether the runtime offers a
    non-exportable key store; default `hardware_bound=false`; loud audit of degraded clients. The
    flagship actor is the weakest-bound actor and that is structural.

---

## 6. Cited sources

- Committed code: `crates/secrets-engine/src/broker/decide.rs` (full), `crates/secretd/src/main.rs`
  (`todo!()`), `docs/db/schema.sql` (`relay_bearers`), workspace `Cargo.toml`, `Cargo.lock`.
- Design: `docs/SERVER-MODE.md` §2.2/§3/§4.2-4.5/§5/§6/§7/§8 (FS-S16–S26, REQ-SEC-10–13, OI-SM-1–8).
- Ops: `docs/ops/07-ci-supplychain.md` §1.1 (Gate 3), §1.2, §2 (MSRV/HF-18), §4.1 (cargo-deny),
  §8.6/§9 (VPS, OQ-1/3); `docs/ops/01`, `docs/ops/02` (manifest/install).
- Research: `docs/research/03` (libSQL bundles C SQLite), `12` (remote token binding / DPoP),
  `15` (VPS gating / snapshot threats).
- Threat model: `docs/THREAT-MODEL.md` (HF-8/HF-11/HF-14, A18/A19/A20, FS-S* lineage).
