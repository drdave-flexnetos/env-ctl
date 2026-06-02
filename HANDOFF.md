# env-ctl — HANDOFF

*Paste this as the first message of the next session to continue.*

## What this is
`env-ctl` = the **secrets vault + credential broker** subsystem for the dual-RTX-5090 Ubuntu 26.04
box, built as a **parallel repo to merge into [`envctl`](../envctl)** (it fills envctl Non-Goal N6).
Live at **github.com/drdave-flexnetos/env-ctl** (origin/main). Local: `~/Desktop/env-ctl`.

The model is a **credential broker (virtual-credit-card)**: the real long-lived key never leaves the
daemon; per-client **relay bearers** (≤24h, scoped, peer-bound, revocable, USB-gated) are swapped for
the real key at egress. Pull the USB = physical kill switch.

## State (as of this handoff)
**Core complete, twice-audited, locally runnable. 117 tests green; stable Rust; no C *library* in the
trust boundary.** All pushed. **OI-1 RESOLVED (a):** the libSQL `remote` store crate is now a
workspace member (build-time `cc` accepted — it is already required by ring+blake3; no C *library* is
linked), with the no-C / single-ring-backend gate materialized + armed at `ci/gates/no-c.sh`.
- **Engine** (`crates/secrets-engine`, lib `envctl_secrets`, pure-Rust): XChaCha20-Poly1305 at-rest,
  argon2id+HKDF dual-KEK keyslots, BLAKE3-keyed MACs, dual-factor vault (init/unlock/lock/secret
  put+get), tamper-evident audit chain + DEK-keyed monotonic high-water anchor, broker (`decide()`
  default-deny, relay mint/swap/revoke, CLOCK_BOOTTIME rollback fence).
- **Local daemon** (`crates/secretd`, `crates/secretctl`): tonic gRPC over UDS + SO_PEERCRED + the
  CLI. `secretctl ↔ secretd ↔ engine` runs e2e.
- **Docs:** `docs/` = ARCHITECTURE · DESIGN-NOTES · ROADMAP · THREAT-MODEL · SERVER-MODE ·
  research/ (15) · ops/ (7) · audits/ (2: Phase-1 crypto+vault, SERVER-MODE design).
- **Build workflows:** `workflows/` (the 12 multi-agent scripts that built it; see its README).

## Remaining
1. **OI-1 (store backend) — RESOLVED (a). ✅** `crates/secrets-store-libsql` (libSQL `remote` `Store`
   impl) is now a `[workspace.members]` entry; `libsql` is pinned in `[workspace.dependencies]`
   (`default-features=false, features=["remote"]`). Operator chose **(a): accept a build-time C
   toolchain** — verified empirically that the engine ALREADY needs `cc` via **ring** (compiles
   C/asm) **and blake3** (SIMD), so the upheld tenet is *"no C **library** linked in the trust
   boundary"* — proven by `ci/gates/no-c.sh` (no `libsql-ffi`/`libsql-sys`/`sqlite3-sys`, no
   `aws-lc-*`/`openssl-sys`, exactly one ring-only `rustls`). Workspace builds + **117 tests green**;
   5 sqld integration tests `#[ignore]`d. `lemon.c` is build-time codegen (emits Rust; nothing C
   linked). **Phase-1 wiring — DONE. ✅** `secretd` runtime-selects the backend via config (env >
   `secretd.toml` > inmem default; see `docs/ops/08-secretd-store-config.md`); `Engine::open_with_store`
   injects it behind the `Store` trait; the store is built off-reactor. Proven against a REAL `sqld`:
   the store's 5 integration tests + a new engine-over-libSQL **durability** e2e (init/unlock/put/get
   that survives across engine instances) pass. Two real-server fixes that only e2e could catch:
   (i) libSQL `remote` ships no connector unless its `tls` feature is on (which would add a 2nd rustls),
   so the store supplies a **plaintext loopback** `HttpConnector` (gate-clean; remote DBs go via a
   loopback TLS terminator); (ii) Hrana rejects `BEGIN/COMMIT`/`PRAGMA` and expires the idle stream
   during argon2 — fixed by Hrana-batch DDL + **reconnect-on-`STREAM_EXPIRED`**. **Residual:** the
   libSQL dup-major stack (`hyper 0.14`, `http 0.2`, `h2 0.3`, `base64 0.21`, 2nd `prost` `0.12`) now
   **links into `secretd`** (the daemon) when the libsql backend is selected — all pure-Rust, no C
   library (gate-proven). **Target** stays strict C-toolchain-free (blake3 `pure` + a pure-Rust Hrana
   client). See `crates/secrets-store-libsql/README.md` + `docs/ops/08-secretd-store-config.md`.
2. **Remote edge (Phase 8, deferred by design):** the HTTPS + DPoP-sender-bound relay plane for remote
   clients (e.g. a Telegram bot). The SERVER-MODE audit lists exactly what to bridge in (remote
   bearer binding into `decide()`/schema, jti replay store, streaming revocation, public-edge TLS).
   Control plane stays local-UDS-only.
3. **Merge into envctl** — see "Merge workflow" below.

---

## The workflow method (the build style — reuse it)
Drive substantive / security-critical work with **multi-agent Workflow orchestration**, not solo
coding. The validated loop:

> **design → implement → adversarial-review → fix**, plus a separate **fresh-eyes audit** pass on
> security-critical surfaces, and **verify-green-then-commit-then-push** between every step. Each phase
> is its own Workflow; build & prove the core before the integration layer.

**Operating rules that made it work:**
- **One workflow at a time on the critical path.** Over-parallelizing trips Anthropic's *server-side
  request-rate throttle* (distinct from the credit limit) — throttled runs FAIL with zero output.
  Keep total concurrent agents under ~16. Only **read-only fleets** (research/audit, new-docs-only,
  no `cargo`) run safely alongside a code workflow.
- **Verify green every step:** `cargo test --workspace` + the dependency gates before each commit.
  Never commit a broken state.
- **Single implementer for interdependent code; parallel implementers only for independent modules.**
- **Adversarial review earns its keep** — it caught real bugs (audit-anchor truncation replay, a
  row_id TOCTOU, the "VERIFIED pure-Rust" overclaim) AND rejected a false positive (a claimed hex OOB
  panic). Have a synth reconcile/downgrade — trust-but-verify the auditors too.
- **Be honest about residuals** in code/docs (e.g. full-snapshot rollback needs off-box anchoring;
  libSQL `remote` needs a C build-toolchain). No overclaiming.
- **JS gotchas:** workflow scripts are plain JS — use backtick template literals for long prompts
  (apostrophe-safe); watch paren balance in `(await parallel(LENSES.map(...))).filter(Boolean)` (a
  dropped closing paren errors at the *next* statement). Backticks inside a bash `commit -m "..."`
  are command-substitution — avoid them.

---

## Operator notes — C-toolchain & Wasmer/WASIX ideas (for OI-1 + the envctl toolchain)
*(Operator's ideas; captured here for the OI-1 decision and broader toolchain work. The Wasmer stack
is already shipped by the envctl wizard, so this dovetails with the merge.)*

**Two-compiler strategy:**
- **Compiler 1 — native Rust speed:** `rustc` + **Wasmer** + the **mold** linker (`rui314/mold`).
- **Compiler 2 — the C/C++ track:** **Clang + CMake + Ninja**; bridge into Rust via the **`cxx`**
  crate or **`bindgen`** alongside Clang. → This is the controlled way to satisfy the C that libSQL's
  `lemon.c` (and any C dep) needs: a pinned Clang/CMake/Ninja toolchain instead of ambient `cc`,
  isolated from the secret-handling trust boundary.
- **WASIX sandboxing (the security angle):** validate **ferrocene** (qualified `rustc`) against
  Wasmer's sandboxing — the "security" side, proving out the new **WASIX permission models**. A
  WASIX-sandboxed build/run path could quarantine C deps so they can never touch the vault address
  space (directly relevant to the OI-1 "C in the trust boundary" concern).

**Wasmer ecosystem (Vite SSR + JS edge + interop):**

| Feature needed | Repo | Specific path / note |
|---|---|---|
| WASIX caching | `wasmerio/wasmer` | look at `lib/wasix` and `lib/vfs` crates |
| Edge.js (engine for **Vite SSR**) | `wasmerio/edgejs` | requires **rust + node** toolchains to build; see `wasmerio/edge-react-starter` |
| Wasmer Edge — the actual JS-edge **server** logic | `wasmerio/winterjs` | server logic for JS Edge apps |
| JS interop bridge (the **JavaScript SDK**) | `wasmerio/wasmer` | specifically the `@wasmer/sdk` directory |
| Python async | `wasmerio/wasmer-python` | use the version **with greenlet support** |

**OI-1 implication:** option (a) "accept a C build-toolchain" becomes much cleaner with **Compiler 2**
(pinned Clang/CMake/Ninja) + optionally **WASIX-sandboxing** the C parser build — keeping it out of
the trust boundary rather than relying on ambient `cc`. Worth a focused spike before adopting the
`secrets-store-libsql` crate into the workspace.

---

## Merge workflow
`workflows/envctl-merge.js` is authored and ready. It plans + executes (in an isolated git worktree,
verify-green) the unification of env-ctl into `envctl/crates/`: crate moves, `[workspace.dependencies]`
union (incl. the HF-17 `rustix` `["process","net","time"]` union), folding the secretctl verbs into
the envctl CLI, adding the secrets components to envctl's manifest (per `docs/ops/02`), and carrying
the no-C-library + ring + MSRV gates. **Run it when OI-1 is decided** (the store backend changes what
moves). Invoke with `Workflow({scriptPath: "workflows/envctl-merge.js"})` (adjust the two repo paths
at the top first). It does NOT auto-commit to envctl — it produces a reviewed, green worktree + a
merge plan for you to land.

## Key pointers
- Decisions + rationale: `docs/DESIGN-NOTES.md` (OI-* / HF-* / CF-*). Merge intent: `docs/CHARTER.md`.
- Audits: `docs/audits/AUDIT-phase1.md`, `docs/audits/AUDIT-server-mode.md`.
- Store blocker analysis: `crates/secrets-store-libsql/README.md`.
- Build narrative + reusable templates: `workflows/README.md`.
