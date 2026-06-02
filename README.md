# env-ctl

The **security, keys, certs, auto-inject, database, and API** subsystem of
[`envctl`](../envctl) — built in a **parallel repo**, designed to **merge into `envctl/crates/`**.

`envctl` is a pure-Rust environment manager for one dual-RTX-5090 Ubuntu 26.04 workstation. It
deliberately declared secrets out of scope:

> **Non-Goal N6:** *Not a secrets/credentials manager. Interactive auth (`claude /login`,
> `gh auth login`) is explicitly out of scope and left to the user.* — `envctl/docs/PRD.md`

`env-ctl` **fills that gap**: a local, single-operator **secrets vault + credential broker**.

## The idea: a credential broker (virtual-credit-card model)

The real long-lived key (your 1-year Claude or GitHub token) **never leaves the daemon**. Instead
env-ctl issues per-client **relay bearers** — the analog of virtual card numbers — and swaps them
for the real key at the moment of use:

```
client (claude CLI)            secretd broker                upstream
  Authorization: evrelay_… ─▶  verify + decide() (default-deny)
                               fetch real key (only if Allow)
                               swap header → sk-ant-real  ─▶  api.anthropic.com
  ◀── response ──────────────  audit (per-client, per-window) ◀──
```

Each bearer is **≤24 h, scoped, peer-bound, revocable**, USB-presence-gated, and traceable — so a
leaked credential expires within a day, is bounded to one client + window, and can be killed
without touching the real key. Pulling the USB is a physical kill switch.

## What works today

The **entire security-critical engine is built, independently audited, and green:**

| Layer | Status |
|---|---|
| **Crypto core** — XChaCha20-Poly1305 at-rest, canonical AAD, argon2id + HKDF dual-KEK keyslots, BLAKE3-keyed MACs | ✅ audited (0 critical) |
| **Functional vault** — `init` / dual-factor `unlock` (USB-PARTUUID keyfile or passphrase) / `lock` (zeroizes the DEK) / `secret_put` / `secret_get` (reveal apply-gated, broker-only refused) | ✅ |
| **Tamper-evident audit** — BLAKE3 hash chain + a DEK-keyed monotonic high-water anchor | ✅ (audit H-1 fixed) |
| **Credential broker** — `decide()` default-deny truth table, `relay_mint` (24 h clamp + USB gate + peer-bind), `relay_swap` (real key only inside `Allow`), revoke; `CLOCK_BOOTTIME` rollback fence | ✅ |
| **Local daemon** — `secretd` tonic gRPC over a Unix socket, `SO_PEERCRED` owner-only, engine-bridged Lock/Vault/Relay/Audit services + event streaming | ✅ e2e |
| **CLI** — `secretctl` (the `env-ctl` verbs) over the UDS, pretty + `--json` | ✅ |

**97 tests pass** (`cargo test --workspace`); the engine is **pure-Rust, C-free, async-free**;
everything compiles on stable. Two independent multi-agent security audits (Phase-1 crypto+vault,
and the SERVER-MODE remote-edge design) are committed under [`docs/audits/`](docs/audits).

## Remaining

- **Durable store** — `secrets-store-libsql` (libSQL behind the `Store` trait; today the vault uses
  a real in-memory store). Gated on a required `cargo tree` C-free check (audit F1).
- **Remote edge (Phase 8, deferred by design)** — the HTTPS + DPoP-sender-bound relay plane for
  remote/cloud agents (e.g. a Telegram bot). The SERVER-MODE audit confirms this needs the remote
  bearer-binding, jti replay-store, streaming-revocation, and public-edge TLS work landed
  deliberately; the control plane stays local-UDS-only.

## Architecture

Pure-Rust Cargo workspace; the engine is a non-printing library (emits a `SecretEvent` stream),
the daemon + CLI are thin front-ends — mirroring `envctl` so the crates drop into `envctl/crates/`
on merge (names chosen to avoid colliding with `envctl-engine`/`envctl`/`envctl-gui`):

```
crates/
  secrets-engine/   envctl-secrets-engine (lib envctl_secrets) — vault + broker + crypto; pure-Rust, C-free
  secrets-proto/    envctl-secrets-proto  — gRPC control-plane proto (env_ctl.v1), compiled with protox
  secretd/          envctl-secretd        — the daemon (gRPC/UDS control plane; relay proxy = Phase 8)
  secretctl/        envctl-secretctl      — the env-ctl CLI
  secrets-store-libsql/  (in progress)    — quarantined libSQL Store impl (C isolated here only)
docs/   ARCHITECTURE · DESIGN-NOTES · ROADMAP · THREAT-MODEL · SERVER-MODE · research/ (15) · ops/ (7) · audits/ (2)
```

## Build

```bash
cargo build --workspace
cargo test  --workspace          # 97 passing
cargo test -p envctl-secrets-engine   # crypto/vault/broker unit + integration tests
# CI gates: engine is C-free + async-free, exactly one rustls on the ring path (no aws-lc).
```

## Status

**Core complete + locally runnable.** The audited engine and the local daemon run end-to-end on the
box (`secretctl ↔ secretd ↔ engine` over the UDS, with a real encrypted vault + relay broker).
Durable libSQL storage and the remote relay edge are the remaining phases — see
[`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/SERVER-MODE.md`](docs/SERVER-MODE.md). Decisions and
their rationale live in [`docs/DESIGN-NOTES.md`](docs/DESIGN-NOTES.md); the merge plan in
[`docs/CHARTER.md`](docs/CHARTER.md).
