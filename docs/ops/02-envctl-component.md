# env-ctl ops — Packaging env-ctl as an envctl manifest component

> **Scope.** How to ship the env-ctl secrets vault + credential broker (`secretd` daemon
> + `secretctl` CLI, four pure-Rust workspace crates) as a first-class **envctl manifest
> component** once the two repos merge (`~/Desktop/env-ctl` → `~/Desktop/envctl/crates/`).
> This is a CONCRETE, sourced ops/deploy design for THIS system (dual-RTX-5090 box,
> Ubuntu 26.04, systemd user session, USB-PARTUUID unlock default, VPS deferred).
> **READ-ONLY analysis — no code changes were made producing this doc.**
>
> **Companion docs (this repo):** [ARCHITECTURE.md](../ARCHITECTURE.md),
> [SERVER-MODE.md](../SERVER-MODE.md), [THREAT-MODEL.md](../THREAT-MODEL.md),
> [DESIGN-NOTES.md](../DESIGN-NOTES.md), [ROADMAP.md](../ROADMAP.md).
>
> **Status legend:** `VERIFIED` = confirmed against repo source or an upstream doc cited
> inline. `UNVERIFIED` = plausible / from a draft, not confirmed here — treated as an open
> question, never as a shipping gate that has passed.

---

## 0. The single most important correction up front (read this first)

The envctl manifest schema this doc targets is the **real, in-tree** one. I verified it
against `~/Desktop/envctl/crates/engine/src/{component.rs,model.rs}` and the shipped
`~/Desktop/envctl/manifest/boot-repair.toml`. Two consequences that diverge from the
incoming draft findings, and which this doc follows instead:

1. **Vault purge is NOT a separate `env-ctl-vault-purge` component.** envctl already has a
   native, guarded purge path: `[component.wiring]` carries `data_paths` (deleted ONLY on
   `envctl reset --purge`, after UUID re-verify) and `config_paths` (removed unless
   `--keep-config`). `Wiring` fields are, verbatim from `model.rs`:
   `path_entries`, `shell_rc`, `desktop_entries`, `systemd_user`, `apt_repos`,
   `nix_conf_lines`, `cdi_specs`, `alternatives`, `data_paths`, `config_paths`. We use
   `data_paths`/`config_paths` for the vault, NOT a bespoke purge component.
   (`~/Desktop/envctl/crates/engine/src/model.rs:284-309`.) `VERIFIED`.

2. **The hook tag is `kind` with two real variants only: `command` and `script`.**
   A `shipped_script` is the `Script` variant with `path = "..."` set (see boot-repair.toml
   `kind = "shipped_script"` maps to `Hook::Script{path}`). There is no separate
   `shipped_script` enum arm; the boot-repair manifest's `"shipped_script"` is the serde tag
   alias for `Script` with a `path`. Use `kind = "command"` (clean argv, no shell) or
   `kind = "script"` (inline `bash -lc`, or `path` to a file).
   (`~/Desktop/envctl/crates/engine/src/component.rs:58-101`.) `VERIFIED`.

The draft's larger story (single component, source-build, systemd-user wiring, USB guard,
CI no-C gate, two profiles) is sound and adopted. The crate/version table is accurate
against `~/Desktop/env-ctl/Cargo.toml`. The one **factual error** in the draft is the
libSQL purity claim — see §7.1, it is a shipping blocker, not a footnote.

---

## 1. Recommended design for THIS system (the decision)

**Ship ONE manifest component, `manifest/env-ctl.toml`, that builds the four crates from
the in-workspace sources and wires `secretd` as a systemd *user* service.** Rationale:

- **Source-build, not a binary artifact.** env-ctl is a workspace member post-merge; the
  build is `cargo build --release` against the same lockfile as the rest of envctl. This
  is how `ai-clis.toml` / `dev-tools.toml` style components already operate (cargo/`~/.cargo/bin`),
  and it keeps the no-C CI gate (§6) authoritative on the exact bytes that ship.
- **systemd *user* service, not system.** The TCB is the owner's address space; the vault,
  the UDS control socket (`$XDG_RUNTIME_DIR/env-ctl/control.sock`), and the USB keyfile are
  all per-user. A system service would run as root and break the `SO_PEERCRED uid == owner`
  authz model (ARCHITECTURE.md §"Control" plane). `systemd_user` is a first-class Wiring
  field. `VERIFIED` (`model.rs:292`, `SystemdUnit{name,content,enable}` at `model.rs:379-384`).
- **detect == verify for the daemon-present predicate** (boot-repair.toml's documented
  pattern): an un-built box reads `detected=false` and drift never nudges a destructive
  rebuild. We make `detect` = "binaries present AND service unit installed", and `verify` =
  "binaries answer `--help` AND `secretd` self-check passes".
- **Guard the destructive phases with a real `Guard`, not a freeform echo.** envctl's
  `Guard` enum gives us `HookSucceeds{hook}` for the USB pre-flight (§5). The cryptographic
  possession proof stays in the daemon (REQ-SEC-3); the manifest guard is only a fast
  pre-filter, exactly as the threat model demotes the PARTUUID itself (THREAT-MODEL.md §72).

**Two deployment profiles.** Profile A (on-box, USB unlock) is the shippable default.
Profile B (VPS, presence-token) is explicitly **deferred / non-shippable** here (SERVER-MODE.md
defers VPS; the on-box USB possession gate is the whole containment story, A2/A7).

**Hard gate before this component can be enabled (not just authored):** Phase 6 `secretd`
bring-up must land — today `crates/secretd/src/main.rs` is `todo!("secretd server bring-up
(Phase 6)")`. `VERIFIED` (read the file). Until then the component installs binaries and
wiring but the service will panic on start; CI must keep `enable=false` (§4.3, §7.3).

---

## 2. What we are packaging (verified crate + version facts)

From `~/Desktop/env-ctl/Cargo.toml` and `crates/*/Cargo.toml` (all `VERIFIED` by read):

| Crate (member) | Package | Binary | Async/net deps? | Pure-Rust? |
|---|---|---|---|---|
| `crates/secrets-engine` | `envctl-secrets-engine` (lib `envctl_secrets`) | — | NO (one `async_trait` seam only; `futures-executor` is dev-only; tokio is **banned** here per its own Cargo.toml comment) | **YES** — CI gate target |
| `crates/secrets-proto` | `envctl-secrets-proto` | — | build-time `tonic-build`/`prost` | YES |
| `crates/secretd` | `envctl-secretd` | `secretd` | YES (tokio 1.43, tonic 0.12, hyper 1.5, reqwest 0.12) | YES today (Phase 0 scaffold); gains libSQL **behind a feature** in Phase 1 |
| `crates/secretctl` | `envctl-secretctl` | `secretctl` | client-side tonic | YES |

Workspace pins (`[workspace.dependencies]`, `VERIFIED`): `rust-version = "1.80"`,
`edition = "2021"`, `resolver = "2"`. Crypto is pure-Rust:
`chacha20poly1305 = 0.10`, `argon2 = 0.5 (features=["zeroize"])`, `hkdf = 0.12`,
`sha2 = 0.10`, `blake3 = 1.5`, `zeroize = 1.8`, `subtle = 2.6`, `rand = 0.8`,
`getrandom = 0.2`. TLS/CA pinned to the **ring** path:
`rustls = 0.23 (default-features=false, features=["ring","logging","std","tls12"])`,
`rcgen = 0.13 (default-features=false, features=["ring","pem"])`.

The engine default feature set is `["inmem-store","mitm-ca"]` and `inmem-store` is RAM-only;
**no C dependency ships in Phase 0** (`crates/secrets-engine/Cargo.toml`, `VERIFIED`).

**Merge edit required (HF-17).** envctl's row is
`rustix = { version = "0.38", features = ["process"] }`
(`~/Desktop/envctl/Cargo.toml:20`, `VERIFIED`); env-ctl needs `["net"]` for `SO_PEERCRED`
and already declares the union locally
(`~/Desktop/env-ctl/Cargo.toml`: `features = ["process", "net"]`, `VERIFIED`, with an
in-file `MERGE NOTE (HF-17)`). The merged workspace row MUST be the union:

```toml
rustix = { version = "0.38", features = ["process", "net"] }
```

### Upstream version provenance (release pages; `UNVERIFIED` against this box's lockfile)

| Dep | Pin | Source | Note |
|---|---|---|---|
| rustup / stable toolchain | MSRV 1.80 | https://rustup.rs/ ; channel pinned in `rust-toolchain.toml` (`VERIFIED`) | `cargo --version` must be ≥ 1.80 |
| tokio | 1.43 | https://github.com/tokio-rs/tokio/releases | check CVE-2024-47609 accept-loop fix is in-tree (see §9) |
| tonic | 0.12 | https://github.com/hyperium/tonic/releases | |
| prost | 0.13 | https://github.com/tokio-rs/prost/releases | |
| chacha20poly1305 | 0.10 | https://github.com/RustCrypto/AEADs | |
| argon2 | 0.5 | https://github.com/RustCrypto/password-hashes | |
| rustls | 0.23 | https://github.com/rustls/rustls/releases | ring provider, NOT aws-lc-rs |
| rcgen | 0.13 | https://docs.rs/crate/rcgen/latest/features | ring is a **default** feature; `aws_lc_rs` is **optional** — `VERIFIED` ring-without-C is buildable |

---

## 3. The component manifest (`manifest/env-ctl.toml`)

Field names, hook `kind`s, and guard `kind`s below are exact against
`~/Desktop/envctl/crates/engine/src/component.rs` and `model.rs`. Paths are the verified
XDG layout from ARCHITECTURE.md §"Layout" (lines 124-127):
`~/.config/env-ctl` (config), `~/.local/share/env-ctl` (0700; `vault.db` 0600, `ca/`),
`~/.local/state/env-ctl` (0700; `secretd.log`, audit mirror),
`$XDG_RUNTIME_DIR/env-ctl` (0700; `control.sock` 0600, relay-proxy bind config). `VERIFIED`.

```toml
# manifest/env-ctl.toml — env-ctl secrets vault + credential broker (Profile A: on-box, USB unlock)
# Builds the four envctl-secrets-* workspace crates and wires secretd as a systemd USER service.
# detect == verify (binaries + unit present, daemon self-check green) so drift never nudges a
# destructive rebuild. Vault purge is the native data_paths path (reset --purge), NOT a side component.

[[component]]
id = "env-ctl"
name = "env-ctl secrets daemon"
description = "Pure-Rust gRPC secrets vault + credential broker. Stores keys AEAD-encrypted at rest, mints <=24h peer-bound relay bearers, terminates TLS in-process for the remote relay edge. Control plane is UDS + SO_PEERCRED (owner-only); data plane is loopback; the only network surface is the relay HTTPS edge."
requires = ["rustup"]      # cargo + stable >= 1.80
destructive = false

# DETECT == the "already installed AND healthy enough to be present" predicate.
[component.detect]
kind = "command"
command = "bash"
args = ["-lc", "test -x \"$HOME/.cargo/bin/secretd\" && test -x \"$HOME/.cargo/bin/secretctl\" && test -f \"$HOME/.config/systemd/user/env-ctl.service\""]

# INSTALL: MSRV-gate, build from the in-workspace sources, place bins, create XDG dirs (0700).
# Does NOT init the vault or enroll keyslots — those are operator-driven, USB-gated daemon ops (§5.3).
[component.install]
kind = "script"
script = '''
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

# MSRV gate (rust-version = 1.80 in the workspace). Fail closed, do not silently upgrade.
ver="$(cargo --version | awk '{print $2}')"
printf '%s\n1.80.0\n' "$ver" | sort -V -C || { echo "FATAL: cargo $ver < MSRV 1.80"; exit 1; }

# Post-merge this is the envctl workspace itself; pre-merge override with ENV_CTL_REPO.
repo="${ENV_CTL_REPO:-$HOME/Desktop/envctl}"
test -d "$repo" || { echo "FATAL: workspace not found at $repo (set ENV_CTL_REPO)"; exit 1; }

cargo build --release --manifest-path "$repo/Cargo.toml" \
  -p envctl-secretd -p envctl-secretctl

install -Dm755 "$repo/target/release/secretd"   "$HOME/.cargo/bin/secretd"
install -Dm755 "$repo/target/release/secretctl" "$HOME/.cargo/bin/secretctl"

# XDG dirs, fail-closed perms (ARCHITECTURE.md layout). RUNTIME dir is created by the unit at start.
install -d -m700 "$HOME/.config/env-ctl"
install -d -m700 "$HOME/.local/share/env-ctl"
install -d -m700 "$HOME/.local/state/env-ctl"
'''

# VERIFY: bins answer, AND secretd's own listener/lockdown self-check passes (SERVER-MODE.md §3,
# items 3-4: refuse to start unless control is UDS-only and exactly one non-loopback listener exists).
# Until Phase 6, `secretd --self-check` is itself todo!(); keep this verify in place so an un-built
# daemon reports verify=false (drift visible) WITHOUT triggering a destructive fix.
[component.verify]
kind = "command"
command = "bash"
args = ["-lc", "export PATH=\"$HOME/.cargo/bin:$PATH\"; secretctl --help >/dev/null && secretd --self-check >/dev/null"]

# FIX: idempotent rebuild + reinstall (the dev-tools.toml `cargo install --force` analogue).
[component.fix]
kind = "script"
script = '''
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
repo="${ENV_CTL_REPO:-$HOME/Desktop/envctl}"
cargo build --release --manifest-path "$repo/Cargo.toml" -p envctl-secretd -p envctl-secretctl
install -Dm755 "$repo/target/release/secretd"   "$HOME/.cargo/bin/secretd"
install -Dm755 "$repo/target/release/secretctl" "$HOME/.cargo/bin/secretctl"
systemctl --user daemon-reload || true
systemctl --user try-restart env-ctl.service || true
'''

# REMOVE: disable + drop the unit and bins. The vault is data_paths and is touched ONLY on --purge.
[component.remove]
kind = "script"
script = '''
set -euo pipefail
systemctl --user disable --now env-ctl.service 2>/dev/null || true
rm -f "$HOME/.cargo/bin/secretd" "$HOME/.cargo/bin/secretctl"
systemctl --user daemon-reload || true
# vault.db / ca/ / audit are data_paths+config_paths below — envctl deletes them ONLY with --purge,
# after a UUID re-verify. remove() never touches user data (THREAT-MODEL: user data is never touched).
'''

# ---- WIRING (engine-owned, reversible: backup-then-excise on reset; see engine/src/wiring.rs) ----
[component.wiring]
path_entries = ["~/.cargo/bin"]

[[component.wiring.shell_rc]]
file = "~/.bashrc"
marker = "env-ctl"     # engine writes "BEGIN env-ctl (added by envctl)" / "END env-ctl" guard lines
content = '''
export SECRETCTL_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/env-ctl/control.sock"
'''

[[component.wiring.systemd_user]]
name = "env-ctl.service"
enable = false          # FLIP TO true ONLY after Phase 6 bring-up lands (see §4.3 / §7.3).
content = '''
[Unit]
Description=env-ctl secrets vault + credential broker
Documentation=file:///home/drdave/Desktop/envctl/docs/ARCHITECTURE.md
# No network ordering for the control/data planes (UDS + loopback). Only the relay HTTPS
# edge needs the network, and that is operator-enabled, not a startup dependency.
After=default.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=%h/.cargo/bin/secretd
Restart=on-failure
RestartSec=10
# Fail-closed memory hygiene is enforced IN secretd (mlockall + RLIMIT_CORE=0 + MADV_DONTDUMP;
# the daemon refuses to start if mlockall fails — THREAT-MODEL.md FS-S4). The unit only RAISES
# the ceiling the daemon needs; it never substitutes for the in-process refusal.
LimitMEMLOCK=infinity
LimitCORE=0
# Defense-in-depth sandbox (does not weaken the in-process TCB story):
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/env-ctl %h/.local/state/env-ctl %t/env-ctl
RuntimeDirectory=env-ctl
RuntimeDirectoryMode=0700
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
# Pulling the enrolled USB auto-relocks within the drain grace (ARCHITECTURE.md §103);
# stop must allow the daemon to drain in-flight relays/streams (SERVER-MODE.md §"long stream").
TimeoutStopSec=30
KillMode=mixed

[Install]
WantedBy=default.target
'''

# ---- VAULT DATA: deleted ONLY by `envctl reset env-ctl --purge` (after UUID re-verify) ----
[[component.wiring.data_paths]]
path = "~/.local/share/env-ctl"   # vault.db (0600), ca/ (local CA private material)
[[component.wiring.data_paths]]
path = "~/.local/state/env-ctl"   # secretd.log, durable hash-chained audit mirror

# ---- CONFIG: kept with `--keep-config`, else engine-removed on reset ----
[[component.wiring.config_paths]]
path = "~/.config/env-ctl"

# ---- GUARD: USB/storage PARTUUID pre-filter on destructive phases. This is a fast pre-flight ----
# ---- ONLY; the daemon proves keyfile POSSESSION cryptographically (REQ-SEC-3, FS-S9). ----
[[component.guards]]
kind = "hook_succeeds"
[component.guards.hook]
kind = "command"
command = "bash"
args = ["-lc", "lsblk -dno PARTUUID | grep -q . || { echo 'FATAL: no PARTUUID storage for USB keyslot pre-filter'; exit 1; }"]
```

### Notes on the manifest above

- `Type=notify` + `NotifyAccess=main` + `LimitMEMLOCK=infinity`: the daemon `mlockall`s and
  refuses to start without it (FS-S4). `LimitMEMLOCK=infinity` lets the lock succeed under a
  systemd user session; `LimitCORE=0` doubles the in-process `RLIMIT_CORE=0`. The daemon's
  refusal remains authoritative — the unit only removes a reason to fail. `UNVERIFIED` that
  Phase 6 `secretd` emits `sd_notify(READY=1)`; if it does not, change `Type=notify`→`simple`.
- `enable = false` is deliberate and load-bearing — see §4.3.
- `secretd --self-check` and `--init` are referenced as the intended Phase 6 surface; they are
  `UNVERIFIED` (do not exist yet). The verify hook degrades gracefully (returns non-zero on a
  `todo!()` daemon → `verify=false`, no destructive fix triggered because `detect` is the
  install predicate, not health).

---

## 4. Build dependencies, CI gates, and the "no-C" contract

### 4.1 Manifest dependency

```toml
requires = ["rustup"]
```

This is the only hard external dependency: `cargo` + a stable toolchain ≥ 1.80. (`rustup` is
the natural `requires` target; envctl's graph resolves `requires` before install —
`executor.rs:157`, `VERIFIED`.) The systemd user session and `$XDG_RUNTIME_DIR` are assumed
present (true on this box's interactive login).

### 4.2 CI gates (run in the merged envctl CI / Makefile)

These are the authoritative "what actually ships is pure-Rust" gates. Per-crate, because the
no-C contract is **per-crate scoped** post-OI-1 (SERVER-MODE.md NEW-3): the engine/proto/CLI
stay green; the libSQL store crate carries a documented, bounded waiver.

```bash
# (1) Engine / proto / CLI carry NO C deps — these MUST pass (hard gate).
for c in envctl-secrets-engine envctl-secrets-proto envctl-secretctl; do
  cargo tree -p "$c" --no-default-features --features inmem-store 2>/dev/null \
    | grep -Eq 'libsql-ffi|libsql-sys|sqlite3-sys|rusqlite|aws-lc-sys|openssl-sys' \
    && { echo "FAIL: C dep leaked into $c"; exit 1; }
done

# (2) Exactly ONE rustls, on the ring path (NOT aws-lc-rs).
cargo tree -i aws-lc-sys 2>/dev/null && { echo "FAIL: aws-lc-sys present (expected ring)"; exit 1; }
test "$(cargo tree -i rustls 2>/dev/null | grep -c '^rustls v')" = "1" || { echo "FAIL: multiple rustls"; exit 1; }

# (3) MSRV gate.
cargo +1.80.0 check -p envctl-secrets-engine -p envctl-secrets-proto -p envctl-secretctl

# (4) The rustix feature UNION survived the merge (HF-17 regression guard).
cargo tree -e features -i rustix 2>/dev/null | grep -q 'feature "net"' \
  && cargo tree -e features -i rustix 2>/dev/null | grep -q 'feature "process"' \
  || { echo "FAIL: rustix lost process|net union (HF-17)"; exit 1; }
```

### 4.3 The Phase-6 / OI-1 enable gate

Add a CI assertion that the manifest ships with `enable = false` until BOTH land:

```bash
# secretd must not be auto-enabled while main.rs is a scaffold.
grep -q 'todo!("secretd server bring-up' crates/secretd/src/main.rs \
  && grep -q 'enable = false' manifest/env-ctl.toml \
  || { echo "Phase 6 not done yet — manifest MUST keep enable=false"; exit 1; }
```

When Phase 6 + OI-1 land, this guard is removed and `enable` flips to `true` in the same PR.

---

## 5. Deployment sequence (Profile A — on-box, USB unlock)

### 5.1 Pre-flight (operator)

```bash
rustup show                 # stable >= 1.80 active
which cargo secretd 2>/dev/null
lsblk -dno PARTUUID         # the USB key partition's PARTUUID (pre-filter selector only)
```

### 5.2 Install via envctl (dry-run is the DEFAULT)

envctl verbs are `install`, `reset` (`--apply`/`--confirm`/`--purge`/`--keep-config`/`--cascade`),
`auto-fix` (`--apply`), `auto-detect` (read-only), and `lock` (the reproducibility lock — distinct
from the daemon's `lock`). `VERIFIED` (`~/Desktop/envctl/crates/cli/src/cli.rs`). Reset/auto-fix
are **dry-run unless `--apply`**.

```bash
envctl install env-ctl            # preview the plan (no changes)
envctl install env-ctl --apply    # build, place bins, write unit + shell-rc, create XDG dirs
systemctl --user status env-ctl.service   # NOTE: inactive until §4.3 gate flips enable=true
```

### 5.3 Vault init + keyslot enrollment (daemon-driven, USB-gated — NOT the manifest)

Enrollment is a control-plane op over the UDS, USB-gated, `--apply`-gated, with the destructive
RPC carrying proto3-default-`false` `apply` (dry-run by default) and `confirm` for root-of-trust
ops (ARCHITECTURE.md §119, `VERIFIED`). The manifest never enrolls keys — it only ensures the
daemon and dirs exist. Intended Phase-6 surface (`UNVERIFIED` — exact verbs not yet implemented):

```bash
secretctl vault init --apply                         # creates vault.db, the DEK, the local CA
secretctl keyslot enroll --usb --partuuid <PARTUUID> --apply   # USB keyslot (proves keyfile content)
secretctl keyslot enroll --passphrase --apply        # 1-of-2 fallback; entropy enforced at enroll
```

LUKS-style 1-of-2: either factor opens the SAME DEK; the AEAD tag is the correctness oracle
(THREAT-MODEL.md §76). **This is a downgrade, not 2FA** — overall strength is the weaker factor
(the passphrase's argon2id work, A12); enforce passphrase entropy at enroll.

### 5.4 Using a relay (data plane; loopback)

```bash
secretctl relay create --ephemeral --policy claude-main --apply \
  -- env ANTHROPIC_API_KEY='<minted-bearer>' bash
```

The real key never enters the child env/argv/history (REQ-SEC-6); the bearer is ≤24h, peer-bound
to the child pid at swap (HF-8), allowlist + quota capped, re-checked at every swap. The eventual
`envctl run -- <tool>` auto-injection is a future seam, not part of this component.

### 5.5 Reset / purge

```bash
envctl reset env-ctl --apply               # disable + remove unit and bins; KEEPS the vault
envctl reset env-ctl --apply --purge --confirm   # ALSO deletes vault.db/ca/audit (data_paths), after UUID re-verify
envctl reset env-ctl --apply --keep-config       # remove daemon but keep ~/.config/env-ctl
```

---

## 6. Reversibility & wiring guarantees

envctl wiring is engine-owned and reversible by construction (`engine/src/wiring.rs`:
"apply()/revert() for Wiring (shell_rc backup-then-excise)", `VERIFIED` `lib.rs:10`):

- **shell_rc** is a marker-delimited block (`BEGIN env-ctl (added by envctl)` … `END env-ctl`);
  detect/revert match the marker regardless of who wrote it (`detect.rs:205-208`, `VERIFIED`).
  Revert excises only the owned block — never hand-edits the file.
- **path_entries** are realized into the single engine-owned "envctl PATH" block in `~/.bashrc`
  and detected via that marker (`detect.rs:212-222`, `VERIFIED`).
- **systemd_user** writes `~/.config/systemd/user/env-ctl.service`; reset disables and removes it
  (`executor.rs:297`, `VERIFIED` that systemd_user counts as an owned footprint).
- **data_paths** are deleted ONLY on `--purge` after a UUID re-verify; **config_paths** are kept
  with `--keep-config` (`model.rs:303-308`, `VERIFIED`). This is exactly the safety property we
  want for an encrypted vault: a plain `reset` is non-destructive to secrets.

Invariant: **reset never touches user data unless `--purge`**, and `--purge` is itself gated by
UUID re-verify + (for the whole roster) `--all --confirm` (`executor.rs:71`, `cli.rs:233`).

---

## 7. Security rationale tied to the threat model

### 7.1 BLOCKER — the libSQL "pure-Rust remote client" claim is wrong as stated

SERVER-MODE.md §2.2 (line 75) and §"Store" (line 175) state the recommended store is the
**`libsql` crate** with `default-features=false, features=["remote"]`, labeled
"VERIFIED pure-Rust, no `libsql-ffi`". **That label is incorrect and must not be trusted as a
shipping gate.** Verified against the upstream feature graph:

- The `libsql` crate's DEFAULT features are `core, remote, replication, sync, tls`, and
  `core` pulls `libsql-sys` (the bundled C SQLite via `libsql-ffi`). `sync`/`replication`
  also pull `core`. So **any default build links C.** (https://docs.rs/crate/libsql/latest/features)
- The `remote` feature *itself* does not list `core` as a dependency, and the API docs state
  that a DB opened with `open_remote` "will not call any C ffi" at runtime
  (https://docs.rs/libsql ; https://crates.io/crates/libsql/0.3.4/dependencies). So
  `default-features=false, features=["remote"]` *can* be C-free, but this is a **non-default,
  fragile** configuration whose graph-level purity must be proven by `cargo tree`, NOT asserted.
- The unambiguously pure-Rust path is the **separate `libsql-client` + `libsql-hrana`** crates
  (https://crates.io/crates/libsql-client ; https://crates.io/crates/libsql-hrana ;
  https://github.com/tursodatabase/libsql-client-rs), which speak Hrana over HTTP with
  `hyper-rustls` and no `libsql-sys`.

**Ops consequence (REQ for shipping):**
1. The store backend MUST live in the quarantined `crates/secrets-store-libsql` (OI-1 / NEW-3),
   consumed ONLY by `secretd` behind the `Store` trait — the engine stays C-free (CI gate §4.2-(1)).
2. The remote-client crate choice MUST be pinned to whichever combination `cargo tree` PROVES has
   no `libsql-sys`/`libsql-ffi` — and a per-crate CI gate must assert it:
   ```bash
   cargo tree -p envctl-secrets-store-libsql --no-default-features --features remote 2>/dev/null \
     | grep -Eq 'libsql-ffi|libsql-sys' && { echo "FAIL: C SQLite in the 'remote' store"; exit 1; }
   ```
   Until that gate is GREEN, the recommended on-box wiring (embedded `sqld` on loopback + remote
   client) is **risk-accepted**, not "verified pure". This is the single largest correction to the
   incoming design and a hard pre-ship item.

This does NOT change the at-rest security story: app-layer XChaCha20-Poly1305 is authoritative;
`sqld` is untrusted ciphertext storage; libSQL's own at-rest encryption is never relied upon
(disabled; libsql issue #1756) (SERVER-MODE.md line 41, `VERIFIED` against repo doc). It changes
the **C-attack-surface** story, which is why §2.2's recommendation to run `sqld` as a SEPARATE
loopback process (not in-process) is the right one regardless.

### 7.2 Why systemd USER + UDS + SO_PEERCRED (TCB and authz)

The TCB is the `secretd` address space — the only place the plaintext DEK and real upstream keys
exist, zeroized on drop, `mlockall(MCL_CURRENT|MCL_FUTURE)` + `RLIMIT_CORE=0` + `MADV_DONTDUMP`,
daemon refuses to start if `mlockall` fails (THREAT-MODEL.md §8, FS-S4, `VERIFIED`). Running as
the owner (user service) is what makes `SO_PEERCRED uid == owner` a meaningful control-plane authz
(ARCHITECTURE.md §20). A root/system service would invert this and is a **forbidden state**. The
unit's `LimitMEMLOCK=infinity`/`LimitCORE=0`/`MADV` are necessary-but-not-sufficient: the
in-process refusal stays authoritative.

### 7.3 Why `enable = false` until Phase 6 (fail-closed deploy)

A Phase-0 `secretd` is `todo!()`. Auto-enabling it would put a panicking unit in a restart loop
and, worse, give operators a false sense that "the vault is up". Fail-closed: the component
installs the *capability* but does not start a daemon that cannot enforce its own guards
(FS-S9 — a guard that cannot prove its precondition must not silently pass; the same principle
applies at the deploy layer). §4.3 makes this a CI invariant.

### 7.4 Why the manifest USB guard is a pre-filter, not the boundary

The `HookSucceeds` guard only checks that *some* PARTUUID storage is visible. The PARTUUID is a
convenience selector, **not** a security boundary — the keyfile CONTENT is the secret and the
daemon PROVES possession cryptographically (REQ-SEC-3, THREAT-MODEL.md §72; A11: on vfat/exfat
`0400` is advisory, physical possession is the real boundary). The manifest guard exists only to
fail an install/fix/purge early on a box with no removable storage at all; it must never be
mistaken for the unlock gate.

### 7.5 Remote relay edge — what the component does and does NOT expose

The ONLY network surface is the relay HTTPS edge, and it is operator-enabled, not started by the
unit (no `network-online.target` ordering for control/data). The remote edge is mTLS-required,
TLS terminated in-process, and remote bearers are sender-constrained (DPoP) and client-bound; a
config where the bearer-validating process cannot compute the channel binding is a forbidden state
(FS-S20). Control is provably unreachable over the network by construction: disjoint route tables,
a CI `control-types-not-in-edge` grep, and a strongly-preferred separate edge PROCESS
(SERVER-MODE.md §3, `VERIFIED` against repo doc). The Telegram cloud agent's binding degrades
toward bearer-only (replay-bounded-by-scope-and-TTL) if it cannot hold a non-exportable key —
push-model, per-task minting, and the bot-token/relay-bearer never co-locating in one process are
the structural mitigations (SERVER-MODE.md §"Telegram"). **None of this is in the manifest** — it
is daemon config under `~/.config/env-ctl`; the component just refrains from exposing it by default.

---

## 8. Post-merge integration checklist

1. Drop the four crates into `envctl/crates/secrets-*`; add them to `[workspace] members`.
   (`VERIFIED` the four members exist and build as a workspace today.)
2. **Edit `rustix` to `features = ["process","net"]`** in the merged
   `[workspace.dependencies]` (HF-17). Add the §4.2-(4) CI regression guard.
3. Confirm `proto/control.proto` is vendored under `crates/secrets-proto/proto/` (OI-15).
   `UNVERIFIED` here — check on merge.
4. `cargo build` the unified workspace; expect ONE resolved `Cargo.lock`.
5. Wire the §4.2 CI gates into envctl CI; wire the §4.3 enable gate.
6. Land OI-1 (`crates/secrets-store-libsql`, C-quarantined, behind the `Store` trait) and the
   §7.1 per-crate "remote store has no `libsql-sys`" gate.
7. Land Phase 6 `secretd` bring-up; flip `enable = true`; remove the §4.3 guard in the same PR.
8. Add the component to `envctl.lock` (the content-hash reproducibility lock; `envctl lock`).
9. Validate on a clean box: `envctl install env-ctl` (dry-run) → `--apply` → `auto-detect`
   shows detected/verified → `reset --apply` keeps the vault → `reset --apply --purge --confirm`
   erases it after UUID re-verify.

---

## 9. Open questions (each is a real decision or an `UNVERIFIED` to close before ship)

1. **libSQL remote-client purity (§7.1) — BLOCKER.** Which exact crate + feature combo gives a
   graph that `cargo tree` proves has no `libsql-sys`/`libsql-ffi`? Candidate A:
   `libsql` `default-features=false, features=["remote"]` (docs say no C ffi at runtime, but graph
   purity unproven). Candidate B: `libsql-client` + `libsql-hrana` (clearly pure-Rust). **Decide
   and CI-gate before enabling the libSQL store.** (https://docs.rs/crate/libsql/latest/features)
2. **`secretd` readiness protocol.** Does Phase-6 `secretd` emit `sd_notify(READY=1)`? If yes keep
   `Type=notify`; if no use `Type=simple`. `UNVERIFIED`.
3. **`secretd --self-check` / `--init` / `secretctl vault init` / `keyslot enroll` surface.**
   The exact CLI verbs used in §3 verify and §5.3 are intended, not implemented. Pin the names in
   SCAFFOLD-SPEC before the manifest hard-codes them. `UNVERIFIED`.
4. **`LimitMEMLOCK` under the systemd user manager.** Confirm the user-session manager permits
   `LimitMEMLOCK=infinity` on this box (some hardened defaults cap `RLIMIT_MEMLOCK` for user units).
   If capped, the daemon's `mlockall` refusal will block startup. `UNVERIFIED` on Ubuntu 26.04.
5. **`ProtectHome=read-only` vs the USB keyfile.** The keyfile lives on a mounted USB, not under
   `$HOME` — confirm the mount point is reachable under the sandbox, or add it to `ReadWritePaths`/
   relax `ProtectHome`. `UNVERIFIED`.
6. **`rustup` as a `requires` id.** Confirm envctl ships a component with `id = "rustup"` (or the
   cargo toolchain id to depend on). If the toolchain is provided by a different component
   (`dev-tools`/`base`), change `requires` accordingly. `UNVERIFIED` against the current manifest set.
7. **tokio 1.43 accept-loop DoS (CVE-2024-47609) and tonic 0.12/hyper 1.5 body/rate limits.**
   Confirm the pinned tokio is at/above the fixed patch and that the remote edge sets body-size and
   connection-rate caps before the public edge is enabled. `UNVERIFIED`.
8. **Profile B (VPS).** Deferred. The USB possession gate is the whole A2/A7 containment story; a
   VPS needs a different presence factor (TPM/enclave-sealed token) before any of §5.3 applies.
   Out of scope for this component until SERVER-MODE.md's VPS deferral is lifted.
9. **`MADV_DONTDUMP` + zeroize residuals.** The argon2 ~1 GiB arena and tonic/hyper receive buffers
   cannot be fully zeroized (THREAT-MODEL.md §75); the install should warn to run on
   encrypted/no-swap storage. Should the component's verify hook assert swap is off/encrypted?
   Open design choice.

---

*Sources inline above. Repo facts cited as `VERIFIED` were read directly from
`~/Desktop/env-ctl` and `~/Desktop/envctl` during authoring (2026-06-02). Upstream crate facts
were checked against docs.rs / crates.io / GitHub release pages as cited. Items marked
`UNVERIFIED` are open questions, not asserted facts.*
