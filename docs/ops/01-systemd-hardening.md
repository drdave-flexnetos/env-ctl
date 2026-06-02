# env-ctl ops — secretd + sqld as hardened systemd services

> Ops/deploy design for **Profile A (default, recommended)** of env-ctl on the dual-RTX-5090 dev box.
> Status: design proposal, READ-ONLY synthesis of the existing design docs + process-hardening research.
> Date: 2026-06-02. All version/URL facts were current at the cited research date; re-verify before locking.
> Anything not directly confirmable on this box is flagged **[UNVERIFIED]**.

Source design docs (all under `/home/drdave/Desktop/env-ctl/docs/`):
[ARCHITECTURE.md](../ARCHITECTURE.md) ·
[SERVER-MODE.md](../SERVER-MODE.md) ·
[THREAT-MODEL.md](../THREAT-MODEL.md) ·
[DESIGN-NOTES.md](../DESIGN-NOTES.md) ·
[ROADMAP.md](../ROADMAP.md) ·
[research/03-libsql-server.md](../research/03-libsql-server.md) ·
[research/05-process-hardening.md](../research/05-process-hardening.md) ·
[research/06-grpc-uds-peercred.md](../research/06-grpc-uds-peercred.md)

---

## 0. TL;DR — the recommended deployment for THIS box

Two **systemd user services** (under the operator's session, not system-wide), wired as:

```
secretctl ──UDS(SO_PEERCRED, 0600)──▶ secretd.service ──loopback HTTP/2 (JWT Ed25519)──▶ sqld.service
   (control plane)                       │  owns DEK in mlock'd RAM                          │ untrusted ciphertext store
                                         │  in-process rustls relay edge (Phase 8 only)      ▼
                                         ▼                                              vault.db (XChaCha20-Poly1305 blobs)
                                  public NIC (relay HTTPS, Phase 8)
```

Key decisions, all tied to the design docs:

1. **Two separate processes**, not one. `secretd` holds the DEK and the network edge; `sqld` is the C-cored libSQL server isolated on loopback. This is the *recommended on-box wiring* in [SERVER-MODE.md §2.2 / NEW-3](../SERVER-MODE.md) — `secretd` talks to `sqld` via the **pure-Rust `remote` libSQL client** (`default-features=false, features=["remote"]`), so the bundled C SQLite never co-resides with the key-handling/network address space (mitigates threat **A18**).
2. **User units, not system units.** The vault is unlocked interactively by the operator (USB-PARTUUID + passphrase); it belongs to the user session and `$XDG_RUNTIME_DIR`. This keeps the daemon unprivileged and makes the UDS `SO_PEERCRED` owner check (FS-S8) trivially correct.
3. **`sqld` is untrusted-by-default and MUST be locked down.** sqld ships with **no auth and is publicly writable by default, and has no usable at-rest encryption** ([research/03 §"Authentication", §"Encryption-at-rest"](../research/03-libsql-server.md); <https://docs.turso.tech/sdk/authentication>). We enforce loopback-only bind + JWT (Ed25519) and rely entirely on app-layer XChaCha20-Poly1305 for confidentiality.
4. **Hardening is split: in-process AND systemd.** `RLIMIT_CORE=0` alone is *insufficient* on a systemd box because `kernel.core_pattern` pipes to `systemd-coredump` and the kernel then ignores `RLIMIT_CORE` ([systemd.io/COREDUMP](https://systemd.io/COREDUMP/)). `secretd` therefore ALSO calls `prctl(PR_SET_DUMPABLE, 0)` + `mlockall` itself (research/05); systemd directives are defense-in-depth around that.
5. **VPS (Profile B) units are present but install-time-gated as non-shippable** until OI-SM-2/OI-SM-3 ship ([SERVER-MODE.md §5.3](../SERVER-MODE.md)).

---

## 1. Topology and unit inventory

| Unit | Type | Binds | Purpose |
|---|---|---|---|
| `env-ctl.target` | target | — | groups the vault services |
| `sqld.service` | `notify` | loopback TCP (HTTP/2 Hrana) | untrusted ciphertext store (C core) |
| `secretd.service` | `notify` | UDS control + (Phase 8) public HTTPS relay | vault daemon, DEK owner, relay broker |

Deliberately **NOT** socket-activated: the `sqld` listener and the `secretд` control UDS. Both are always-on for an unlocked session and ordering is expressed with `After=`/`Requires=`. Socket activation buys nothing here (no scale-to-zero requirement) and would complicate the `secretd` startup self-check that enumerates listeners ([SERVER-MODE.md §3 startup self-check](../SERVER-MODE.md)). *(The earlier draft proposed `sqld.socket`; dropped — see Open Questions Q5.)*

### Ports

`sqld` HTTP listener: **`127.0.0.1:8080`** (sqld's documented default HTTP port). The design docs do **not** pin a port; **[UNVERIFIED]** that 8080 is free on this box — pick any free loopback port and keep it consistent across the unit, the `secretd --sqld-url`, and the `secretd` listener self-check allowlist. Do **not** bind `[::1]` unless explicitly needed (separate AF, separate attack surface).

---

## 2. systemd units (concrete)

All paths use systemd `%h` (home) / `%U` (numeric uid) specifiers. Install under `~/.config/systemd/user/`.

### 2.1 `env-ctl.target`

```ini
# ~/.config/systemd/user/env-ctl.target
[Unit]
Description=env-ctl secrets vault services
Documentation=file:///home/drdave/Desktop/env-ctl/docs/SERVER-MODE.md
Wants=sqld.service secretd.service
After=basic.target
```

### 2.2 `sqld.service` (untrusted store, loopback-only, JWT-gated)

```ini
# ~/.config/systemd/user/sqld.service
[Unit]
Description=env-ctl embedded libSQL server (sqld v0.24.32) — untrusted ciphertext store
Documentation=https://github.com/tursodatabase/libsql
PartOf=env-ctl.target
Before=secretd.service
After=basic.target

# Fail-closed preconditions: refuse to start if the data dir or JWT key is missing.
ConditionPathExists=%h/.local/share/env-ctl
ConditionPathExists=%h/.local/share/env-ctl/sqld_jwt_pub.pem

[Service]
Type=notify
NotifyAccess=main

# JWT auth MUST be configured (sqld default = NO AUTH, publicly writable — research/03).
# Bind loopback only. No TLS on the loopback hop (ciphertext-only payloads; app-AEAD authoritative).
ExecStart=/usr/local/bin/sqld \
  --http-listen-addr 127.0.0.1:8080 \
  --db-path %h/.local/share/env-ctl/vault.db \
  --auth-jwt-key-file %h/.local/share/env-ctl/sqld_jwt_pub.pem \
  --no-welcome

Restart=on-failure
RestartSec=2s
TimeoutStartSec=15s
TimeoutStopSec=10s
KillSignal=SIGTERM

# ---- identity / least privilege ----
# (User services already run as the operator; these are belt-and-suspenders for a
#  potential future system-scoped install. Harmless in --user scope.)
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
UMask=0077

# ---- core-dump / debug suppression (C core: highest-value to lock down) ----
# RLIMIT_CORE=0 is NOT sufficient alone on a systemd box (core_pattern pipes to
# systemd-coredump; kernel ignores RLIMIT_CORE) — systemd.io/COREDUMP. We also
# globally disable the coredump handler (see §5) and run non-SUID (CVE-2025-4598).
LimitCORE=0

# ---- memory hardening ----
MemoryDenyWriteExecute=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes

# ---- filesystem isolation ----
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/env-ctl
PrivateTmp=yes
PrivateDevices=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid

# ---- namespace + network restriction ----
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET
IPAddressDeny=any
IPAddressAllow=localhost
SystemCallArchitectures=native

# ---- syscall filter ----
# sqld is C + tokio: needs networking + event loop. Allowlist + blocklist.
# [UNVERIFIED] exact set — capture with `systemd-analyze` / strace, then tighten.
SystemCallFilter=@system-service
SystemCallFilter=~@privileged ~@obsolete ~@resources @clock
SystemCallErrorNumber=EPERM

StandardOutput=journal
StandardError=journal
SyslogIdentifier=sqld

[Install]
WantedBy=env-ctl.target
```

Notes:
- `--no-welcome` suppresses sqld's ASCII banner; **[UNVERIFIED]** that this exact flag exists in `v0.24.32` — confirm with `sqld --help`. The intent (no decorative output to journal) matters more than the flag name.
- `IPAddressAllow=localhost`/`IPAddressDeny=any` enforce the loopback constraint at the cgroup/BPF level, independent of the bind address — a second wall behind `--http-listen-addr 127.0.0.1`.
- We pass the **public** half of the Ed25519 JWT key to sqld (`sqld_jwt_pub.pem`); the private signing key lives only inside `secretd`'s mlock'd memory and is never on `sqld`'s side.

### 2.3 `secretd.service` (vault daemon, DEK owner)

```ini
# ~/.config/systemd/user/secretd.service
[Unit]
Description=env-ctl secrets vault daemon (DEK owner, relay broker, control UDS)
Documentation=file:///home/drdave/Desktop/env-ctl/docs/ARCHITECTURE.md
PartOf=env-ctl.target
Requires=sqld.service
After=sqld.service
Before=default.target

# Fail-closed preconditions (FS-S9, REQ-SEC-4).
ConditionPathExists=%h/.config/env-ctl/secrets.toml
ConditionPathExists=%h/.local/share/env-ctl/vault.db

[Service]
Type=notify
NotifyAccess=main

# secretd resolves the USB-PARTUUID + reads the keyfile, derives the DEK, and binds the
# control UDS. It performs its OWN in-process hardening (mlockall + PR_SET_DUMPABLE)
# BEFORE the unlock path runs — see research/05 §"USB-unlock timing is the critical window".
ExecStart=/usr/local/bin/secretd \
  --config %h/.config/env-ctl/secrets.toml \
  --sqld-url http://127.0.0.1:8080 \
  --sqld-jwt-priv %h/.local/share/env-ctl/sqld_jwt_priv.pem \
  --control-socket %t/env-ctl/control.sock

ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s
TimeoutStartSec=60s
TimeoutStopSec=10s
KillSignal=SIGTERM

# ---- identity / least privilege ----
NoNewPrivileges=yes
# Zero capabilities. NOTABLY no CAP_IPC_LOCK: we raise RLIMIT_MEMLOCK instead so the
# daemon stays unprivileged (research/05 §"Capability vs limit" — prefer the systemd route).
# NOTABLY no CAP_NET_BIND_SERVICE: the relay edge (Phase 8) binds a high port, and the
# control plane is a UDS — neither needs a privileged port.
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
UMask=0077

# ---- memory locking (anti-swap for the DEK / bearers) — FS-S4 ----
# Default RLIMIT_MEMLOCK for an unprivileged process is only 64 KiB (research/05).
# Size to (locked working set + headroom). 512M soft/hard is generous; tune down later.
LimitMEMLOCK=512M:512M

# ---- core-dump suppression — FS-S4 ----
LimitCORE=0
# (secretd ALSO calls prctl(PR_SET_DUMPABLE,0) internally; this directive is belt-only.)

# ---- memory hardening ----
MemoryDenyWriteExecute=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes

# ---- filesystem isolation ----
ProtectSystem=strict
ProtectHome=read-only
# RW: vault state + audit mirror + (config writes for keyslot rotation). USB mount is read
# via the device path / by-partuuid; secretd reads the keyfile, never writes the USB.
ReadWritePaths=%h/.local/share/env-ctl %h/.local/state/env-ctl
ReadOnlyPaths=%h/.config/env-ctl
PrivateTmp=yes
# NOT PrivateDevices=yes here: secretd must read the USB block device / by-partuuid for
# REQ-SEC-3 possession proof. Use DeviceAllow to scope it instead (see Open Questions Q3).
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid

# ---- namespace + network restriction ----
RestrictNamespaces=yes
# AF_UNIX  : control plane (SO_PEERCRED).  AF_INET : loopback to sqld + Phase-8 relay edge.
RestrictAddressFamilies=AF_UNIX AF_INET
SystemCallArchitectures=native
# IPAddress*: in Profile A pre-relay, loopback-only. RELAX to add the public edge in Phase 8.
IPAddressDeny=any
IPAddressAllow=localhost

# ---- syscall filter ----
# secretd is Rust/tokio/rustls. Default-deny allowlist; explicitly keep mlock-related calls.
# [UNVERIFIED] tokio/hyper/rustls syscall set on Ubuntu 26.04 — capture with strace, tighten.
SystemCallFilter=@system-service
SystemCallFilter=~@privileged ~@obsolete ~@resources @debug
SystemCallErrorNumber=EPERM

# ---- runtime dir for the control UDS (%t = $XDG_RUNTIME_DIR = /run/user/%U) ----
RuntimeDirectory=env-ctl
RuntimeDirectoryMode=0700

StandardInput=null
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secretd

[Install]
WantedBy=env-ctl.target
```

Critical, non-obvious points (each tied to a source):

- **`RuntimeDirectory=env-ctl`** makes systemd create `/run/user/$UID/env-ctl/` mode 0700 and clean it up on stop. The control socket lands at `%t/env-ctl/control.sock`; combined with `UMask=0077` it is 0600. This satisfies the "UDS under `$XDG_RUNTIME_DIR`, no TCP control bind" property the `secretd` startup self-check enforces ([SERVER-MODE.md §3](../SERVER-MODE.md)). The `SO_PEERCRED` owner check (FS-S8) is done in-process — see [research/06](../research/06-grpc-uds-peercred.md); systemd file perms are only the first wall.
- **`mlockall` locks are lost across `fork(2)` and cleared on `execve`** (research/05). `secretd` MUST spawn any child via `posix_spawn`/`Command` (which `execve`s), never bare `fork`. The relay/UDS threads must avoid forking libraries. Nothing in the unit enforces this — it is an in-process invariant; the unit's job is only to grant the `RLIMIT_MEMLOCK` headroom.
- **`MemoryDenyWriteExecute=yes`** forbids W^X pages. If `secretd` ever links a JIT (it should not), this breaks it — that is the desired fail-closed behavior for a secrets daemon.

---

## 3. The unlock-timing window (the most important in-process invariant)

research/05 §"USB-unlock timing is the critical window" is explicit and was **not** covered by the upstream source research, so it is restated here as a hard ops requirement:

> Run `setrlimit(MEMLOCK)` → `prctl(PR_SET_DUMPABLE,0)` (via `secmem_proc::harden_process()`) → `mlockall(MCL_CURRENT|MCL_FUTURE)` **before** the USB-PARTUUID unlock path reads or derives **any** key material. If unlock runs first, a freshly read key can be paged to swap before it is ever locked.

Ops consequence: the `secretd` unlock RPC handler must be **unreachable until hardening completes**. The `Type=notify` contract above is the lever — `secretd` should call `sd_notify(READY=1)` **only after** hardening + listener bind, so systemd does not consider the service "started" (and ordering-dependent units do not proceed) until the daemon is in its locked-down state.

Recommended startup ordering inside `secretd`:

```
1. setrlimit(RLIMIT_MEMLOCK, want, want)            // research/05 step 1
2. setrlimit(RLIMIT_CORE, 0, 0)
3. secmem_proc::harden_process()                    // PR_SET_DUMPABLE(0) + ptrace block
4. rustix::mm::mlockall(CURRENT | FUTURE)
5. bind control UDS (0600) + verify no TCP control listener (self-check, SERVER-MODE §3)
6. <NOW unlock is reachable>  derive DEK, madvise(MADV_DONTDUMP) on each secret buffer
7. connect to sqld on loopback (JWT), confirm reachable
8. sd_notify(READY=1)
```

Sources: [mlockall(2)](https://man7.org/linux/man-pages/man2/mlockall.2.html), [PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/pr_set_dumpable.2const.html), [secmem-proc](https://github.com/niluxv/secmem-proc), crates `zeroize 1.8.2` / `secrecy 0.10.3` / `nix 0.31.3` (2026-05-11) / `rustix` (research/05 version table).

---

## 4. Security rationale tied to the threat model

| Threat (THREAT-MODEL.md / SERVER-MODE.md) | Control in THIS ops design |
|---|---|
| **FS-S4** — DEK swapped to disk, or daemon runs without `mlockall`+`RLIMIT_CORE=0` | `LimitMEMLOCK=512M` (raise the 64 KiB default) + `LimitCORE=0` in the unit; in-process `mlockall` + `PR_SET_DUMPABLE(0)` ordered *before* unlock (§3). `RLIMIT_CORE=0` alone is insufficient on systemd, so we also kill the coredump handler globally (§5) and run non-SUID. |
| **FS-S8** — control RPC from `uid != owner` served | User-scoped service; control plane is a UDS at `%t/env-ctl/control.sock`, dir 0700 / socket 0600 via `RuntimeDirectory` + `UMask`. In-process `SO_PEERCRED` owner check (research/06) is authoritative; no TCP control bind (self-check). |
| **FS-S9 / REQ-SEC-4** — guard silently passes when it cannot prove a precondition | `ConditionPathExists=` on `vault.db`, `secrets.toml`, and the sqld JWT key — the unit refuses to start if a precondition is unprovable. Runtime guards stay in `secretd`. |
| **A18** — C SQLite memory-safety bug in a network-facing daemon | Two-process split: C core lives only in `sqld`; `secretd` uses the pure-Rust `remote` client (SERVER-MODE §2.2). Even if `sqld` is popped, it sees only XChaCha20-Poly1305 ciphertext and never touches the DEK or the public NIC. |
| **sqld open-by-default** (research/03) | `--auth-jwt-key-file` (Ed25519) mandatory; `ConditionPathExists` on the pub key; loopback bind + `IPAddressAllow=localhost`/`IPAddressDeny=any`. App-layer AEAD is authoritative regardless. |
| **FS-S19 / FS-S25** — relay edge behind a TLS-terminating proxy; edge cert chained to the MITM CA | Phase-8 relay TLS terminates **in-process** in `secretd` (no separate proxy unit), so RFC5705 EKM/DPoP binding survives (SERVER-MODE §4, §7). The MITM CA path is a distinct type the edge cannot load (SERVER-MODE §7). Out of scope for Profile-A pre-relay but the unit is structured to keep the edge in-process. |
| **CVE-2025-5054 (apport) / CVE-2025-4598 (systemd-coredump)** — crashing program leaks memory to the coredump handler | Run non-SUID (user service, no SUID bit), `sysctl fs.suid_dumpable=0`, and disable the coredump handler for these units (§5). ([Qualys TRU](https://blog.qualys.com/vulnerabilities-threat-research/2025/05/29/qualys-tru-discovers-two-local-information-disclosure-vulnerabilities-in-apport-and-systemd-coredump-cve-2025-5054-and-cve-2025-4598), [Ubuntu advisory](https://ubuntu.com/blog/apport-local-information-disclosure-vulnerability-fixes-available)) |
| Suspend-to-disk (S4) / cold-boot RAM capture | `mlock` does NOT stop these (research/05). Ops requirement: **LUKS full-disk encryption** on this box and **disable hibernation** while the vault is unlocked (`systemctl mask hibernate.target suspend-to-hibernate`). |

Hardening directive references: [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) (`CapabilityBoundingSet`, `RestrictNamespaces`, `RestrictAddressFamilies`, `MemoryDenyWriteExecute`, `ProtectSystem`, `ProtectProc`, `SystemCallFilter`), [systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) (`IPAddressDeny`/`IPAddressAllow`), [systemd.io/COREDUMP](https://systemd.io/COREDUMP/).

---

## 5. Host-level prerequisites (one-time, requires sudo)

These cannot be expressed in a user unit; they are box-level config. **[UNVERIFIED]** against the exact Ubuntu 26.04 defaults on this machine — confirm before relying.

```bash
# 1. Disable the global coredump handler so no secret memory is ever piped to it.
#    (RLIMIT_CORE=0 in the unit is ignored when core_pattern pipes to a handler.)
sudo tee /etc/sysctl.d/90-env-ctl-coredump.conf >/dev/null <<'EOF'
kernel.core_pattern=|/bin/false
fs.suid_dumpable=0
EOF
sudo sysctl --system

# Alternatively / additionally, mask the systemd-coredump socket:
sudo systemctl mask systemd-coredump.socket

# 2. ptrace hardening (defends a live DEK against attach from another same-uid process).
#    PR_SET_DUMPABLE(0) blocks non-root PTRACE_ATTACH already; this is belt-and-suspenders.
sudo tee /etc/sysctl.d/91-env-ctl-ptrace.conf >/dev/null <<'EOF'
kernel.yama.ptrace_scope=2
EOF
sudo sysctl --system
#    [UNVERIFIED] Ubuntu 26.04 default for kernel.yama.ptrace_scope — research/05 OQ#1.

# 3. Full-disk encryption (LUKS) MUST be present, and hibernation disabled while unlocked:
sudo systemctl mask hibernate.target hybrid-sleep.target

# 4. Allow the operator user's services to linger (so the vault can run without an active login
#    shell — optional; omit if you only want it up during interactive sessions):
loginctl enable-linger drdave
```

Note on `ptrace_scope=2`: stricter than the Ubuntu default (`1`) — only root may trace. This is intentional for a secrets box but will break user-space debuggers; flip to `1` during dev if needed.

---

## 6. Key + config provisioning (one-time, no sudo)

```bash
# XDG layout (research/05 paths model)
mkdir -p ~/.config/env-ctl ~/.local/share/env-ctl ~/.local/state/env-ctl
chmod 700 ~/.config/env-ctl ~/.local/share/env-ctl ~/.local/state/env-ctl

# sqld JWT signing keypair (Ed25519). PRIVATE half -> secretd only; PUBLIC half -> sqld.
openssl genpkey -algorithm Ed25519 -out ~/.local/share/env-ctl/sqld_jwt_priv.pem
openssl pkey -in ~/.local/share/env-ctl/sqld_jwt_priv.pem \
  -pubout -out ~/.local/share/env-ctl/sqld_jwt_pub.pem
chmod 600 ~/.local/share/env-ctl/sqld_jwt_priv.pem
chmod 644 ~/.local/share/env-ctl/sqld_jwt_pub.pem
# [UNVERIFIED] sqld v0.24.32's exact JWT key-file format expectation (PEM vs raw vs JWK).
# research/03 confirms Ed25519 JWT auth via --auth-jwt-key-file; confirm the encoding
# against `sqld --help` / libsql-server docs before init.

# Vault init (creates vault.db ciphertext + argon2id keyslots + USB keyslot).
# This is an envctl/secretctl verb, NOT an ops step — shown for ordering only.
secretctl vault init --usb-partuuid AUTO_DETECT
```

`secrets.toml` (Profile A, the install-time gate that blocks VPS mode):

```toml
# ~/.config/env-ctl/secrets.toml
[store]
profile = "embedded"          # Profile A. "remote"/VPS is install-gated (see §8).

[store.embedded]
sqld_url = "http://127.0.0.1:8080"

[unlock]
usb_partuuid = "AUTO_DETECT"  # REQ-SEC-3 possession proof; FS-S22: a usb_keyfile keyslot
usb_keyfile  = true           # MUST be enabled or the USB gate backs nothing.

[relay]
enabled = false               # Phase-8 public HTTPS edge. Off for Profile-A pre-relay.
```

---

## 7. Deploy + operate

```bash
# Install binaries (build is an envctl concern; shown for completeness)
sudo install -m0755 target/release/sqld     /usr/local/bin/sqld
sudo install -m0755 target/release/secretd  /usr/local/bin/secretd
sudo install -m0755 target/release/secretctl /usr/local/bin/secretctl

# Install + enable the user units
install -d ~/.config/systemd/user
cp env-ctl.target sqld.service secretd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now env-ctl.target

# Verify
systemctl --user status env-ctl.target sqld.service secretd.service
journalctl --user -u secretd -n 50 --no-pager
journalctl --user -u sqld    -n 50 --no-pager

# Audit the actual hardening systemd applied (do this after every unit change):
systemd-analyze --user security secretd.service
systemd-analyze --user security sqld.service
# Aim: a low exposure score; investigate any directive systemd reports as "off".

# Smoke test the control plane (UDS, SO_PEERCRED):
secretctl vault status
ls -l /run/user/$(id -u)/env-ctl/control.sock   # expect srw------- (0600)

# Panic stops (work for local AND, in Phase 8, remote egress):
secretctl lock                 # zeroize DEK
secretctl relay revoke --all   # kill all bearers
```

Pull the USB → the in-process `UsbProbe` returns `AbsentSince(now)`; after the short grace window new egress is denied and (operator opt-in) the DEK is zeroized ([SERVER-MODE.md §5.2](../SERVER-MODE.md)). systemd is not involved in that path — it is the daemon's own gate.

---

## 8. Profile B (VPS) — present but install-gated, NOT shippable

Per [SERVER-MODE.md §5.3](../SERVER-MODE.md), VPS mode is **non-shippable until OI-SM-2 (operator-box authorizer protocol) and OI-SM-3 (trusted VPS time source) ship**. The ops gate:

```bash
# install-time guard (envctl install script). Refuse VPS profile without a substitute factor.
if grep -qE '^\s*profile\s*=\s*"remote"' ~/.config/env-ctl/secrets.toml; then
  if ! grep -q 'operator_authorizer_url' ~/.config/env-ctl/secrets.toml; then
    echo "FATAL: profile=remote (VPS) requires an operator-box authorizer (OI-SM-2 unshipped)." >&2
    exit 1
  fi
  echo "FATAL: Profile B is non-shippable until OI-SM-2/OI-SM-3 land. Refusing." >&2
  exit 1
fi
```

When it does ship, the unit deltas are: a hardened **remote** `sqld` node (JWT Ed25519 + TLS + pinned cert, never the open default — research/03); an `operator-box → secretd-VPS` authorizer link (mTLS, pinned, narrow schema, cannot invoke any vault-management verb — SERVER-MODE §7); and a **forbidden-factor check** (no vTPM gating; SEV-SNP only if attestation TCB ≥ 1.58, fail-closed — SERVER-MODE §5.3 / FS-S24). The DEK still lives in VPS RAM while unlocked, so Profile B is a documented, audited risk acceptance — Profile A is the default for exactly this reason.

---

## 9. Open questions

- **Q1 [UNVERIFIED] — Ubuntu 26.04 kernel/sysctl defaults.** Shipped kernel version, default `kernel.yama.ptrace_scope`, `kernel.perf_event_paranoid`, and whether `systemd-coredump` is the default `core_pattern` handler. These change how much §5 host config is actually needed. (research/05 OQ#1.)
- **Q2 [UNVERIFIED] — `LimitMEMLOCK` on 26.04.** Confirm the unit directive takes effect and the 64 KiB kernel default is what we're overriding. Validate with `cat /proc/$(pgrep -x secretd)/limits | grep locked` after start. (research/05 OQ#2.)
- **Q3 — `PrivateDevices` vs USB read.** `secretd` needs to read the USB block device for REQ-SEC-3 possession proof, so it cannot use `PrivateDevices=yes`. The right scoping (`DeviceAllow=` for the specific by-partuuid device, vs reading the keyfile from a mounted filesystem so no block-device access is needed at all) depends on how `UsbProbe` is implemented. Resolve against research/04 (USB-PARTUUID detect) before finalizing the unit.
- **Q4 [UNVERIFIED] — `SystemCallFilter` minimal sets** for tokio/hyper/rustls (`secretd`) and the sqld C+tokio runtime. Capture real syscalls (`systemd-analyze` doesn't enumerate; use `strace -ff -e trace=all` or an audit/seccomp-log pass) and tighten the allowlist. Watch for fork-related calls in any relay-path library (research/05 §"gRPC/relay threads must not fork").
- **Q5 — socket activation reconsidered.** This design drops `sqld.socket`/socket-activation in favor of plain ordering. If a future requirement wants scale-to-zero or fd-passing of the control UDS, revisit — but note it complicates the listener self-check (SERVER-MODE §3).
- **Q6 [UNVERIFIED] — sqld v0.24.32 flag/format specifics.** Exact `--http-listen-addr` / `--auth-jwt-key-file` flag names, the JWT key encoding (PEM vs JWK vs raw), and whether banner-suppression exists. Confirm with `sqld --help` on the pinned binary; the sqld release is **v0.24.32 (Feb 14, 2025)**, `libsql` crate **0.9.30** (research/03 version table; <https://github.com/tursodatabase/libsql/releases>).
- **Q7 — libSQL at-rest encryption status.** research/03 records it as still disabled/unusable as of 2026-06-02 and **[UNVERIFIED]** for newer point releases. We rely on app-AEAD only and never enable sqld's built-in at-rest crypto (would re-add a C cipher dependency — forbidden). Re-check on any sqld upgrade.
- **Q8 — merge into `envctl`.** When this merges into `~/Desktop/envctl` (the 5-verb TOML env manager), decide whether unit-file installation becomes a declarative `envctl` component (one of the 5 verbs emits/enables these units) or stays a separate ops step. Affects whether `daemon-reload`/`enable` is idempotent under the component model.
- **Q9 — relay edge as a separate process (Phase 8).** SERVER-MODE §7 *strongly prefers* running the public relay edge as a separate process from the control listener. That implies a future third unit (`secretd-relay.service`) with the public-NIC `IPAddress*` relaxation, while `secretd.service` stays loopback-only. Design the split before Phase 8 rather than relaxing this unit's `IPAddressDeny=any`.

---

## 10. Sources

Design docs (local, verified 2026-06-02): `THREAT-MODEL.md`, `SERVER-MODE.md`, `ARCHITECTURE.md`, `DESIGN-NOTES.md`, `ROADMAP.md`, `research/03-libsql-server.md`, `research/05-process-hardening.md`, `research/06-grpc-uds-peercred.md` under `/home/drdave/Desktop/env-ctl/docs/`.

External (URLs inline above; consolidated):
- systemd hardening: <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html>, <https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html>, <https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html>
- coredump policy: <https://systemd.io/COREDUMP/>
- memory/dump/ptrace primitives: <https://man7.org/linux/man-pages/man2/mlockall.2.html>, <https://man7.org/linux/man-pages/man2/getrlimit.2.html>, <https://man7.org/linux/man-pages/man2/pr_set_dumpable.2const.html>, <https://man7.org/linux/man-pages/man2/madvise.2.html>
- crates: <https://docs.rs/zeroize/1.8.2/zeroize/>, <https://docs.rs/secrecy/0.10.3/secrecy/>, <https://github.com/niluxv/secmem-proc>, <https://github.com/thatnewyorker/os-memlock>, <https://docs.rs/rustix/latest/rustix/mm/index.html>
- libSQL / sqld: <https://github.com/tursodatabase/libsql/releases>, <https://docs.rs/crate/libsql/latest/>, <https://docs.turso.tech/sdk/authentication>
- CVEs: <https://blog.qualys.com/vulnerabilities-threat-research/2025/05/29/qualys-tru-discovers-two-local-information-disclosure-vulnerabilities-in-apport-and-systemd-coredump-cve-2025-5054-and-cve-2025-4598>, <https://ubuntu.com/blog/apport-local-information-disclosure-vulnerability-fixes-available>
