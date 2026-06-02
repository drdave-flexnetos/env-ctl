# env-ctl ops — env-ctl run UX + .env-ctl profile format + injection table

**Status:** Ops/deployment design, grounded in the reconciled + adversarial-hardened design set
**Scope:** the operator-facing UX and concrete wiring for `env-ctl run` (Phase 6), the `.env-ctl`
profile file, and the per-provider injection + CA-trust tables. READ-ONLY design — no code here.
**Anchors:** ARCHITECTURE.md §9/§6/§8/§10/§11 · THREAT-MODEL.md (FS-S1/3/5/6/7/9/11/14/15,
REQ-SEC-1/3/5/6/7/8) · DESIGN-NOTES.md (OI-3, CF-7/8/9, HF-8/11) · ROADMAP.md Phase 6 ·
SERVER-MODE.md §7 · research/08–11.
**Date:** 2026-06-02. Provider/SDK facts carry inline source URLs; anything not re-verified
against a live source today is flagged **UNVERIFIED**.

> This doc is deliberately concrete: it pins command shapes, the TOML schema, the systemd unit,
> and the provider env deltas. It does NOT re-derive the threat model — it cites the forbidden
> states each design choice is defending.

---

## 0. Recommended design at a glance (THIS system)

`env-ctl run` is a **fork/exec wrapper**, not a sourced shell mutation (ARCHITECTURE.md §9). It:

1. resolves a `.env-ctl` profile fail-closed (or honors `--relay`/`--no-profile`);
2. asks `secretd` over the UDS control plane to mint a `<=24h` bearer **bound to the child pid**
   (HF-8) and to return a provider-shaped `ResolvedInjection`;
3. clones the parent env, overlays ONLY the injected keys, and `execvp`s the child;
4. the real upstream key NEVER enters the child env, argv, shell history, or git (FS-S1).

The recommended default deployment is **Profile A** (SERVER-MODE.md §7.2): `secretd` runs as a
**user** systemd service on this box, the embedded `sqld` is loopback-only, USB-PARTUUID unlock is
the default factor, and only the relay HTTPS edge is ever network-exposed. `env-ctl run` always
talks to the LOCAL control socket — it never crosses the network and never reaches a remote edge.

---

## 1. `env-ctl run` UX

### 1.1 Command shapes

```bash
# Default: discover a .env-ctl profile at/under cwd, mint ephemeral(s), exec the child.
env-ctl run -- claude -p "summarize"

# Explicit relay, no profile discovery noise.
env-ctl run --relay claude-main -- claude

# Multiple relays (provider-agnostic; one bearer minted per relay).
env-ctl run --relay gh-ci --relay anthropic-main -- ./ci.sh

# Disable discovery entirely.
env-ctl run --no-profile -- env        # child env shows NO injected keys

# Explicitly load a profile by path (still gated for NAMED relays — see 1.3).
env-ctl run --profile ./profiles/build.env-ctl --apply -- cargo run

# Inspect without executing: print the resolved ChildEnvPlan, mint nothing real.
env-ctl run --dry-run --relay claude-main -- claude     # default for attach review
```

After merge (ROADMAP.md Phase 7) the verb folds into the unified binary as `envctl run …`; the
flags and semantics are identical. The standalone `env-ctl`/`secretctl` form remains during the
parallel-repo phase.

### 1.2 Pre-exec discovery order (fail-closed; OI-3, FS-S15)

`env-ctl run` resolves the profile **before fork**, halting at the first match:

1. **At-or-below cwd:** `$PWD/.env-ctl`, then walk DOWN is N/A — only the cwd file is honored
   without trust config. A file strictly *below* cwd is never auto-discovered.
2. **Walk UP toward `/` only inside an operator-trusted root.** The allowlist lives in
   `~/.config/env-ctl/trusted-roots` (ARCHITECTURE.md §11 names this the
   "trusted-profile-roots allowlist"). A profile in an ancestor dir that is NOT under a trusted
   root is **refused**, not silently honored.
3. **`--profile <path>`** loads exactly that file (still gated for named relays).
4. **`--no-profile`** skips discovery completely.

> **Open question (OI-3, flagged in DESIGN-NOTES):** the exact UX of the trusted-root config
> (file format, per-root vs glob, how a root is enrolled) is "Spec in Phase 6" and is NOT yet
> locked. The recommendation below (a newline-delimited path allowlist) is a **proposal**, not a
> ratified format.

**Proposed `~/.config/env-ctl/trusted-roots`:**

```
# env-ctl trusted profile roots — one absolute path per line; '#' comments.
# A .env-ctl found at or under one of these dirs may auto-attach NAMED relays
# without a per-invocation prompt. Everything else still requires confirmation.
/home/drdave/work
/home/drdave/Desktop/envctl
```

### 1.3 The attach gate (the emit IS the gate — not an FYI)

Per ARCHITECTURE.md §9, attaching a **named** (long-lived-policy) relay from a discovered profile
requires explicit confirmation; **ephemeral** relays declared inline may mint automatically.
This is the operator-facing surface of FS-S15.

| Profile contents | Trusted root? | Behavior |
|---|---|---|
| ephemeral relays only | any | mint automatically, exec |
| named relays | yes (in trusted-roots) | attach, exec (no prompt) |
| named relays | no | **refuse without `--profile` or interactive `y`** (FS-S15) |
| named relays | `--apply` passed | attach without prompt (operator asserted intent) |

**Recommended stderr emit (the gate):**

```
DRY-RUN: profile discovery
  Location : /home/drdave/work/api/.env-ctl   (under trusted root /home/drdave/work)
  Relays to attach:
    - claude-main   policy_ttl=1y   bearer_ttl<=24h   mode=BaseUrlRepoint   host=api.anthropic.com
    - gh-ci         policy_ttl=90d  bearer_ttl<=24h   mode=NativeSubToken   host=api.github.com
  Child injects: ANTHROPIC_BASE_URL, ANTHROPIC_API_KEY(bearer)  |  GH_TOKEN(scoped 1h)
  Real upstream keys remain daemon-only (FS-S1 / REQ-SEC-6).

Approve named-relay attach? [y/N]  (pass --apply to skip this prompt)
```

> Security rationale: an untrusted-ancestor `.env-ctl` that names `prod-stripe` cannot silently
> attach a high-value relay just because you `cd`'d into a cloned repo. The pre-exec emit forces a
> human (or an explicit `--apply`) into the loop — this is precisely FS-S15 ("a walk-up `.env-ctl`
> profile from an untrusted ancestor auto-attaches a NAMED relay without explicit confirmation").

### 1.4 USB-absent behavior

If the enrolled USB is absent beyond the grace window (default ~5 min; ARCHITECTURE.md §7, FS-S5),
`run` **refuses a renewable long-lived token and offers only a `<=24h` ephemeral that then expires**
(ROADMAP.md Phase 6 acceptance). New egress for that ephemeral is itself denied at swap time if the
USB stays absent (REQ-SEC-5), so "pull the USB and access stops" holds without a full 24h tail.

### 1.5 Child injection mechanics (FS-S1)

Pre-exec, inside the wrapper:

- mint one bearer per resolved relay via the control plane; bearer TTL = `clamp_ttl(now,
  policy_ttl, requested)` capped at `MAX_BEARER_TTL_SECS = 86400` (single choke point, REQ-SEC-5);
- bearer is peer-bound to the child **pid** at mint (HF-8 / A10) so a sibling same-uid process
  cannot replay the plain-HTTP bearer;
- clone parent env, overlay ONLY `ResolvedInjection.env` (+ per-tool CA env for MITM mode), then
  `execvp` — no return;
- the real key is fetched ONLY inside `decide()==Allow` at swap time, never written to the child
  (CF-9 / REQ-SEC-6).

**Acceptance (ROADMAP.md Phase 6):** the child's `/proc/<pid>/environ` contains the bearer +
base-URL/proxy and NO real key (FS-S1); the parent shell env is unchanged after `run`.

---

## 2. `.env-ctl` profile file format

### 2.1 Schema (TOML; names-only; NEVER secrets)

```toml
# .env-ctl — per-directory relay profile.
# ROLE: declare which relays to attach when this dir is (at/under) cwd for `env-ctl run`.
# HARD RULE: relay NAMES and policy knobs ONLY. A plaintext key anywhere => the file is REJECTED.

[profile]
# Named relays to auto-attach. Must already exist (enabled) in the vault.
relays = ["claude-main", "gh-ci"]

[relay.claude-main]
enabled = true            # must resolve to an enabled named relay in the vault

[relay.gh-ci]
enabled = true

# Inline one-off relays minted just for this run's child (no vault row needed).
[[ephemeral]]
provider     = "anthropic"
name         = "temp-build"
host_allow   = ["api.anthropic.com"]
path_allow   = ["/v1/messages"]
method_allow = ["POST"]
ttl_secs     = 600        # clamped to min(requested, policy_ttl, 86400)

[[ephemeral]]
provider     = "github"
name         = "temp-ci"
host_allow   = ["api.github.com"]
path_allow   = ["/repos/owner/repo/"]
method_allow = ["GET", "POST"]
ttl_secs     = 3600
```

### 2.2 Validation rules (reject = fail-closed)

A profile is **rejected** (and `run` refuses) if any of:

- it sits above all trusted roots and is not the cwd file (§1.2);
- a `[profile].relays` entry names a relay absent/disabled in the vault;
- an `[[ephemeral]]` `provider` is not in the engine-owned provider set
  (`anthropic|openai|github|generic`);
- an `[[ephemeral]].host_allow` host is outside the provider's canonical upstream allowlist
  (`Anthropic => {api.anthropic.com}`, `Openai => {api.openai.com}`,
  `Github => {api.github.com}`) — ARCHITECTURE.md §6 / HF-11 / A8;
- ANY key/value that looks like a literal secret is present (e.g. `api_key = "sk-…"`). The parser
  rejects rather than ignores, so a profile can never become a secret-leak vector (FS-S1).

`ttl_secs` is always clamped through the single `clamp_ttl` choke point; a `<=0` or out-of-range
TTL is refused (REQ-SEC-5, FS-S3). Named-relay attach from this file still passes through the §1.3
gate.

---

## 3. Provider injection tables

Each provider maps to a `ResolvedInjection { provider, mode, env, ca_env_keys, proxy_url,
base_url }` produced by `inject.rs`'s `injection_template` table (ARCHITECTURE.md §3/§9). Mode
choices follow the three locked swap modes (ARCHITECTURE.md §6).

### 3.1 Anthropic — primary `BaseUrlRepoint`

Sources: research/08-anthropic-proxy.md.

| Field | Value | Notes / source |
|---|---|---|
| Upstream host | `api.anthropic.com` (pinned; out-of-set refused, HF-11) | <https://platform.claude.com/docs/en/api/messages> |
| Endpoint | `POST /v1/messages` | same |
| Client env | `ANTHROPIC_BASE_URL=http://127.0.0.1:<relay_port>` | precedence: arg → env → default `https://api.anthropic.com` (TS SDK source) <https://github.com/anthropics/anthropic-sdk-typescript/blob/main/src/client.ts> |
| Auth header | inject `x-api-key: <real key>` on swap (NOT `Authorization: Bearer`) | strip inbound bearer + any inbound `x-api-key`/`Authorization` first <https://platform.claude.com/docs/en/api/messages> |
| Version header | `anthropic-version: 2023-06-01` (inject if client omitted) | <https://platform.claude.com/docs/en/api/sdks/typescript> |
| Streaming | SSE, pass-through **unbuffered**; preserve `Content-Type: text/event-stream`; events delimited by **`\n\n`** (LF blank line), NOT `\r\n\r\n` | <https://platform.claude.com/docs/en/api/streaming> · <https://html.spec.whatwg.org/multipage/server-sent-events.html> |
| Rate-limit headers | pass through verbatim: `anthropic-ratelimit-*`, `retry-after` | do not rewrite unless env-ctl imposes stricter quota — **open**, research/08 §9 |
| Relay timeout | SDK default request timeout is **10 min**; size relay read timeouts above this | research/08 §"SDK error/timeout"; **UNVERIFIED** that the floor holds across all SDK patch levels |
| Fallback | `ProxyMitm` (feature `mitm-ca`) for tools that hardcode `api.anthropic.com` and ignore `ANTHROPIC_BASE_URL` | ARCHITECTURE.md §6 |

`ResolvedInjection` (BaseUrlRepoint): `env = { ANTHROPIC_BASE_URL=http://127.0.0.1:<port>,
ANTHROPIC_API_KEY=<bearer> }`, `ca_env_keys = []`, `base_url = Some(...)`. The bearer (not the real
`sk-ant-…`) goes in `ANTHROPIC_API_KEY`; the daemon swaps it for the real key at egress.

### 3.2 GitHub — primary `NativeSubToken`

Sources: research/09-github-subtokens.md.

| Field | Value | Notes / source |
|---|---|---|
| Upstream hosts | `api.github.com` (+ `uploads.github.com` for uploads) | ARCHITECTURE.md §6 pins `{api.github.com}` |
| Master credential | **GitHub App private key** (+ App ID + installation ID), sealed in the vault | research/09 §"crown jewel" |
| Mint | `POST /app/installations/{installation_id}/access_tokens`, authed by RS256 JWT (`iat` now−60s, `exp` ≤ now+10m, `iss`=App ID) | <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app> |
| Token TTL | **fixed 1h**; broker re-mints per swap (user-facing relay bearer can outlive it) | same docs URL |
| Scoping | `repository_ids` (≤500) + `permissions` (down-scope within installation grant) | same; keep installation grants narrow — down-scope is best-effort |
| Token formats | accept BOTH legacy opaque AND new stateless `ghs_`; detector `ghs_[A-Za-z0-9.\-_]{36,}` (2 dots ⇒ stateless, 0 ⇒ legacy); pass through, do not parse the body | <https://github.blog/changelog/2026-04-24-notice-about-upcoming-new-format-for-github-app-installation-tokens/> |
| Do NOT depend on | `X-GitHub-Stateless-S2S-Token: enabled` override header — transitional, slated for deprecation ("coming weeks") | <https://github.blog/changelog/2026-05-15-github-app-installation-tokens-per-request-override-header/> |
| Complexity limit | many-repos×many-permissions mint requests may be rejected (Feb 22 2024); fall back to fewer repos / fewer perms / all-repos, and LOG it | <https://github.blog/changelog/2024-02-22-new-limits-on-scoped-token-creation-for-github-apps/> |
| Revocation | `DELETE /installation/token` on `relay_revoke` for early kill | <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation> |
| Auth header | `Authorization: Bearer <token>` (standard Bearer, unlike Anthropic) | research/09 |
| Client env | `GH_TOKEN=<scoped 1h token>` (gh/GitHub CLI standard) | research/09 §recommendations |
| Fine-grained PATs | **NOT mintable via API** (governance endpoints only: list/approve/deny/revoke) — do not plan to mint these | <https://docs.github.com/en/rest/orgs/personal-access-tokens> |
| Suggested crates | `octocrab` **0.49.7** (pin; 0.49.9 is not a released tag), `jsonwebtoken` **10.4.0** + `rsa` | <https://github.com/XAMPPRocky/octocrab/releases> · <https://docs.rs/jsonwebtoken/latest/jsonwebtoken/> |

`ResolvedInjection` (NativeSubToken): `env = { GH_TOKEN=<scoped 1h installation token> }`,
`ca_env_keys = []`. ProxyMitm fallback uses `HTTPS_PROXY` + CA env (see §4) for tools that ignore
`GH_TOKEN`.

### 3.3 OpenAI — primary `BaseUrlRepoint`, optional `NativeSubToken` (service accounts)

Sources: research/10-openai-subtokens.md.

| Field | Value | Notes / source |
|---|---|---|
| Upstream host | `api.openai.com` (pinned) | ARCHITECTURE.md §6 |
| Client env | `OPENAI_BASE_URL=http://127.0.0.1:<relay_port>` | precedence arg → env → default <https://developers.openai.com/docs/api-reference/authentication> · <https://openai.github.io/openai-agents-python/config/> |
| Auth header | `Authorization: Bearer <token>` (keys, service-account keys, WIF, ephemeral all use Bearer) | <https://developers.openai.com/docs/api-reference/authentication> |
| Org/project headers | optional `OpenAI-Organization`, `OpenAI-Project` | research/10 |
| Streaming | SSE pass-through unbuffered; preserve `text/event-stream` | <https://developers.openai.com/api/docs/guides/streaming-responses> |
| NativeSubToken path | service accounts: `POST /v1/organization/projects/{project_id}/service_accounts` (Admin key, daemon-only) | <https://developers.openai.com/api/reference/resources/organization/subresources/projects/subresources/service_accounts/methods/create> |
| Do NOT plan | project API key **CREATE** via API — dashboard-only; no admin create endpoint | <https://developers.openai.com/api/docs/guides/admin-apis> |
| Realtime ephemeral | `ek_*` via `POST /v1/realtime/client_secrets` — **TTL ambiguous** (docs ~configurable vs community ~2h) | <https://platform.openai.com/docs/api-reference/realtime-sessions/create-realtime-client-secret>; **UNVERIFIED TTL — do not rely on the documented value; verify empirically** (research/10 open Q1) |
| Fallback | `ProxyMitm` for hardcoded-host tools | ARCHITECTURE.md §6 |

`ResolvedInjection` (BaseUrlRepoint): `env = { OPENAI_BASE_URL=http://127.0.0.1:<port>,
OPENAI_API_KEY=<bearer> }`, `ca_env_keys = []`.

### 3.4 Generic / fallback — `ProxyMitm` only

A provider with no canonical upstream cannot use `BaseUrlRepoint` (there is nothing to pin), so it
is **default-deny for repoint** and only `ProxyMitm` is offered (ARCHITECTURE.md §6, HF-11).

`ResolvedInjection`: `mode = ProxyMitm`, `env = { HTTPS_PROXY=http://127.0.0.1:<port>,
HTTP_PROXY=…, NO_PROXY=127.0.0.1,localhost }` plus the per-tool CA env of §4; the client's original
auth header is passed through only if the relay policy permits. A MITM leaf is minted ONLY inside
the relay-gated resolver for an SNI covered by a currently-valid USB-gated relay
(`not_after <= min(now+24h, relay validity)`); no covering relay ⇒ handshake fails closed
(ARCHITECTURE.md §8, FS-S6, REQ-SEC-7).

---

## 4. Per-tool CA-trust wiring (ProxyMitm only)

Sources: research/11-ca-trust-wiring.md. Trust is wired **per-tool, child-only**, via `env-ctl
run` — never globally by default (ARCHITECTURE.md §8/§10).

### 4.1 Env-var injection (primary; child process only)

| Tool | Env var injected | Caveat / source |
|---|---|---|
| Node.js | `NODE_EXTRA_CA_CERTS` | additive; **ignored** under setuid/caps; complementary to `NODE_USE_SYSTEM_CA`. <https://nodejs.org/learn/http/enterprise-network-configuration> · <https://github.com/nodejs/node/commit/913c4910c7> (the v22.15 floor for `NODE_USE_SYSTEM_CA` is **UNVERIFIED**, research/11 §53) |
| Python `requests` | `REQUESTS_CA_BUNDLE` | precedence winner over `CURL_CA_BUNDLE` → certifi; a `Session` must call `merge_environment_settings()` or it is ignored. <https://requests.readthedocs.io/en/latest/user/advanced/> |
| curl | `CURL_CA_BUNDLE` ONLY | precedence vs `SSL_CERT_FILE`/`SSL_CERT_DIR` is **undocumented/conflicting** — set only `CURL_CA_BUNDLE`. <https://curl.se/docs/sslcerts.html> |
| git | `GIT_SSL_CAINFO` | env wins over `git config http.sslCAInfo`. <https://www.scivision.dev/git-ssl-certificate/> |
| OpenSSL apps | `SSL_CERT_FILE` (single file) | prefer single-file form; `SSL_CERT_DIR` needs `c_rehash`. <https://docs.openssl.org/master/man7/openssl-env/> |
| Rust `reqwest` | code, not env (`ClientBuilder` explicit roots) | env-ctl's own upstream client uses frozen webpki-roots (FS-S7), not these vars. <https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html> |

**Recommended default per known tool** (generic tools get the union so an unknown client still
finds the CA):

```
node    -> NODE_EXTRA_CA_CERTS=<ca.pem>
python  -> REQUESTS_CA_BUNDLE=<ca.pem>            # caller must merge_environment_settings()
curl    -> CURL_CA_BUNDLE=<ca.pem>
git     -> GIT_SSL_CAINFO=<ca.pem>
generic -> REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE
```

`<ca.pem>` is the public CA cert at `~/.local/share/env-ctl/ca/ca.pem` (0644, public cert only —
ARCHITECTURE.md §11). The CA private key stays sealed under the DEK and never touches disk in clear
(ARCHITECTURE.md §8).

### 4.2 System bundle (last resort; default OFF; `--apply --confirm`)

Only for tools that refuse env vars. Gated as a RootOfTrust op (REQ-SEC-8, FS-S11, CF-7). The
monolithic bundle is NEVER hand-edited:

```bash
# APPLY (--apply --confirm): backup, write an OWNED discrete file, regenerate.
cp /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt.bak-$(date +%s)
install -m 0644 ~/.local/share/env-ctl/ca/ca.pem \
  /usr/local/share/ca-certificates/env-ctl-local-mitm-ca.crt
update-ca-certificates

# REVERT: delete only the owned file, regenerate (fingerprint-verified).
rm /usr/local/share/ca-certificates/env-ctl-local-mitm-ca.crt
update-ca-certificates --fresh
```

Sources: <https://ubuntu.com/server/docs/how-to/security/install-a-root-ca-certificate-in-the-trust-store/>.
Never edit `/etc/ca-certificates.conf` directly (research/11 §30-31, CF-7).

**Confinement reality:** Snap (strict) does NOT see the system bundle (sandbox); Flatpak DOES via
the p11-kit bridge. <https://forum.snapcraft.io/t/using-the-system-certificate-authorities/10732/> ·
<https://datalabtechtv.com/posts/yotld-part-3-flatpak-trusted-certs/>. Prefer env-var injection;
the system bundle is a fallback only.

---

## 5. Daemon deployment (Profile A — recommended, this box)

`env-ctl run` is useless without `secretd` reachable on the local UDS. Recommended standup
(SERVER-MODE.md §7.2 Profile A; ARCHITECTURE.md §11):

1. `envctl install secretd` — installs the manifest `SystemdUnit` as a **user** service under
   `$XDG_RUNTIME_DIR/env-ctl/`. Insert + enroll the USB keyslot. The daemon **refuses to start
   on-box with no USB keyslot** (FS-S22).
2. Store: `store.profile = "embedded"`; an embedded `sqld` bound to **loopback only**; `secretd`
   talks to it via the pure-Rust `remote` libSQL client (`default-features=false,
   features=["remote"]` — keeps the C SQLite core in a separate process, NEW-3 / A18).
3. The relay HTTPS edge is the ONLY non-loopback listener; the control plane is UDS-only and
   proven network-unreachable by construction (REQ-SEC-11, FS-S17).

**Proposed user unit** `~/.config/systemd/user/secretd.service` (UNVERIFIED exact directives —
treat as a starting template; reconcile against the manifest `SystemdUnit` emitted by `envctl
install secretd`):

```ini
[Unit]
Description=env-ctl secrets daemon (secretd)
After=default.target

[Service]
Type=notify
ExecStart=%h/.local/bin/secretd --store-profile embedded
# Control socket lives under the per-user runtime dir; 0700 dir / 0600 sock.
RuntimeDirectory=env-ctl
RuntimeDirectoryMode=0700
# TCB hardening (THREAT-MODEL §1: daemon refuses to start if mlockall fails).
LimitMEMLOCK=infinity
LimitCORE=0
NoNewPrivileges=true
MemoryDenyWriteExecute=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/env-ctl %h/.local/state/env-ctl
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=default.target
```

> Rationale ties: `LimitMEMLOCK=infinity` + `LimitCORE=0` back the `mlockall` + `RLIMIT_CORE=0`
> requirement (FS-S4); the daemon itself still re-asserts and refuses to start if `mlockall` fails.
> `RuntimeDirectoryMode=0700` matches the 0700 control-socket dir (A1). The unit binds NO TCP
> control listener — control is UDS + `SO_PEERCRED` only (FS-S8/FS-S17).

**Containment / panic stops:** `secretctl lock` (zeroize the DEK) and `secretctl relay revoke --all`
(durable, count-reporting) are the true stops; pulling the USB auto-relocks after the drain grace
(default-ON; ARCHITECTURE.md §7).

---

## 6. Security rationale → threat-model map

| Design choice (this doc) | Defends |
|---|---|
| fork/exec wrapper, real key never in child env | FS-S1, REQ-SEC-6 |
| bearer peer-bound to child pid | HF-8 / A10 (same-uid plain-HTTP replay) |
| `clamp_ttl` single choke, ≤24h ceiling | FS-S3, REQ-SEC-5 |
| fail-closed walk-up discovery + named-relay attach gate | FS-S15, OI-3 |
| profile is names-only; literal-secret ⇒ reject | FS-S1, FS-S2 |
| host_allow validated vs canonical provider set | HF-11 / A8 (repoint exfil) |
| ProxyMitm leaf only via relay-gated resolver, USB-gated, ≤24h | FS-S6, REQ-SEC-7 |
| per-tool child-only CA env; system bundle owned-file + backup | FS-S11, REQ-SEC-8, CF-7 |
| upstream client trusts frozen webpki-roots only | FS-S7 / A6 (never the MITM CA or OS store) |
| USB re-checked at swap, run offers only ephemeral when absent | FS-S5 |
| daemon `mlockall`+`RLIMIT_CORE=0` or refuse start | FS-S4 |
| control UDS-only + `SO_PEERCRED`, no TCP control bind | FS-S8, FS-S17, REQ-SEC-11 |

---

## 7. Open questions (carry into Phase 6 implementation)

1. **Trusted-root config UX (OI-3, NOT locked).** Format/location of
   `~/.config/env-ctl/trusted-roots`, per-root vs glob semantics, and how a root is enrolled
   (CLI verb? interactive on first walk-up?) are unspecified. §1.2's allowlist file is a proposal.
2. **Anthropic rate-limit header policy (research/08 §9).** Pass through verbatim vs rewrite when
   env-ctl imposes a stricter quota than the upstream — undecided.
3. **OpenAI realtime `ek_*` TTL (research/10 Q1).** Documented vs observed TTL diverge; **UNVERIFIED**
   — must be measured empirically before any realtime relay relies on it.
4. **GitHub stateless `ghs_` revocation post-Phase-2 (research/09 OPEN).** Whether `DELETE
   /installation/token` reliably kills a self-validating stateless token before `exp` is unconfirmed.
5. **GitHub mint endpoint rate limit (research/09 OPEN).** `POST …/access_tokens` limit is not
   documented; assume ~5,000/hr as a conservative bound until measured.
6. **`X-GitHub-Stateless-S2S-Token` deprecation date (research/09 OPEN).** "coming weeks", no firm
   date — do not build on the override header.
7. **`NODE_USE_SYSTEM_CA` version floor (research/11, UNVERIFIED).** Claimed v22.15.0+; not
   re-verified — `NODE_EXTRA_CA_CERTS` is the safe primary regardless.
8. **systemd unit directives (§5, UNVERIFIED).** The unit template must be reconciled against the
   actual manifest `SystemdUnit` that `envctl install secretd` emits at merge (Phase 7); directive
   names/values above are a starting point, not a ratified unit.
9. **SDK request-timeout floor (research/08).** Anthropic 10-min default used to size relay
   timeouts is **UNVERIFIED** across all SDK patch levels.

---

*All provider/SDK/CA facts carry inline source URLs as of 2026-06-02; design assertions cite the
env-ctl design set (ARCHITECTURE / THREAT-MODEL / DESIGN-NOTES / ROADMAP / SERVER-MODE / research).
Items not re-verified against a live source are flagged UNVERIFIED.*
