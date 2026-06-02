# env-ctl ops — secretd store backend configuration (OI-1 (a), Phase 1)

**Reads with:** `DESIGN-NOTES.md` (OI-1), `07-ci-supplychain.md` (no-C gate), `ARCHITECTURE.md`
(FS-S4/FS-S7), `crates/secrets-store-libsql/README.md`.

**Scope:** how `secretd` selects and connects its persistence backend. `secretd` runs the engine on
one of two `Store` backends behind the identical `vault::Store` trait:

| Backend | What it is | When |
|---|---|---|
| `inmem` (default) | RAM-only vault; lost on restart | tests/CI, first-run, or before a DB is provisioned |
| `libsql` | the durable libSQL `remote` store, talking HTTP/Hrana to a **loopback** `sqld` | production durability (OI-1 (a)) |

The engine, proto, and CLI never link libSQL; only `secretd` does (and only `secretd` carries the
libSQL dependency stack). The no-C-**library** tenet still holds — `ci/gates/no-c.sh` proves it.

## 1. Configuration

Precedence (highest first): **environment variables > the TOML file > defaults** (`inmem`).

### 1.1 TOML file — `~/.config/env-ctl/secretd.toml` (optional)

```toml
[store]
backend = "libsql"            # "inmem" (default) | "libsql"
url     = "http://127.0.0.1:8080"   # the LOOPBACK sqld (see §2). https/remote is refused (see §3).
# NOTE: the auth token is a credential and is NEVER read from this file — see §1.3.
```

Override the file location with `SECRETD_CONFIG=/path/to/secretd.toml`. A missing file is fine
(defaults apply).

### 1.2 Environment variables (override the file)

| Var | Meaning |
|---|---|
| `SECRETD_STORE_BACKEND` | `inmem` \| `libsql` |
| `SECRETD_LIBSQL_URL` | the loopback sqld URL, e.g. `http://127.0.0.1:8080` |
| `SECRETD_LIBSQL_AUTH_TOKEN` | the libSQL/sqld auth token (JWT), if the server requires one |
| `SECRETD_LIBSQL_AUTH_TOKEN_FILE` | path to a **`0600`** file holding the token (preferred over the inline var) |
| `SECRETD_CONFIG` | override the TOML path |

### 1.3 Auth-token hygiene

The token is a credential, so it is **never** taken from the TOML file. Provide it via
`SECRETD_LIBSQL_AUTH_TOKEN` (e.g. a systemd `LoadCredential`/`Environment=`) or, preferably, via
`SECRETD_LIBSQL_AUTH_TOKEN_FILE` pointing at a **`0600`** file — a group/other-readable token file is
**refused** (fail-closed). The **config-layer** token copy is held in a zeroizing buffer and never
logged (the config's `Debug` redacts it); note the downstream libSQL client takes a plain `String`
(its public API) and keeps its own non-zeroized copy for the connection's lifetime. An empty token is
accepted only for a loopback sqld with open auth (dev).

## 2. Standing up a loopback sqld (Profile A — recommended)

`sqld` (a.k.a. `libsql-server`) is run **on loopback**, co-located with `secretd`:

```sh
sqld --http-listen-addr 127.0.0.1:8080 -d /var/lib/env-ctl/sqld
# production: configure auth with --auth-jwt-key-file and set SECRETD_LIBSQL_AUTH_TOKEN(_FILE)
```

Then:

```sh
SECRETD_STORE_BACKEND=libsql SECRETD_LIBSQL_URL=http://127.0.0.1:8080 secretd
```

`secretd` provisions the schema on first connect (idempotent), so no manual migration step is needed.

## 3. Transport: loopback-only, or a loopback TLS terminator for a remote DB

`secretd`'s libSQL client uses a **plaintext** HTTP connector. This is deliberate and gate-clean:
libSQL's `tls` feature would pull a **second** rustls (`hyper-rustls 0.25 → rustls 0.22`) alongside
the workspace's single ring-only `rustls 0.23`, breaking the no-C / single-rustls gate (DESIGN-NOTES
OI-1), and there is no hyper-0.14 `hyper-rustls` on rustls 0.23. Therefore:

- **Accepted:** `http`/`ws` to a **loopback** host (`127.0.0.0/8`, `::1`, `localhost`).
- **Refused (fail-closed):** plaintext to a non-loopback host (FS-S7 — the auth token + metadata +
  write-integrity would cross the network in the clear).
- **Refused with guidance:** `https`/`wss`/`libsql` URLs. For a **remote** DB (Turso, a remote sqld),
  run a **loopback TLS terminator** and point `secretd` at it:

  ```sh
  # e.g. stunnel / spiped / cloudflared, listening on 127.0.0.1:8080 and TLS-forwarding to the remote
  SECRETD_LIBSQL_URL=http://127.0.0.1:8080   # -> terminator -> https://<remote-sqld>
  ```

  This keeps the daemon's dependency graph gate-clean while still encrypting the off-box hop. (A
  future opt-in `remote-tls` build that accepts the second rustls is possible but is NOT enabled —
  it would fail the single-rustls gate by design.)

## 4. Durability & resilience

- **Durability** is the server's responsibility for the remote backend: `sqld` persists each write to
  its WAL (durable by default), and the store's `fsync_barrier` (a `SELECT 1` round-trip after each
  write) confirms the prior statement was applied by the server before success is reported (HF-14). A
  client-side `PRAGMA synchronous=FULL` is not issued (Hrana rejects `PRAGMA`).
- **Hrana stream-expiry:** a libSQL `remote` connection's Hrana stream baton is expired by `sqld`
  after a short idle window. The engine interleaves slow CPU work between store ops — notably argon2id
  during `init_vault` (seconds–tens of seconds) — so the store **reconnects once and retries** on a
  `STREAM_EXPIRED` (the retried statements are idempotent and an expiry means the prior attempt never
  committed). This makes `init_vault`/`unlock` on libSQL transparent to the operator.

## 5. Verification

The libSQL path has real-server coverage (both `#[ignore]`d — they need a running loopback sqld and a
fresh DB):

```sh
rm -rf /tmp/sqld-data && sqld --http-listen-addr 127.0.0.1:8080 -d /tmp/sqld-data &
# the Store impl against a real sqld (9 offline + 5 integration):
LIBSQL_TEST_URL=http://127.0.0.1:8080 LIBSQL_TEST_AUTH= \
  cargo test -p envctl-secrets-store-libsql --features remote -- --ignored --test-threads=1
# the engine-over-libSQL durability e2e (init/unlock/put/get + persistence across engine instances):
LIBSQL_TEST_URL=http://127.0.0.1:8080 LIBSQL_TEST_AUTH= \
  cargo test -p envctl-secretd --test libsql_e2e -- --ignored --nocapture
```

The default `cargo test --workspace` keeps these `#[ignore]`d (no sqld needed) and stays green;
`ci/gates/no-c.sh` confirms the libSQL stack adds no C **library** and keeps the single ring-only
rustls.
