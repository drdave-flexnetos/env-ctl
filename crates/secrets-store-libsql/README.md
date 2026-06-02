# envctl-secrets-store-libsql

A libSQL-backed implementation of the engine's `envctl_secrets::vault::Store` trait, over the
**remote (HTTP/Hrana) client only**. The sync `Store` trait is bridged to the async libSQL client
by a private current-thread tokio runtime (`block_on`). Ciphertext in, ciphertext out — the store
only ever moves opaque blobs + non-secret metadata.

## STATUS: ADOPTED — a `[workspace.members]` entry (OI-1 RESOLVED (a))

This crate **compiles, its 9 offline unit tests pass under the unified workspace (106 total green),
and its `Store` impl is complete.** As of **OI-1 RESOLVED (a)** it is a **member of the root
`env-ctl` workspace**: the standalone `[workspace]` table was removed and its deps are
workspace-pinned. The engine default store stays `inmem-store`; **secretd runtime selection of this
backend is the Phase-1 follow-on.** The C-purity reasoning that justified adoption is below.

## C-purity gate (audit F1)

The DESIGN specifies this gate:

```sh
cargo tree -p envctl-secrets-store-libsql --no-default-features --features remote \
  | grep -E 'libsql-ffi|libsql-sys|sqlite3-sys'   # MUST find NOTHING
```

### Result: no C *library* is linked; a build-time `cc` is required — ACCEPTED under decision (a)

**Candidate A — `libsql = { version = "0.9.30", default-features = false, features = ["remote"] }`**
(what this crate is built against):

- ✅ **Literal gate PASSES.** `grep -E 'libsql-ffi|libsql-sys|sqlite3-sys'` finds **nothing**. The
  C-SQLite `core` path (`core → libsql-sys → libsql-ffi`, the ~8.9 MB bundled SQLite) is genuinely
  **NOT** pulled by `remote`. Verified against the libsql 0.9.30 feature table: `remote → hrana`,
  `core → libsql-sys`, and `remote` does **not** enable `core`.

- ⚠️ **A build-time `cc` IS required (a C toolchain, NOT a linked C library) — ACCEPTED under decision (a).** The `remote` feature
  unconditionally pulls `hrana → parser → libsql-sqlite3-parser v0.13.0`, whose `build.rs`
  **compiles `third_party/lemon/lemon.c` with `cc`** (to build the `rlemon` parser-generator, then
  runs it to codegen the SQL grammar). Reproduced exactly from this crate:

  ```
  cc v1.2.63
  [build-dependencies]
  └── libsql-sqlite3-parser v0.13.0
      └── libsql v0.9.30
          └── libsql feature "hrana"
              └── libsql feature "remote"
                  └── envctl-secrets-store-libsql (feature "remote")
  ```

  ```rust
  // libsql-sqlite3-parser-0.13.0/build.rs (excerpt)
  use cc::Build;
  // compile rlemon (a C program) from third_party/lemon/lemon.c, then run it on parse.y
  Build::new().get_compiler().to_command().arg("-o").arg(rlemon).arg(rlemon_src) /* lemon.c */
  ```

  So `remote` is **not C-free at the build-toolchain level**: it needs `cc` + a working C compiler
  to run `lemon.c` (which then EMITS Rust — nothing C is linked into the binary). Under decision (a)
  this build-time `cc` is **ACCEPTED**: it is already mandatory for the engine itself (`cargo tree -i
  cc` shows both **ring** and **blake3** pull `cc`), so it adds no new *class* of dependency. The
  upheld tenet is "no C *library* linked into the trust boundary," which holds — the literal gate's
  three crate names are necessary but not sufficient, so `ci/gates/no-c.sh` Gate 4 additionally
  proves zero `aws-lc-*`/`openssl-sys` and exactly one ring-only `rustls`.

**Candidate B — `libsql-client = "0.1"` + `libsql-hrana = "0.1"`** (the DESIGN's "unambiguously
pure-Rust" fallback):

- ✅ C-free by design — no `libsql-ffi`/`libsql-sys`/`sqlite3-sys`, no `cc`/`bindgen`/`cmake`.
- ❌ **Does not compile in 2026.** `libsql-client 0.1.7` has an empty feature table and
  unconditionally depends on `worker 0.0.12` (Cloudflare Workers SDK) → `worker-macros 0.0.6`,
  which fails to build against the resolved `syn 1.0.109` (`unresolved import syn::ItemFn` /
  `ImplItemMethod` — items gated behind a feature that no longer exists). There is no feature to
  trim the `worker` dependency. Its 0.1.x Hrana API also predates the DESIGN's API shape entirely.
  **Dead end.**

**Candidate C (investigated) — `libsql-hrana 0.9.30` alone:** genuinely C-free (just `prost`,
`base64`, `bytes`, `serde` — no `cc`), but it is **only the Hrana wire-protocol message types**. It
provides no HTTP transport, no `Database`/`Connection`/`Rows` API, no statement pipeline. Building a
full Hrana-over-HTTP client on it is a large from-scratch effort well outside "implement the Store
trait over the libSQL remote client," and is not the DESIGN's specified API. Recorded as a future
option if a C-toolchain-free remote client becomes a hard requirement.

## Decision — OI-1 RESOLVED (a): ADOPTED

The only **buildable** remote client (Candidate A) requires a **C build-toolchain** (via
`libsql-sqlite3-parser`'s `lemon.c`). The operator ruled **(a): accept it.** The deciding fact,
verified empirically: the engine **already** requires `cc` at build time — `cargo tree -i cc` shows
both **ring** (which compiles C/asm for its crypto primitives) and **blake3** (SIMD) pull it. So `cc`
is not a new class of dependency, and the precise, upheld tenet is **"no C *library* linked into the
trust boundary"** (no SQLite/OpenSSL/aws-lc). Under that tenet libSQL `remote` is clean:

- Root `Cargo.toml` `[workspace.members]` **includes** `crates/secrets-store-libsql`; `libsql` is
  pinned in `[workspace.dependencies]` (`default-features=false, features=["remote"]`).
- The engine/proto/cli stay pure-Rust / C-free; this crate is consumed ONLY by secretd, behind the
  `Store` trait. Engine default store stays `inmem-store`.
- `ci/gates/no-c.sh` Gate 3a (auto-armed) PROVES no `libsql-ffi`/`libsql-sys`/`sqlite3-sys` is
  linked; Gate 4 PROVES exactly one ring-only `rustls` and zero `aws-lc-*`/`openssl-sys`.
- The whole workspace builds + tests green (106 passed; the 5 sqld integration tests `#[ignore]`d).

### Residuals (honest)

- `lemon.c` is build-time codegen (emits Rust); nothing C is linked into any address space.
- libSQL `remote` drags in a duplicate-major legacy stack confined to its subtree: `hyper 0.14`
  (vs the workspace's `1.x`), `http 0.2`, `http-body 0.4`, `h2 0.3`, `base64 0.21`, `itertools 0.12`,
  and a **2nd `prost` major** (`0.12` via `libsql-hrana`, vs the workspace's `0.13`). All pure-Rust,
  linked into no shipping binary — dependency duplication (bloat), not a C/gate violation. Revisit on
  a libSQL bump.
- The production sqld transport must be loopback or TLS (the integration tests use plaintext
  `http://127.0.0.1` for TEST ONLY). secretd runtime wiring + transport hardening is Phase 1.

### Target (the standing goal)

Strict C-toolchain-free remains the target: blake3 `pure` + a maintained pure-Rust Hrana client
(Candidate C is wire-types-only today). Revisit if such a client lands — the `core`/`libsql-ffi`
C-SQLite path stays forbidden regardless.

## Design notes

- **Sync `Store` over async libSQL:** one `Arc<tokio::runtime::Runtime>` (current-thread) per store
  instance, `block_on` per method (`sync::SyncConnection`). The runtime is private to this crate.
- **No dynamic SQL:** every statement is a pre-defined parameterized constant in `schema.rs`; all
  row/user values are bound to `?` placeholders (`serial.rs`).
- **Ciphertext in, opaque out:** the store never decrypts or inspects blobs.
- **Durable audit (HF-14):** `append_audit` links the row with the engine's shared chain math
  (`vault::audit::link_row`), inserts it, then calls `fsync_barrier()` (a `SELECT 1` round-trip
  against a `synchronous=FULL` connection) before returning the `seq`. `verify_audit_chain` reuses
  `vault::audit::verify_chain` so this backend can never disagree with `InMemStore`.
- **Row-id authority:** `reserve_secret_row_id` is an atomic `UPDATE … +1; SELECT` under one
  transaction; `put_secret` validates reservation + collision + version-monotonicity under one
  transaction (mirrors the `InMemStore` contract).
- **Health probe:** `health()` reports `{ durable, schema_version, profile }`.

## Tests

- **Offline unit tests** (`src/tests.rs`, run by `cargo test`): parameter-binding shape, error
  `Display`, anyhow conversion, wiring flags. **No sqld required.**
- **Integration tests** (`tests/integration_remote.rs`): `#[ignore]`d; require a running sqld. Run:

  ```sh
  sqld --http-listen-addr 127.0.0.1:8080          # open auth: TEST ONLY, never production
  LIBSQL_TEST_URL=http://127.0.0.1:8080 LIBSQL_TEST_AUTH= \
    cargo test -p envctl-secrets-store-libsql --features remote -- --ignored --nocapture
  ```
