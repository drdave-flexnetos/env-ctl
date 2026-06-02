# envctl-secrets-store-libsql

A libSQL-backed implementation of the engine's `envctl_secrets::vault::Store` trait, over the
**remote (HTTP/Hrana) client only**. The sync `Store` trait is bridged to the async libSQL client
by a private current-thread tokio runtime (`block_on`). Ciphertext in, ciphertext out — the store
only ever moves opaque blobs + non-secret metadata.

## STATUS: CONDITIONAL — held OUT of `[workspace.members]` (audit F1 blocker)

This crate **compiles, its 9 offline unit tests pass, and its `Store` impl is complete**, but it is
**deliberately NOT a member of the root `env-ctl` workspace**. It carries its own empty
`[workspace]` table so it can be built/inspected standalone (`cargo build`, `cargo tree` from this
directory) without being absorbed by the root workspace. Phase 0 stays on `inmem-store`.

The reason is the **C-purity gate (audit F1)**, evaluated honestly below.

## C-purity gate (audit F1)

The DESIGN specifies this gate:

```sh
cargo tree -p envctl-secrets-store-libsql --no-default-features --features remote \
  | grep -E 'libsql-ffi|libsql-sys|sqlite3-sys'   # MUST find NOTHING
```

### Result: the LITERAL gate PASSES, but the SPIRIT FAILS

**Candidate A — `libsql = { version = "0.9.30", default-features = false, features = ["remote"] }`**
(what this crate is built against):

- ✅ **Literal gate PASSES.** `grep -E 'libsql-ffi|libsql-sys|sqlite3-sys'` finds **nothing**. The
  C-SQLite `core` path (`core → libsql-sys → libsql-ffi`, the ~8.9 MB bundled SQLite) is genuinely
  **NOT** pulled by `remote`. Verified against the libsql 0.9.30 feature table: `remote → hrana`,
  `core → libsql-sys`, and `remote` does **not** enable `core`.

- ❌ **Spirit of F1 FAILS — a C toolchain is still required at BUILD time.** The `remote` feature
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
  and ships/compiles a C source file (`lemon.c`). That violates the intent of audit F1 ("no C in
  the remote client"). The three *crate names* in the literal gate simply do not happen to include
  `libsql-sqlite3-parser`, so the grep passes by accident, not by purity.

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

## Decision (scoped waiver)

Because the only **buildable** remote client (Candidate A) still requires a **C build-toolchain**
(via `libsql-sqlite3-parser`'s `lemon.c`), it fails the spirit of audit F1. Per the task's
fall-through rule ("If NO pure-Rust remote path exists, do NOT add the crate to
`[workspace.members]`; document the blocker + the scoped-waiver decision; keep the workspace
green"), this crate is **kept out of the root workspace**:

- Root `Cargo.toml` `[workspace.members]` is **unchanged** (still
  `secrets-engine`, `secrets-proto`, `secretd`, `secretctl`).
- The engine stays pure-Rust / C-free / async-free; the per-crate engine gate
  (`! cargo tree -p envctl-secrets-engine | grep libsql-ffi`) stays green.
- The workspace continues to build and test on `inmem-store` with no regressions.
- **OI-1 is reopened** for the store/serving backend: the libSQL remote client is not C-free at the
  build toolchain.

### To adopt this crate later

If a C-toolchain-free remote path lands — e.g. a future libsql release whose `remote`/`hrana`
feature no longer pulls `libsql-sqlite3-parser`, or a maintained pure-Rust Hrana client crate, or an
explicitly risk-accepted decision to require a C compiler on the build host — then:

1. Delete the `[workspace]` table at the top of this crate's `Cargo.toml`.
2. Add `"crates/secrets-store-libsql"` to the root `[workspace.members]`.
3. Re-run both gates: the literal grep AND the `cc`/`libsql-sqlite3-parser` check.

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
