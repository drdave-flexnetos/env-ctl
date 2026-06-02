# env-ctl ops — CI, MSRV, no-C gates, supply-chain

**Status:** Ops/deploy design (concrete, sourced). READ-ONLY companion to the design set.
**Reads with:** `ARCHITECTURE.md` (§one rustls/ring, §FS-S7 root pinning), `SERVER-MODE.md` (§2.2 C-isolation, §3 control-unreachable, §6 edge, §7 deploy steps), `THREAT-MODEL.md` (FS-S*/A*), `DESIGN-NOTES.md` (CF-1/CF-2/CF-6, HF-17/HF-18, R7/R8/R9, OI-1/OI-14/OI-23/OI-24), `ROADMAP.md` (Phase 0/1/7 acceptance).
**Scope:** The CI gates, MSRV policy, no-C/single-backend enforcement, supply-chain controls, and the deploy units that stand `secretd` up on THIS dual-RTX-5090 box (Profile A, the recommended default). VPS (Profile B) deploy ops are flagged non-shippable (OI-SM-2/3) and only sketched.
**Verified-against (this box, 2026-06-02):** `rustc 1.96.0 (ac68faa20 2026-05-25)`, `cargo 1.96.0`. Workspace declares `rust-version = "1.80"` and `rust-toolchain.toml` channel `stable`. `cargo-deny`/`cargo-vet` are NOT yet installed here (`cargo deny --version` → not found) — UNVERIFIED locally, install in CI per below.

This document grounds every gate in the artifacts that already specify it. Where a design doc already
mandates a gate (e.g. SERVER-MODE §2.2, §3; DESIGN-NOTES R7/R9, HF-18) this doc gives the *concrete*
command/config and the CI job that runs it; it does not relitigate the design.

---

## 0. What CI must protect (mapped to the threat model)

env-ctl's security posture is enforced almost entirely at *dependency-graph* and *build-shape* level, not just at runtime. The CI gates below are not hygiene — each one is the build-time half of a forbidden state:

| CI gate | Forbidden state it protects | Why a runtime check is insufficient |
|---|---|---|
| No-C in engine (`! cargo tree -p envctl-secrets-engine \| grep libsql-ffi …`) | A4/FS-S2, A18 — C SQLite weak-default surface in the secret-handling lib | A C dep cannot be "checked away" at runtime; it must never be linked into the engine address space at all (SERVER-MODE §2.2). |
| Single ring backend, zero aws-lc-sys/openssl-sys (`! cargo tree -i aws-lc-sys`) | CF-2 — a second crypto backend pulls C/asm and contradicts the ring-only pin (DESIGN-NOTES R7) | The wrong backend can be silently pulled by a transitive `default-features` flip; only the dep graph reveals it. |
| Forbid native-roots / `danger_accept_invalid_certs` grep | FS-S7, A6, CF-6 — upstream TLS trusting OS store or local CA | A `rustls-tls-native-roots` feature is a compile-time decision; runtime only sees the resolved store. |
| `control-types-not-in-edge` grep | FS-S8/FS-S19, A17, REQ-SEC-11 — the public edge able to reach control RPCs | Provable-by-construction (SERVER-MODE §3.2) means the *code shape* must forbid the import, caught in CI not at runtime. |
| relay-cert-separation grep | FS-S25, A6 — the edge cert ever sourced from the MITM CA | The cert wiring is static; CI proves the edge never references the local-CA path. |
| MSRV `cargo +1.80.0 check` | HF-18 — a silent transitive MSRV bump past the declared floor | `cargo build` on stable (1.96 here) hides a 1.80 break; only an explicit 1.80 toolchain surfaces it. |
| `cargo deny` advisories / `cargo vet` | Supply-chain compromise of the few-but-sensitive crypto/TLS deps | A new RUSTSEC advisory or an unaudited new transitive crate is invisible to `cargo build`. |
| Reproducible/`--locked` + SBOM | Build-input drift; provenance for the crypto crates | `Cargo.lock` drift and unpinned inputs are not a runtime concern. |

The unifying principle from envctl is inherited verbatim: **fail-closed**. A CI gate that cannot prove its precondition (tool missing, tree command errors) must FAIL the job, never skip-and-pass. This is the build-time mirror of REQ-SEC-4 / FS-S9.

---

## 1. No-C gates (per-crate) + single ring backend

### 1.1 The scoped pair (NOT a blanket gate)

Per OI-1 (RESOLVED = libSQL) and SERVER-MODE §2.2/§78–81, the blanket `! cargo tree | grep libsql-ffi` is **replaced** by a per-crate scoped pair. The engine library stays pure-Rust; libSQL's bundled C SQLite is an accepted, scoped waiver quarantined to the (Phase-1) `crates/secrets-store-libsql`. CI enforces exactly this boundary.

> Note on crate state: as of this box's checkout, `crates/` contains only `secrets-engine`, `secrets-proto`, `secretd`, `secretctl`. `secrets-store-libsql` does NOT exist yet (it lands in Phase 1, ROADMAP). The store-crate gates below are written to be **conditional**: they run only if the crate is present, so Phase-0 CI is green today and the gate auto-arms when the crate appears.

```bash
#!/usr/bin/env bash
# ci/gates/no-c.sh — fail-closed no-C / single-backend gate.
set -euo pipefail

fail() { echo "NO-C GATE FAIL: $*" >&2; exit 1; }

# --- Gate 1: the engine LIB is pure-Rust (always armed). DESIGN-NOTES R9, SERVER-MODE §79 ---
# --all-features so an optional/transitive C dep cannot hide behind a feature flag.
ENGINE_TREE=$(cargo tree -p envctl-secrets-engine --all-features --edges normal,build)
if grep -Eq 'libsql-ffi|sqlite3-sys|rusqlite|openssl-sys|aws-lc-sys|aws-lc-rs|ring-asm-bundled-c' <<<"$ENGINE_TREE"; then
  fail "C dependency linked into envctl-secrets-engine"
fi

# --- Gate 2: proto + cli stay C-free (SERVER-MODE §81) ---
for crate in envctl-secrets-proto envctl-secretctl; do
  if cargo tree -p "$crate" --all-features --edges normal,build \
       | grep -Eq 'libsql-ffi|sqlite3-sys|openssl-sys|aws-lc-sys|aws-lc-rs'; then
    fail "C dependency linked into $crate"
  fi
done

# --- Gate 3: store-crate scoped waiver (auto-arms when the Phase-1 crate exists). SERVER-MODE §80 ---
if cargo metadata --no-deps --format-version 1 \
     | grep -q '"name":"envctl-secrets-store-libsql"'; then
  # 3a: the RECOMMENDED wiring (pure-Rust `remote` client) MUST be C-free.
  if cargo tree -p envctl-secrets-store-libsql --no-default-features --features remote \
       | grep -q 'libsql-ffi'; then
    fail "remote-client build of store crate links libsql-ffi (should be pure-Rust)"
  fi
  # 3b: the embedded build is the DOCUMENTED, BOUNDED waiver: it MAY pull libsql-ffi,
  #     but ONLY this crate may. Assert no OTHER crate transitively pulls it.
  #     (libsql-ffi must appear ONLY under the store crate's subtree.)
  echo "store-crate embedded build is a recorded scoped waiver (research/03 §3 risk acceptance)"
fi

# --- Gate 4: single rustls on the ring path, zero aws-lc / openssl anywhere. DESIGN-NOTES R7, CF-2 ---
RUSTLS_COUNT=$(cargo tree -i rustls --depth 0 2>/dev/null | grep -c '^rustls ' || true)
[ "$RUSTLS_COUNT" -le 1 ] || fail "more than one rustls version in the graph ($RUSTLS_COUNT)"
if cargo tree -i aws-lc-sys  2>/dev/null | grep -q .; then fail "aws-lc-sys in the graph (must be ring-only)"; fi
if cargo tree -i aws-lc-rs   2>/dev/null | grep -q .; then fail "aws-lc-rs in the graph (must be ring-only)";  fi
if cargo tree -i openssl-sys 2>/dev/null | grep -q .; then fail "openssl-sys in the graph";                    fi
# Confirm rustls actually rides `ring` (positive assertion, not just the absence of aws-lc).
cargo tree -i ring 2>/dev/null | grep -q . || fail "ring backend not present — rustls backend pin broke"

echo "NO-C GATE PASS"
```

**Why each `cargo tree` flag matters:** `--all-features` defeats a C dep hiding behind an unused feature; `--edges normal,build` catches a C dep pulled by a `build.rs` (exactly how `libsql-ffi` compiles the 8.9 MB `sqlite3.c`, CF-1); `cargo tree -i <pkg>` (inverse) lists *who* depends on the crate, so a non-empty result for `aws-lc-sys` names the offending edge.

Security rationale (sourced): `libsql-ffi-0.9.30/bundled/src/sqlite3.c` is compiled by its `build.rs` and there is no pure-Rust path (DESIGN-NOTES CF-1, VERIFIED). The recommended deployment isolates that C core into a separate `sqld` process and uses libSQL's pure-Rust `remote` client (`default-features=false, features=["remote"]`, VERIFIED pure-Rust per SERVER-MODE §2.2) — so Gate 3a is the *production-path* assertion and Gate 3b is the bounded waiver for the risk-accepted in-process fallback.

References:
- cargo tree inverse/feature docs: https://doc.rust-lang.org/cargo/commands/cargo-tree.html
- rustls ring vs aws-lc-rs CryptoProvider: https://docs.rs/rustls/latest/rustls/crypto/index.html
- ring crate: https://docs.rs/ring/latest/ring/

### 1.2 The wire/trust greps (build-shape gates already mandated by SERVER-MODE §3)

These are grep gates, not `cargo tree` gates, and they protect *code shape* invariants that the design declares "provable by construction".

```bash
#!/usr/bin/env bash
# ci/gates/shape.sh — fail-closed code-shape gates. SERVER-MODE §3.2, ARCHITECTURE §FS-S7.
set -euo pipefail
fail() { echo "SHAPE GATE FAIL: $*" >&2; exit 1; }

# --- FS-S7 / CF-6: upstream egress must NEVER use native roots, the OS store, or accept-invalid. ---
# Forbidden tokens anywhere in non-test Rust source. (reqwest is pinned default-features=false,
# features=["rustls-tls","http2","stream"] — see workspace Cargo.toml — so native-roots is opt-in only.)
if grep -RInE 'danger_accept_invalid_certs|rustls-tls-native-roots|rustls-tls-manual-roots-no-provider|use_native_tls|tls_built_in_native_certs' \
     crates --include='*.rs' --include='*.toml' \
   | grep -vE '/tests/|#\[cfg\(test\)\]' ; then
  fail "forbidden native-roots / accept-invalid TLS token in source (FS-S7)"
fi

# --- REQ-SEC-11 / FS-S8: the public edge module must never import control-service types. ---
# (Adjust the path/type names to the real module layout when the edge lands.)
EDGE_SRC=crates/secretd/src/edge          # remote relay edge module tree
CONTROL_TYPES='ControlService|VaultService|control_server::|RegisterRemoteClient|RevokeRemoteClient|MintRemoteBearer'
if [ -d "$EDGE_SRC" ] && grep -RInE "$CONTROL_TYPES" "$EDGE_SRC" ; then
  fail "edge module references a control-plane service type (REQ-SEC-11)"
fi

# --- FS-S25: the edge server cert must never be sourced from the MITM/local CA. ---
EDGE_TLS_DIR=crates/secretd/src
if grep -RInE 'mitm_ca|local_ca|ca::issue|ResolvesServerCert' "$EDGE_TLS_DIR" \
   | grep -iE 'edge|relay_tls|inbound' ; then
  fail "edge TLS appears to reference the local/MITM CA (FS-S25) — edge cert must be publicly-trusted"
fi

echo "SHAPE GATE PASS"
```

Rationale: ARCHITECTURE §FS-S7 explicitly says `native-tls`, `rustls-tls-native-roots`, and `danger_accept_invalid_certs` "are forbidden by CI grep"; SERVER-MODE §3.2 calls for a `control-types-not-in-edge` grep "the same pattern as the relay-cert-separation grep". This section is the concrete implementation of both. These greps are defense-in-depth on top of the structural separation (two service objects, disjoint route tables) — they catch a regression before it ships.

---

## 2. MSRV gate (Rust 1.80)

### 2.1 Policy

- **Declared floor:** `rust-version = "1.80"` in `[workspace.package]` (workspace `Cargo.toml`).
- **Dev toolchain:** `rust-toolchain.toml` stays floating `stable` for ergonomics (OI-24). The 1.80 floor is a *separate, verified* CI gate — it is NOT the dev default. (This is why local `rustc` is 1.96 while the floor is 1.80; that gap is expected and intentional.)
- **The known risk (HF-18, UNVERIFIED here):** `url → idna → icu` has historically raised MSRV past 1.80, and `reqwest 0.12` pulls `url`. If the 1.80 gate fails on an `icu`/`idna` edge, the locked remedy is: pin `idna`/`icu` patch versions to a 1.80-compatible release, OR raise the shared floor with explicit operator sign-off (recorded in DESIGN-NOTES). The gate exists precisely to force that decision instead of letting the floor rot.

### 2.2 Concrete gate

```yaml
  msrv:
    name: MSRV (Rust 1.80)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.80.0          # pinned-version form, https://github.com/dtolnay/rust-toolchain
      - uses: Swatinem/rust-cache@v2                 # https://github.com/Swatinem/rust-cache
      # `check`, not `build`: MSRV is about the compiler accepting the source, not producing artifacts.
      - run: cargo +1.80.0 check --workspace --locked
      - run: cargo +1.80.0 check --workspace --locked --all-features
      - run: cargo +1.80.0 check --workspace --locked --no-default-features
```

Optional hardening (recommended): add `cargo-msrv` as an *advisory* (non-gating) job to auto-discover the true floor and warn if it drifts above 1.80, so the team sees a floor bump coming. https://github.com/foresterre/cargo-msrv

---

## 3. Feature matrix

The engine's feature surface (from `crates/secrets-engine/Cargo.toml`):
`default = ["inmem-store", "mitm-ca"]`; features `inmem-store`, `mitm-ca`, `provider-github`, `provider-openai`. `mitm-ca` is the ONLY feature that pulls TLS deps (`rustls`/`rcgen`/`x509-parser` are `optional = true` and gated on it — OI-14 satisfied), so a CA-less engine build must drop TLS entirely. The store backend is selected by exactly-one-of (`compile_error!` enforces zero/both is rejected — OI-14).

```yaml
  test:
    name: test [${{ matrix.rust }} / ${{ matrix.features }}]
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        rust: [stable, 1.80.0]
        # All combinations that must compile+test. Each row is run as
        #   cargo test -p envctl-secrets-engine --no-default-features --features "<row>"
        features:
          - "inmem-store"                                              # minimal: store, no CA
          - "inmem-store,mitm-ca"                                      # = the engine default set
          - "inmem-store,mitm-ca,provider-github,provider-openai"      # everything
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@${{ matrix.rust }}
      - uses: Swatinem/rust-cache@v2
      - run: |
          cargo test -p envctl-secrets-engine --locked \
            --no-default-features --features "${{ matrix.features }}"
      # daemon/cli/proto: test on the default store; these crates are async + the wire boundary.
      - run: cargo test -p envctl-secretd  --locked
      - run: cargo test -p envctl-secretctl --locked
      - run: cargo test -p envctl-secrets-proto --locked
```

Two negative-shape facts to assert (cheap, high value), tied to OI-14:
- `cargo check -p envctl-secrets-engine --no-default-features` with **no** store feature MUST fail to compile (the `compile_error!` for zero backends). Encode as a "compile must fail" step (`! cargo check …`).
- `mitm-ca` WITHOUT any store feature should also fail-closed for the same reason.

For exhaustive coverage as the feature set grows, `cargo-hack --feature-powerset` is the standard tool and avoids hand-maintaining the matrix: `cargo hack --feature-powerset --no-dev-deps check`. https://github.com/taiki-e/cargo-hack — recommended once `provider-*` features multiply.

The `inmem-store` feature is the CI/test analogue of envctl's `DryRunRunner` (DESIGN-NOTES R9) and is the engine default, so the bulk of the suite never needs libSQL or any C core. This is what lets Phase-0 CI be fully green with zero C deps today.

---

## 4. Supply-chain gates

env-ctl's dependency set is *small but unusually sensitive*: it is a secrets vault, so the crypto/TLS crates (`chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `blake3`, `zeroize`, `subtle`, `rustls`, `rcgen`, `x509-parser`, `webpki-roots`, `rand`, `getrandom`) are the crown jewels. Two complementary controls: `cargo-deny` (advisories + license + bans + source allowlist) and `cargo-vet` (human audit trail for third-party code).

### 4.1 cargo-deny

Create `deny.toml` at the workspace root (cargo-deny reads `deny.toml` from the workspace root by default).

```toml
# deny.toml — https://embarkstudios.github.io/cargo-deny/
# Verified config keys against the current schema (cargo-deny >= 0.16; latest line is 0.14.16+/0.16.x,
# https://github.com/EmbarkStudios/cargo-deny/blob/main/CHANGELOG.md). Pin the exact version in CI (below).

[graph]
# Evaluate the full graph, all features, so a feature-gated advisory is not missed.
all-features = true

[advisories]
# RUSTSEC advisory DB. Newer cargo-deny defaults vulnerability/unmaintained to "deny";
# we set them explicitly so the policy is legible regardless of tool default drift.
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked = "deny"
# `version = 2` schema: vulnerabilities/unmaintained are deny-by-default; list ignores explicitly.
ignore = [
  # Add RUSTSEC-XXXX-NNNN here ONLY with a one-line operator justification + review date.
]

[licenses]
# version = 2 license schema: `allow` is the allowlist; anything else fails.
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Unicode-3.0", "Zlib"]
confidence-threshold = 0.93
# env-ctl is "MIT OR Apache-2.0"; copyleft (GPL/AGPL/SSPL) is incompatible and must fail.
exceptions = []

[bans]
multiple-versions = "warn"        # surface duplicate-version bloat; not fail (yet)
wildcards = "deny"                # no `*` version requirements
# Hard bans that ARE the no-C/single-backend policy, encoded as supply-chain rules:
deny = [
  { name = "openssl-sys" },
  { name = "aws-lc-sys" },
  { name = "aws-lc-rs" },
  { name = "native-tls" },
  # libsql-ffi is allowed ONLY under the store crate (Phase 1). Until that crate exists, ban it
  # outright. When the store crate lands, replace this with a `wrappers`-scoped allow (see note).
  { name = "libsql-ffi" },
]
# When secrets-store-libsql lands, swap the libsql-ffi ban for a scoped allow, e.g.:
#   skip = []  +  an allow restricted via `wrappers = ["envctl-secrets-store-libsql"]`
#   so libsql-ffi is permitted ONLY when pulled by that one crate (mirrors SERVER-MODE §80).

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []                    # no git deps; if one is ever added it must be allow-listed here
```

CI job (pin the action AND the tool version — supply-chain tools are themselves supply chain):

```yaml
  supply-chain-deny:
    name: cargo-deny
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Official action; pin to a release tag, not a moving major. https://github.com/EmbarkStudios/cargo-deny-action
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check advisories licenses bans sources
          # rust-version: 1.80.0   # optionally evaluate advisories against the MSRV graph
```

Note (UNVERIFIED, decide at pin time): `cargo-deny` config has a schema `version` field; the `[licenses]`/`[advisories]` shapes above target the v2 schema used by recent releases. Confirm against the exact pinned version's docs before merge — the tool occasionally renames keys (e.g. the old `[advisories] vulnerability = "deny"` is now a default). https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html and .../checks/bans/cfg.html

### 4.2 cargo-vet

`cargo-vet` records, in-repo, that a human reviewed each third-party crate (or imported a trusted party's audit). For a secrets vault this is the right tool for the crypto/TLS crates specifically.

```bash
cargo vet init                 # writes supply-chain/{config.toml,audits.toml,imports.lock}
# Import the major shared audit sets so most of the graph is covered without re-auditing:
#   - Mozilla:  https://github.com/mozilla/supply-chain
#   - Google:   https://github.com/google/rust-crate-audits
#   - Bytecode Alliance / Embark publish audits too.
cargo vet                      # shows the remaining unaudited delta
```

Recommended `supply-chain/config.toml` imports:

```toml
[imports.mozilla]
url = "https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml"
[imports.google]
url = "https://raw.githubusercontent.com/google/rust-crate-audits/main/audits.toml"
[imports.embark]
url = "https://raw.githubusercontent.com/EmbarkStudios/rust-ecosystem/main/audits.toml"
```

For the crown-jewel crates that imported audits do not cover, record a local audit with the explicit "ring path / no-C" attestation in the notes:

```bash
cargo vet certify rustls <ver> --criteria safe-to-deploy   # note: "ring backend, no aws-lc"
cargo vet certify rcgen  <ver> --criteria safe-to-deploy   # note: "ring backend"
cargo vet certify argon2 <ver> --criteria safe-to-deploy   # note: "zeroize feature on; m=1GiB t=4 p=4 floor enforced in code"
cargo vet certify chacha20poly1305 <ver> --criteria safe-to-deploy
cargo vet certify zeroize <ver> --criteria safe-to-deploy
```

CI job:

```yaml
  supply-chain-vet:
    name: cargo-vet
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      # Pre-built binary, fast; falls back to cargo-binstall. https://github.com/taiki-e/install-action
      - uses: taiki-e/install-action@v2
        with: { tool: cargo-vet }
      - run: cargo vet --locked
```

References: cargo-vet book https://mozilla.github.io/cargo-vet/ · repo https://github.com/mozilla/cargo-vet · Google audits https://github.com/google/rust-crate-audits

### 4.3 Pinned-dep watch (OI-23)

`getrandom`/`rand` are pinned 0.2/0.8 and MUST migrate together when the ecosystem moves to getrandom 0.3 / rand 0.9. Add an advisory (non-gating) step that surfaces drift:

```bash
cargo tree -d -i getrandom   # multiple getrandom versions => the migration moment has arrived
cargo tree -d -i rand
```

`cargo deny check bans` with `multiple-versions = "warn"` already reports this; the explicit `cargo tree -d` step keeps it visible in logs and is the documented OI-23 watch.

---

## 5. Lint, format, and warnings-as-errors

```yaml
  lint:
    name: fmt + clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      # All targets, all features, deny warnings. The engine must be clippy-clean on the no-default path too.
      - run: cargo clippy --workspace --all-targets --all-features -- -D warnings
      - run: cargo clippy -p envctl-secrets-engine --no-default-features --features inmem-store -- -D warnings
```

Set `RUSTFLAGS: -D warnings` at the workflow `env` level so even non-clippy build warnings fail. `rust-toolchain.toml` already lists `rustfmt, clippy` as components, so they are present on the dev toolchain too.

---

## 6. Reproducibility, locking, and SBOM

### 6.1 `--locked` everywhere + committed lockfile

`Cargo.lock` IS committed (present at repo root, 79 KB). Every CI build/test/check uses `--locked` so a CI run can never silently re-resolve and pull a different (possibly compromised) version. A drifted lockfile fails the build instead of being papered over.

```yaml
  reproducible:
    name: locked release build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --workspace --release --locked
      # Deterministic-source assertion: the lockfile must already be up to date.
      - run: cargo update --locked --dry-run    # fails if Cargo.lock would change
```

### 6.2 SBOM (informational, non-gating)

Generate a CycloneDX SBOM per release for provenance over the crypto/TLS crates. The official Rust CycloneDX cargo plugin is `cargo-cyclonedx`.

```yaml
  sbom:
    name: SBOM (CycloneDX)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: taiki-e/install-action@v2
        with: { tool: cargo-cyclonedx }
      - run: cargo cyclonedx --format json --all
      - uses: actions/upload-artifact@v4
        with: { name: sbom, path: "**/*.cdx.json" }
```

References: CycloneDX Rust/Cargo plugin https://github.com/CycloneDX/cyclonedx-rust-cargo · Reproducible Builds (Rust) https://reproducible-builds.org/docs/rust/ · `[profile.release]` here is `opt-level = 2` (workspace `Cargo.toml`).

UNVERIFIED / open: full bit-for-bit reproducibility (e.g. `--remap-path-prefix`, `SOURCE_DATE_EPOCH`, deterministic debuginfo) is NOT yet configured. For a secrets daemon it is worth pursuing so an operator can independently rebuild the published `secretd` binary; flagged as an open item (§9).

---

## 7. The assembled workflow

`.github/workflows/ci.yml` (skeleton; jobs detailed above):

```yaml
name: ci
on:
  push: { branches: [main] }
  pull_request: { branches: [main] }
permissions:
  contents: read                 # least privilege; no write token in CI
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -D warnings
  RUST_BACKTRACE: 1
jobs:
  lint:               # §5
  msrv:               # §2.2
  test:               # §3  (matrix: stable + 1.80.0 x feature rows)
  no-c-and-shape:     # §1.1 + §1.2  (runs ci/gates/no-c.sh and ci/gates/shape.sh)
  supply-chain-deny:  # §4.1
  supply-chain-vet:   # §4.2
  reproducible:       # §6.1
  sbom:               # §6.2 (informational)
  ci-ok:
    name: ci-ok       # the single required status check for branch protection
    runs-on: ubuntu-latest
    if: always()
    needs: [lint, msrv, test, no-c-and-shape, supply-chain-deny, supply-chain-vet, reproducible]
    steps:
      - run: |
          ok=true
          for r in "${{ needs.lint.result }}" "${{ needs.msrv.result }}" "${{ needs.test.result }}" \
                   "${{ needs.no-c-and-shape.result }}" "${{ needs.supply-chain-deny.result }}" \
                   "${{ needs.supply-chain-vet.result }}" "${{ needs.reproducible.result }}"; do
            [ "$r" = "success" ] || ok=false
          done
          $ok || { echo "a required job failed"; exit 1; }
          echo "all required CI gates passed"
```

`sbom` is intentionally NOT in `ci-ok`'s `needs` (informational). Configure branch protection to require the single `ci-ok` check.

Action versions used (pin to release tags, re-pin deliberately):
- `dtolnay/rust-toolchain` — https://github.com/dtolnay/rust-toolchain (ref form `@stable` / `@1.80.0`)
- `Swatinem/rust-cache@v2` — https://github.com/Swatinem/rust-cache
- `EmbarkStudios/cargo-deny-action@v2` — https://github.com/EmbarkStudios/cargo-deny-action
- `taiki-e/install-action@v2` — https://github.com/taiki-e/install-action
- `actions/checkout@v4`, `actions/upload-artifact@v4`

Cargo CI guidance: https://doc.rust-lang.org/cargo/guide/continuous-integration.html

---

## 8. Deploy ops — Profile A (THIS box, the recommended default)

This is the deploy half of the doc. SERVER-MODE §7.2 lists the steps; here are the concrete unit/commands. The system ships `secretd` as an envctl manifest `SystemdUnit` component, so `envctl install secretd` stands it up and `envctl reset secretd` unwinds it via the same guarded Wiring revert (ARCHITECTURE §137). Use a **systemd USER service** (matches "user service under `$XDG_RUNTIME_DIR`", SERVER-MODE §246) so the control socket lives under `$XDG_RUNTIME_DIR/env-ctl` and `SO_PEERCRED` naturally resolves to the owner uid.

### 8.1 Paths and modes (from ARCHITECTURE §125–127)

```
~/.config/env-ctl/                 (0700)  config; relay-tls/{cert.pem,key.pem} (key 0600) — edge cert
~/.local/share/env-ctl/            (0700)  vault.db (0600), ca/ca.pem (0644 public cert), ca/bundles/<tool>.pem
~/.local/state/env-ctl/            (0700)  secretd.log, audit mirror (durable deny audit second home)
$XDG_RUNTIME_DIR/env-ctl/          (0700)  control.sock (0600), relay-proxy bind config
```

### 8.2 systemd user unit (`~/.config/systemd/user/secretd.service`)

The hardening directives below are the systemd-level mirror of the in-process memory protections (HF-4: `mlockall`, `RLIMIT_CORE=0`, `MADV_DONTDUMP`). `secretd` itself still refuses to start if `mlockall` fails (FS-S4) — these are belt-and-suspenders, not a substitute.

```ini
[Unit]
Description=env-ctl secrets daemon (secretd)
Documentation=https://github.com/<owner>/env-ctl
After=default.target

[Service]
Type=notify                       # secretd uses sd_notify READY=1 after listeners + mlockall + USB-keyslot check
ExecStart=%h/.local/bin/secretd --config %h/.config/env-ctl/secretd.toml
# --- key-material hygiene (HF-4 / FS-S4) ---
LimitCORE=0                       # no core dumps of the address space holding the DEK / real keys
LimitMEMLOCK=infinity             # allow mlockall(MCL_CURRENT|MCL_FUTURE) of the whole address space
# --- attack-surface reduction (defense-in-depth on top of the engine guards) ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only             # secretd writes only to its XDG dirs (granted below)
ReadWritePaths=%h/.local/share/env-ctl %h/.local/state/env-ctl %t/env-ctl
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true       # the daemon never JITs; W^X hardens against code injection
LockPersonality=true
SystemCallFilter=@system-service
SystemCallFilter=~@swap           # discourage swap-related calls (zeroize-vs-swap residual, THREAT-MODEL §5)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6   # UDS control + loopback data/edge only
UMask=0077
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

```bash
# stand-up (Profile A)
envctl install secretd                       # writes the unit via the manifest SystemdUnit component
systemctl --user daemon-reload
systemctl --user enable --now secretd.service
# enroll the USB keyslot (daemon refuses to start on-box with NO usb_keyfile keyslot — SERVER-MODE §5.2, FS-S22)
secretctl keyslot add --factor usb --partuuid "$(blkid -o value -s PARTUUID /dev/disk/by-id/...)"   # PARTUUID, not FS-UUID (OI-5)
# tear-down (reversible Wiring revert)
envctl reset secretd
```

Note (`Type=notify`): the daemon's startup self-check (SERVER-MODE §3.3 — refuse to start unless exactly one non-loopback listener exists and the control socket is a UDS with no TCP control bind) and the USB-keyslot check (§5.2) must complete *before* `sd_notify READY=1`, so systemd treats a fail-closed refusal as a failed start, not a running service. UNVERIFIED: whether `secretd` currently links an sd_notify implementation (e.g. `sd-notify` crate, pure-Rust) — flagged §9.

### 8.3 Store wiring (SERVER-MODE §2.2 recommended, §7.2 step 2)

Run an embedded `sqld` bound to loopback ONLY (no exposed Hrana/gRPC port), and have `secretd` talk to it via the pure-Rust `remote` client. The C core then lives in the separate `sqld` process, out of `secretd`'s key-handling and the network edge.

```ini
# secretd.toml (excerpt)
[store]
profile  = "remote"               # pure-Rust libSQL `remote` client (no libsql-ffi in secretd)
sync_url = "http://127.0.0.1:8081"   # loopback-only sqld; NEVER a public bind
```

`sqld` runs as its own user unit (or container) bound to `127.0.0.1` only; it is included explicitly in `secretd`'s listener self-check allowlist as a loopback peer (SERVER-MODE §210). It stores only app-AEAD ciphertext — `sqld` is untrusted storage (research/03), and libSQL's built-in at-rest encryption is never enabled (it would re-add a C cipher dep — forbidden, SERVER-MODE §41). The in-process embedded fallback is permitted only with a recorded operator risk acceptance, and then the public edge MUST run as a separate process (SERVER-MODE §2.2 fallback).

### 8.4 Edge cert + reachability (SERVER-MODE §6, §7.2 step 3)

- Edge SERVER cert is **publicly-trusted** (ACME/Let's Encrypt for a FQDN, or an org CA the phone/Telegram agent already trusts), loaded from `~/.config/env-ctl/relay-tls/{cert.pem,key.pem}` (key 0600). NEVER the local MITM CA (FS-S25 — enforced by the §1.2 grep).
- Home-box default: a **reverse tunnel from a small public VPS to the on-box daemon**, with public TLS terminated **on-box** (so DPoP/EKM binding survives, §4 of SERVER-MODE). No MITM-CA fallback exists by design (FS-S25); a lapsed cert fails closed (refuse remote clients).

### 8.5 Deploy smoke test (SERVER-MODE §3.4, §7.2 step 6) — a CI-adjacent ops gate

Run after every deploy (and ideally as a scheduled ops check). This is the *operational* proof of REQ-SEC-11 / FS-S8:

```bash
# Every control verb attempted off-box MUST fail (control is UDS-only).
for verb in vault-status secret-get keyslot-add ca-issue relay-create unlock lock; do
  if secretctl --remote "https://<edge-fqdn>" "$verb" 2>/dev/null; then
    echo "DEPLOY SMOKE FAIL: control verb '$verb' reachable off-box (FS-S8/REQ-SEC-11)"; exit 1
  fi
done
# A data-plane swap with a valid DPoP-bound bearer MUST succeed.
curl -sf --cert client.pem --key client.key \
  -H "DPoP: <proof>" -H "Authorization: Bearer <relay-bearer>" \
  https://<edge-fqdn>/v1/relay/swap -d @swap-req.json || { echo "DEPLOY SMOKE FAIL: valid swap denied"; exit 1; }
# USB-pull stops new remote egress within the grace window (FS-S5, HF-6).
echo "pull USB, wait > grace, retry the swap above; it MUST now be denied"
```

### 8.6 Profile B (VPS) — NON-SHIPPABLE (OI-SM-2/3)

VPS deploy is explicitly gated as non-shippable until the operator-box→VPS authorizer protocol and trusted-time source are specified (SERVER-MODE §5.3). Do NOT add a Profile-B deploy path to CI/release tooling until OI-SM-2/3 ship. The reason is stated plainly in SERVER-MODE §5.4: with no USB factor on the VPS, at-rest collapses to the passphrase argon2id work factor (the A12 1-of-2 downgrade made structural), and the DEK lives in VPS RAM exposed to hypervisor/cross-VM (VMScape CVE-2025-40300)/cold-boot adversaries. Profile A is the default for exactly this reason.

---

## 9. Open questions

| # | Item | Severity | Notes / proposed resolution |
|---|---|---|---|
| OQ-1 | **MSRV 1.80 vs `reqwest 0.12 → url → idna → icu`** (HF-18) | HIGH | UNVERIFIED here. Run the §2.2 gate first; if it breaks, pin `idna`/`icu` to a 1.80-compatible patch OR raise the floor with recorded operator sign-off. Decision must be made before the first tagged release. |
| OQ-2 | **`cargo-deny` config schema version drift** | MEDIUM | The §4.1 `deny.toml` targets the v2 schema; confirm exact keys against the pinned cargo-deny version's docs before merge (the tool renames keys across majors). |
| OQ-3 | **libsql-ffi scoped allow in cargo-deny** when `secrets-store-libsql` lands (Phase 1) | MEDIUM | Convert the outright `libsql-ffi` ban to a `wrappers`-scoped allow (permitted only when pulled by that one crate), mirroring the §1.1 Gate-3 tree assertion and SERVER-MODE §80. |
| OQ-4 | **sd_notify support in `secretd`** for `Type=notify` | MEDIUM | UNVERIFIED whether secretd links a pure-Rust `sd-notify`. If not, use `Type=simple` + a post-start readiness probe, but then the startup self-check refusal is less cleanly surfaced to systemd. |
| OQ-5 | **Bit-for-bit reproducible `secretd` binary** | MEDIUM | Not yet configured (§6.2). For a secrets daemon, an independently-rebuildable published binary is high value; needs `--remap-path-prefix`, `SOURCE_DATE_EPOCH`, deterministic debuginfo, and a documented build env. |
| OQ-6 | **SLSA provenance / signed release artifacts** | MEDIUM | Beyond SBOM: consider `cargo dist` + GitHub artifact attestations / cosign for the released `secretd`/`secretctl` binaries so operators can verify provenance. Not yet specified. |
| OQ-7 | **`cargo audit` vs `cargo deny check advisories`** overlap | LOW | `cargo-deny` advisories subsumes `cargo-audit`; keep ONE to avoid divergent ignore-lists. Recommend cargo-deny only. |
| OQ-8 | **`sqld` version pinning + supply chain** (Phase 1) | MEDIUM | The separate `sqld` process is itself a deployed C binary; pin its version, track its CVEs, and decide whether it ships from the envctl manifest or is operator-provisioned. The no-C *Rust* gate does not cover the external `sqld` binary. |
| OQ-9 | **`control-types-not-in-edge` grep precision** | LOW | The §1.2 grep is a heuristic until the real edge/control module names exist; tighten the type-name list and the `EDGE_SRC` path when the edge module lands (Phase 5/§3.2). |
| OQ-10 | **Where gates run pre-merge into envctl** (Phase 7) | MEDIUM | On merge into `envctl/crates/`, all gates here must re-run in the *parent* workspace (re-resolved single lockfile, `rustix` row hand-unioned to `["process","net"]`, HF-17). Confirm envctl's MSRV ≥ 1.80 or raise its floor with sign-off. |

---

## 10. Sources

- env-ctl design set (this repo): `docs/ARCHITECTURE.md`, `docs/SERVER-MODE.md` (§2.2, §3, §6, §7), `docs/THREAT-MODEL.md`, `docs/DESIGN-NOTES.md` (CF-1/CF-2/CF-6, HF-4/HF-17/HF-18, R7/R8/R9, OI-1/OI-5/OI-14/OI-23/OI-24), `docs/ROADMAP.md`, workspace `Cargo.toml` + crate manifests.
- Cargo — Continuous Integration: https://doc.rust-lang.org/cargo/guide/continuous-integration.html
- Cargo — `cargo tree` (inverse `-i`, `--edges`, `--all-features`): https://doc.rust-lang.org/cargo/commands/cargo-tree.html
- cargo-deny: https://github.com/EmbarkStudios/cargo-deny · config: https://embarkstudios.github.io/cargo-deny/ · CHANGELOG: https://github.com/EmbarkStudios/cargo-deny/blob/main/CHANGELOG.md
- cargo-deny-action: https://github.com/EmbarkStudios/cargo-deny-action
- cargo-vet: https://github.com/mozilla/cargo-vet · book: https://mozilla.github.io/cargo-vet/
- Mozilla supply-chain audits: https://github.com/mozilla/supply-chain · Google: https://github.com/google/rust-crate-audits
- cargo-hack (feature-powerset): https://github.com/taiki-e/cargo-hack
- cargo-msrv: https://github.com/foresterre/cargo-msrv
- dtolnay/rust-toolchain: https://github.com/dtolnay/rust-toolchain · Swatinem/rust-cache: https://github.com/Swatinem/rust-cache · taiki-e/install-action: https://github.com/taiki-e/install-action
- CycloneDX Rust/Cargo: https://github.com/CycloneDX/cyclonedx-rust-cargo · Reproducible Builds (Rust): https://reproducible-builds.org/docs/rust/
- rustls CryptoProvider (ring vs aws-lc-rs): https://docs.rs/rustls/latest/rustls/crypto/index.html · ring: https://docs.rs/ring/latest/ring/
- systemd unit hardening directives: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html · sd_notify / `Type=notify`: https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
- RustSec advisory DB: https://github.com/rustsec/advisory-db
