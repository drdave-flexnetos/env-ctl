#!/usr/bin/env bash
# ci/gates/no-c.sh — fail-closed no-C / single-backend gate.
#
# Materialized from docs/ops/07-ci-supplychain.md §1.1 (keep the two in sync). Gate 3a ARMS
# automatically now that `crates/secrets-store-libsql` is a workspace member (OI-1 RESOLVED (a)).
# Upheld tenet: "no C *library* in the trust boundary" (no SQLite/OpenSSL/aws-lc). A build-time
# C toolchain (`cc`) is accepted — it is already mandatory via ring + blake3 in the engine, and the
# libSQL `remote` client adds only `libsql-sqlite3-parser`'s build-time `lemon.c` codegen (emits Rust;
# nothing C is linked). Run from the repo root: `bash ci/gates/no-c.sh`.
#
# HARDENING (audit wqj72spx0): every `cargo tree` is captured to a variable FIRST so a tree error
# fails the gate CLOSED (an inline `if cargo tree | grep` reads a failed/empty tree as "no C dep" and
# silently passes). Gate 4 reads the AUTHORITATIVE resolved graph from `cargo metadata` via python3,
# NOT `cargo tree -i`: the inverse tree errors "specification is ambiguous" (exit 101, empty stdout)
# the moment a crate has two versions — which, swallowed by `2>/dev/null || true`, was a FALSE PASS
# exactly when a second rustls/aws-lc would appear. `cargo metadata` is also immune to false-matching
# an optional/unresolved dependency *declaration* (e.g. rustls declares aws-lc-rs optional).
set -euo pipefail

fail() { echo "NO-C GATE FAIL: $*" >&2; exit 1; }

# --- Gate 1: the engine LIB is pure-Rust (always armed). DESIGN-NOTES R9, SERVER-MODE §79 ---
# --all-features so an optional/transitive C dep cannot hide behind a feature flag. Capture-first:
# a `cargo tree` failure aborts (fail-closed) instead of being misread as "no C dep".
ENGINE_TREE=$(cargo tree -p envctl-secrets-engine --all-features --edges normal,build)
if grep -Eq 'libsql-ffi|sqlite3-sys|rusqlite|openssl-sys|aws-lc-sys|aws-lc-rs' <<<"$ENGINE_TREE"; then
  fail "C dependency linked into envctl-secrets-engine"
fi

# --- Gate 2: proto + cli stay C-free (SERVER-MODE §81) ---
for crate in envctl-secrets-proto envctl-secretctl; do
  CRATE_TREE=$(cargo tree -p "$crate" --all-features --edges normal,build)
  if grep -Eq 'libsql-ffi|sqlite3-sys|openssl-sys|aws-lc-sys|aws-lc-rs' <<<"$CRATE_TREE"; then
    fail "C dependency linked into $crate"
  fi
done

# --- Gate 3: store-crate scoped waiver (auto-arms when the crate exists). SERVER-MODE §80 ---
if cargo metadata --no-deps --format-version 1 | grep -q '"name":"envctl-secrets-store-libsql"'; then
  # 3a: the SHIPPING wiring (pure-Rust `remote` client) MUST link no C SQLite. Capture-first.
  STORE_TREE=$(cargo tree -p envctl-secrets-store-libsql --no-default-features --features remote)
  if grep -Eq 'libsql-ffi|libsql-sys|sqlite3-sys' <<<"$STORE_TREE"; then
    fail "remote-client build of store crate links a C SQLite (libsql-ffi/libsql-sys/sqlite3-sys)"
  fi
  # 3b: no-op note (honest). The `embedded` feature (a future risk-accepted in-process C-SQLite
  #     fallback) is an UNIMPLEMENTED placeholder that pulls no libsql feature, so there is nothing to
  #     scope yet. If it is ever implemented, add an assertion here that libsql-ffi is reachable ONLY
  #     via this crate. Workspace-wide absence of libsql-ffi is already proven by Gate 4 below.
  echo "note: store-crate 'embedded' (in-process C-SQLite) is an unbuilt placeholder; remote-only ships"
fi

# --- Gate 4: exactly one ring-only rustls; zero aws-lc/openssl/C-SQLite ANYWHERE. DESIGN-NOTES R7, CF-2 ---
# Authoritative resolved graph (`cargo metadata` .resolve.nodes), parsed with python3.
cargo metadata --format-version 1 | python3 -c '
import json,sys
m=json.load(sys.stdin)
idmap={p["id"]:(p["name"],p["version"]) for p in m["packages"]}
resolved={}
for node in m["resolve"]["nodes"]:
    name,ver=idmap[node["id"]]
    resolved.setdefault(name,set()).add(ver)
def die(msg):
    sys.stderr.write("NO-C GATE FAIL: "+msg+"\n"); sys.exit(1)
banned=["aws-lc-sys","aws-lc-rs","openssl-sys","libsql-ffi","libsql-sys","sqlite3-sys","rusqlite"]
present=[c for c in banned if resolved.get(c)]
if present:
    die("forbidden C crate(s) resolved into the graph: "+", ".join(c+" "+str(sorted(resolved[c])) for c in present))
rv=sorted(resolved.get("rustls",[]))
if len(rv)>1:
    die("more than one rustls version in the graph: "+str(rv))
if not resolved.get("ring"):
    die("ring backend not present — rustls crypto-provider pin broke")
print("resolved graph clean: rustls="+(str(rv) if rv else "none")+" on ring="+str(sorted(resolved["ring"]))+"; zero aws-lc/openssl/C-SQLite")
'

echo "NO-C GATE PASS"
