#!/usr/bin/env bash
# ci/gates/shape.sh — fail-closed code-shape gates. SERVER-MODE §3.2, ARCHITECTURE §FS-S7.
#
# Materialized from docs/ops/07-ci-supplychain.md §1.2 (keep the two in sync). The edge gates are
# inert until the Phase-8 remote edge module (crates/secretd/src/edge) lands; the FS-S7 native-roots
# grep is always armed. Run from the repo root: `bash ci/gates/shape.sh`.
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
