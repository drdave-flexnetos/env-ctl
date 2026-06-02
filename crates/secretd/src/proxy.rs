//! The relay data-plane proxy: a hyper server implementing the engine's `Upstream` seam via
//! reqwest. Its upstream client seeds its `RootCertStore` from `webpki_roots::TLS_SERVER_ROOTS`
//! ONLY (never the OS store or the local CA, FS-S7). Handles base-URL repoint and HTTPS_PROXY
//! CONNECT + relay-gated in-RAM leaf minting. Phase 4/6.
