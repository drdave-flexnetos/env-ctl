//! `secretd` as a library: the control-plane daemon's gRPC services, the SO_PEERCRED owner gate, the
//! proto<->engine conversions, the sync->async event bridge, and the server assembly.
//!
//! `main.rs` is a thin binary over this crate; the e2e integration test (`tests/e2e.rs`) consumes
//! these SAME modules so the REAL daemon code — `server::serve`, the `grpc` handlers, `conv`, and the
//! `peercred::OwnerGuard` interceptor — is under test, not an inline replica.
pub mod audit;
pub mod config;
pub mod conv;
pub mod grpc;
pub mod peercred;
pub mod proxy;
pub mod server;
