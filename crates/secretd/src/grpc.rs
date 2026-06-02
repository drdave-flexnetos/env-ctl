//! gRPC service implementations (Vault / Relay / Certs / Lock / Audit) over the engine. Each
//! mutating RPC server-streams `Event`s; security outcomes are committed to the durable audit log
//! before the RPC returns. Phase 6.
