//! Drains the cosmetic `SecretEvent` stream to the gRPC server-stream + the on-disk log, while the
//! engine commits security outcomes to the durable hash-chained audit log before each RPC returns
//! (HF-14). Phase 6.
