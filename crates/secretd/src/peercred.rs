//! A tower interceptor that reads `SO_PEERCRED` (via rustix `getsockopt`) on the UDS connection
//! and refuses any peer whose uid != the owner uid. Phase 6.
