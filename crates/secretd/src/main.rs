//! secretd — the env-ctl control-plane daemon (gRPC over a Unix-domain socket) + the relay
//! data-plane proxy. The ONLY place async/network deps live. Phase 0 is a scaffold: bring-up is
//! `todo!()`. Phase 6 wires it up.
mod audit;
mod grpc;
mod peercred;
mod proxy;

fn main() -> anyhow::Result<()> {
    // Phase 6 bring-up, in order:
    //   1. install the ring CryptoProvider (CF-2) — never aws-lc-rs;
    //   2. mlockall(MCL_CURRENT|MCL_FUTURE) + RLIMIT_CORE=0, refusing to start on failure (HF-4);
    //   3. Engine::open(Paths::resolve()?);
    //   4. bind the UDS, serve the gRPC services behind the SO_PEERCRED owner interceptor;
    //   5. start the relay proxy whose Upstream impl pins the frozen webpki roots (FS-S7).
    todo!("secretd server bring-up (Phase 6)")
}
