//! secretd — the env-ctl control-plane daemon (gRPC over a Unix-domain socket).
//!
//! `main` stays SYNC and builds a multi-thread runtime explicitly so process hardening runs BEFORE
//! any async/key path (ops doc §3). Bring-up order inside [`serve`]:
//!   1. install the rustls RING `CryptoProvider` (CF-2) — never aws-lc-rs;
//!   2. process hardening (FS-S4): `RLIMIT_CORE=0` + `RLIMIT_MEMLOCK` raised. (See the NOTE below on
//!      the one place the spec's in-process `mlockall` cannot be honored with the pinned rustix
//!      feature set; systemd `LimitMEMLOCK`/`LimitCORE` provide defense-in-depth meanwhile.)
//!   3. `Paths::resolve()` + create runtime/data/state dirs `0700`;
//!   4. `Engine::open(paths)`; first-run bootstrap leaves vault init out-of-band (no `Vault.Init`
//!      RPC; the vault stays Locked until an explicit `Lock.Unlock`);
//!   5. bind the UDS `0600` (stale-socket reaped), serve the gRPC services behind the SO_PEERCRED
//!      owner interceptor with graceful shutdown on SIGINT/SIGTERM.
//!
//! NOTE (pinned-rustix limitation, documented): rustix 0.38 with `features=["process","net","time"]`
//! does NOT include the `mm` module, so `mlockall(MCL_CURRENT|MCL_FUTURE)` is not callable through
//! the pinned feature set, and we do not add new deps. The buildable hardening within the pins is
//! `RLIMIT_CORE=0` + raising `RLIMIT_MEMLOCK` (so a future mlock can succeed) — the spec's in-process
//! `mlockall` is deferred to a follow-up. This is the ONE place the in-process `mlockall` cannot be
//! honored as written; the systemd unit's `LimitMEMLOCK=infinity` / `LimitCORE=0` cover it as
//! defense-in-depth.
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use envctl_secrets::paths::Paths;
use envctl_secrets::Engine;
use envctl_secretd::{config, peercred, server};
use rustix::process::{setrlimit, Resource, Rlimit};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    rt.block_on(serve())
}

async fn serve() -> anyhow::Result<()> {
    // 1. Install the rustls RING crypto provider (CF-2). Idempotent; ignore "already installed".
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls ring CryptoProvider already installed");
    }

    // 2. Process hardening (FS-S4): no core dumps; raise the memlock ceiling. See the module NOTE on
    // why in-process `mlockall` is deferred under the pinned rustix feature set.
    harden_process();

    // 3. Resolve paths and create the runtime/data/state dirs 0700.
    let paths = Paths::resolve().context("resolving XDG paths")?;
    ensure_dir_0700(&paths.runtime)?;
    ensure_dir_0700(&paths.data)?;
    ensure_dir_0700(&paths.state)?;

    // 4. Select the store backend from config (env > secretd.toml > inmem default) and open the
    // engine (Arc-backed; Clone + Send + Sync). First-run bootstrap: there is no `Vault.Init` RPC in
    // the control proto, so a fresh vault stays Locked until an out-of-band init + an explicit
    // `Lock.Unlock`. We do not auto-init here (no passphrase/USB to enroll).
    let store_cfg =
        config::StoreConfig::load(&paths.config_file()).context("loading store config")?;
    let engine = build_engine(paths.clone(), store_cfg).await?;

    // 5. Bind the UDS (reaping a stale socket from a dead daemon), chmod 0600.
    let sock = paths.control_socket();
    let listener = bind_uds(&sock).await?;

    let owner_uid = peercred::owner_uid();
    tracing::info!(socket = %sock.display(), owner_uid, "secretd listening");

    // Graceful shutdown on SIGINT / SIGTERM.
    let shutdown = async {
        let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler");
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received; shutting down"),
            _ = sigterm.recv() => tracing::info!("SIGTERM received; shutting down"),
        }
    };

    let result = server::serve(engine, owner_uid, listener, shutdown).await;

    // Best-effort cleanup of the socket on graceful exit.
    let _ = std::fs::remove_file(&sock);
    result.context("serving the control plane")?;
    Ok(())
}

/// Build the engine on the configured store backend (OI-1 (a), Phase 1).
///
/// The libSQL store drives its OWN current-thread runtime via `block_on`, so it is constructed on a
/// `spawn_blocking` thread — NEVER on the async reactor, where a nested `block_on` would panic (see
/// `secrets-store-libsql/src/sync.rs`). `InMemStore` does no async and is built inline.
async fn build_engine(paths: Paths, cfg: config::StoreConfig) -> anyhow::Result<Engine> {
    match cfg.backend {
        config::Backend::InMem => {
            tracing::info!("store backend = in-memory (ephemeral; set [store] in secretd.toml for durability)");
            Engine::open(paths).context("opening the engine on the in-memory store")
        }
        config::Backend::LibSql => {
            let url = cfg
                .url
                .expect("resolve() guarantees a URL for the libSQL backend");
            tracing::info!(url = %url, "store backend = libSQL remote (durable)");
            let token = cfg.auth_token; // Zeroizing; moved into + dropped by the blocking task
            tokio::task::spawn_blocking(move || -> anyhow::Result<Engine> {
                let store = envctl_secrets_store_libsql::LibSqlStoreBuilder::new(
                    url,
                    token.as_str().to_owned(),
                )
                .build()
                .context("opening the libSQL remote store (is sqld reachable?)")?;
                Engine::open_with_store(paths, Box::new(store))
                    .context("opening the engine on the libSQL store")
            })
            .await
            .context("the libSQL store-construction task panicked")?
        }
    }
}

/// `RLIMIT_CORE=0` (no core dumps that could leak key material) + raise `RLIMIT_MEMLOCK` so a
/// future mlock can succeed. A `setrlimit` failure here is logged, not fatal: the systemd unit
/// provides the authoritative `LimitCORE`/`LimitMEMLOCK` as defense-in-depth.
fn harden_process() {
    if let Err(e) = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    ) {
        tracing::warn!(error = %e, "could not set RLIMIT_CORE=0 (relying on systemd LimitCORE)");
    }
    if let Err(e) = setrlimit(
        Resource::Memlock,
        Rlimit {
            current: None, // None => infinity, raising the ceiling for a future mlock
            maximum: None,
        },
    ) {
        tracing::warn!(error = %e, "could not raise RLIMIT_MEMLOCK (relying on systemd LimitMEMLOCK)");
    }
}

/// Create `dir` (and parents) with mode 0700, tightening perms if it already exists.
fn ensure_dir_0700(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    Ok(())
}

/// Bind the control UDS at `sock`, reaping a stale socket left by a dead daemon (connect-probe: a
/// refused connection means no live daemon -> remove + rebind; a successful connection means a
/// daemon is already running -> bail). Sets the socket to 0600 after bind.
async fn bind_uds(sock: &Path) -> anyhow::Result<tokio::net::UnixListener> {
    if sock.exists() {
        match tokio::net::UnixStream::connect(sock).await {
            Ok(_) => anyhow::bail!("daemon already running at {}", sock.display()),
            Err(_) => {
                // No live peer; reap the stale socket.
                std::fs::remove_file(sock)
                    .with_context(|| format!("removing stale socket {}", sock.display()))?;
            }
        }
    }
    // NOTE (bind/chmod window): `bind` creates the socket with a umask-governed mode and the tighten
    // to 0600 is a SEPARATE call below, so for the window between the two the socket may be
    // group/other-readable. The LOAD-BEARING WALL during that window is the parent runtime dir, which
    // `ensure_dir_0700` created 0700 BEFORE this bind: a non-owner cannot traverse into it to reach
    // the socket, and the SO_PEERCRED `OwnerGuard` would deny on uid regardless. (A `umask(0o077)`
    // guard would close the window correct-by-construction at the socket level, but `rustix::umask`
    // needs the `fs` feature, which is not in the pinned feature set — no new deps, so we rely on the
    // 0700 dir + chmod here.)
    let listener = tokio::net::UnixListener::bind(sock)
        .with_context(|| format!("binding {}", sock.display()))?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", sock.display()))?;
    Ok(listener)
}
