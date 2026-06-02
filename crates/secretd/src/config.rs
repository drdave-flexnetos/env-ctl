//! secretd runtime configuration: store-backend selection (in-memory vs the durable libSQL `remote`
//! store — OI-1 (a), Phase 1) and the libSQL connection parameters.
//!
//! ## Precedence (highest first)
//! environment variables > the optional TOML config file (`~/.config/env-ctl/secretd.toml`) >
//! defaults (`backend = "inmem"`).
//!
//! ## Credential hygiene
//! The libSQL AUTH TOKEN is a credential and is therefore **never** read from the TOML file — only
//! from `SECRETD_LIBSQL_AUTH_TOKEN`, or from a file named by `SECRETD_LIBSQL_AUTH_TOKEN_FILE` (which
//! must be `0600` — a group/other-readable token file is refused, fail-closed). The CONFIG-layer
//! token copy is held in a [`Zeroizing`] buffer and never logged (Debug redacts it); note the
//! downstream libSQL client takes a plain `String` (its public API) and keeps its own non-zeroized
//! copy for the connection's lifetime — unavoidable without libSQL support.
//!
//! ## Transport safety (FS-S7 spirit)
//! The daemon's libSQL client uses a PLAINTEXT connector — the gate-clean choice, because libSQL's
//! `tls` feature would pull a SECOND rustls (`hyper-rustls 0.25 -> rustls 0.22`); see
//! `secrets-store-libsql/src/sync.rs` + DESIGN-NOTES OI-1. So a libSQL URL must be **loopback**
//! `http`/`ws` (`http://127.0.0.1`, `http://[::1]`, `http://localhost`). A plaintext URL to a
//! NON-loopback host is **refused** (the auth token + metadata + write-integrity would otherwise
//! cross the network in the clear). A direct TLS URL (`https`/`wss`/`libsql`) is also **refused**,
//! with guidance to front a remote sqld with a LOOPBACK TLS terminator (stunnel/spiped/cloudflared)
//! and point secretd at `http://127.0.0.1:<local-port>` — keeping the daemon's graph gate-clean. An
//! empty auth token is accepted for a loopback sqld (local/dev open auth); a token may still be
//! supplied (e.g. a loopback terminator forwarding to an authenticated remote).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use zeroize::Zeroizing;

pub const ENV_BACKEND: &str = "SECRETD_STORE_BACKEND";
pub const ENV_URL: &str = "SECRETD_LIBSQL_URL";
pub const ENV_TOKEN: &str = "SECRETD_LIBSQL_AUTH_TOKEN";
pub const ENV_TOKEN_FILE: &str = "SECRETD_LIBSQL_AUTH_TOKEN_FILE";
pub const ENV_CONFIG: &str = "SECRETD_CONFIG";

/// Which persistence backend the daemon's engine is built on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// RAM-only store (ephemeral; the default until a durable store is configured).
    InMem,
    /// The durable libSQL `remote` store (talks HTTP/Hrana to a sqld).
    LibSql,
}

/// Resolved, validated store configuration.
pub struct StoreConfig {
    pub backend: Backend,
    /// Present iff `backend == LibSql` (validated non-empty + transport-safe).
    pub url: Option<String>,
    /// The libSQL auth token (possibly empty for a loopback sqld). Never logged.
    pub auth_token: Zeroizing<String>,
}

impl std::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreConfig")
            .field("backend", &self.backend)
            .field("url", &self.url)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

/// The TOML file shape. The auth token is DELIBERATELY absent — credentials never live in the file.
#[derive(serde::Deserialize, Default)]
struct FileConfig {
    store: Option<FileStore>,
}
#[derive(serde::Deserialize, Default)]
struct FileStore {
    backend: Option<String>,
    url: Option<String>,
}

impl StoreConfig {
    /// Load + validate the config: read the TOML file (env `SECRETD_CONFIG` overrides
    /// `default_config_path`; a missing file is fine), apply environment overrides, then [`resolve`].
    pub fn load(default_config_path: &Path) -> anyhow::Result<StoreConfig> {
        let cfg_path = std::env::var_os(ENV_CONFIG)
            .map(PathBuf::from)
            .unwrap_or_else(|| default_config_path.to_path_buf());
        let file_text = match std::fs::read_to_string(&cfg_path) {
            Ok(t) => Some(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("reading {}", cfg_path.display())),
        };
        let file: FileConfig = match &file_text {
            Some(t) => toml::from_str(t).context("parsing secretd config TOML")?,
            None => FileConfig::default(),
        };
        let fstore = file.store.unwrap_or_default();

        let backend = env_nonempty(ENV_BACKEND).or(fstore.backend);
        let url = env_nonempty(ENV_URL).or(fstore.url);
        let token = load_token().context("loading the libSQL auth token")?;

        resolve(backend, url, token)
    }
}

/// Read an env var, treating unset OR empty/whitespace as `None`.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Load the auth token from `SECRETD_LIBSQL_AUTH_TOKEN`, else from the `0600` file at
/// `SECRETD_LIBSQL_AUTH_TOKEN_FILE`. A group/other-readable token file is refused (fail-closed).
fn load_token() -> anyhow::Result<Option<Zeroizing<String>>> {
    if let Some(t) = env_nonempty(ENV_TOKEN) {
        return Ok(Some(Zeroizing::new(t)));
    }
    if let Some(p) = env_nonempty(ENV_TOKEN_FILE) {
        let path = PathBuf::from(p);
        check_token_file_mode(&path)?;
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading token file {}", path.display()))?;
        return Ok(Some(Zeroizing::new(raw.trim().to_string())));
    }
    Ok(None)
}

/// Refuse a token file that is group/other-readable (mode & 0o077 != 0).
fn check_token_file_mode(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat token file {}", path.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "token file {} is group/other-accessible (mode {:o}); chmod 0600 it",
            path.display(),
            mode & 0o7777
        );
    }
    Ok(())
}

/// Pure, testable validation core: turn the (already env/file-merged) raw values into a validated
/// [`StoreConfig`]. See the module docs for the rules enforced here.
fn resolve(
    backend: Option<String>,
    url: Option<String>,
    token: Option<Zeroizing<String>>,
) -> anyhow::Result<StoreConfig> {
    let backend = parse_backend(backend.as_deref())?;
    match backend {
        Backend::InMem => Ok(StoreConfig {
            backend,
            url: None,
            auth_token: Zeroizing::new(String::new()),
        }),
        Backend::LibSql => {
            let url = url
                .filter(|u| !u.trim().is_empty())
                .ok_or_else(|| anyhow!("store backend = \"libsql\" requires a URL ({ENV_URL} or [store].url)"))?;
            url_is_acceptable(&url)?;
            let auth_token = token.unwrap_or_else(|| Zeroizing::new(String::new()));
            if auth_token.is_empty() && !url_host_is_loopback(&url) {
                bail!(
                    "store backend = \"libsql\" to a non-loopback URL requires an auth token \
                     ({ENV_TOKEN} or {ENV_TOKEN_FILE})"
                );
            }
            Ok(StoreConfig {
                backend,
                url: Some(url),
                auth_token,
            })
        }
    }
}

fn parse_backend(s: Option<&str>) -> anyhow::Result<Backend> {
    match s.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("inmem") | Some("in-mem") | Some("memory") => Ok(Backend::InMem),
        Some("libsql") => Ok(Backend::LibSql),
        Some(other) => bail!("unknown store backend {other:?} (expected \"inmem\" or \"libsql\")"),
    }
}

/// Split a URL into `(scheme_lowercase, host_lowercase)`, stripping userinfo and port (and ipv6
/// brackets). Returns `None` if there is no `scheme://`.
fn split_scheme_host(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    };
    let host = if let Some(after) = authority.strip_prefix('[') {
        // [ipv6]:port
        after.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority)
    };
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

fn host_is_loopback(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

fn url_host_is_loopback(url: &str) -> bool {
    split_scheme_host(url).is_some_and(|(_, host)| host_is_loopback(&host))
}

/// Enforce the transport rule for THIS build. The daemon's libSQL client uses a **plaintext**
/// connector (the gate-clean choice — libSQL's `tls` feature would pull a second rustls; see
/// `secrets-store-libsql/src/sync.rs` + DESIGN-NOTES OI-1). So only **loopback** `http`/`ws` is
/// accepted. A direct TLS URL is refused with guidance to front a remote sqld with a loopback TLS
/// terminator; a plaintext non-loopback URL is refused outright (FS-S7).
fn url_is_acceptable(url: &str) -> anyhow::Result<()> {
    let (scheme, host) = split_scheme_host(url)
        .ok_or_else(|| anyhow!("libSQL url {url:?} has no scheme:// prefix"))?;
    match scheme.as_str() {
        "http" | "ws" if host_is_loopback(&host) => Ok(()),
        "http" | "ws" => bail!(
            "plaintext libSQL url to non-loopback host {host:?} is refused (FS-S7); \
             point secretd at a LOOPBACK sqld (http://127.0.0.1:<port>)"
        ),
        "https" | "wss" | "libsql" => bail!(
            "direct TLS to a remote sqld is not supported in this build: libSQL's `tls` feature would \
             add a SECOND rustls (rustls 0.22 via hyper-rustls 0.25), breaking the single ring-only \
             rustls gate (DESIGN-NOTES OI-1). Run a loopback TLS terminator (stunnel/spiped/cloudflared) \
             and set the URL to http://127.0.0.1:<local-port>"
        ),
        other => bail!("unsupported libSQL url scheme {other:?} (use http/ws to a loopback sqld)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_parsing() {
        assert_eq!(parse_backend(None).unwrap(), Backend::InMem);
        assert_eq!(parse_backend(Some("")).unwrap(), Backend::InMem);
        assert_eq!(parse_backend(Some("inmem")).unwrap(), Backend::InMem);
        assert_eq!(parse_backend(Some("  InMem ")).unwrap(), Backend::InMem);
        assert_eq!(parse_backend(Some("memory")).unwrap(), Backend::InMem);
        assert_eq!(parse_backend(Some("libsql")).unwrap(), Backend::LibSql);
        assert_eq!(parse_backend(Some(" LIBSQL ")).unwrap(), Backend::LibSql);
        assert!(parse_backend(Some("postgres")).is_err());
    }

    #[test]
    fn scheme_host_split() {
        assert_eq!(
            split_scheme_host("http://127.0.0.1:8080"),
            Some(("http".into(), "127.0.0.1".into()))
        );
        assert_eq!(
            split_scheme_host("https://Db.Turso.IO/path?x=1"),
            Some(("https".into(), "db.turso.io".into()))
        );
        assert_eq!(
            split_scheme_host("http://[::1]:8080/x"),
            Some(("http".into(), "::1".into()))
        );
        assert_eq!(
            split_scheme_host("libsql://user:pw@host.example:443"),
            Some(("libsql".into(), "host.example".into()))
        );
        assert_eq!(split_scheme_host("no-scheme"), None);
    }

    #[test]
    fn loopback_detection() {
        assert!(host_is_loopback("127.0.0.1"));
        assert!(host_is_loopback("127.5.6.7"));
        assert!(host_is_loopback("localhost"));
        assert!(host_is_loopback("::1"));
        assert!(!host_is_loopback("10.0.0.1"));
        assert!(!host_is_loopback("db.turso.io"));
        assert!(!host_is_loopback("0.0.0.0"));
    }

    #[test]
    fn url_acceptability() {
        // Plaintext to loopback: the ONLY accepted transport in this build.
        assert!(url_is_acceptable("http://127.0.0.1:8080").is_ok());
        assert!(url_is_acceptable("http://localhost:8080").is_ok());
        assert!(url_is_acceptable("http://[::1]:8080").is_ok());
        assert!(url_is_acceptable("ws://127.0.0.1:8080").is_ok());
        // Plaintext to a remote host: REFUSED (FS-S7).
        assert!(url_is_acceptable("http://db.turso.io:8080").is_err());
        assert!(url_is_acceptable("ws://10.0.0.1:8080").is_err());
        // Direct TLS: REFUSED (would add a 2nd rustls; use a loopback terminator).
        for u in ["https://db.turso.io", "wss://db.turso.io", "libsql://db.turso.io"] {
            let e = url_is_acceptable(u).unwrap_err().to_string();
            assert!(
                e.contains("terminator") || e.contains("second rustls"),
                "unexpected msg for {u}: {e}"
            );
        }
        // Garbage / unsupported scheme.
        assert!(url_is_acceptable("ftp://x").is_err());
        assert!(url_is_acceptable("noscheme").is_err());
    }

    #[test]
    fn resolve_inmem_default_ignores_libsql_fields() {
        let c = resolve(None, Some("http://db.turso.io".into()), None).unwrap();
        assert_eq!(c.backend, Backend::InMem);
        assert!(c.url.is_none());
        assert!(c.auth_token.is_empty());
    }

    #[test]
    fn resolve_libsql_requires_url() {
        assert!(resolve(Some("libsql".into()), None, None).is_err());
        assert!(resolve(Some("libsql".into()), Some("   ".into()), None).is_err());
    }

    #[test]
    fn resolve_libsql_refuses_plaintext_remote() {
        let err = resolve(
            Some("libsql".into()),
            Some("http://db.turso.io:8080".into()),
            Some(Zeroizing::new("tok".into())),
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-loopback"));
    }

    #[test]
    fn resolve_libsql_rejects_direct_tls() {
        // https is refused in this build (would add a 2nd rustls) — even WITH a token.
        let err = resolve(
            Some("libsql".into()),
            Some("https://db.turso.io".into()),
            Some(Zeroizing::new("tok".into())),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("terminator") || err.contains("second rustls"),
            "unexpected msg: {err}"
        );
    }

    #[test]
    fn resolve_libsql_loopback_with_token_ok() {
        // A loopback sqld may still require a token (e.g. a loopback terminator to an auth'd remote).
        let c = resolve(
            Some("libsql".into()),
            Some("http://127.0.0.1:8080".into()),
            Some(Zeroizing::new("tok".into())),
        )
        .unwrap();
        assert_eq!(c.backend, Backend::LibSql);
        assert_eq!(c.url.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(&*c.auth_token, "tok");
    }

    #[test]
    fn resolve_libsql_loopback_allows_empty_token() {
        let c = resolve(Some("libsql".into()), Some("http://127.0.0.1:8080".into()), None).unwrap();
        assert_eq!(c.backend, Backend::LibSql);
        assert!(c.auth_token.is_empty());
    }

    #[test]
    fn debug_redacts_token() {
        let c = resolve(
            Some("libsql".into()),
            Some("http://127.0.0.1:8080".into()),
            Some(Zeroizing::new("super-secret".into())),
        )
        .unwrap();
        let s = format!("{c:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("super-secret"));
    }
}
