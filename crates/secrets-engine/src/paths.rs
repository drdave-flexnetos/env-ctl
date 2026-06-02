//! XDG, env-ctl-namespaced paths. Config `~/.config/env-ctl`, data `~/.local/share/env-ctl`
//! (0700), state/log `~/.local/state/env-ctl`, runtime socket under `$XDG_RUNTIME_DIR`.
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Paths {
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
}

impl Paths {
    /// Resolve from the environment (`HOME` + the XDG base-dir vars).
    pub fn resolve() -> anyhow::Result<Paths> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
        let base = |var: &str, default: PathBuf| -> PathBuf {
            std::env::var_os(var).map(PathBuf::from).unwrap_or(default)
        };
        let config = base("XDG_CONFIG_HOME", home.join(".config")).join("env-ctl");
        let data = base("XDG_DATA_HOME", home.join(".local/share")).join("env-ctl");
        let state = base("XDG_STATE_HOME", home.join(".local/state")).join("env-ctl");
        let runtime = match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(r) => PathBuf::from(r).join("env-ctl"),
            None => state.clone(),
        };
        Ok(Paths {
            config,
            data,
            state,
            runtime,
        })
    }

    /// Explicit roots (for tests / a sandboxed instance).
    pub fn under(root: PathBuf) -> Paths {
        Paths {
            config: root.join("config"),
            data: root.join("data"),
            state: root.join("state"),
            runtime: root.join("run"),
        }
    }

    pub fn vault_db(&self) -> PathBuf {
        self.data.join("vault.db")
    }
    pub fn control_socket(&self) -> PathBuf {
        self.runtime.join("secretd.sock")
    }
    pub fn log_file(&self) -> PathBuf {
        self.state.join("env-ctl.log")
    }
}
