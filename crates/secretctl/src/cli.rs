//! The `env-ctl` command tree (clap derive). The surface mirrors `docs/SCAFFOLD-SPEC.md`.
//! Destructive verbs carry `--apply` (default dry-run, CF-8); root-of-trust verbs also `--confirm`.
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "env-ctl", about = "env-ctl — local secrets vault + credential broker")]
pub struct Cli {
    /// Emit machine-readable NDJSON instead of pretty output.
    #[arg(long, global = true)]
    pub json: bool,
    /// Override the daemon control socket path.
    #[arg(long, global = true)]
    pub socket: Option<String>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Vault lock status (no unlock side effect).
    Status,
    /// Unlock the vault (USB-first; passphrase only if the USB is absent).
    Unlock {
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Zeroize the DEK + CA issuer in RAM (the true panic stop).
    Lock,
    /// Manage stored secrets.
    Secret {
        #[command(subcommand)]
        cmd: SecretCmd,
    },
    /// Manage relay policies + mint bearers.
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
    /// Manage the local CA, leaf certs, and trust wiring.
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
    /// Query the tamper-evident audit log.
    Audit(AuditArgs),
    /// Run a command with relay credentials injected into the child only.
    Run(RunArgs),
}

#[derive(Subcommand, Debug)]
pub enum SecretCmd {
    /// Add a secret (additive; backs up on overwrite).
    Add {
        name: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        value_stdin: bool,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        overwrite: bool,
        /// The real key is broker-only: `get --reveal` will refuse it.
        #[arg(long)]
        broker_only: bool,
    },
    /// Show metadata; the raw value only with `--reveal --apply` (audited; refused if broker-only).
    Get {
        name: String,
        #[arg(long)]
        reveal: bool,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// List secrets (metadata only).
    List {
        #[arg(long)]
        provider: Option<String>,
    },
    /// Remove a secret (destructive; dry-run unless `--apply`).
    Rm {
        name: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// Rotate a secret's value (destructive; dry-run unless `--apply`).
    Rotate {
        name: String,
        #[arg(long)]
        value_stdin: bool,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum RelayCmd {
    /// Create a named relay policy (additive).
    Create {
        name: String,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        provider: String,
        /// base-url | proxy | native
        #[arg(long)]
        mode: String,
        #[arg(long)]
        upstream_base: Option<String>,
        #[arg(long = "host")]
        hosts: Vec<String>,
        #[arg(long = "path")]
        paths: Vec<String>,
        #[arg(long = "method")]
        methods: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        rate: Option<u32>,
        #[arg(long)]
        quota: Option<u64>,
        #[arg(long)]
        disabled: bool,
    },
    /// Revoke a relay policy (destructive; dry-run unless `--apply`).
    Revoke {
        name: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// Revoke a single leaked bearer by its token id (OI-10).
    RevokeToken {
        token_id: String,
        #[arg(long)]
        apply: bool,
    },
    /// List relay policies.
    List {
        #[arg(long)]
        all: bool,
    },
    /// Mint a `<=24h` peer-bound bearer under a policy (USB-gated).
    Mint {
        name: String,
        #[arg(long)]
        ttl: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum CaCmd {
    /// Initialize the local CA.
    Init {
        #[arg(long)]
        apply: bool,
    },
    /// Rotate the CA (root-of-trust: `--apply --confirm`).
    Rotate {
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// Issue a leaf cert. `--usage` is control-server | control-client (NEVER mitm-leaf).
    Issue {
        cn: String,
        #[arg(long = "san")]
        sans: Vec<String>,
        #[arg(long)]
        ttl_days: Option<u64>,
        #[arg(long)]
        usage: String,
    },
    /// Renew a leaf cert.
    Renew {
        cn: String,
        #[arg(long)]
        apply: bool,
    },
    /// Revoke a leaf cert (destructive; dry-run unless `--apply`).
    Revoke {
        cn: String,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// Wire CA trust into tool env / the system bundle (reversible, owned-file-only).
    Trust {
        targets: Vec<String>,
        /// Root-of-trust: requires `--apply --confirm`.
        #[arg(long)]
        system_bundle: bool,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[arg(long)]
    pub actor: Option<String>,
    #[arg(long)]
    pub relay: Option<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Attach one or more named relays (else inferred from a profile / provider).
    #[arg(long = "relay")]
    pub relays: Vec<String>,
    #[arg(long)]
    pub provider: Option<String>,
    /// Mint a one-off ephemeral bearer for this process.
    #[arg(long)]
    pub ephemeral: bool,
    #[arg(long = "no-profile")]
    pub no_profile: bool,
    #[arg(long)]
    pub profile: Option<String>,
    /// The command to run: `env-ctl run -- <cmd> [args...]`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}
