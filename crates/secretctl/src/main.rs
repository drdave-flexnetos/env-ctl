//! secretctl — the `env-ctl` CLI. A thin gRPC client over the daemon's Unix socket; it drains the
//! `Event` stream and pretty-prints (or `--json`). Mirrors envctl ergonomics: destructive verbs
//! default to dry-run (`--apply` to act, `--confirm` for root-of-trust). Phase 0: parses the full
//! command tree, then `todo!()`s the RPC dispatch.
mod cli;
mod render;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let args = cli::Cli::parse();
    let _ = &args; // Phase 6 dispatches `args.cmd` to the daemon and renders the Event stream.
    todo!("secretctl RPC dispatch (Phase 6)")
}
