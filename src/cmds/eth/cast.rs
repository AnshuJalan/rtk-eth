//! Filters Foundry `cast` output for LLM-friendly summaries.
//!
//! Mirrors the multi-subcommand proxy pattern of
//! [`crate::cmds::cloud::container`]: a single entry point routes each
//! supported subcommand to a dedicated filter module. Unknown subcommands
//! and machine-readable/verbose invocations are passed through unchanged,
//! so JSON integrations and `-vvvv` traces are never lossy.

use crate::core::runner::{self, RunOptions};
use crate::core::utils::resolved_command;
use anyhow::Result;
use std::ffi::OsString;

use super::{block, logs, receipt, run as run_trace, tx};

/// Filtered subcommand variant.
#[derive(Debug, Clone, Copy)]
pub enum CastCmd {
    Receipt,
    Tx,
    Run,
    Logs,
    Block,
    BlockFull,
}

impl CastCmd {
    fn as_str(self) -> &'static str {
        match self {
            CastCmd::Receipt => "receipt",
            CastCmd::Tx => "tx",
            CastCmd::Run => "run",
            CastCmd::Logs => "logs",
            CastCmd::Block => "block",
            CastCmd::BlockFull => "block",
        }
    }
}

/// Dispatch a filtered `cast <subcommand>` invocation.
pub fn run(cmd: CastCmd, args: &[String], verbose: u8) -> Result<i32> {
    if should_passthrough(args) {
        return run_cast_passthrough_with_sub(cmd.as_str(), args, verbose);
    }

    // For BlockFull we must inject `--full` into the args if the caller used
    // the convenience variant without typing it out.
    let mut effective: Vec<String> = Vec::with_capacity(args.len() + 1);
    if matches!(cmd, CastCmd::BlockFull) && !args.iter().any(|a| a == "--full") {
        effective.push("--full".to_string());
    }
    effective.extend_from_slice(args);

    let mut command = resolved_command("cast");
    command.arg(cmd.as_str());
    command.args(&effective);

    let args_display = format!("{} {}", cmd.as_str(), effective.join(" "));
    let opts = RunOptions::stdout_only().early_exit_on_failure();

    match cmd {
        CastCmd::Receipt => runner::run_filtered(
            command,
            "cast",
            &args_display,
            receipt::filter,
            opts.no_trailing_newline(),
        ),
        CastCmd::Tx => runner::run_filtered(
            command,
            "cast",
            &args_display,
            tx::filter,
            opts.no_trailing_newline(),
        ),
        CastCmd::Run => runner::run_filtered(
            command,
            "cast",
            &args_display,
            run_trace::filter,
            opts.no_trailing_newline(),
        ),
        CastCmd::Logs => runner::run_filtered(
            command,
            "cast",
            &args_display,
            logs::filter,
            opts.no_trailing_newline(),
        ),
        CastCmd::Block | CastCmd::BlockFull => runner::run_filtered(
            command,
            "cast",
            &args_display,
            block::filter,
            opts.no_trailing_newline(),
        ),
    }
}

/// Passthrough for `cast` subcommands rtk does not filter.
pub fn run_cast_passthrough(args: &[OsString], verbose: u8) -> Result<i32> {
    runner::run_passthrough("cast", args, verbose)
}

fn run_cast_passthrough_with_sub(sub: &str, args: &[String], verbose: u8) -> Result<i32> {
    let mut all: Vec<OsString> = Vec::with_capacity(args.len() + 1);
    all.push(sub.into());
    all.extend(args.iter().map(OsString::from));
    runner::run_passthrough("cast", &all, verbose)
}

/// Return true when the invocation should be passed through unfiltered.
///
/// Triggers:
/// - machine-readable flags: `--json`, `-j`, `--md`, `--raw`, `--rawbytes`
/// - high-verbosity traces (`-vvvv` or more) for `cast run`
///
/// Note: TTY detection is deliberately NOT used — agents (Claude Code,
/// Copilot, etc.) always invoke rtk through a pipe, which is precisely the
/// case where filtering matters most. Users who need raw bytes for piping
/// into jq/awk should use one of the explicit flags above.
fn should_passthrough(args: &[String]) -> bool {
    for a in args {
        match a.as_str() {
            "--json" | "-j" | "--md" | "--raw" | "--rawbytes" => return true,
            s if is_vvvv_flag(s) => return true,
            _ => {}
        }
    }
    false
}

/// Foundry accepts `-v`, `-vv`, `-vvv`, `-vvvv`, `-vvvvv`. Treat 4+ as
/// "user wants full detail — don't filter".
fn is_vvvv_flag(s: &str) -> bool {
    if !s.starts_with('-') {
        return false;
    }
    let vs = &s[1..];
    !vs.is_empty() && vs.len() >= 4 && vs.bytes().all(|b| b == b'v')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vvvv_flag_detection() {
        assert!(is_vvvv_flag("-vvvv"));
        assert!(is_vvvv_flag("-vvvvv"));
        assert!(!is_vvvv_flag("-vvv"));
        assert!(!is_vvvv_flag("-vv"));
        assert!(!is_vvvv_flag("-v"));
        assert!(!is_vvvv_flag("--verbose"));
        assert!(!is_vvvv_flag(""));
    }

    #[test]
    fn passthrough_triggers_on_json_flag() {
        let args = vec!["0xabc".to_string(), "--json".to_string()];
        // Might also trigger on non-TTY; the positive signal from --json is
        // what we're asserting.
        assert!(should_passthrough(&args));
    }

    #[test]
    fn passthrough_triggers_on_vvvv() {
        let args = vec!["0xabc".to_string(), "-vvvv".to_string()];
        assert!(should_passthrough(&args));
    }
}
