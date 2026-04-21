//! Per-filter gain measurement against real mainnet fixtures.
//!
//! Run with `cargo test --release cast_gain -- --nocapture` to see a
//! savings table. Mirrors what `rtk gain` reports, but aggregated per
//! subcommand (rtk gain aggregates at the top-level `rtk cast` only).

#![cfg(test)]

use super::{block, logs, receipt, run as run_trace, tx};

/// Mirrors `core::tracking::estimate_tokens` — `ceil(len/4)`.
fn estimate_tokens(s: &str) -> usize {
    s.len().div_ceil(4)
}

fn report(name: &str, raw: &str, filtered: &str) -> f64 {
    let rt = estimate_tokens(raw);
    let ft = estimate_tokens(filtered);
    let pct = if rt == 0 {
        0.0
    } else {
        100.0 * (1.0 - (ft as f64 / rt as f64))
    };
    println!(
        "{:<18}  raw_bytes={:>8}  filtered_bytes={:>8}  raw_tok={:>6}  filt_tok={:>6}  savings={:>5.1}%",
        name,
        raw.len(),
        filtered.len(),
        rt,
        ft,
        pct
    );
    pct
}

#[test]
fn cast_gain_receipt() {
    let raw = include_str!("../../../tests/fixtures/cast/receipt_raw.txt");
    let filtered = receipt::filter(raw);
    let pct = report("cast receipt", raw, &filtered);
    assert!(filtered.len() <= raw.len(), "filter grew output");
    // Target from plan: ≥70%. Leave a soft assert so we see the number first.
    eprintln!("target: ≥70% | actual: {:.1}%", pct);
    println!("--- filtered receipt output ---");
    println!("{}", filtered);
    println!("--- end ---");
}

#[test]
fn cast_gain_tx() {
    let raw = include_str!("../../../tests/fixtures/cast/tx_raw.txt");
    let filtered = tx::filter(raw);
    let pct = report("cast tx", raw, &filtered);
    assert!(filtered.len() <= raw.len(), "filter grew output");
    eprintln!("target: ≥60% | actual: {:.1}%", pct);
}

#[test]
fn cast_gain_run() {
    let raw = include_str!("../../../tests/fixtures/cast/run_raw.txt");
    let filtered = run_trace::filter(raw);
    let pct = report("cast run", raw, &filtered);
    assert!(filtered.len() <= raw.len(), "filter grew output");
    eprintln!("target: ≥50% moderate / ≥75% proxy-heavy | actual: {:.1}%", pct);
}

#[test]
fn cast_gain_logs() {
    let raw = include_str!("../../../tests/fixtures/cast/logs_raw.txt");
    let filtered = logs::filter(raw);
    let pct = report("cast logs", raw, &filtered);
    assert!(filtered.len() <= raw.len(), "filter grew output");
    eprintln!("target: ≥70% | actual: {:.1}%", pct);
    println!("--- first 800 chars of filtered logs output ---");
    let head: String = filtered.chars().take(800).collect();
    println!("{}", head);
    println!("--- (truncated) ---");
}

#[test]
fn cast_gain_block_default() {
    let raw = include_str!("../../../tests/fixtures/cast/block_default_raw.txt");
    let filtered = block::filter(raw);
    let pct = report("cast block", raw, &filtered);
    assert!(filtered.len() <= raw.len(), "filter grew output");
    eprintln!("target: ≥60% | actual: {:.1}%", pct);
}

#[test]
fn cast_gain_block_full() {
    let raw = include_str!("../../../tests/fixtures/cast/block_full_raw.txt");
    let filtered = block::filter(raw);
    let pct = report("cast block --full", raw, &filtered);
    assert!(filtered.len() <= raw.len(), "filter grew output");
    eprintln!("target: ≥85% | actual: {:.1}%", pct);
    println!("--- first 1200 chars of filtered block --full output ---");
    let head: String = filtered.chars().take(1200).collect();
    println!("{}", head);
    println!("--- (truncated) ---");
}
