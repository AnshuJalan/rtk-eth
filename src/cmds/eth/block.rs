//! Filter for `cast block` (§4.1 default + §4.2 `--full`).
//!
//! Default mode:
//!   - drop `logsBloom`, `difficulty`, `mixHash`, `nonce`, `sha3Uncles`,
//!     `uncles` (unless non-empty), `extraData` unless meaningful.
//!   - collapse `transactions: [0xaa, 0xbb, 0xcc, ...]` to
//!     `transactions: N (first: 0xabc… last: 0xdef…)`.
//!
//! `--full` mode (transactions expanded as objects):
//!   - keep the compressed header (same drops as default).
//!   - for each transaction, emit a single line
//!     `idx N: 0xfrom… → 0xto…  value=<decimal>  sel=<sig>` (selector
//!     decoded via [`super::fourbyte`] — shell-out to `cast 4byte`,
//!     cached per invocation).
//!
//! `--full` is detected via the raw content (presence of expanded `hash:`
//! objects) AND via the `--full` injection the dispatcher performs.

use super::fourbyte;

const ALWAYS_DROP: &[&str] = &[
    "logsBloom",
    "sha3Uncles",
    "mixHash",
    "nonce",
    "difficulty",
    "extraData",
];

pub fn filter(raw: &str) -> String {
    let stripped = crate::core::utils::strip_ansi(raw);
    match try_filter(&stripped) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("[rtk] cast block: filter fallthrough: {}", e);
            raw.to_string()
        }
    }
}

fn try_filter(raw: &str) -> Result<String, &'static str> {
    fourbyte::reset_cache();
    // Heuristic: a --full response contains per-tx objects whose `input`
    // field starts with `0x` and a `hash` line within a nested block. The
    // reliable signal is a `blockHash` line inside the transactions array.
    let is_full = detect_full(raw);

    if is_full {
        filter_full(raw)
    } else {
        filter_default(raw)
    }
}

fn detect_full(raw: &str) -> bool {
    // In --full output each transaction is an object with a `from` key.
    // In default output the transactions section is a flat list of hashes.
    // Counting more than one `from` line suggests --full.
    let mut from_count = 0usize;
    for line in raw.lines() {
        if line.trim_start().starts_with("from") {
            from_count += 1;
            if from_count >= 2 {
                return true;
            }
        }
    }
    false
}

fn filter_default(raw: &str) -> Result<String, &'static str> {
    let mut out = String::with_capacity(raw.len() / 2);
    let mut tx_hashes: Vec<String> = Vec::new();
    let mut in_tx_list = false;

    for line in raw.lines() {
        let trimmed = line.trim_end();
        let t = trimmed.trim_start();

        if should_drop_key(t) {
            continue;
        }

        if starts_with_key(t, "transactions") {
            in_tx_list = true;
            continue;
        }

        if in_tx_list {
            if t.starts_with("0x") {
                tx_hashes.push(t.trim_end_matches(',').trim_matches('"').to_string());
                continue;
            }
            if t.starts_with(']') || t.is_empty() {
                in_tx_list = false;
                emit_tx_summary(&mut out, &tx_hashes);
                continue;
            }
            // Something else — end the section.
            in_tx_list = false;
            emit_tx_summary(&mut out, &tx_hashes);
            // fall through to emit the current line
        }

        out.push_str(trimmed);
        out.push('\n');
    }

    if in_tx_list {
        emit_tx_summary(&mut out, &tx_hashes);
    }

    Ok(out)
}

fn emit_tx_summary(out: &mut String, txs: &[String]) {
    if txs.is_empty() {
        out.push_str("transactions: 0\n");
        return;
    }
    // Tx hashes stay full so the agent can pipe them into the next
    // `cast receipt`/`cast tx`/`cast run` without a second lookup.
    let first = txs.first().map(|h| h.as_str()).unwrap_or_default();
    let last = txs.last().map(|h| h.as_str()).unwrap_or_default();
    out.push_str(&format!(
        "transactions: {} (first: {} last: {})\n",
        txs.len(),
        first,
        last
    ));
}

fn filter_full(raw: &str) -> Result<String, &'static str> {
    let mut out = String::with_capacity(raw.len() / 3);
    let mut tx_lines: Vec<String> = Vec::new();
    let mut current = FullTx::default();
    let mut header_lines: Vec<String> = Vec::new();
    let mut saw_tx_block = false;
    // Track accessList nesting so we don't treat its entries as new txs.
    let mut access_depth: i32 = 0;
    // Detect the sentinel that each tx starts with (`blockHash` line):
    // when we see a *second* blockHash and we already have fields, flush.
    let mut has_any_field = false;

    let flush = |current: &mut FullTx, tx_lines: &mut Vec<String>, has: &mut bool| {
        if *has {
            tx_lines.push(format_full_tx(current, tx_lines.len()));
            *current = FullTx::default();
            *has = false;
        }
    };

    for line in raw.lines() {
        let trimmed = line.trim_end();
        let t = trimmed.trim_start();

        if !saw_tx_block {
            if starts_with_key(t, "transactions") {
                saw_tx_block = true;
                continue;
            }
            if should_drop_key(t) {
                continue;
            }
            header_lines.push(trimmed.to_string());
            continue;
        }

        // Inside the transactions list.
        // Real foundry --full format: each tx is a sequence of key-value lines.
        // A new tx begins with `blockHash`; accessList/JSON objects may have
        // their own nesting via `[` / `]` which we must not confuse.
        if t.starts_with(']') && access_depth == 0 {
            // end of transactions list
            break;
        }
        // Track accessList's nested `[` and `]`.
        if t.starts_with('[') || t.ends_with('[') {
            access_depth += 1;
        }
        if t == "]" && access_depth > 0 {
            access_depth -= 1;
            continue;
        }

        if access_depth == 0 {
            if starts_with_key(t, "blockHash") {
                flush(&mut current, &mut tx_lines, &mut has_any_field);
                has_any_field = true;
                continue;
            }
            if starts_with_key(t, "accessList") {
                // The accessList value is on the same line if empty (`[]`)
                // or opens a multi-line block. Detect multi-line by `[` at end.
                if t.trim_end().ends_with('[') {
                    // already counted via starts_with('[')||ends_with('[') above
                } else {
                    // inline `[]` or value — ignore
                }
                continue;
            }
            consume_tx_kv(&mut current, t);
            if current.from.is_some()
                || current.to.is_some()
                || current.hash.is_some()
                || current.value.is_some()
                || current.input.is_some()
            {
                has_any_field = true;
            }
        }
    }
    flush(&mut current, &mut tx_lines, &mut has_any_field);

    for line in &header_lines {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&format!("transactions: {}\n", tx_lines.len()));
    for (i, tx) in tx_lines.iter().enumerate() {
        out.push_str(&format!("  [{}] {}\n", i, tx));
    }

    Ok(out)
}

#[derive(Default)]
struct FullTx {
    from: Option<String>,
    to: Option<String>,
    value: Option<String>,
    input: Option<String>,
    hash: Option<String>,
}

fn consume_tx_kv(tx: &mut FullTx, line: &str) {
    let t = line.trim();
    if let Some(v) = strip_key(t, "from") {
        tx.from = Some(clean_value(v));
    } else if let Some(v) = strip_key(t, "to") {
        tx.to = Some(clean_value(v));
    } else if let Some(v) = strip_key(t, "value") {
        tx.value = Some(clean_value(v));
    } else if let Some(v) = strip_key(t, "input") {
        tx.input = Some(clean_value(v));
    } else if let Some(v) = strip_key(t, "hash") {
        tx.hash = Some(clean_value(v));
    }
}

fn format_full_tx(tx: &FullTx, fallback_index: usize) -> String {
    let from = tx.from.as_deref().map(short_hash).unwrap_or_else(|| "?".into());
    let to = tx
        .to
        .as_deref()
        .map(short_hash)
        .unwrap_or_else(|| "(create)".into());
    let value = tx.value.as_deref().unwrap_or("0");
    let sel_label = tx
        .input
        .as_deref()
        .map(summarise_selector)
        .unwrap_or_default();
    // Tx hash stays full — the agent pipes it into follow-up cast commands.
    let hash = tx
        .hash
        .as_deref()
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|| format!("idx{}", fallback_index));
    format!("{} {} → {}  value={}{}", hash, from, to, value, sel_label)
}

fn summarise_selector(input: &str) -> String {
    let body = input.trim().trim_start_matches("0x");
    if body.len() < 8 {
        return String::new();
    }
    let sel_hex = &body[..8];
    match fourbyte::lookup_selector_hex(sel_hex) {
        Some(sig) => format!("  sel={}", sig),
        None => format!("  sel=0x{}", sel_hex),
    }
}

fn starts_with_key(line: &str, key: &str) -> bool {
    let t = line.trim_start();
    t.starts_with(key) && {
        let after = &t[key.len()..];
        after.is_empty() || after.starts_with(':') || after.starts_with(' ') || after.starts_with('\t')
    }
}

fn should_drop_key(line: &str) -> bool {
    let t = line.trim_start();
    ALWAYS_DROP.iter().any(|k| {
        t.starts_with(k) && {
            let after = &t[k.len()..];
            after.is_empty() || after.starts_with(':') || after.starts_with(' ') || after.starts_with('\t')
        }
    })
}

fn strip_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let t = line.trim_start();
    if !t.starts_with(key) {
        return None;
    }
    let rest = &t[key.len()..];
    let rest = rest.strip_prefix(':').unwrap_or(rest).trim_start();
    Some(rest)
}

fn clean_value(s: &str) -> String {
    s.trim()
        .trim_end_matches(',')
        .trim_matches('"')
        .to_string()
}

fn short_hash(hash: &str) -> String {
    let h = hash.trim();
    if h.len() >= 12 && h.starts_with("0x") {
        format!("{}…{}", &h[..10], &h[h.len() - 4..])
    } else {
        h.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_on_empty() {
        assert_eq!(filter(""), "");
    }

    #[test]
    fn default_collapses_tx_list() {
        let raw = "number              19000000\ngasLimit            30000000\ntransactions        [\n  0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n  0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n]\nlogsBloom           0xabcdef\n";
        let out = filter(raw);
        assert!(!out.contains("logsBloom"));
        assert!(out.contains("transactions: 3"));
        assert!(out.contains("first:"));
    }

    #[test]
    fn drops_always_drop_keys() {
        let raw = "logsBloom 0xabc\nmixHash 0xdef\nnumber 100\n";
        let out = filter(raw);
        assert!(!out.contains("logsBloom"));
        assert!(!out.contains("mixHash"));
        assert!(out.contains("number"));
    }

    #[test]
    fn full_mode_per_tx_oneliner() {
        // SAFETY: tests run sequentially; set_var is safe here since no
        // other thread reads FOURBYTE_TEST_MOCK.
        unsafe {
            std::env::set_var(
                "FOURBYTE_TEST_MOCK",
                "0xa9059cbb=transfer(address,uint256)",
            );
        }
        // Real `cast block --full` output: each tx is a block of key-value
        // lines delimited by a leading `blockHash` field.
        let raw = "number              100\ntransactions:        [\n\tblockHash            0xabc\n\tblockNumber          100\n\tfrom                 0x1111111111111111111111111111111111111111\n\taccessList           []\n\thash                 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\tinput                0xa9059cbb000000000000000000000000333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000003e8\n\tto                   0x2222222222222222222222222222222222222222\n\tvalue                1000\n\tblockHash            0xabc\n\tblockNumber          100\n\tfrom                 0x4444444444444444444444444444444444444444\n\taccessList           []\n\thash                 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\tinput                0x\n\tto                   0x5555555555555555555555555555555555555555\n\tvalue                2000\n]\n";
        let out = filter(raw);
        unsafe {
            std::env::remove_var("FOURBYTE_TEST_MOCK");
        }
        assert!(out.contains("[0]"), "missing [0] in: {}", out);
        assert!(out.contains("[1]"), "missing [1] in: {}", out);
        assert!(
            out.contains("transfer(address,uint256)"),
            "missing selector decode in: {}",
            out
        );
    }
}
