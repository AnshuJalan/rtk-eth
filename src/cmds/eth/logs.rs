//! Filter for `cast logs` — compresses Foundry log queries.
//!
//! Strategy (report §3.4): group entries by `blockNumber`, show
//! `Block N (M logs)` headers, then a one-line summary per entry
//! `  <Event> @ <addr>  tx 0x…` using [`super::fourbyte`] for topic0
//! decoding (shell-outs to `cast 4byte-event`, cached per invocation).
//! `data` >128 chars is truncated with byte count.

use std::collections::BTreeMap;

use super::fourbyte;

#[derive(Default, Debug, Clone)]
struct LogEntry {
    address: Option<String>,
    block_number: Option<String>,
    tx_hash: Option<String>,
    topics: Vec<String>,
    data: Option<String>,
    removed: Option<String>,
}

pub fn filter(raw: &str) -> String {
    let stripped = crate::core::utils::strip_ansi(raw);
    match try_filter(&stripped) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("[rtk] cast logs: filter fallthrough: {}", e);
            raw.to_string()
        }
    }
}

fn try_filter(raw: &str) -> Result<String, &'static str> {
    fourbyte::reset_cache();
    let entries = parse_entries(raw);
    if entries.is_empty() {
        // Either no logs or we failed to parse. Return raw so the agent
        // isn't starved of information.
        return Ok(raw.to_string());
    }

    let mut by_block: BTreeMap<u64, Vec<LogEntry>> = BTreeMap::new();
    let mut unknown_block: Vec<LogEntry> = Vec::new();
    for e in entries {
        match e.block_number.as_deref().and_then(parse_block_number) {
            Some(n) => by_block.entry(n).or_default().push(e),
            None => unknown_block.push(e),
        }
    }

    let mut out = String::with_capacity(raw.len() / 3);
    for (block, logs) in &by_block {
        out.push_str(&format!("Block {} ({} log{}):\n", block, logs.len(), if logs.len() == 1 { "" } else { "s" }));
        for log in logs {
            out.push_str("  ");
            out.push_str(&format_log_line(log));
            out.push('\n');
        }
    }
    if !unknown_block.is_empty() {
        out.push_str(&format!("Unspecified block ({} logs):\n", unknown_block.len()));
        for log in &unknown_block {
            out.push_str("  ");
            out.push_str(&format_log_line(log));
            out.push('\n');
        }
    }

    Ok(out)
}

fn parse_entries(raw: &str) -> Vec<LogEntry> {
    let mut entries: Vec<LogEntry> = Vec::new();
    let mut current = LogEntry::default();
    let mut in_topics = false;

    for line in raw.lines() {
        let t = line.trim();

        if t.is_empty() {
            if !current_is_empty(&current) {
                entries.push(std::mem::take(&mut current));
            }
            in_topics = false;
            continue;
        }

        // Foundry `cast logs` uses `- address:` as the entry separator (no
        // blank line between entries). Treat a new address key as the start
        // of a new entry and flush the previous one.
        let dashless = t.strip_prefix("- ").unwrap_or(t);
        if let Some(rest) = strip_key(dashless, "address") {
            if !current_is_empty(&current) {
                entries.push(std::mem::take(&mut current));
            }
            current.address = Some(rest.to_string());
            in_topics = false;
            continue;
        }

        if let Some(rest) = strip_key(t, "blockHash") {
            let _ = rest;
            in_topics = false;
        } else if let Some(rest) = strip_key(t, "blockNumber") {
            current.block_number = Some(rest.to_string());
            in_topics = false;
        } else if let Some(rest) = strip_key(t, "transactionHash") {
            current.tx_hash = Some(rest.to_string());
            in_topics = false;
        } else if let Some(rest) = strip_key(t, "data") {
            current.data = Some(rest.to_string());
            in_topics = false;
        } else if let Some(rest) = strip_key(t, "removed") {
            current.removed = Some(rest.to_string());
            in_topics = false;
        } else if strip_key(t, "topics").is_some() {
            in_topics = true;
        } else if in_topics && t.starts_with("0x") {
            let cleaned = t.trim_end_matches(',').trim_matches('"').to_string();
            current.topics.push(cleaned);
        } else if in_topics && t.starts_with(']') {
            in_topics = false;
        } else {
            // Unknown line (logIndex, transactionIndex, continuations).
            // Don't reset in_topics — we're only *inside* topics between
            // `topics: [` and the closing `]`.
        }
    }

    if !current_is_empty(&current) {
        entries.push(current);
    }

    entries
}

fn strip_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let t = line.trim_start();
    if !t.starts_with(key) {
        return None;
    }
    let rest = &t[key.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':').unwrap_or(rest).trim_start();
    Some(rest)
}

fn current_is_empty(e: &LogEntry) -> bool {
    e.address.is_none()
        && e.block_number.is_none()
        && e.tx_hash.is_none()
        && e.topics.is_empty()
        && e.data.is_none()
        && e.removed.is_none()
}

fn parse_block_number(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn format_log_line(log: &LogEntry) -> String {
    let addr = log
        .address
        .as_deref()
        .map(short_addr)
        .unwrap_or_else(|| "?".to_string());
    let sig: String = match log.topics.first() {
        Some(t0) => match fourbyte::lookup_topic0_hex(t0) {
            Some(name) => name,
            None => short_hash(t0),
        },
        None => "(anonymous)".to_string(),
    };
    let extra = if log.topics.len() > 1 {
        format!(" [+{}]", log.topics.len() - 1)
    } else {
        String::new()
    };
    // Tx hash stays full — composes with the next `cast receipt`/`cast tx`.
    let tx = log
        .tx_hash
        .as_deref()
        .map(|h| format!("  tx {}", h.trim()))
        .unwrap_or_default();
    let data = log
        .data
        .as_deref()
        .filter(|d| !d.is_empty() && *d != "0x")
        .map(|d| format!("  data={}", compact_data(d)))
        .unwrap_or_default();

    format!("{} @ {}{}{}{}", sig, addr, extra, tx, data)
}

fn short_addr(addr: &str) -> String {
    let a = addr.trim();
    if a.len() >= 12 && a.starts_with("0x") {
        format!("{}…{}", &a[..6], &a[a.len() - 4..])
    } else {
        a.to_string()
    }
}

fn short_hash(hash: &str) -> String {
    let h = hash.trim();
    if h.len() >= 12 && h.starts_with("0x") {
        format!("{}…", &h[..10])
    } else {
        h.to_string()
    }
}

fn compact_data(data: &str) -> String {
    let d = data.trim();
    // "0x" + 256 hex chars = 128 bytes. Small data fields render in full;
    // only larger payloads get middle-elided.
    if d.len() <= 258 {
        return d.to_string();
    }
    let body = d.trim_start_matches("0x");
    let byte_len = body.len() / 2;
    format!("{}…{} ({} bytes)", &d[..18], &d[d.len() - 14..], byte_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_on_empty() {
        assert_eq!(filter(""), "");
    }

    #[test]
    fn groups_by_block_number() {
        // SAFETY: tests run sequentially; set_var is safe here since no
        // other thread reads FOURBYTE_TEST_MOCK.
        let t0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
        unsafe {
            std::env::set_var(
                "FOURBYTE_TEST_MOCK",
                format!("{}=Transfer(address,address,uint256)", t0),
            );
        }
        let raw = "address: 0x1111111111111111111111111111111111111111\nblockNumber: 100\ntransactionHash: 0xaaaa\ntopics: [\n  0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\n]\ndata: 0x\n\naddress: 0x2222222222222222222222222222222222222222\nblockNumber: 100\ntransactionHash: 0xbbbb\ntopics: [\n  0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\n]\ndata: 0x\n";
        let out = filter(raw);
        unsafe {
            std::env::remove_var("FOURBYTE_TEST_MOCK");
        }
        assert!(out.contains("Block 100"), "missing block header:\n{out}");
        assert!(out.contains("Transfer"), "missing Transfer label:\n{out}");
    }

    #[test]
    fn shrinks_output() {
        let raw = "address: 0x1111111111111111111111111111111111111111\nblockNumber: 0x64\ntransactionHash: 0xaaaabbbbccccdddd\ntopics: [\n  0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\n  0x0000000000000000000000000000000000000000000000000000000000000001\n  0x0000000000000000000000000000000000000000000000000000000000000002\n]\ndata: 0x\n";
        let out = filter(raw);
        assert!(out.len() < raw.len());
    }
}
