//! Filter for `cast receipt` — compresses Foundry receipt output.
//!
//! Strategy (report §3.1): drop `logsBloom`, decode each log's `topics[0]`
//! via [`crate::cmds::eth::fourbyte`] (shell-out to `cast 4byte-event`,
//! cached per invocation), truncate long `data` fields, preserve
//! everything else so the agent still sees status, block, gas, and log
//! addresses.

use std::fmt::Write;

use super::fourbyte;

const DATA_HEAD: usize = 18;
const DATA_TAIL: usize = 14;
// "0x" + 256 hex chars = 128 bytes. Events up to this size render in full;
// only larger payloads get middle-elided.
const DATA_TRUNCATE_THRESHOLD: usize = 258;

/// Filter a raw `cast receipt` stdout string into a compact summary.
pub fn filter(raw: &str) -> String {
    let stripped = crate::core::utils::strip_ansi(raw);
    match try_filter(&stripped) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("[rtk] cast receipt: filter fallthrough: {}", e);
            raw.to_string()
        }
    }
}

fn try_filter(raw: &str) -> Result<String, &'static str> {
    fourbyte::reset_cache();
    let mut out = String::with_capacity(raw.len() / 3);
    let mut in_logs_block = false;
    let mut in_logs_entry = false;
    let mut entry_buf: Vec<String> = Vec::new();
    let mut log_index = 0usize;

    for line in raw.lines() {
        let trimmed = line.trim_end();

        // Drop logsBloom — it's always present and always huge.
        if starts_with_key(trimmed, "logsBloom") {
            continue;
        }

        // The `logs` block appears in two variants:
        //   (a) Single-line JSON: `logs  [{"address":"0x...","topics":[...]}, ...]`
        //       (the format produced by recent foundry `cast receipt`)
        //   (b) Multi-line key-value blocks with `{` / `}` delimiters.
        // Detect (a) first by scanning for the `[{` opener on the same line.
        if starts_with_key(trimmed, "logs") {
            let t = trimmed.trim_start();
            let after_key = &t[4..]; // past "logs"
            let after_key = after_key.trim_start();
            let after_key = after_key.strip_prefix(':').unwrap_or(after_key).trim_start();
            if after_key.starts_with("[{") {
                // Variant (a): parse as JSON array.
                summarise_json_logs(after_key, &mut out);
                continue;
            }
            if after_key.starts_with("[]") {
                out.push_str("logs: 0\n");
                continue;
            }
            in_logs_block = true;
            out.push_str("logs:\n");
            continue;
        }

        if !in_logs_block {
            out.push_str(trimmed);
            out.push('\n');
            continue;
        }

        // Inside the logs block.
        if trimmed.trim_start().starts_with('{') {
            in_logs_entry = true;
            entry_buf.clear();
            continue;
        }
        if in_logs_entry && trimmed.trim_start().starts_with('}') {
            in_logs_entry = false;
            if let Some(line) = summarise_log_entry(log_index, &entry_buf) {
                out.push_str("  ");
                out.push_str(&line);
                out.push('\n');
            }
            log_index += 1;
            continue;
        }
        if in_logs_entry {
            entry_buf.push(trimmed.to_string());
            continue;
        }

        // A line after the logs block closes (e.g., `status`, `transactionHash`)
        // — re-enable plain passthrough for anything not under a log entry.
        if trimmed.trim_start().starts_with(']') || trimmed.is_empty() {
            in_logs_block = false;
            continue;
        }

        // Lines that come after the logs block ends in certain Foundry
        // formats: fall back to direct emit.
        out.push_str(trimmed);
        out.push('\n');
    }

    Ok(out)
}

fn summarise_log_entry(index: usize, entry_lines: &[String]) -> Option<String> {
    let mut address: Option<String> = None;
    let mut topic0: Option<String> = None;
    let mut extra_topics: Vec<String> = Vec::new();
    let mut data: Option<String> = None;
    let mut in_topics = false;

    for line in entry_lines {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("address:") {
            address = Some(rest.trim().to_string());
            in_topics = false;
        } else if l.starts_with("topics:") {
            in_topics = true;
        } else if in_topics {
            let t = l.trim_end_matches(',').trim_matches('"').trim();
            if t.starts_with("0x") {
                if topic0.is_none() {
                    topic0 = Some(t.to_string());
                } else {
                    extra_topics.push(t.to_string());
                }
            } else if l.starts_with(']') {
                in_topics = false;
            }
        } else if let Some(rest) = l.strip_prefix("data:") {
            data = Some(rest.trim().to_string());
            in_topics = false;
        }
    }

    let mut line = String::new();
    let _ = write!(line, "#{} ", index);
    if let Some(addr) = address {
        let _ = write!(line, "@ {} ", short_addr(&addr));
    }
    match &topic0 {
        Some(t) => {
            let decoded = fourbyte::lookup_topic0_hex(t);
            match decoded {
                Some(sig) => {
                    let _ = write!(line, "{}", sig);
                    if !extra_topics.is_empty() {
                        let _ = write!(line, " [+{}]", extra_topics.len());
                    }
                }
                None => {
                    let _ = write!(line, "topic0={}", short_hash(t));
                    if !extra_topics.is_empty() {
                        let _ = write!(line, " [+{} topics]", extra_topics.len());
                    }
                }
            }
        }
        None => {
            let _ = write!(line, "(anonymous)");
        }
    }
    if let Some(d) = data {
        if !d.is_empty() && d != "0x" {
            let _ = write!(line, "  data={}", truncate_hex(&d));
        }
    }
    Some(line)
}

fn starts_with_key(line: &str, key: &str) -> bool {
    let t = line.trim_start();
    t.len() > key.len() && t.as_bytes().first().copied() == Some(key.as_bytes()[0]) && t.starts_with(key)
}

/// Parse a single-line JSON-encoded logs array and append a summary per entry.
///
/// Accepts the `[{...}, {...}, ...]` slice as produced by modern `cast receipt`.
/// On any parse error falls back to emitting a bare `logs: <N entries>` line
/// so the caller still gets a non-fatal output.
fn summarise_json_logs(json_text: &str, out: &mut String) {
    let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(json_text);
    match parsed {
        Ok(entries) => {
            out.push_str(&format!("logs: {}\n", entries.len()));
            for (i, entry) in entries.iter().enumerate() {
                let address = entry
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let data = entry.get("data").and_then(|v| v.as_str()).unwrap_or("");
                let topics: Vec<String> = entry
                    .get("topics")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|t| t.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();

                let mut line = format!("  #{} @ {} ", i, short_addr(address));
                match topics.first() {
                    Some(t0) => match super::fourbyte::lookup_topic0_hex(t0) {
                        Some(sig) => {
                            line.push_str(&sig);
                            if topics.len() > 1 {
                                line.push_str(&format!(" [+{}]", topics.len() - 1));
                            }
                        }
                        None => {
                            line.push_str(&format!("topic0={}", short_hash(t0)));
                            if topics.len() > 1 {
                                line.push_str(&format!(" [+{} topics]", topics.len() - 1));
                            }
                        }
                    },
                    None => line.push_str("(anonymous)"),
                }
                if !data.is_empty() && data != "0x" {
                    line.push_str(&format!("  data={}", truncate_hex(data)));
                }
                out.push_str(&line);
                out.push('\n');
            }
        }
        Err(_) => {
            out.push_str("logs: (unparsed JSON array)\n");
        }
    }
}

fn short_addr(addr: &str) -> String {
    if addr.len() >= 12 && addr.starts_with("0x") {
        format!("{}…{}", &addr[..6], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

fn short_hash(hash: &str) -> String {
    if hash.len() >= 12 && hash.starts_with("0x") {
        format!("{}…", &hash[..10])
    } else {
        hash.to_string()
    }
}

fn truncate_hex(hex: &str) -> String {
    let hex = hex.trim();
    if hex.len() <= DATA_TRUNCATE_THRESHOLD {
        return hex.to_string();
    }
    let hex_body = hex.trim_start_matches("0x");
    let byte_len = hex_body.len() / 2;
    format!(
        "{}…{} ({} bytes)",
        &hex[..DATA_HEAD.min(hex.len())],
        &hex[hex.len() - DATA_TAIL..],
        byte_len
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_on_empty() {
        let out = filter("");
        assert!(out.is_empty());
    }

    #[test]
    fn drops_logsbloom() {
        let raw = "status               1 (success)\nlogsBloom            0x00000000000000000000000000000000\ngasUsed              21000\n";
        let out = filter(raw);
        assert!(!out.contains("logsBloom"));
        assert!(out.contains("status"));
        assert!(out.contains("gasUsed"));
    }

    #[test]
    fn truncate_hex_short_untouched() {
        assert_eq!(truncate_hex("0x1234"), "0x1234");
    }

    #[test]
    fn truncate_hex_128_bytes_untouched() {
        // 128-byte payloads render in full so small events stay readable.
        let at_threshold = format!("0x{}", "ab".repeat(128));
        assert_eq!(truncate_hex(&at_threshold), at_threshold);
    }

    #[test]
    fn truncate_hex_long_shortened() {
        // 200-byte payload (> 128 bytes) gets middle-elided.
        let long = format!("0x{}", "ab".repeat(200));
        let short = truncate_hex(&long);
        assert!(short.len() < long.len());
        assert!(short.contains("…"));
        assert!(short.ends_with("bytes)"));
    }
}
