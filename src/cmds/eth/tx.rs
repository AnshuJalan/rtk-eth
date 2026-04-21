//! Filter for `cast tx` — compresses Foundry transaction output.
//!
//! Strategy (report §3.2): drop `r`/`s`/`v`/`yParity` signature fields
//! (agent can't verify without the private key anyway), decode the
//! `input` field's 4-byte selector via [`super::fourbyte`] (shell-out
//! to `cast 4byte`, cached per invocation), compact `accessList`
//! entries, and preserve the full calldata so the agent can actually
//! read the call arguments — reading calldata is the primary reason to
//! run `cast tx`.

use super::fourbyte;

pub fn filter(raw: &str) -> String {
    let stripped = crate::core::utils::strip_ansi(raw);
    match try_filter(&stripped) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("[rtk] cast tx: filter fallthrough: {}", e);
            raw.to_string()
        }
    }
}

fn try_filter(raw: &str) -> Result<String, &'static str> {
    fourbyte::reset_cache();
    let mut out = String::with_capacity(raw.len() / 2);
    let mut in_access_list = false;
    let mut access_entries = 0usize;
    let mut access_total_slots = 0usize;
    let mut access_addr_buf: Option<String> = None;
    let mut access_slot_count = 0usize;

    for line in raw.lines() {
        let trimmed = line.trim_end();

        if starts_with_key(trimmed, "r ")
            || starts_with_key(trimmed, "s ")
            || starts_with_key(trimmed, "v ")
            || starts_with_key(trimmed, "yParity")
        {
            continue;
        }

        if starts_with_key(trimmed, "accessList") {
            // Detect inline empty form: `accessList           []` (Foundry's
            // shape for any tx without storage keys, i.e. the vast majority).
            // Skip the state-machine entirely so we don't swallow the fields
            // that follow on subsequent lines.
            let after_key = trimmed
                .trim_start()
                .trim_start_matches("accessList")
                .trim_start();
            let after_key = after_key.strip_prefix(':').unwrap_or(after_key).trim_start();
            if after_key.starts_with("[]") {
                out.push_str("accessList: [0 entries, 0 slots total]\n");
                continue;
            }
            in_access_list = true;
            access_entries = 0;
            access_total_slots = 0;
            access_addr_buf = None;
            access_slot_count = 0;
            out.push_str("accessList: ");
            // leave the count placeholder — we patch it at block end
            continue;
        }

        if in_access_list {
            let t = trimmed.trim();
            // End of accessList: a blank line.
            if t.is_empty() {
                in_access_list = false;
                if let Some(a) = access_addr_buf.take() {
                    access_entries += 1;
                    access_total_slots += access_slot_count;
                    append_access_entry(&mut out, &a, access_slot_count);
                    access_slot_count = 0;
                }
                finalize_access_list(&mut out, access_entries, access_total_slots);
                continue;
            }
            // Foundry's access list pretty form typically has:
            //   address: 0x...
            //     storageKeys: [ 0x..., 0x... ]
            if let Some(addr) = t.strip_prefix("address:") {
                if let Some(a) = access_addr_buf.take() {
                    access_entries += 1;
                    access_total_slots += access_slot_count;
                    append_access_entry(&mut out, &a, access_slot_count);
                }
                access_addr_buf = Some(addr.trim().to_string());
                access_slot_count = 0;
                continue;
            }
            if t.starts_with("0x") && t.len() >= 66 {
                access_slot_count += 1;
                continue;
            }
            // A top-level field line (unindented, letter-initial, e.g.
            // `chainId 1`) ends the access list. Finalize and fall through
            // so this line gets processed normally — otherwise we'd swallow
            // `chainId`/`gasLimit`/`to`/`value`/... on the common
            // `accessList` → next-section shape without a blank separator.
            let first = trimmed.as_bytes().first().copied();
            let is_unindented_key =
                !trimmed.starts_with(' ') && first.is_some_and(|b| b.is_ascii_alphabetic());
            if is_unindented_key {
                if let Some(a) = access_addr_buf.take() {
                    access_entries += 1;
                    access_total_slots += access_slot_count;
                    append_access_entry(&mut out, &a, access_slot_count);
                    access_slot_count = 0;
                }
                finalize_access_list(&mut out, access_entries, access_total_slots);
                in_access_list = false;
                // fall through — do NOT `continue`
            } else {
                // Unknown indented line inside the access list (storageKeys:
                // header, `[`/`]` brackets, etc.) — skip silently.
                continue;
            }
        }

        if let Some(input) = trimmed.strip_prefix("input") {
            let after = input.trim_start();
            let value = after.trim();
            out.push_str("input: ");
            out.push_str(&summarise_input(value));
            out.push('\n');
            continue;
        }
        // Some foundry formats prefix with extra spaces or align keys.
        let leading_trimmed = trimmed.trim_start();
        if let Some(rest) = leading_trimmed.strip_prefix("input ") {
            out.push_str("input: ");
            out.push_str(&summarise_input(rest.trim()));
            out.push('\n');
            continue;
        }
        if let Some(rest) = leading_trimmed.strip_prefix("input:") {
            out.push_str("input: ");
            out.push_str(&summarise_input(rest.trim()));
            out.push('\n');
            continue;
        }

        out.push_str(trimmed);
        out.push('\n');
    }

    if in_access_list {
        if let Some(a) = access_addr_buf.take() {
            access_entries += 1;
            access_total_slots += access_slot_count;
            append_access_entry(&mut out, &a, access_slot_count);
        }
        finalize_access_list(&mut out, access_entries, access_total_slots);
    }

    Ok(out)
}

fn append_access_entry(out: &mut String, addr: &str, slots: usize) {
    let short = short_addr(addr);
    out.push_str(&format!("\n  {} ({} slot{})", short, slots, if slots == 1 { "" } else { "s" }));
}

fn finalize_access_list(out: &mut String, entries: usize, total_slots: usize) {
    out.push_str(&format!(
        "\n  [{} entries, {} slots total]\n",
        entries, total_slots
    ));
}

fn summarise_input(value: &str) -> String {
    let v = value.trim();
    if !v.starts_with("0x") {
        return v.to_string();
    }
    let body = &v[2..];
    if body.len() < 8 {
        return v.to_string();
    }
    let sel_hex = &body[..8];
    let decoded = fourbyte::lookup_selector_hex(sel_hex);
    compact_calldata(v, decoded.as_deref())
}

fn compact_calldata(hex: &str, decoded: Option<&str>) -> String {
    let label = match decoded {
        Some(sig) => format!("0x{} [{}]", &hex[2..10], sig),
        None => format!("0x{}", &hex[2..10]),
    };
    if hex.len() <= 10 {
        return label;
    }
    format!("{} {}", label, &hex[10..])
}

fn starts_with_key(line: &str, key: &str) -> bool {
    line.trim_start().starts_with(key)
}

fn short_addr(addr: &str) -> String {
    if addr.len() >= 12 && addr.starts_with("0x") {
        format!("{}…{}", &addr[..6], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
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
    fn drops_signature_fields() {
        let raw = "blockNumber         19000000\nr                    0xaaaaaa\ns                    0xbbbbbb\nv                    27\nyParity              0x1\ngas                  21000\n";
        let out = filter(raw);
        assert!(!out.contains("\nr "));
        assert!(!out.contains("\ns "));
        assert!(!out.contains("yParity"));
        assert!(out.contains("blockNumber"));
        assert!(out.contains("gas"));
    }

    #[test]
    fn decodes_known_selector() {
        // SAFETY: tests run sequentially; set_var is safe here since no
        // other thread reads FOURBYTE_TEST_MOCK.
        unsafe {
            std::env::set_var(
                "FOURBYTE_TEST_MOCK",
                "0xa9059cbb=transfer(address,uint256)",
            );
        }
        let raw = "input                0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000016345785d8a0000\n";
        let out = filter(raw);
        unsafe {
            std::env::remove_var("FOURBYTE_TEST_MOCK");
        }
        assert!(
            out.contains("transfer(address,uint256)"),
            "expected decoded selector, got:\n{out}"
        );
    }

    #[test]
    fn preserves_fields_after_inline_empty_accesslist() {
        // Foundry emits `accessList           []` inline for any tx without
        // storage keys. Before the fix, the state machine entered
        // in_access_list mode and swallowed every subsequent field until a
        // blank line — dropping `chainId`, `gasLimit`, `to`, `value`, `input`,
        // etc. Regression guard for the exact shape from
        // tests/fixtures/cast/tx_raw.txt.
        let raw = concat!(
            "accessList           []\n",
            "chainId              1\n",
            "gasLimit             27300\n",
            "hash                 0xc520c8028b7da779c113140fc6c30dbef4c8696d9cad73eadb37ef06052c8021\n",
            "input                0x\n",
            "maxFeePerGas         703345112\n",
            "maxPriorityFeePerGas 150000\n",
            "nonce                0\n",
            "to                   0x2CfF890f0378a11913B6129B2E97417a2c302680\n",
            "type                 2\n",
            "value                993000000000000\n",
        );
        let out = filter(raw);
        for key in [
            "chainId",
            "gasLimit",
            "hash",
            "input",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "nonce",
            "to",
            "type",
            "value",
        ] {
            assert!(
                out.contains(key),
                "field `{}` missing from filtered output:\n{}",
                key,
                out
            );
        }
        // The inline `[]` form should still render the access-list summary.
        assert!(
            out.contains("accessList: [0 entries, 0 slots total]"),
            "access-list summary missing:\n{}",
            out
        );
    }

    #[test]
    fn preserves_fields_after_populated_accesslist() {
        // Non-empty access list followed immediately by another top-level
        // key (no blank separator). Before the fix, `chainId`/`to`/`value`
        // would be swallowed by the state machine waiting for a blank line.
        //
        // Uses the `address:`-bare shape the existing parser recognises;
        // Foundry's `- address:` shape for populated lists is a broader
        // rework, out of scope for this bug fix.
        let raw = concat!(
            "accessList:\n",
            "  address: 0xabababababababababababababababababababab\n",
            "    storageKeys: [\n",
            "      0x0000000000000000000000000000000000000000000000000000000000000001,\n",
            "      0x0000000000000000000000000000000000000000000000000000000000000002\n",
            "    ]\n",
            "chainId              1\n",
            "to                   0x2CfF890f0378a11913B6129B2E97417a2c302680\n",
            "value                1000\n",
        );
        let out = filter(raw);
        assert!(out.contains("chainId"), "chainId dropped:\n{}", out);
        assert!(out.contains("to "), "to dropped:\n{}", out);
        assert!(out.contains("value"), "value dropped:\n{}", out);
        // Access-list summary renders with the entry count.
        assert!(
            out.contains("entries") && out.contains("slots total"),
            "access-list summary missing:\n{}",
            out
        );
    }

    #[test]
    fn preserves_full_calldata_args() {
        // Reading calldata is the primary value of `cast tx` — the args
        // after the selector must survive the filter verbatim.
        let raw = "input                0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000016345785d8a0000\n";
        let out = filter(raw);
        assert!(
            out.contains("0000000000000000000000001111111111111111111111111111111111111111"),
            "address arg dropped from calldata: {}",
            out
        );
        assert!(
            out.contains("000000000000000000000000000000000000000000000000016345785d8a0000"),
            "value arg dropped from calldata: {}",
            out
        );
    }
}
