//! Filter for `cast run` — compresses Foundry transaction trace output.
//!
//! Strategy (report §3.3, open question 4 → conservative):
//! 1. Strip ANSI (cast colorizes by default).
//! 2. Collapse runs of syntactically identical **consecutive pairs** of
//!    lines (period-2) — Foundry interleaves call + return lines, so a
//!    loop-body `call/ret/call/ret/...` only collapses when we compare
//!    two-line windows. Still works with period-1 (run of identical
//!    single lines) as a degenerate case.
//! 3. Detect and collapse proxy delegatecall echo — two consecutive frames
//!    with matching selector + CALL/DELEGATECALL kind pair (addresses may
//!    differ, as in EIP-1967 proxy → implementation).
//! 4. Pass through unchanged lines (everything outside collapsible runs).
//! 5. On any parse issue fall back to raw.

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Matches Foundry's boxed trace frame prefix: leading whitespace +
    /// optional box-drawing chars. Used to find the "payload" for equality
    /// comparison independent of depth indentation.
    static ref INDENT_RE: Regex =
        Regex::new(r"^[\s│├└─┬│]*").expect("INDENT_RE");

    /// Extracts the target address from a trace line like `[...] 0xABC::foo()`.
    static ref TARGET_ADDR_RE: Regex =
        Regex::new(r"(0x[0-9a-fA-F]{40})::").expect("TARGET_ADDR_RE");

    /// Extracts the function signature from a trace line body.
    static ref FN_SIG_RE: Regex =
        Regex::new(r"::(\w+)\(").expect("FN_SIG_RE");

    /// CALL / STATICCALL / DELEGATECALL marker.
    static ref CALL_KIND_RE: Regex =
        Regex::new(r"\[(CALL|STATICCALL|DELEGATECALL|CREATE|CREATE2)\]")
            .expect("CALL_KIND_RE");
}

const RUN_COLLAPSE_MIN: usize = 3;

pub fn filter(raw: &str) -> String {
    let stripped = crate::core::utils::strip_ansi(raw);
    match try_filter(&stripped) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("[rtk] cast run: filter fallthrough: {}", e);
            raw.to_string()
        }
    }
}

fn try_filter(raw: &str) -> Result<String, &'static str> {
    let lines: Vec<&str> = raw.lines().collect();
    if lines.is_empty() {
        return Ok(String::new());
    }

    // Normalised payload per line (strip leading indent/box-drawing) used
    // for equality comparison independent of depth.
    let normalised: Vec<String> = lines
        .iter()
        .map(|l| INDENT_RE.replace(l, "").into_owned())
        .collect();

    let mut out = String::with_capacity(raw.len() / 2);
    let mut i = 0;
    while i < lines.len() {
        // Try period-2 collapse first: a `call/ret` pair that repeats
        // ≥RUN_COLLAPSE_MIN times. This is the common Foundry trace shape
        // for loop bodies (getReserves, balanceOf, per-iteration swaps).
        if i + 4 <= lines.len()
            && normalised[i] == normalised[i + 2]
            && normalised[i + 1] == normalised[i + 3]
            && normalised[i] != normalised[i + 1]
        {
            let mut k = 2; // at least 2 repetitions confirmed
            while i + 2 * (k + 1) <= lines.len()
                && normalised[i] == normalised[i + 2 * k]
                && normalised[i + 1] == normalised[i + 2 * k + 1]
            {
                k += 1;
            }
            if k >= RUN_COLLAPSE_MIN {
                out.push_str(lines[i]);
                out.push('\n');
                out.push_str(lines[i + 1]);
                out.push('\n');
                out.push_str(&format!("  … (×{} pairs)\n", k));
                i += 2 * k;
                continue;
            }
        }

        // Period-1 collapse: run of identical consecutive lines
        // (e.g., 4 identical multicall DELEGATECALLs with no return line).
        let mut j = i + 1;
        while j < lines.len() && normalised[j] == normalised[i] {
            j += 1;
        }
        let run_len = j - i;
        if run_len >= RUN_COLLAPSE_MIN {
            out.push_str(lines[i]);
            out.push_str(&format!("  … (×{})", run_len));
            out.push('\n');
            i = j;
            continue;
        }

        // Proxy delegatecall echo: two adjacent frames with same selector
        // and CALL/DELEGATECALL kind pair (EIP-1967 proxy → impl).
        if i + 1 < lines.len() && run_len == 1 && is_proxy_echo(lines[i], lines[i + 1]) {
            out.push_str(lines[i]);
            out.push('\n');
            out.push_str("  ↳ (proxy delegatecall echoed)\n");
            i += 2;
            continue;
        }

        // Emit the small run as-is.
        for k in 0..run_len {
            out.push_str(lines[i + k]);
            out.push('\n');
        }
        i = j;
    }

    Ok(out)
}

fn is_proxy_echo(a: &str, b: &str) -> bool {
    // Proxy echo: immediately-adjacent CALL/DELEGATECALL frames with the
    // same function selector. Target addresses typically DIFFER for real
    // EIP-1967 proxies (proxy ↔ implementation) but may match in synthetic
    // tests — so we only require selector + kind-pair equality.
    let a_sig = FN_SIG_RE.captures(a).and_then(|c| c.get(1));
    let b_sig = FN_SIG_RE.captures(b).and_then(|c| c.get(1));
    let a_kind = CALL_KIND_RE.captures(a).and_then(|c| c.get(1));
    let b_kind = CALL_KIND_RE.captures(b).and_then(|c| c.get(1));

    let (Some(asig), Some(bsig)) = (a_sig, b_sig) else {
        return false;
    };
    let (Some(ak), Some(bk)) = (a_kind, b_kind) else {
        return false;
    };

    if asig.as_str() != bsig.as_str() {
        return false;
    }

    let k1 = ak.as_str();
    let k2 = bk.as_str();
    matches!(
        (k1, k2),
        ("CALL", "DELEGATECALL") | ("DELEGATECALL", "CALL") | ("STATICCALL", "DELEGATECALL")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_on_empty() {
        assert_eq!(filter(""), "");
    }

    #[test]
    fn collapses_identical_consecutive_lines() {
        let raw = "│   ├─ [CALL] 0xAaa::foo()\n│   ├─ [CALL] 0xAaa::foo()\n│   ├─ [CALL] 0xAaa::foo()\n│   ├─ [CALL] 0xBbb::bar()\n";
        let out = filter(raw);
        assert!(out.contains("×3"));
        assert!(out.contains("0xBbb::bar()"));
    }

    #[test]
    fn single_lines_untouched() {
        let raw = "│   ├─ [CALL] 0xAaa::foo()\n│   ├─ [CALL] 0xBbb::bar()\n";
        let out = filter(raw);
        assert!(!out.contains("×"));
    }

    #[test]
    fn detects_proxy_delegatecall_echo() {
        let raw = "│   ├─ [CALL] 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa::foo()\n│   │   └─ [DELEGATECALL] 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa::foo()\n";
        let out = filter(raw);
        assert!(out.contains("proxy delegatecall echoed"));
    }

    #[test]
    fn collapses_period2_call_return_pairs() {
        let raw = "├─ [24567] 0xbbb::balanceOf() [STATICCALL]\n│   └─ ← [Return] 1\n├─ [24567] 0xbbb::balanceOf() [STATICCALL]\n│   └─ ← [Return] 1\n├─ [24567] 0xbbb::balanceOf() [STATICCALL]\n│   └─ ← [Return] 1\n";
        let out = filter(raw);
        assert!(out.contains("(×3 pairs)"), "expected pair-collapse marker, got:\n{out}");
        assert!(out.len() < raw.len());
    }
}
