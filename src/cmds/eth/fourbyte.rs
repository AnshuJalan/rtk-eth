//! On-demand function selector / event topic decoding via `cast 4byte`.
//!
//! Replaces the old bundled selector/topic tables. Each lookup shells out
//! to `cast 4byte <sel>` or `cast 4byte-event <topic0>` (openchain.xyz),
//! with:
//!   - a **2000ms per-call timeout** — the child is killed on expiry so a
//!     slow or hung remote cannot stall the filter. Empirically `cast`
//!     cold-call is ~850-950ms (TLS handshake + openchain RTT), so 500ms
//!     was too aggressive and caused every call to time out.
//!   - per-invocation **memoization** in a `thread_local!` HashMap so the
//!     same selector/topic seen 100× in one `cast logs` dump only costs
//!     one network call,
//!   - **silent fallback to `None`** on every failure path (timeout,
//!     non-zero exit, empty stdout, `cast` not on PATH). Callers already
//!     handle `None` by rendering truncated hex, which is the desired
//!     degraded behaviour.
//!
//! Call `reset_cache()` at the top of each filter's `try_filter` so state
//! doesn't leak across RTK invocations.
//!
//! Tests: the `FOURBYTE_TEST_MOCK` env var overrides the subprocess with a
//! canned response so unit tests never hit the network.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::core::utils::{resolved_command, strip_ansi};

const LOOKUP_TIMEOUT: Duration = Duration::from_millis(2000);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

thread_local! {
    static SEL_CACHE: RefCell<HashMap<String, Option<String>>> = RefCell::new(HashMap::new());
    static TOPIC_CACHE: RefCell<HashMap<String, Option<String>>> = RefCell::new(HashMap::new());
}

/// Clear both caches. Call at the start of every `try_filter` so lookups
/// don't bleed between invocations.
pub fn reset_cache() {
    SEL_CACHE.with(|c| c.borrow_mut().clear());
    TOPIC_CACHE.with(|c| c.borrow_mut().clear());
}

/// Decode a 4-byte selector given as a hex string (with or without `0x`,
/// case-insensitive). Returns `None` if the input isn't 8 hex chars.
pub fn lookup_selector_hex(hex8: &str) -> Option<String> {
    let clean = hex8.trim_start_matches("0x").trim_start_matches("0X");
    if clean.len() != 8 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let normalised = format!("0x{}", clean.to_ascii_lowercase());
    cached_lookup(&SEL_CACHE, &normalised, &["4byte", &normalised])
}

/// Decode a 32-byte event topic0 hash into its canonical signature.
/// Accepts hex with or without `0x`, case-insensitive.
pub fn lookup_topic0_hex(hex64: &str) -> Option<String> {
    let clean = hex64.trim_start_matches("0x").trim_start_matches("0X");
    if clean.len() != 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let normalised = format!("0x{}", clean.to_ascii_lowercase());
    cached_lookup(&TOPIC_CACHE, &normalised, &["4byte-event", &normalised])
}

fn cached_lookup(
    cache: &'static std::thread::LocalKey<RefCell<HashMap<String, Option<String>>>>,
    key: &str,
    cast_args: &[&str],
) -> Option<String> {
    if let Some(hit) = cache.with(|c| c.borrow().get(key).cloned()) {
        return hit;
    }
    let resolved = run_cast(cast_args);
    cache.with(|c| c.borrow_mut().insert(key.to_string(), resolved.clone()));
    resolved
}

/// Run `cast <args...>`, returning the first non-empty stdout line on
/// clean exit. Any failure path (spawn error, non-zero exit, timeout,
/// empty stdout) returns `None`.
fn run_cast(args: &[&str]) -> Option<String> {
    #[cfg(test)]
    if let Ok(mock) = std::env::var("FOURBYTE_TEST_MOCK") {
        return mock_response(&mock, args);
    }

    let mut cmd = resolved_command("cast");
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    let mut child = cmd.spawn().ok()?;
    let started = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut buf = String::new();
                child.stdout.as_mut()?.read_to_string(&mut buf).ok()?;
                return parse_first_line(&buf);
            }
            Ok(None) => {
                if started.elapsed() >= LOOKUP_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return None,
        }
    }
}

fn parse_first_line(raw: &str) -> Option<String> {
    for line in strip_ansi(raw).lines() {
        let t = line.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    None
}

#[cfg(test)]
fn mock_response(spec: &str, args: &[&str]) -> Option<String> {
    if spec == "__empty__" {
        return None;
    }
    let needle = *args.last()?;
    for pair in spec.split(';') {
        let (k, v) = pair.split_once('=')?;
        if k == needle {
            return Some(v.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_mock<F: FnOnce()>(spec: &str, f: F) {
        reset_cache();
        // SAFETY: tests run sequentially in the same process; set_var is
        // safe here because no other thread reads FOURBYTE_TEST_MOCK.
        unsafe {
            std::env::set_var("FOURBYTE_TEST_MOCK", spec);
        }
        f();
        unsafe {
            std::env::remove_var("FOURBYTE_TEST_MOCK");
        }
        reset_cache();
    }

    #[test]
    fn selector_hit_via_mock() {
        with_mock("0xa9059cbb=transfer(address,uint256)", || {
            let sig = lookup_selector_hex("0xa9059cbb");
            assert_eq!(sig.as_deref(), Some("transfer(address,uint256)"));
        });
    }

    #[test]
    fn topic_hit_via_mock() {
        let t = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
        with_mock(
            &format!("{}=Transfer(address,address,uint256)", t),
            || {
                let sig = lookup_topic0_hex(t);
                assert_eq!(sig.as_deref(), Some("Transfer(address,address,uint256)"));
            },
        );
    }

    #[test]
    fn selector_miss_returns_none() {
        with_mock("__empty__", || {
            assert!(lookup_selector_hex("0xdeadbeef").is_none());
        });
    }

    #[test]
    fn rejects_malformed_selector_hex() {
        // Short-circuit before any subprocess attempt.
        assert!(lookup_selector_hex("0xdead").is_none());
        assert!(lookup_selector_hex("nothex!!").is_none());
    }

    #[test]
    fn rejects_malformed_topic_hex() {
        assert!(lookup_topic0_hex("0xabc").is_none());
        assert!(lookup_topic0_hex(&"z".repeat(64)).is_none());
    }

    #[test]
    fn case_insensitive_hex_normalisation() {
        with_mock("0xa9059cbb=transfer(address,uint256)", || {
            assert_eq!(
                lookup_selector_hex("0xA9059CBB").as_deref(),
                Some("transfer(address,uint256)")
            );
        });
    }

    #[test]
    fn cache_collapses_repeat_lookups() {
        // Prime the cache with a mock hit, then change the mock to empty.
        // If the cache works, the second call still returns the original hit.
        reset_cache();
        unsafe {
            std::env::set_var("FOURBYTE_TEST_MOCK", "0xa9059cbb=transfer(address,uint256)");
        }
        let first = lookup_selector_hex("0xa9059cbb");
        unsafe {
            std::env::set_var("FOURBYTE_TEST_MOCK", "__empty__");
        }
        let second = lookup_selector_hex("0xa9059cbb");
        unsafe {
            std::env::remove_var("FOURBYTE_TEST_MOCK");
        }
        reset_cache();
        assert_eq!(first, second);
        assert_eq!(first.as_deref(), Some("transfer(address,uint256)"));
    }

    #[test]
    fn reset_cache_clears_entries() {
        reset_cache();
        unsafe {
            std::env::set_var("FOURBYTE_TEST_MOCK", "0xa9059cbb=transfer(address,uint256)");
        }
        assert!(lookup_selector_hex("0xa9059cbb").is_some());
        unsafe {
            std::env::set_var("FOURBYTE_TEST_MOCK", "__empty__");
        }
        reset_cache();
        let miss_after_reset = lookup_selector_hex("0xa9059cbb");
        unsafe {
            std::env::remove_var("FOURBYTE_TEST_MOCK");
        }
        reset_cache();
        assert!(miss_after_reset.is_none());
    }

    #[test]
    fn parse_first_line_skips_blanks() {
        assert_eq!(
            parse_first_line("\n\n  Transfer(address,address,uint256)\n").as_deref(),
            Some("Transfer(address,address,uint256)")
        );
    }

    #[test]
    fn parse_first_line_strips_ansi() {
        let ansi = "\x1b[32mtransfer(address,uint256)\x1b[0m";
        assert_eq!(
            parse_first_line(ansi).as_deref(),
            Some("transfer(address,uint256)")
        );
    }
}
