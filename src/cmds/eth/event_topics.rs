//! Bundled event topic-0 table for canonical Solidity events.
//!
//! Ethereum events record the keccak256 of the event signature as the first
//! log topic (`topics[0]`). This table maps well-known topic0 values to the
//! human-readable signature so log output can be labelled.
//!
//! The list is deliberately conservative — it ships only canonical topics
//! that have been verified against their signatures. A wrong mapping would
//! mislabel a log (worse than no label), so speculative entries are omitted.
//! For unknown topics the filter falls back to a truncated hex display.
//!
//! Entries are sorted ascending by the 32-byte key (split as two `u128`
//! halves) and resolved via `binary_search_by_key` in O(log N).

/// Look up a human-readable event signature for a 32-byte topic0 hash.
pub fn lookup(topic0: [u8; 32]) -> Option<&'static str> {
    let hi = u128::from_be_bytes(topic0[..16].try_into().ok()?);
    let lo = u128::from_be_bytes(topic0[16..].try_into().ok()?);
    TOPICS
        .binary_search_by_key(&(hi, lo), |&(h, l, _)| (h, l))
        .ok()
        .map(|i| TOPICS[i].2)
}

/// Look up by hex string (with or without `0x` prefix, case-insensitive).
pub fn lookup_hex(hex: &str) -> Option<&'static str> {
    let clean = hex.trim_start_matches("0x").trim_start_matches("0X");
    if clean.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    lookup(bytes)
}

/// Sorted (ascending by the 32-byte key) table of canonical event topics and
/// their Solidity signatures. Each entry is `(hi128, lo128, signature)`.
///
/// Keep this list sorted — a runtime test enforces strict ordering.
pub const TOPICS: &[(u128, u128, &str)] = &[
    // ApprovalForAll(address,address,bool) — ERC721, ERC1155
    // keccak256 = 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31
    (
        0x17307eab39ab6107e8899845ad3d59bd,
        0x9653f200f220920489ca2b5937696c31,
        "ApprovalForAll(address,address,bool)",
    ),
    // Approval(address,address,uint256) — ERC20, ERC721
    // keccak256 = 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925
    (
        0x8c5be1e5ebec7d5bd14f71427d1e84f3,
        0xdd0314c0f7b2291e5b200ac8c7c3b925,
        "Approval(address,address,uint256)",
    ),
    // Transfer(address,address,uint256) — ERC20, ERC721
    // keccak256 = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
    (
        0xddf252ad1be2c89b69c2b068fc378daa,
        0x952ba7f163c4a11628f55a4df523b3ef,
        "Transfer(address,address,uint256)",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_table_is_strictly_sorted() {
        for w in TOPICS.windows(2) {
            let a = (w[0].0, w[0].1);
            let b = (w[1].0, w[1].1);
            assert!(a < b, "TOPICS must be strictly ascending");
        }
    }

    #[test]
    fn lookup_transfer_by_hex() {
        assert_eq!(
            lookup_hex("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
            Some("Transfer(address,address,uint256)")
        );
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert_eq!(
            lookup_hex("0xDDF252AD1BE2C89B69C2B068FC378DAA952BA7F163C4A11628F55A4DF523B3EF"),
            Some("Transfer(address,address,uint256)")
        );
    }

    #[test]
    fn lookup_approval() {
        assert_eq!(
            lookup_hex("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"),
            Some("Approval(address,address,uint256)")
        );
    }

    #[test]
    fn lookup_rejects_wrong_length() {
        assert!(lookup_hex("0xdeadbeef").is_none());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        )
        .is_none());
    }
}
