// Project tag
pub const PROJECT_TAG: &str = "Cube";

// Genesis payload inscription data.
pub const GENESIS_INSCRIPTION: &[u8] = b"O Moses! Do not be afraid. Indeed, you will be the one who prevails. \n\nThrow what is in your right hand. It will swallow up what those magicians have crafted.";

/// Signet parameters.
///
// Port number
pub const SIGNET_PORT: u16 = 6272;
// Bitcoin block height at which the syncing begins.
pub const SIGNET_SYNC_START_HEIGHT: u64 = 303_234;
// Well-known Engine public key
pub const SIGNET_ENGINE_PUBLIC_KEY: [u8; 32] = [
    0xc8, 0xc8, 0x6b, 0x92, 0x1e, 0x6b, 0x6d, 0x8c, 0xe9, 0xec, 0xe6, 0x5e, 0xad, 0x75, 0xbc, 0xb1,
    0x07, 0xe1, 0x9e, 0x56, 0x60, 0xd0, 0x3a, 0x65, 0xcb, 0x49, 0x33, 0x04, 0x4c, 0x88, 0x69, 0x2f,
];
// Transaction ID of where the genesis payload is located.
pub const SIGNET_GENESIS_PAYLOAD_TX_ID: [u8; 32] = [
    0xc5, 0xb4, 0xeb, 0xc3, 0x6d, 0x70, 0x3d, 0x57, 0x18, 0x19, 0x5f, 0x29, 0x52, 0x2f, 0x1e, 0x74,
    0x9a, 0x89, 0x7e, 0x73, 0xe7, 0x61, 0x0c, 0x16, 0xa9, 0x6e, 0xe7, 0x30, 0x7c, 0x80, 0x4e, 0xfd,
];
// Output index of where the genesis payload is located.
pub const SIGNET_GENESIS_PAYLOAD_VOUT: u32 = 0;
// satoshi amount of the genesis payload.
pub const SIGNET_GENESIS_PAYLOAD_AMOUNT: u64 = 20_000;

/// Returns the local testbed Engine public key from `CUBE_ENGINE_PUBLIC_KEY`, when set.
///
/// A regtest chain has no baked Engine identity, so the operator supplies one. The Engine's nsec
/// must be the secret of this key, and the node uses the same value to find the Engine.
pub fn testbed_engine_public_key() -> Option<[u8; 32]> {
    let value = std::env::var("CUBE_ENGINE_PUBLIC_KEY").ok()?;
    hex::decode(value.trim()).ok()?.try_into().ok()
}

/// Returns the local testbed genesis payload location from the environment, when fully set.
///
/// Format: `(txid, vout, amount_sats)`. The location must be a confirmed output paying the
/// genesis payload script for `testbed_engine_public_key()` (or the signet key when that override
/// is absent). `cargo run genesis testbed` prints the address to fund.
pub fn testbed_genesis_payload() -> Option<([u8; 32], u32, u64)> {
    let txid = display_txid_to_internal(&std::env::var("CUBE_TESTBED_GENESIS_TXID").ok()?)?;
    let vout: u32 = std::env::var("CUBE_TESTBED_GENESIS_VOUT")
        .ok()?
        .parse()
        .ok()?;
    let amount: u64 = std::env::var("CUBE_TESTBED_GENESIS_AMOUNT")
        .ok()?
        .parse()
        .ok()?;
    Some((txid, vout, amount))
}

/// Decodes an RPC/display-order txid into the internal byte order used by outpoints.
fn display_txid_to_internal(txid: &str) -> Option<[u8; 32]> {
    let mut bytes: [u8; 32] = hex::decode(txid.trim()).ok()?.try_into().ok()?;
    bytes.reverse();
    Some(bytes)
}

/// Returns the local Engine TCP address override from `CUBE_ENGINE_ADDR`, when set.
///
/// Local runs skip Nostr discovery and connect straight to this socket address
/// (for example `127.0.0.1:6272`).
pub fn testbed_engine_addr() -> Option<String> {
    std::env::var("CUBE_ENGINE_ADDR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Mainnet parameters.
///
// Port number
pub const MAINNET_PORT: u16 = 6272;
// Bitcoin block height at which the syncing begins.
pub const MAINNET_SYNC_START_HEIGHT: u64 = 888_116;
// Well-known Engine public key
pub const MAINNET_ENGINE_PUBLIC_KEY: [u8; 32] = [
    0xa3, 0x08, 0xf8, 0x7d, 0x88, 0x7d, 0x78, 0x34, 0x19, 0xb8, 0x4b, 0x97, 0x65, 0x1f, 0xd8, 0xa5,
    0xf8, 0x8f, 0x6d, 0xb6, 0x41, 0x4a, 0xe6, 0xeb, 0x19, 0x84, 0xcc, 0x67, 0x42, 0xee, 0xf0, 0x9e,
];
// Transaction ID of where the genesis payload is located.
pub const MAINNET_GENESIS_PAYLOAD_TX_ID: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Output index of where the genesis payload is located.
pub const MAINNET_GENESIS_PAYLOAD_VOUT: u32 = 0;
// satoshi amount of the genesis payload.
pub const MAINNET_GENESIS_PAYLOAD_AMOUNT: u64 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_display_txid_decodes_to_internal_order() {
        // The RPC txid and the internal outpoint txid are byte-reversed relative to each other.
        // Mixing them makes the batch spend a non-existent output (`bad-txns-inputs-missingorspent`).
        let internal = display_txid_to_internal(
            "4fab931529933a61e8b7eafaf97d8b9291c28162bfca28473f7e12d0b5962402",
        )
        .expect("valid txid");
        assert_eq!(
            hex::encode(internal),
            "022496b5d0127e3f4728cabf6281c291928b7df9faeab7e8613a93291593ab4f"
        );
    }

    #[test]
    fn a_malformed_txid_is_rejected() {
        assert!(display_txid_to_internal("00").is_none());
        assert!(display_txid_to_internal("zz").is_none());
    }
}
