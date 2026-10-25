//! Deterministic regtest keys.
//!
//! These values are **test fixtures**. They are printed by the CLI in plain text only because they
//! are also written in the repository's tests. Never use them on a network with value.

use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Network, ScriptBuf};
use cube::constructive::taproot::TapRoot;
use cube::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;

/// The relative timelock the LiftV2 refund leaf commits to, in blocks.
///
/// `return_liftv2_taproot` encodes `CSVThreeMonths`; this is the sequence the refund transaction
/// must carry, and the number of blocks that must confirm before it is final.
pub const REFUND_DELAY_BLOCKS: u16 = 12_960;

/// Alice's deposit/fee key.
pub const ALICE_SECRET: [u8; 32] = [0x77; 32];
/// The Engine's key in the deposit aggregate. The CLI simulates both signers in one process, so
/// the aggregate signature is produced here rather than exchanged with a separate Engine; the
/// resulting signature is what Bitcoin Core checks against the tweaked output key.
pub const ENGINE_SECRET: [u8; 32] = [0x21; 32];
/// Bob's secret key.
pub const BOB_SECRET: [u8; 32] = [0x41; 32];
/// Carol's secret key.
pub const CAROL_SECRET: [u8; 32] = [0x42; 32];
/// The operator's assertion key.
pub const OPERATOR_SECRET: [u8; 32] = [0x31; 32];
/// The execution-fee recipient key named by the scenario manifest.
pub const FEE_KEY: [u8; 32] = [0x66; 32];
/// The disclosure secret the scenario table is configured with.
pub const DISCLOSURE_SECRET: [u8; 32] = [0x11; 32];

/// Returns the secp256k1 keypair for a raw secret.
pub fn keypair(secret: [u8; 32]) -> Keypair {
    let secp = Secp256k1::new();
    Keypair::from_secret_key(&secp, &SecretKey::from_slice(&secret).expect("valid key"))
}

/// Returns the x-only public key of a raw secret.
pub fn xonly(secret: [u8; 32]) -> [u8; 32] {
    keypair(secret).x_only_public_key().0.serialize()
}

/// Returns the LiftV2 taproot for the fixture account and Engine keys.
pub fn liftv2_taproot() -> Option<TapRoot> {
    return_liftv2_taproot(xonly(ALICE_SECRET), xonly(ENGINE_SECRET))
}

/// Returns the regtest address of the fixture deposit taproot.
pub fn liftv2_address() -> Option<String> {
    let script = ScriptBuf::from_bytes(liftv2_taproot()?.spk()?);
    Address::from_script(&script, Network::Regtest)
        .ok()
        .map(|address| address.to_string())
}

/// Returns a key-path-only P2TR scriptpubkey for `key` on regtest.
///
/// Used for the fixture fee inputs: their whole value becomes the miner fee, so the script must be
/// one the fixture can actually sign.
pub fn p2tr_script(key: [u8; 32]) -> ScriptBuf {
    let secp = Secp256k1::new();
    let xonly = XOnlyPublicKey::from_slice(&key).expect("valid x-only key");
    Address::p2tr(&secp, xonly, None, Network::Regtest).script_pubkey()
}

/// The fixture secret behind an x-only key, if the key is one of the fixtures.
pub fn secret_for_xonly(key: [u8; 32]) -> Option<[u8; 32]> {
    FIXTURES
        .iter()
        .find(|(_, _, secret)| xonly(*secret) == key)
        .map(|(_, _, secret)| *secret)
}

/// The fixture name behind an x-only key, for reports.
pub fn name_for_xonly(key: [u8; 32]) -> Option<&'static str> {
    FIXTURES
        .iter()
        .find(|(_, _, secret)| xonly(*secret) == key)
        .map(|(name, _, _)| *name)
}

/// The deterministic regression fixtures, with their names.
pub const FIXTURES: [(&str, &str, [u8; 32]); 6] = [
    ("alice", "deposit and fee input", ALICE_SECRET),
    ("engine", "deposit aggregate", ENGINE_SECRET),
    ("bob", "first beneficiary", BOB_SECRET),
    ("carol", "second beneficiary", CAROL_SECRET),
    ("operator", "assertion operator", OPERATOR_SECRET),
    ("fee", "execution fee recipient", FEE_KEY),
];
