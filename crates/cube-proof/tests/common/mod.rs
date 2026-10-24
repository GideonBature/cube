//! Shared fixture for the `cube-proof` integration tests.
//!
//! One manifest, built by the model, used both for the constraint tests and for the end-to-end
//! proof test. Keeping a single fixture means a change to the encoding breaks every test at once
//! instead of silently diverging.

#![allow(dead_code)]

use cube::model::fixed_split_vault_v1::manifest::{
    Anchor, Payout, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
};

/// Bob's allocation.
pub const BOB_SATS: u64 = 70_000;
/// Carol's allocation.
pub const CAROL_SATS: u64 = 30_000;
/// The disclosed execution fee.
pub const FEE_SATS: u64 = 500;

/// A one-anchor funding manifest: the shape the circuit supports.
pub fn manifest() -> TransitionManifest {
    TransitionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        profile: ReleaseProfile::ArgoSplitRegtest,
        network_genesis_hash: [0x11; 32],
        template_hash: [0x22; 32],
        circuit_id: [0x33; 32],
        verifier_key_digest: [0x44; 32],
        previous_state_digest: [0x55; 32],
        resulting_state_digest: [0x66; 32],
        batch_sequence: 1,
        anchors: vec![Anchor::new([0x77; 32], 0)],
        entry_digest: [0x88; 32],
        caller_key: [0x99; 32],
        caller_sequence: 2,
        operation_id: [0xaa; 32],
        payouts: vec![
            Payout::new([0x21; 32], BOB_SATS, PayoutKind::BeneficiaryAllocation),
            Payout::new([0x22; 32], CAROL_SATS, PayoutKind::BeneficiaryAllocation),
            Payout::new([0x23; 32], FEE_SATS, PayoutKind::ExecutionFee),
        ],
        setup_instance_id: [0xbb; 32],
        graph_template_version: 1,
        challenge_config_digest: [0xcc; 32],
        recovery_package_digest: [0xdd; 32],
        batch_data_digest: [0xee; 32],
        availability_descriptor_digest: [0xff; 32],
    }
}

/// The canonical bytes of the fixture.
pub fn manifest_bytes() -> Vec<u8> {
    manifest().encode()
}
