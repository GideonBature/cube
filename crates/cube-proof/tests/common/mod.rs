//! Shared fixture for the `cube-proof` integration tests.
//!
//! The states and the manifest are produced by the model, not by hand: the vault is instantiated,
//! its state is captured, funded, and the resulting state is captured again. The manifest commits
//! those two digests, so the circuit is tested against a transition the model actually accepted.

#![allow(dead_code)]

use cube::model::fixed_split_vault_v1::manifest::{
    Anchor, Payout, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
};
use cube::model::fixed_split_vault_v1::{
    split_amounts, Auth, Ledger, Operation, Role, SplitDescriptor, SplitVault,
};

/// The gross amount funded.
pub const GROSS_SATS: u64 = 100_000;
/// The disclosed execution fee.
pub const FEE_SATS: u64 = 500;
/// The keys of the four slots.
pub const OWNER_KEY: [u8; 32] = [0x21; 32];
pub const BOB_KEY: [u8; 32] = [0x22; 32];
pub const CAROL_KEY: [u8; 32] = [0x23; 32];
pub const FEE_KEY: [u8; 32] = [0x24; 32];

/// A funded transition, with the states the model produced.
pub struct Fixture {
    /// The manifest committing both state digests and the payouts.
    pub manifest: TransitionManifest,
    /// The canonical state before the funding.
    pub previous_state: Vec<u8>,
    /// The canonical state after the funding.
    pub resulting_state: Vec<u8>,
    /// Bob's allocation, from the model.
    pub bob_sats: u64,
    /// Carol's allocation, from the model.
    pub carol_sats: u64,
    /// The execution fee.
    pub fee_sats: u64,
}

impl Fixture {
    /// The canonical manifest bytes.
    pub fn manifest_bytes(&self) -> Vec<u8> {
        self.manifest.encode()
    }
}

/// Builds the fixture by running `InstantiateSplit` and `FundSplit` in the reference model.
pub fn fixture() -> Fixture {
    let descriptor = SplitDescriptor::new(
        [0x11; 32], [0x22; 32], OWNER_KEY, BOB_KEY, CAROL_KEY, FEE_KEY,
    );

    let mut vault = SplitVault::new(Ledger::new(GROSS_SATS, 0, 0, 0));
    vault
        .instantiate(
            descriptor,
            Auth::new(Role::Owner, 1),
            Operation::new(
                SplitVault::next_operation_id(1),
                SplitVault::payload_digest(b"instantiate"),
            ),
        )
        .expect("the fixture must instantiate");

    let previous_state = vault.state().encode();
    let previous_state_digest = vault.state_digest();

    vault
        .fund(
            GROSS_SATS,
            FEE_SATS,
            Auth::new(Role::Owner, 2),
            Operation::new(
                SplitVault::next_operation_id(2),
                SplitVault::payload_digest(b"fund"),
            ),
        )
        .expect("the fixture must fund");

    let resulting_state = vault.state().encode();
    let resulting_state_digest = vault.state_digest();

    let amounts = split_amounts(GROSS_SATS, FEE_SATS).expect("a valid split");

    let manifest = TransitionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        profile: ReleaseProfile::ArgoSplitRegtest,
        network_genesis_hash: [0x11; 32],
        template_hash: [0x22; 32],
        circuit_id: [0x33; 32],
        verifier_key_digest: [0x44; 32],
        previous_state_digest,
        resulting_state_digest,
        batch_sequence: 1,
        anchors: vec![Anchor::new([0x77; 32], 0)],
        entry_digest: [0x88; 32],
        caller_key: OWNER_KEY,
        caller_sequence: 2,
        operation_id: [0xaa; 32],
        payouts: vec![
            Payout::new(BOB_KEY, amounts.bob_sats, PayoutKind::BeneficiaryAllocation),
            Payout::new(
                CAROL_KEY,
                amounts.carol_sats,
                PayoutKind::BeneficiaryAllocation,
            ),
            Payout::new(FEE_KEY, FEE_SATS, PayoutKind::ExecutionFee),
        ],
        setup_instance_id: [0xbb; 32],
        graph_template_version: 1,
        challenge_config_digest: [0xcc; 32],
        recovery_package_digest: [0xdd; 32],
        batch_data_digest: [0xee; 32],
        availability_descriptor_digest: [0xff; 32],
    };
    manifest
        .validate()
        .expect("the fixture manifest must validate");

    Fixture {
        manifest,
        previous_state,
        resulting_state,
        bob_sats: amounts.bob_sats,
        carol_sats: amounts.carol_sats,
        fee_sats: FEE_SATS,
    }
}
