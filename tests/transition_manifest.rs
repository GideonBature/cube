//! Tests for the canonical transition manifest.
//!
//! The manifest is the object a proof statement and a Bitcoin assertion must both bind. These tests
//! check three things: that it has exactly one encoding, that the encoding is stable, and that the
//! statement digest actually changes when any consensus-relevant field changes.
//!
//! Nothing here demonstrates a proof, a Bitcoin commitment or Argo. The manifest is a data
//! structure; binding it on-chain is a separate deliverable.

#[cfg(test)]
mod transition_manifest_tests {
    use cube::model::fixed_split_vault_v1::manifest::{
        ManifestError, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
    };
    use cube::model::fixed_split_vault_v1::types::{Ledger, Role};
    use cube::model::fixed_split_vault_v1::{
        split_amounts, Auth, Operation, SplitDescriptor, SplitVault,
    };

    const NETWORK_GENESIS_HASH: [u8; 32] = [0x11; 32];
    const TEMPLATE_HASH: [u8; 32] = [0x22; 32];
    const CIRCUIT_ID: [u8; 32] = [0x33; 32];
    const VERIFIER_KEY_DIGEST: [u8; 32] = [0x44; 32];
    const ENTRY_DIGEST: [u8; 32] = [0x55; 32];
    const OPERATION_ID: [u8; 32] = [0x66; 32];
    const SETUP_INSTANCE_ID: [u8; 32] = [0x77; 32];
    const CHALLENGE_CONFIG_DIGEST: [u8; 32] = [0x88; 32];
    const RECOVERY_PACKAGE_DIGEST: [u8; 32] = [0x99; 32];
    const BATCH_DATA_DIGEST: [u8; 32] = [0xaa; 32];
    const AVAILABILITY_DESCRIPTOR_DIGEST: [u8; 32] = [0xbb; 32];
    const ANCHOR_TXID: [u8; 32] = [0xcc; 32];

    const BOB_KEY: [u8; 32] = [0x21; 32];
    const CAROL_KEY: [u8; 32] = [0x31; 32];
    const FEE_KEY: [u8; 32] = [0x41; 32];
    const ALICE_KEY: [u8; 32] = [0x51; 32];

    /// One labelled mutation of a manifest, used by the sensitivity test.
    type Mutation = (&'static str, Box<dyn Fn(&mut TransitionManifest)>);

    const GROSS_SATS: u64 = 100_000;
    const EXECUTION_FEE_SATS: u64 = 500;

    /// Returns the accepted state digests of a real `InstantiateSplit` then `FundSplit`.
    fn transition_digests() -> ([u8; 32], [u8; 32]) {
        let descriptor = SplitDescriptor::new(
            NETWORK_GENESIS_HASH,
            TEMPLATE_HASH,
            ALICE_KEY,
            BOB_KEY,
            CAROL_KEY,
            FEE_KEY,
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
            .expect("instantiate");
        let parent = vault.state_digest();

        vault
            .fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                Auth::new(Role::Owner, 2),
                Operation::new(
                    SplitVault::next_operation_id(2),
                    SplitVault::payload_digest(b"fund"),
                ),
            )
            .expect("fund");
        let resulting = vault.state_digest();

        (parent, resulting)
    }

    /// Returns a valid manifest describing the `FundSplit` transition.
    fn fixture() -> TransitionManifest {
        let (parent, resulting) = transition_digests();
        let amounts = split_amounts(GROSS_SATS, EXECUTION_FEE_SATS).expect("valid split");

        TransitionManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            profile: ReleaseProfile::ArgoSplitRegtest,
            network_genesis_hash: NETWORK_GENESIS_HASH,
            template_hash: TEMPLATE_HASH,
            circuit_id: CIRCUIT_ID,
            verifier_key_digest: VERIFIER_KEY_DIGEST,
            previous_state_digest: parent,
            resulting_state_digest: resulting,
            batch_sequence: 101,
            anchors: vec![
                cube::model::fixed_split_vault_v1::Anchor::new(ANCHOR_TXID, 0),
                cube::model::fixed_split_vault_v1::Anchor::new([0xdd; 32], 3),
            ],
            entry_digest: ENTRY_DIGEST,
            caller_key: ALICE_KEY,
            caller_sequence: 2,
            operation_id: OPERATION_ID,
            payouts: vec![
                cube::model::fixed_split_vault_v1::Payout::new(
                    BOB_KEY,
                    amounts.bob_sats,
                    PayoutKind::BeneficiaryAllocation,
                ),
                cube::model::fixed_split_vault_v1::Payout::new(
                    CAROL_KEY,
                    amounts.carol_sats,
                    PayoutKind::BeneficiaryAllocation,
                ),
                cube::model::fixed_split_vault_v1::Payout::new(
                    FEE_KEY,
                    EXECUTION_FEE_SATS,
                    PayoutKind::ExecutionFee,
                ),
            ],
            setup_instance_id: SETUP_INSTANCE_ID,
            graph_template_version: 1,
            challenge_config_digest: CHALLENGE_CONFIG_DIGEST,
            recovery_package_digest: RECOVERY_PACKAGE_DIGEST,
            batch_data_digest: BATCH_DATA_DIGEST,
            availability_descriptor_digest: AVAILABILITY_DESCRIPTOR_DIGEST,
        }
    }

    // ---------------------------------------------------------------------------------------
    // Encoding and stability
    // ---------------------------------------------------------------------------------------

    #[test]
    fn manifest_round_trips_and_has_one_encoding() {
        let manifest = fixture();
        manifest.validate().expect("the fixture must be valid");

        let bytes = manifest.encode();
        let decoded = TransitionManifest::decode(&bytes).expect("canonical bytes must decode");

        assert_eq!(decoded, manifest);
        assert_eq!(decoded.encode(), bytes, "the encoding must be canonical");
        assert_eq!(decoded.statement_digest(), manifest.statement_digest());
    }

    #[test]
    fn manifest_binds_the_model_payouts() {
        let manifest = fixture();

        // The obligations must match the reference model's arithmetic exactly.
        let amounts = split_amounts(GROSS_SATS, EXECUTION_FEE_SATS).expect("valid split");
        assert_eq!(
            manifest
                .payout_index_of(BOB_KEY)
                .map(|index| manifest.payouts[index].amount_sats),
            Some(amounts.bob_sats)
        );
        assert_eq!(
            manifest
                .payout_index_of(CAROL_KEY)
                .map(|index| manifest.payouts[index].amount_sats),
            Some(amounts.carol_sats)
        );
        assert_eq!(manifest.total_payout_sats(), u128::from(GROSS_SATS));
        assert_eq!(
            TransitionManifest::expected_roles(),
            [Role::Bob, Role::Carol, Role::Fee]
        );
    }

    // ---------------------------------------------------------------------------------------
    // Sensitivity: every consensus-relevant field must move the digest
    // ---------------------------------------------------------------------------------------

    #[test]
    fn changing_any_bound_field_changes_the_statement_digest() {
        let manifest = fixture();
        let reference = manifest.statement_digest();

        // Each mutation targets one field group of specification.md section 7.1.
        let mutations: Vec<Mutation> = vec![
            (
                "previous state",
                Box::new(|m: &mut TransitionManifest| m.previous_state_digest[0] ^= 0x01),
            ),
            (
                "resulting state",
                Box::new(|m: &mut TransitionManifest| m.resulting_state_digest[0] ^= 0x01),
            ),
            (
                "caller sequence",
                Box::new(|m: &mut TransitionManifest| m.caller_sequence += 1),
            ),
            (
                "operation id",
                Box::new(|m: &mut TransitionManifest| m.operation_id[0] ^= 0x01),
            ),
            (
                "anchor outpoint",
                Box::new(|m: &mut TransitionManifest| m.anchors[0].vout += 1),
            ),
            (
                "payout amount",
                Box::new(|m: &mut TransitionManifest| m.payouts[0].amount_sats += 1),
            ),
            (
                "payout recipient",
                Box::new(|m: &mut TransitionManifest| m.payouts[1].recipient_key[0] ^= 0x01),
            ),
            (
                "payout kind",
                Box::new(|m: &mut TransitionManifest| {
                    m.payouts[0].kind = PayoutKind::NativeSuccessor
                }),
            ),
            (
                "verifier key",
                Box::new(|m: &mut TransitionManifest| m.verifier_key_digest[0] ^= 0x01),
            ),
            (
                "setup instance",
                Box::new(|m: &mut TransitionManifest| m.setup_instance_id[0] ^= 0x01),
            ),
            (
                "recovery package",
                Box::new(|m: &mut TransitionManifest| m.recovery_package_digest[0] ^= 0x01),
            ),
            (
                "batch data",
                Box::new(|m: &mut TransitionManifest| m.batch_data_digest[0] ^= 0x01),
            ),
            (
                "profile",
                Box::new(|m: &mut TransitionManifest| m.profile = ReleaseProfile::PaymentsV1),
            ),
        ];

        for (label, mutate) in mutations {
            let mut mutated = manifest.clone();
            mutate(&mut mutated);
            assert_ne!(
                mutated.statement_digest(),
                reference,
                "the statement digest did not change when {label} changed"
            );
            // The mutated manifest must still be a legal manifest, so the difference is the field
            // and not an incidental validation failure.
            mutated
                .validate()
                .unwrap_or_else(|error| panic!("{label} produced an invalid manifest: {error:?}"));
        }
    }

    #[test]
    fn payout_order_is_part_of_the_commitment() {
        // "Ordered payout obligations": swapping two recipients must not produce the same digest,
        // because output order is consensus relevant.
        let manifest = fixture();
        let mut swapped = manifest.clone();
        swapped.payouts.swap(0, 1);

        assert_ne!(swapped.statement_digest(), manifest.statement_digest());
    }

    // ---------------------------------------------------------------------------------------
    // Rejections
    // ---------------------------------------------------------------------------------------

    #[test]
    fn rejects_invalid_manifests() {
        // Schema version.
        let mut manifest = fixture();
        manifest.schema_version = 2;
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::UnsupportedSchemaVersion { actual: 2 })
        );

        // No anchors.
        let mut manifest = fixture();
        manifest.anchors.clear();
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::AnchorCount { count: 0 })
        );

        // Duplicate anchor.
        let mut manifest = fixture();
        let anchor = manifest.anchors[0];
        manifest.anchors.push(anchor);
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::DuplicateAnchor { index: 2 })
        );

        // No payouts.
        let mut manifest = fixture();
        manifest.payouts.clear();
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::PayoutCount { count: 0 })
        );

        // Zero recipient.
        let mut manifest = fixture();
        manifest.payouts[0].recipient_key = [0u8; 32];
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::ZeroRecipient { index: 0 })
        );

        // Zero amount.
        let mut manifest = fixture();
        manifest.payouts[1].amount_sats = 0;
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::ZeroAmount { index: 1 })
        );

        // Duplicate recipient.
        let mut manifest = fixture();
        let key = manifest.payouts[0].recipient_key;
        manifest.payouts[1].recipient_key = key;
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::DuplicateRecipient { index: 1 })
        );
    }

    #[test]
    fn decoder_rejects_malformed_bytes() {
        let bytes = fixture().encode();

        // Truncation.
        assert!(matches!(
            TransitionManifest::decode(&bytes[..bytes.len() - 1]),
            Err(ManifestError::Truncated { .. })
        ));

        // Trailing bytes.
        let mut extended = bytes.clone();
        extended.push(0x00);
        assert_eq!(
            TransitionManifest::decode(&extended),
            Err(ManifestError::TrailingBytes {
                decoded: bytes.len(),
                actual: bytes.len() + 1,
            })
        );

        // Unknown profile tag: the byte after the schema version.
        let mut wrong_profile = bytes.clone();
        wrong_profile[1] = 0x7f;
        assert_eq!(
            TransitionManifest::decode(&wrong_profile),
            Err(ManifestError::UnknownProfileTag(0x7f))
        );

        // A manifest that decodes structurally but fails validation must also be rejected.
        let mut zero_amount = fixture();
        zero_amount.payouts[0].amount_sats = 0;
        assert_eq!(
            TransitionManifest::decode(&zero_amount.encode()),
            Err(ManifestError::ZeroAmount { index: 0 })
        );
    }

    // ---------------------------------------------------------------------------------------
    // Golden vector
    // ---------------------------------------------------------------------------------------

    /// Prints the frozen statement digest. Regenerate deliberately, never by guessing.
    #[test]
    fn golden_statement_digest_printer() {
        println!(
            "statement_digest = {}",
            hex::encode(fixture().statement_digest())
        );
        println!("manifest_bytes_len = {}", fixture().encode().len());
    }

    /// The frozen `CubeV1/Statement/v0` vector.
    ///
    /// Changing any field order, width, tag or bound breaks this test on purpose. A second
    /// implementation must reproduce this digest byte for byte before any interoperability claim
    /// is made, and a Bitcoin output that commits to a different digest is a different claim.
    #[test]
    fn golden_statement_digest_is_frozen() {
        assert_eq!(
            hex::encode(fixture().statement_digest()),
            "4a7f0624c1a7ecc85e607c00545b998265eabae22fcf3111e4db0c2243acaa32"
        );

        // Field-by-field: 2 header bytes, 128 context keys, 64 state digests, 8 batch sequence,
        // 1 anchor count, 2 anchors of 36, 32 entry digest, 32 caller key, 8 caller sequence,
        // 32 operation id, 1 payout count, 3 payouts of 41, 32 setup id, 2 graph version,
        // 32 challenge config, 32 recovery package, 32 batch data, 32 availability descriptor.
        assert_eq!(fixture().encode().len(), 665);
    }
}
