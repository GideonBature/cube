//! Tests for the `SuccessorFunding` graph edge.
//!
//! The verifier is the point of this module, so most tests are hostile: they take a transaction the
//! builder produced and check that one mutation is rejected for the stated reason. A test that only
//! showed a correct transaction being accepted would not tell a signer what the rule protects
//! against.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Txid};
use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::ClaimRecoveryPackage;
use cube::constructive::graph::claim_recovery::ClaimRecovery;
use cube::constructive::graph::successor_funding::{
    DepositAnchor, FeeBounds, FundingOutput, SuccessorFunding, SuccessorFundingError,
};
use cube::model::fixed_split_vault_v1::manifest::{
    Anchor, Payout, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
};

const BOB_KEY: [u8; 32] = [0x21; 32];
const CAROL_KEY: [u8; 32] = [0x22; 32];
const FEE_KEY: [u8; 32] = [0x23; 32];
const BOB_BINDING: [u8; 32] = [0xb1; 32];
const CAROL_BINDING: [u8; 32] = [0xc1; 32];

const BOB_SATS: u64 = 70_000;
const CAROL_SATS: u64 = 29_900;
const FEE_SATS: u64 = 100;
const MINER_FEE_SATS: u64 = 1_000;
const DEPOSIT_SATS: u64 = BOB_SATS + CAROL_SATS + FEE_SATS + MINER_FEE_SATS;

/// A funding manifest with the bounded profile's three obligations.
fn manifest() -> TransitionManifest {
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
            Payout::new(BOB_KEY, BOB_SATS, PayoutKind::BeneficiaryAllocation),
            Payout::new(CAROL_KEY, CAROL_SATS, PayoutKind::BeneficiaryAllocation),
            Payout::new(FEE_KEY, FEE_SATS, PayoutKind::ExecutionFee),
        ],
        setup_instance_id: [0xbb; 32],
        graph_template_version: 1,
        challenge_config_digest: [0xcc; 32],
        recovery_package_digest: [0xdd; 32],
        batch_data_digest: [0xee; 32],
        availability_descriptor_digest: [0xff; 32],
    }
}

/// The deposit the successor spends.
fn deposit() -> DepositAnchor {
    DepositAnchor::new(
        OutPoint {
            txid: Txid::from_byte_array([0x01; 32]),
            vout: 0,
        },
        DEPOSIT_SATS,
    )
}

/// An arbitrary fee account script. The graph does not derive it from the key.
fn fee_script() -> ScriptBuf {
    let mut script = vec![0x00, 0x14];
    script.extend([0x42u8; 20]);
    ScriptBuf::from_bytes(script)
}

/// The descriptor the builder produces for the fixture.
fn funding() -> SuccessorFunding {
    SuccessorFunding::new(&manifest(), deposit(), MINER_FEE_SATS, Some(fee_script()))
        .expect("the fixture must fund")
}

/// One assertion binding per beneficiary allocation, in payout order.
fn bindings() -> Vec<[u8; 32]> {
    vec![BOB_BINDING, CAROL_BINDING]
}

/// The descriptor the v2 builder produces for the fixture.
fn funding_v2() -> SuccessorFunding {
    SuccessorFunding::new_with_assertions(
        &manifest(),
        deposit(),
        MINER_FEE_SATS,
        Some(fee_script()),
        &bindings(),
    )
    .expect("the v2 fixture must fund")
}

/// Verifies a transaction with the fixture's v2 bindings.
fn verify_v2(
    transaction: &Transaction,
    assertion_bindings: &[[u8; 32]],
) -> Result<SuccessorFunding, SuccessorFundingError> {
    SuccessorFunding::verify_with_assertions(
        transaction,
        &manifest(),
        deposit().outpoint,
        DEPOSIT_SATS,
        wide_bounds(),
        assertion_bindings,
    )
}

/// The accept-everything fee range used where the fee itself is not under test.
fn wide_bounds() -> FeeBounds {
    FeeBounds::new(0, 10_000)
}

/// Verifies a transaction against the fixture manifest.
fn verify(transaction: &Transaction) -> Result<SuccessorFunding, SuccessorFundingError> {
    SuccessorFunding::verify(
        transaction,
        &manifest(),
        deposit().outpoint,
        DEPOSIT_SATS,
        wide_bounds(),
    )
}

#[test]
fn successor_funding_builds_the_manifest_obligations_in_order() {
    let descriptor = funding();
    assert_eq!(descriptor.miner_fee_sats(), MINER_FEE_SATS);
    assert_eq!(descriptor.statement_digest(), manifest().statement_digest());

    let outputs = descriptor.outputs();
    assert_eq!(outputs.len(), 4);

    // 1 The two allocations become claims bound to the statement digest and the payout keys.
    for (index, key) in [(0usize, BOB_KEY), (1, CAROL_KEY)] {
        match &outputs[index] {
            FundingOutput::Claim {
                beneficiary_key,
                assertion_binding_digest,
                amount_sats,
                script_pubkey,
            } => {
                assert_eq!(*beneficiary_key, key);
                assert_eq!(*assertion_binding_digest, None);
                assert_eq!(*amount_sats, if index == 0 { BOB_SATS } else { CAROL_SATS });
                let expected =
                    cube::constructive::contracts::fixed_split_vault_v1::claim::claim_scriptpubkey(
                        descriptor.statement_digest(),
                        key,
                    )
                    .expect("claim script");
                assert_eq!(*script_pubkey, ScriptBuf::from_bytes(expected));
            }
            other => panic!("output {index} must be a claim, got {other:?}"),
        }
    }

    // 2 The execution fee is paid to the supplied script, not to a derived one.
    match &outputs[2] {
        FundingOutput::ExecutionFee {
            recipient_key,
            amount_sats,
            script_pubkey,
        } => {
            assert_eq!(*recipient_key, FEE_KEY);
            assert_eq!(*amount_sats, FEE_SATS);
            assert_eq!(*script_pubkey, fee_script());
        }
        other => panic!("output 2 must be the execution fee, got {other:?}"),
    }

    // 3 The commitment is last and carries the digest.
    match &outputs[3] {
        FundingOutput::StatementCommitment {
            statement_digest, ..
        } => assert_eq!(*statement_digest, manifest().statement_digest()),
        other => panic!("the last output must be the commitment, got {other:?}"),
    }

    // 4 The transaction shape is the one the graph commits to.
    let transaction = descriptor.transaction();
    assert_eq!(transaction.input.len(), 1);
    assert_eq!(transaction.input[0].previous_output, deposit().outpoint);
    assert_eq!(
        transaction.input[0].sequence,
        Sequence::ENABLE_RBF_NO_LOCKTIME
    );
    assert_eq!(
        transaction
            .output
            .iter()
            .map(|output| output.value.to_sat())
            .collect::<Vec<_>>(),
        vec![BOB_SATS, CAROL_SATS, FEE_SATS, 0]
    );
}

#[test]
fn successor_funding_can_carry_assertion_bindings() {
    let descriptor = funding_v2();
    let outputs = descriptor.outputs();

    for (index, key, binding) in [
        (0usize, BOB_KEY, BOB_BINDING),
        (1, CAROL_KEY, CAROL_BINDING),
    ] {
        match &outputs[index] {
            FundingOutput::Claim {
                beneficiary_key,
                assertion_binding_digest,
                amount_sats,
                script_pubkey,
            } => {
                assert_eq!(*beneficiary_key, key);
                assert_eq!(*assertion_binding_digest, Some(binding));
                assert_eq!(*amount_sats, if index == 0 { BOB_SATS } else { CAROL_SATS });
                let expected = cube::constructive::contracts::fixed_split_vault_v1::claim::assertion_claim_scriptpubkey(
                    descriptor.statement_digest(),
                    binding,
                    key,
                )
                .expect("assertion claim script");
                assert_eq!(*script_pubkey, ScriptBuf::from_bytes(expected));
            }
            other => panic!("output {index} must be a claim, got {other:?}"),
        }
    }

    // The v2 claims are structurally different from the v1 claims.
    assert_ne!(
        outputs[0].script_pubkey(),
        funding().outputs()[0].script_pubkey()
    );

    // The same bindings verify the transaction; the v1 verifier refuses it.
    let parsed = verify_v2(&descriptor.transaction(), &bindings()).expect("v2 verify");
    assert_eq!(parsed, descriptor);
    assert_eq!(
        verify(&descriptor.transaction()),
        Err(SuccessorFundingError::PayoutOutputMismatch { index: 0 })
    );
}

#[test]
fn a_v2_successor_output_is_recoverable_through_a_v2_package() {
    let descriptor = funding_v2();

    for (index, key, binding) in [
        (0usize, BOB_KEY, BOB_BINDING),
        (1, CAROL_KEY, CAROL_BINDING),
    ] {
        let output = &descriptor.outputs()[index];
        let anchor = Anchor::new([0x01; 32], index as u32);
        let package = ClaimRecoveryPackage::new_with_assertion(
            ReleaseProfile::ArgoSplitRegtest,
            [0x90 + index as u8; 32],
            None,
            key,
            [0x22; 32],
            [0x33; 32],
            descriptor.statement_digest(),
            binding,
            output.amount_sats(),
            Some(anchor),
            1_000,
            2,
            [0xbb; 32],
            [0xcc; 32],
        )
        .expect("the v2 package must construct");

        // The successor output and the package derive the same two-leaf claim.
        assert_eq!(
            package.claim_scriptpubkey(),
            Some(output.script_pubkey().as_bytes().to_vec())
        );

        let prevout = TxOut {
            value: Amount::from_sat(output.amount_sats()),
            script_pubkey: output.script_pubkey().clone(),
        };
        let recovery =
            ClaimRecovery::new(&package, &prevout, ScriptBuf::from_bytes(vec![0x51]), 500)
                .expect("the recovery spend must build");
        assert_eq!(
            recovery.claim_outpoint(),
            OutPoint {
                txid: Txid::from_byte_array([0x01; 32]),
                vout: index as u32,
            }
        );
    }
}

#[test]
fn assertion_bindings_are_per_beneficiary_and_exact() {
    let transaction = funding_v2().transaction();

    // 1 A non-empty vector must have one entry per beneficiary.
    assert_eq!(
        SuccessorFunding::new_with_assertions(
            &manifest(),
            deposit(),
            MINER_FEE_SATS,
            Some(fee_script()),
            &[BOB_BINDING],
        ),
        Err(SuccessorFundingError::AssertionBindingCountMismatch {
            expected: 2,
            found: 1,
        })
    );

    // 2 A zero binding is not a digest.
    assert_eq!(
        SuccessorFunding::new_with_assertions(
            &manifest(),
            deposit(),
            MINER_FEE_SATS,
            Some(fee_script()),
            &[[0u8; 32], CAROL_BINDING],
        ),
        Err(SuccessorFundingError::ZeroAssertionBinding { index: 0 })
    );

    // 3 Swapping the two bindings puts each claim at the wrong key.
    assert_eq!(
        verify_v2(&transaction, &[CAROL_BINDING, BOB_BINDING]),
        Err(SuccessorFundingError::PayoutOutputMismatch { index: 0 })
    );

    // 4 Changing one binding changes that output's key.
    assert_eq!(
        verify_v2(&transaction, &[[0xb2u8; 32], CAROL_BINDING]),
        Err(SuccessorFundingError::PayoutOutputMismatch { index: 0 })
    );
}

#[test]
fn verification_accepts_the_transaction_the_builder_produced() {
    let descriptor = funding();
    let parsed = verify(&descriptor.transaction()).expect("the builder's output must verify");
    assert_eq!(parsed, descriptor);
}

#[test]
fn verification_rejects_a_redirected_or_resized_claim() {
    // 1 Pay Carol's claim to Bob's key: the value still matches, the commitment does not.
    let mut redirected = funding().transaction();
    let mut bob_script = Vec::new();
    bob_script.extend([0x51]);
    redirected.output[0].script_pubkey = ScriptBuf::from_bytes(bob_script);
    assert_eq!(
        verify(&redirected),
        Err(SuccessorFundingError::PayoutOutputMismatch { index: 0 })
    );

    // 2 Reduce a beneficiary allocation by one satoshi.
    let mut resized = funding().transaction();
    resized.output[1].value = bitcoin::Amount::from_sat(CAROL_SATS - 1);
    assert_eq!(
        verify(&resized),
        Err(SuccessorFundingError::PayoutOutputMismatch { index: 1 })
    );

    // 3 Swap the two claims: both amounts and scripts now sit at the wrong index.
    let mut swapped = funding().transaction();
    swapped.output.swap(0, 1);
    assert_eq!(
        verify(&swapped),
        Err(SuccessorFundingError::PayoutOutputMismatch { index: 0 })
    );
}

#[test]
fn verification_rejects_a_missing_or_foreign_commitment() {
    // 1 Dropping the commitment changes the output count.
    let mut missing = funding().transaction();
    missing.output.pop();
    assert_eq!(
        verify(&missing),
        Err(SuccessorFundingError::UnexpectedOutputCount {
            expected: 4,
            found: 3
        })
    );

    // 2 A commitment to another statement is rejected even when every payout is correct.
    let mut foreign = funding().transaction();
    foreign.output[3].script_pubkey = ScriptBuf::from_bytes(
        cube::constructive::contracts::fixed_split_vault_v1::claim::statement_op_return_script(
            [0x77u8; 32],
        ),
    );
    assert_eq!(
        verify(&foreign),
        Err(SuccessorFundingError::StatementCommitmentMismatch)
    );

    // 3 A commitment carrying value is not the graph's commitment.
    let mut funded = funding().transaction();
    funded.output[3].value = bitcoin::Amount::from_sat(1);
    assert_eq!(
        verify(&funded),
        Err(SuccessorFundingError::StatementCommitmentMismatch)
    );
}

#[test]
fn verification_rejects_a_transaction_that_is_not_the_anchored_spend() {
    // 1 Version.
    let mut versioned = funding().transaction();
    versioned.version = bitcoin::transaction::Version::ONE;
    assert_eq!(
        verify(&versioned),
        Err(SuccessorFundingError::TransactionShapeMismatch)
    );

    // 2 Locktime.
    let mut locked = funding().transaction();
    locked.lock_time = bitcoin::absolute::LockTime::from_height(1).expect("valid height");
    assert_eq!(
        verify(&locked),
        Err(SuccessorFundingError::TransactionShapeMismatch)
    );

    // 3 Input count.
    let mut doubled = funding().transaction();
    let extra = doubled.input[0].clone();
    doubled.input.push(extra);
    assert_eq!(
        verify(&doubled),
        Err(SuccessorFundingError::TransactionShapeMismatch)
    );

    // 4 Outpoint.
    let mut redirected = funding().transaction();
    redirected.input[0].previous_output.vout = 1;
    assert_eq!(
        verify(&redirected),
        Err(SuccessorFundingError::TransactionInputMismatch)
    );

    // 5 Sequence: changing it changes what a signature authorises.
    let mut resequenced = funding().transaction();
    resequenced.input[0].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
    assert_eq!(
        verify(&resequenced),
        Err(SuccessorFundingError::TransactionInputMismatch)
    );
}

#[test]
fn verification_rejects_fees_outside_the_accepted_range() {
    let transaction = funding().transaction();

    // 1 The fixture leaves exactly MINER_FEE_SATS, so a range that starts above it refuses.
    assert_eq!(
        SuccessorFunding::verify(
            &transaction,
            &manifest(),
            deposit().outpoint,
            DEPOSIT_SATS,
            FeeBounds::new(MINER_FEE_SATS + 1, 10_000),
        ),
        Err(SuccessorFundingError::MinerFeeOutOfBounds {
            fee_sats: MINER_FEE_SATS,
            min_sats: MINER_FEE_SATS + 1,
            max_sats: 10_000,
        })
    );

    // 2 A range that ends below it refuses as well.
    assert_eq!(
        SuccessorFunding::verify(
            &transaction,
            &manifest(),
            deposit().outpoint,
            DEPOSIT_SATS,
            FeeBounds::new(0, MINER_FEE_SATS - 1),
        ),
        Err(SuccessorFundingError::MinerFeeOutOfBounds {
            fee_sats: MINER_FEE_SATS,
            min_sats: 0,
            max_sats: MINER_FEE_SATS - 1,
        })
    );

    // 3 A deposit below the obligations cannot cover them at all.
    assert_eq!(
        SuccessorFunding::verify(
            &transaction,
            &manifest(),
            deposit().outpoint,
            BOB_SATS + CAROL_SATS + FEE_SATS - 1,
            FeeBounds::new(0, 10_000),
        ),
        Err(SuccessorFundingError::DepositUnderfunded {
            deposit_sats: BOB_SATS + CAROL_SATS + FEE_SATS - 1,
            outputs_sats: BOB_SATS + CAROL_SATS + FEE_SATS,
        })
    );
}

#[test]
fn builder_refuses_obligations_this_edge_cannot_fund() {
    let fee_script = Some(fee_script());

    // 1 A native successor payout belongs to a redemption, not to a Bitcoin successor.
    let mut native = manifest();
    native.payouts[0] = Payout::new(BOB_KEY, BOB_SATS, PayoutKind::NativeSuccessor);
    assert_eq!(
        SuccessorFunding::new(&native, deposit(), MINER_FEE_SATS, fee_script.clone()),
        Err(SuccessorFundingError::UnsupportedPayoutKind {
            kind: PayoutKind::NativeSuccessor
        })
    );

    // 2 Two execution fees would create a second unaccounted payout.
    let mut double_fee = manifest();
    double_fee.payouts[2] = Payout::new(FEE_KEY, FEE_SATS - 1, PayoutKind::ExecutionFee);
    double_fee
        .payouts
        .push(Payout::new([0x24u8; 32], 1, PayoutKind::ExecutionFee));
    assert_eq!(
        SuccessorFunding::new(&double_fee, deposit(), MINER_FEE_SATS, fee_script.clone()),
        Err(SuccessorFundingError::MultipleExecutionFees)
    );

    // 3 The fee script is mandatory when a fee payout exists.
    assert_eq!(
        SuccessorFunding::new(&manifest(), deposit(), MINER_FEE_SATS, None),
        Err(SuccessorFundingError::MissingExecutionFeeScript)
    );

    // 4 A fee script without a fee payout would look authorised while paying nobody.
    let mut no_fee = manifest();
    no_fee.payouts.remove(2);
    assert_eq!(
        SuccessorFunding::new(
            &no_fee,
            DepositAnchor::new(deposit().outpoint, BOB_SATS + CAROL_SATS + MINER_FEE_SATS),
            MINER_FEE_SATS,
            fee_script,
        ),
        Err(SuccessorFundingError::UnusedExecutionFeeScript)
    );
}

#[test]
fn builder_refuses_a_deposit_that_does_not_leave_the_requested_fee() {
    // One satoshi more in the deposit becomes one satoshi more of fee, which the exact bounds refuse.
    let richer = DepositAnchor::new(deposit().outpoint, DEPOSIT_SATS + 1);
    assert_eq!(
        SuccessorFunding::new(&manifest(), richer, MINER_FEE_SATS, Some(fee_script())),
        Err(SuccessorFundingError::MinerFeeOutOfBounds {
            fee_sats: MINER_FEE_SATS + 1,
            min_sats: MINER_FEE_SATS,
            max_sats: MINER_FEE_SATS,
        })
    );

    // A deposit below the obligations cannot pay them.
    let poorer = DepositAnchor::new(deposit().outpoint, BOB_SATS + CAROL_SATS + FEE_SATS - 1);
    assert_eq!(
        SuccessorFunding::new(&manifest(), poorer, 0, Some(fee_script())),
        Err(SuccessorFundingError::DepositUnderfunded {
            deposit_sats: BOB_SATS + CAROL_SATS + FEE_SATS - 1,
            outputs_sats: BOB_SATS + CAROL_SATS + FEE_SATS,
        })
    );
}
