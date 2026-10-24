//! Offline tests for the `CooperativeSettle` edge.
//!
//! The verifier is the point: most tests take the honest settlement and change one thing a
//! coordinator could change — an omitted claim, a redirected output, a different fee input, a
//! package from another statement. The settlement has to refuse each one without relying on the
//! coordinator's honesty.

use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::ClaimRecoveryPackage;
use cube::constructive::graph::cooperative_settle::{
    CooperativeSettle, CooperativeSettleError, SETTLE_INPUT_SEQUENCE,
};
use cube::constructive::graph::successor_funding::FeeBounds;
use cube::constructive::taproot::hash_tap_leaf;
use cube::model::fixed_split_vault_v1::manifest::{
    Anchor, Payout, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
};

const BOB_KEY: [u8; 32] = [0x21; 32];
const CAROL_KEY: [u8; 32] = [0x22; 32];
const FEE_KEY: [u8; 32] = [0x23; 32];
const BOB_SATS: u64 = 70_000;
const CAROL_SATS: u64 = 29_900;
const FEE_SATS: u64 = 100;
const FEE_INPUT_SATS: u64 = 2_000;
const BOB_BINDING: [u8; 32] = [0xb1; 32];
const CAROL_BINDING: [u8; 32] = [0xc1; 32];

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

/// A package for one beneficiary. `binding = None` builds the v1 single-leaf claim.
fn package(
    key: [u8; 32],
    entitlement_sats: u64,
    claim_txid: [u8; 32],
    binding: Option<[u8; 32]>,
) -> ClaimRecoveryPackage {
    let statement_digest = manifest().statement_digest();
    let anchor = Some(Anchor::new(claim_txid, 0));
    match binding {
        Some(binding) => ClaimRecoveryPackage::new_with_assertion(
            ReleaseProfile::ArgoSplitRegtest,
            [0x90; 32],
            None,
            key,
            [0x22; 32],
            [0x33; 32],
            statement_digest,
            binding,
            entitlement_sats,
            anchor,
            432,
            10,
            [0xbb; 32],
            [0xcc; 32],
        )
        .expect("v2 package"),
        None => ClaimRecoveryPackage::new(
            ReleaseProfile::ArgoSplitRegtest,
            [0x90; 32],
            None,
            key,
            [0x22; 32],
            [0x33; 32],
            statement_digest,
            entitlement_sats,
            anchor,
            432,
            10,
            [0xbb; 32],
            [0xcc; 32],
        )
        .expect("v1 package"),
    }
}

fn packages() -> Vec<ClaimRecoveryPackage> {
    vec![
        package(BOB_KEY, BOB_SATS, [0x01; 32], None),
        package(CAROL_KEY, CAROL_SATS, [0x02; 32], None),
    ]
}

fn packages_v2() -> Vec<ClaimRecoveryPackage> {
    vec![
        package(BOB_KEY, BOB_SATS, [0x01; 32], Some(BOB_BINDING)),
        package(CAROL_KEY, CAROL_SATS, [0x02; 32], Some(CAROL_BINDING)),
    ]
}

fn destinations() -> Vec<ScriptBuf> {
    vec![
        ScriptBuf::from_bytes(vec![0x51]),
        ScriptBuf::from_bytes(vec![0x52]),
    ]
}

fn fee_input() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([0x99; 32]),
        vout: 0,
    }
}

fn fee_prevout() -> TxOut {
    TxOut {
        value: Amount::from_sat(FEE_INPUT_SATS),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn settle() -> CooperativeSettle {
    CooperativeSettle::new(
        &manifest(),
        &packages(),
        destinations(),
        fee_input(),
        &fee_prevout(),
        FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
    )
    .expect("the fixture must settle")
}

fn verify(transaction: &bitcoin::Transaction) -> Result<CooperativeSettle, CooperativeSettleError> {
    CooperativeSettle::verify(
        transaction,
        &manifest(),
        &packages(),
        &destinations(),
        fee_input(),
        &fee_prevout(),
        FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
    )
}

#[test]
fn the_settlement_spends_every_claim_and_pays_the_manifest() {
    let settlement = settle();
    assert_eq!(settlement.statement_digest(), manifest().statement_digest());
    assert_eq!(settlement.fee_input(), fee_input());
    assert_eq!(settlement.miner_fee_sats(), FEE_INPUT_SATS);
    assert_eq!(
        settlement.claim_outpoints(),
        vec![
            OutPoint {
                txid: Txid::from_byte_array([0x01; 32]),
                vout: 0
            },
            OutPoint {
                txid: Txid::from_byte_array([0x02; 32]),
                vout: 0
            },
        ]
    );

    let transaction = settlement.transaction();
    assert_eq!(transaction.input.len(), 3);
    assert_eq!(transaction.output.len(), 2);
    assert_eq!(
        transaction.input[0].previous_output,
        settlement.claim_outpoints()[0]
    );
    assert_eq!(
        transaction.input[1].previous_output,
        settlement.claim_outpoints()[1]
    );
    assert_eq!(transaction.input[2].previous_output, fee_input());
    for input in &transaction.input {
        assert_eq!(input.sequence, SETTLE_INPUT_SEQUENCE);
        assert!(input.witness.is_empty());
    }
    assert_eq!(transaction.output[0].value, Amount::from_sat(BOB_SATS));
    assert_eq!(transaction.output[0].script_pubkey, destinations()[0]);
    assert_eq!(transaction.output[1].value, Amount::from_sat(CAROL_SATS));
    assert_eq!(transaction.output[1].script_pubkey, destinations()[1]);

    assert_eq!(
        settlement,
        verify(&transaction).expect("the honest settlement")
    );
}

#[test]
fn the_signing_hash_covers_the_whole_settlement() {
    let settlement = settle();
    let prevouts = [
        settlement.claim_prevouts().expect("claim prevouts")[0].clone(),
        settlement.claim_prevouts().expect("claim prevouts")[1].clone(),
        fee_prevout(),
    ];

    let leaf_hash = TapLeafHash::from_byte_array(hash_tap_leaf(&packages()[0].claim_script, 0xc0));
    let expected = SighashCache::new(settlement.transaction())
        .taproot_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            None,
            Some((leaf_hash, 0xffff_ffff)),
            TapSighashType::Default,
        )
        .expect("reference sighash")
        .to_byte_array();
    assert_eq!(
        settlement
            .claim_signing_hash(0, &prevouts)
            .expect("sighash"),
        expected
    );

    // The two claims sign over different input indices, so the digests differ.
    assert_ne!(
        settlement
            .claim_signing_hash(1, &prevouts)
            .expect("second sighash"),
        expected
    );

    // A prevout list that is missing the fee, or carries another fee prevout, is refused.
    assert!(matches!(
        settlement.claim_signing_hash(0, &prevouts[..2]),
        Err(CooperativeSettleError::PrevoutCountMismatch { .. })
    ));
    let mut wrong_fee = prevouts.clone();
    wrong_fee[2].value = Amount::from_sat(FEE_INPUT_SATS + 1);
    assert_eq!(
        settlement.claim_signing_hash(0, &wrong_fee),
        Err(CooperativeSettleError::FeePrevoutMismatch)
    );
    let mut wrong_claim = prevouts.clone();
    wrong_claim[0].value = Amount::from_sat(BOB_SATS - 1);
    assert_eq!(
        settlement.claim_signing_hash(0, &wrong_claim),
        Err(CooperativeSettleError::ClaimPrevoutMismatch { index: 0 })
    );

    let witness = settlement.claim_witness(0, [0x77; 64]).expect("witness");
    assert_eq!(witness.len(), 3);
    assert_eq!(witness[0], [0x77; 64]);
    assert_eq!(witness[1], packages()[0].claim_script);
    assert_eq!(witness[2], packages()[0].control_block);
}

#[test]
fn v2_packages_settle_through_the_two_leaf_recovery() {
    let settlement = CooperativeSettle::new(
        &manifest(),
        &packages_v2(),
        destinations(),
        fee_input(),
        &fee_prevout(),
        FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
    )
    .expect("the v2 fixture must settle");
    assert_eq!(settlement.transaction().input.len(), 3);

    let witness = settlement.claim_witness(0, [0x77; 64]).expect("witness");
    assert_eq!(witness[2].len(), 65, "two-leaf control block");
    assert_eq!(
        settlement,
        CooperativeSettle::verify(
            &settlement.transaction(),
            &manifest(),
            &packages_v2(),
            &destinations(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        )
        .expect("v2 verify")
    );
}

#[test]
fn an_incomplete_or_rewritten_tree_is_refused() {
    // 1 One package for two beneficiaries.
    assert_eq!(
        CooperativeSettle::new(
            &manifest(),
            &packages()[..1],
            destinations()[..1].to_vec(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::ClaimCountMismatch {
            expected: 2,
            found: 1,
        })
    );

    // 2 A package from another statement.
    let mut foreign = packages();
    foreign[0].statement_digest[0] ^= 1;
    assert!(matches!(
        CooperativeSettle::new(
            &manifest(),
            &foreign,
            destinations(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::PackageInvalid(_))
    ));

    // 3 A valid package for another beneficiary, at Bob's position.
    let beneficiary = vec![
        package(CAROL_KEY, BOB_SATS, [0x01; 32], None),
        packages()[1].clone(),
    ];
    assert_eq!(
        CooperativeSettle::new(
            &manifest(),
            &beneficiary,
            destinations(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::BeneficiaryMismatch { index: 0 })
    );

    // 4 A valid package whose entitlement differs from the manifest.
    let entitlement = vec![
        package(BOB_KEY, BOB_SATS + 1, [0x01; 32], None),
        packages()[1].clone(),
    ];
    assert_eq!(
        CooperativeSettle::new(
            &manifest(),
            &entitlement,
            destinations(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::EntitlementMismatch {
            index: 0,
            manifest_sats: BOB_SATS,
            package_sats: BOB_SATS + 1,
        })
    );

    // 5 The fee input cannot be one of the claims.
    let mut conflicting = packages();
    conflicting[0].claim_outpoint = Some(Anchor::new([0x99; 32], 0));
    assert_eq!(
        CooperativeSettle::new(
            &manifest(),
            &conflicting,
            destinations(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::FeeInputConflictsWithClaim { index: 0 })
    );

    // 6 Two packages cannot point at the same claim.
    let mut repeated = packages();
    repeated[1].claim_outpoint = repeated[0].claim_outpoint;
    assert_eq!(
        CooperativeSettle::new(
            &manifest(),
            &repeated,
            destinations(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::RepeatedClaimOutpoint { index: 1 })
    );

    // 7 A destination list of the wrong length, an empty destination and an empty fee script.
    assert_eq!(
        CooperativeSettle::new(
            &manifest(),
            &packages(),
            destinations()[..1].to_vec(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::DestinationCountMismatch {
            expected: 2,
            found: 1,
        })
    );
    let mut empty_destination = destinations();
    empty_destination[0] = ScriptBuf::new();
    assert_eq!(
        CooperativeSettle::new(
            &manifest(),
            &packages(),
            empty_destination,
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::EmptyDestination { index: 0 })
    );
    let mut empty_fee = fee_prevout();
    empty_fee.script_pubkey = ScriptBuf::new();
    assert_eq!(
        CooperativeSettle::new(
            &manifest(),
            &packages(),
            destinations(),
            fee_input(),
            &empty_fee,
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        ),
        Err(CooperativeSettleError::EmptyFeeInputScript)
    );

    // 8 The fee range is part of what the coordinator may propose.
    assert!(matches!(
        CooperativeSettle::new(
            &manifest(),
            &packages(),
            destinations(),
            fee_input(),
            &fee_prevout(),
            FeeBounds::new(FEE_INPUT_SATS + 1, FEE_INPUT_SATS + 1),
        ),
        Err(CooperativeSettleError::MinerFeeOutOfBounds { .. })
    ));
}

#[test]
fn a_rewritten_transaction_is_refused() {
    let settlement = settle();

    // 1 Redirect one output.
    let mut redirected = settlement.transaction();
    redirected.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x53]);
    assert_eq!(
        verify(&redirected),
        Err(CooperativeSettleError::TransactionOutputMismatch { index: 0 })
    );

    // 2 Reduce one output while keeping the destination.
    let mut resized = settlement.transaction();
    resized.output[1].value = Amount::from_sat(CAROL_SATS - 1);
    assert_eq!(
        verify(&resized),
        Err(CooperativeSettleError::TransactionOutputMismatch { index: 1 })
    );

    // 3 Spend another claim outpoint.
    let mut other_input = settlement.transaction();
    other_input.input[0].previous_output.vout = 1;
    assert_eq!(
        verify(&other_input),
        Err(CooperativeSettleError::TransactionInputMismatch { index: 0 })
    );

    // 4 Change a claim sequence: the signer would be authorising a different transaction.
    let mut resequenced = settlement.transaction();
    resequenced.input[1].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
    assert_eq!(
        verify(&resequenced),
        Err(CooperativeSettleError::TransactionInputMismatch { index: 1 })
    );

    // 5 Move or redirect the fee input.
    let mut fee_moved = settlement.transaction();
    fee_moved.input[2].previous_output.vout = 1;
    assert_eq!(
        verify(&fee_moved),
        Err(CooperativeSettleError::FeeInputMismatch)
    );

    // 6 Drop the fee input entirely.
    let mut no_fee = settlement.transaction();
    no_fee.input.pop();
    assert_eq!(
        verify(&no_fee),
        Err(CooperativeSettleError::TransactionShapeMismatch)
    );
}
