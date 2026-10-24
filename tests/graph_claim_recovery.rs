//! Tests for the `Recovery` role.
//!
//! The point of the module is that a beneficiary can check a transaction a helper produced. Most
//! tests are therefore hostile: they take the honest transaction and change one thing a malicious
//! helper would want to change.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::{
    ClaimRecoveryPackage, DischargeState,
};
use cube::constructive::graph::claim_recovery::{ClaimRecovery, ClaimRecoveryError};
use cube::constructive::graph::successor_funding::FeeBounds;
use cube::model::fixed_split_vault_v1::manifest::ReleaseProfile;

const STATEMENT_DIGEST: [u8; 32] = [0x0a; 32];
const BENEFICIARY_KEY: [u8; 32] = [0x21; 32];
const ENTITLEMENT_SATS: u64 = 50_000;
const FEE_SATS: u64 = 1_000;
const CLAIM_TXID: [u8; 32] = [0x71; 32];

/// A recovery package for a funded claim, built the normal way.
fn package() -> ClaimRecoveryPackage {
    ClaimRecoveryPackage::new(
        ReleaseProfile::ArgoSplitRegtest,
        [0xa1; 32],
        None,
        BENEFICIARY_KEY,
        [0x22; 32],
        [0x33; 32],
        STATEMENT_DIGEST,
        ENTITLEMENT_SATS,
        Some(cube::model::fixed_split_vault_v1::manifest::Anchor::new(
            CLAIM_TXID, 0,
        )),
        1_000,
        2,
        [0xbb; 32],
        [0xcc; 32],
    )
    .expect("the fixture package must build")
}

/// The claim outpoint the package refers to.
fn claim_outpoint() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array(CLAIM_TXID),
        vout: 0,
    }
}

/// The prevout holding the claim.
fn claim_prevout() -> TxOut {
    TxOut {
        value: Amount::from_sat(ENTITLEMENT_SATS),
        script_pubkey: ScriptBuf::from_bytes(
            package()
                .claim_scriptpubkey()
                .expect("the package must carry its script"),
        ),
    }
}

/// A destination script for the recovered coins.
fn destination() -> ScriptBuf {
    let mut script = vec![0x00, 0x14];
    script.extend([0x42u8; 20]);
    ScriptBuf::from_bytes(script)
}

/// An alternative destination, as a malicious helper would substitute.
fn other_destination() -> ScriptBuf {
    let mut script = vec![0x00, 0x14];
    script.extend([0x43u8; 20]);
    ScriptBuf::from_bytes(script)
}

/// The honest recovery.
fn recovery() -> ClaimRecovery {
    ClaimRecovery::new(&package(), &claim_prevout(), destination(), FEE_SATS).expect("recovery")
}

/// The accept-everything fee range used where the fee itself is not under test.
fn wide_bounds() -> FeeBounds {
    FeeBounds::new(0, 10_000)
}

#[test]
fn recovery_builds_the_spend_and_binds_the_signing_hash() {
    let recovery = recovery();
    assert_eq!(recovery.claim_outpoint(), claim_outpoint());
    assert_eq!(recovery.output_value_sats(), ENTITLEMENT_SATS - FEE_SATS);

    // 1 One claim input and one destination output, unsigned.
    let transaction = recovery.transaction();
    assert_eq!(transaction.input.len(), 1);
    assert_eq!(transaction.output.len(), 1);
    assert_eq!(transaction.input[0].previous_output, claim_outpoint());
    assert!(transaction.input[0].witness.is_empty());
    assert_eq!(
        transaction.output[0].value.to_sat(),
        ENTITLEMENT_SATS - FEE_SATS
    );
    assert_eq!(transaction.output[0].script_pubkey, destination());

    // 2 The signing hash covers the destination and the fee.
    let hash = recovery
        .signing_hash(&claim_prevout())
        .expect("the sighash must compute");
    let redirected =
        ClaimRecovery::new(&package(), &claim_prevout(), other_destination(), FEE_SATS)
            .expect("recovery");
    assert_ne!(
        redirected
            .signing_hash(&claim_prevout())
            .expect("the sighash must compute"),
        hash
    );

    let cheaper_fee = ClaimRecovery::new(&package(), &claim_prevout(), destination(), FEE_SATS - 1)
        .expect("recovery");
    assert_ne!(
        cheaper_fee
            .signing_hash(&claim_prevout())
            .expect("the sighash must compute"),
        hash
    );
}

#[test]
fn verification_accepts_and_rejects_a_redirected_destination() {
    let recovery = recovery();
    let mut transaction = recovery.transaction();

    // 1 The honest transaction verifies.
    assert_eq!(
        ClaimRecovery::verify(
            &transaction,
            &package(),
            &claim_prevout(),
            &destination(),
            wide_bounds()
        ),
        Ok(recovery)
    );

    // 2 A helper that pays itself is refused.
    transaction.output[0].script_pubkey = other_destination();
    assert_eq!(
        ClaimRecovery::verify(
            &transaction,
            &package(),
            &claim_prevout(),
            &destination(),
            wide_bounds()
        ),
        Err(ClaimRecoveryError::DestinationMismatch)
    );
}

#[test]
fn verification_rejects_fees_outside_the_bounds_and_overpayment() {
    let transaction = recovery().transaction();

    // 1 The honest spend leaves FEE_SATS.
    assert_eq!(
        ClaimRecovery::verify(
            &transaction,
            &package(),
            &claim_prevout(),
            &destination(),
            FeeBounds::new(FEE_SATS + 1, 10_000),
        ),
        Err(ClaimRecoveryError::MinerFeeOutOfBounds {
            fee_sats: FEE_SATS,
            min_sats: FEE_SATS + 1,
            max_sats: 10_000,
        })
    );

    // 2 An output above the claim is not a transaction, it is a request for money.
    let mut overpaid = recovery().transaction();
    overpaid.output[0].value = Amount::from_sat(ENTITLEMENT_SATS + 1);
    assert_eq!(
        ClaimRecovery::verify(
            &overpaid,
            &package(),
            &claim_prevout(),
            &destination(),
            wide_bounds()
        ),
        Err(ClaimRecoveryError::OutputExceedsClaim {
            claim_sats: ENTITLEMENT_SATS,
            output_sats: ENTITLEMENT_SATS + 1,
        })
    );
}

#[test]
fn recovery_requires_the_claim_prevout_and_its_entitlement() {
    // 1 A prevout with another script is not this claim.
    let mut wrong_script = claim_prevout();
    wrong_script.script_pubkey = other_destination();
    assert_eq!(
        ClaimRecovery::new(&package(), &wrong_script, destination(), FEE_SATS),
        Err(ClaimRecoveryError::ClaimScriptMismatch)
    );

    // 2 A prevout worth something else means the package is about another output.
    let mut wrong_value = claim_prevout();
    wrong_value.value = Amount::from_sat(ENTITLEMENT_SATS - 1);
    assert_eq!(
        ClaimRecovery::new(&package(), &wrong_value, destination(), FEE_SATS),
        Err(ClaimRecoveryError::EntitlementMismatch {
            package_sats: ENTITLEMENT_SATS,
            claim_sats: ENTITLEMENT_SATS - 1,
        })
    );
}

#[test]
fn recovery_refuses_a_discharged_package() {
    let mut package = package();
    package.discharge = DischargeState::Discharged;
    assert_eq!(
        ClaimRecovery::new(&package, &claim_prevout(), destination(), FEE_SATS),
        Err(ClaimRecoveryError::ClaimDischarged)
    );
}

#[test]
fn recovery_refuses_a_fee_that_consumes_the_claim() {
    assert_eq!(
        ClaimRecovery::new(
            &package(),
            &claim_prevout(),
            destination(),
            ENTITLEMENT_SATS
        ),
        Err(ClaimRecoveryError::FeeExceedsValue {
            value_sats: ENTITLEMENT_SATS,
            fee_sats: ENTITLEMENT_SATS,
        })
    );
}

#[test]
fn the_witness_layout_is_frozen() {
    let recovery = recovery();
    let signature = [0x11u8; 64];
    let witness = recovery.witness(signature);

    assert_eq!(witness.len(), 3, "signature, script, control block");
    assert_eq!(witness[0], signature.to_vec());
    assert_eq!(witness[1], package().claim_script);
    assert_eq!(witness[2], package().control_block);
}

#[test]
fn verification_rejects_a_transaction_that_is_already_signed() {
    // `verify` checks the shape a helper hands over, before the beneficiary signs it.
    let recovery = recovery();
    let mut transaction = recovery.transaction();
    transaction.input[0].witness = recovery.witness([0x11u8; 64]);
    assert_eq!(
        ClaimRecovery::verify(
            &transaction,
            &package(),
            &claim_prevout(),
            &destination(),
            wide_bounds()
        ),
        Err(ClaimRecoveryError::TransactionShapeMismatch)
    );
}
