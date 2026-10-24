//! Offline tests for the `Assert`, `Take` and `Disprove` edges.
//!
//! The regtest test in `tests/assertion_regtest.rs` checks that Bitcoin accepts the paths. These
//! tests pin the bytes: the encoding, the scripts inside the taproot, the commitments and the
//! transaction shapes the module will sign.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::ControlBlock;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid, Witness};
use cube::constructive::contracts::fixed_split_vault_v1::claim::{
    assertion_claim_script, parse_assertion_claim_script,
};
use cube::constructive::graph::assertion::{
    disclosure_secret_commitment, take_script, Assertion, AssertionAnchor, AssertionClaim,
    AssertionError, AssertionTerms, ContestedOutput, DisproveSpend, TakeSpend,
    ASSERTION_SCHEMA_VERSION,
};
use cube::constructive::graph::successor_funding::FeeBounds;

const OPERATOR: [u8; 32] = [0x31; 32];
const BENEFICIARY: [u8; 32] = [0x41; 32];
const STATEMENT: [u8; 32] = [0x0a; 32];
const INSTANCE: [u8; 16] = [0x22; 16];
const SECRET: [u8; 32] = [0x11; 32];
const OTHER_SECRET: [u8; 32] = [0x12; 32];

fn terms() -> AssertionTerms {
    AssertionTerms {
        statement_digest: STATEMENT,
        claim_id: [0x42; 32],
        setup_instance_id: INSTANCE,
        verifier_key_identity: [0x51; 32],
        table_digest: [0x61; 32],
        secret_commitment: disclosure_secret_commitment(&SECRET),
        input_digest: [0x71; 32],
        challenge_blocks: 144,
        operator_key: OPERATOR,
        beneficiary_key: BENEFICIARY,
    }
}

fn contested() -> ContestedOutput {
    ContestedOutput {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([0x43; 32]),
            vout: 1,
        },
        value_sats: 100_000,
    }
}

fn anchor() -> AssertionAnchor {
    AssertionAnchor::new(
        OutPoint {
            txid: Txid::from_byte_array([0x43; 32]),
            vout: 0,
        },
        99_000,
    )
}

#[test]
fn assertion_terms_have_a_frozen_encoding() {
    let terms = terms();
    assert_eq!(terms.encode().len(), 277);
    assert_eq!(terms.encode()[0], ASSERTION_SCHEMA_VERSION);

    // Every field participates in the digest. Mutating one field must invalidate a signature over
    // the old value, which is what "the output key commits the terms" means.
    let base = terms.binding_digest();
    let mut changed = terms.clone();
    changed.challenge_blocks += 1;
    assert_ne!(base, changed.binding_digest());

    let mut changed = terms.clone();
    changed.input_digest[0] ^= 1;
    assert_ne!(base, changed.binding_digest());

    let mut changed = terms.clone();
    changed.claim_id[0] ^= 1;
    assert_ne!(base, changed.binding_digest());

    let mut changed = terms.clone();
    changed.operator_key[0] ^= 1;
    assert_ne!(base, changed.binding_digest());

    let mut changed = terms.clone();
    changed.beneficiary_key[0] ^= 1;
    assert_ne!(base, changed.binding_digest());
}

#[test]
fn assertion_terms_refuse_unusable_values() {
    let mut bad = terms();
    bad.statement_digest[0] |= 0xe0;
    assert_eq!(
        bad.validate(),
        Err(AssertionError::StatementDigestNotFieldSized)
    );

    let mut bad = terms();
    bad.table_digest = [0u8; 32];
    assert!(matches!(
        bad.validate(),
        Err(AssertionError::ZeroField { .. })
    ));

    let mut bad = terms();
    bad.operator_key = BENEFICIARY;
    assert_eq!(bad.validate(), Err(AssertionError::RepeatedKey));

    let mut bad = terms();
    bad.challenge_blocks = 0;
    assert!(matches!(
        bad.validate(),
        Err(AssertionError::InvalidChallengeWindow { .. })
    ));

    let mut bad = terms();
    bad.challenge_blocks = u32::from(u16::MAX) + 1;
    assert!(matches!(
        bad.validate(),
        Err(AssertionError::InvalidChallengeWindow { .. })
    ));

    let mut bad = terms();
    bad.claim_id = [0u8; 32];
    assert!(matches!(
        bad.validate(),
        Err(AssertionError::ZeroField { .. })
    ));
}

#[test]
fn the_claim_taproot_commits_both_leaves() {
    let claim = AssertionClaim::new(STATEMENT, [0x81; 32], BENEFICIARY).expect("claim");
    let scriptpubkey = claim.scriptpubkey().expect("scriptpubkey");
    assert_eq!(&scriptpubkey.as_bytes()[..2], &[0x51, 0x20]);

    let output_key = XOnlyPublicKey::from_slice(&scriptpubkey.as_bytes()[2..]).expect("output key");
    let secp = Secp256k1::verification_only();
    let recovery = ScriptBuf::from_bytes(claim.recovery_script());
    let assertion = ScriptBuf::from_bytes(claim.assertion_script());
    assert_ne!(recovery, assertion);

    for (script, control_block) in [
        (
            recovery,
            claim.recovery_control_block().expect("recovery cb"),
        ),
        (
            assertion,
            claim.assertion_control_block().expect("assertion cb"),
        ),
    ] {
        let control_block = ControlBlock::decode(&control_block).expect("decode control block");
        assert!(
            control_block.verify_taproot_commitment(&secp, output_key, &script),
            "each leaf must be committed by the claim output key"
        );
    }

    // The recovery leaf is the frozen v1 claim script; the assertion leaf is the new one.
    assert_eq!(
        claim.recovery_script(),
        cube::constructive::contracts::fixed_split_vault_v1::claim::claim_script(
            STATEMENT,
            BENEFICIARY
        )
    );
    let other_binding = AssertionClaim::new(STATEMENT, [0x82; 32], BENEFICIARY).expect("other");
    assert_ne!(
        claim.scriptpubkey().unwrap(),
        other_binding.scriptpubkey().unwrap(),
        "a different binding digest must produce a different claim output key"
    );

    // The assertion leaf carries the statement and the binding as dropped constants.
    let script = claim.assertion_script();
    assert_eq!(script.len(), 102);
    assert_eq!(script[0], 0x20);
    assert_eq!(&script[1..33], &STATEMENT);
    assert_eq!(script[33], 0x75);
    assert_eq!(script[34], 0x20);
    assert_eq!(&script[35..67], &[0x81; 32]);
    assert_eq!(script[67], 0x75);
    assert_eq!(script[68], 0x20);
    assert_eq!(&script[69..101], &BENEFICIARY);
    assert_eq!(script[101], 0xac);
}

#[test]
fn the_scripts_have_the_frozen_layout() {
    let binding = terms().binding_digest();
    let take = take_script(binding, 144, OPERATOR);
    assert_eq!(take[0], 0x20);
    assert_eq!(&take[1..33], &binding);
    assert_eq!(take[33], 0x75);
    // 144 is minimally encoded as `02 90 00`, not as `01 90` or four bytes.
    assert_eq!(&take[34..37], &[0x02, 0x90, 0x00]);
    assert_eq!(take[37], 0xb2);
    assert_eq!(take[38], 0x75);
    assert_eq!(take[39], 0x20);
    assert_eq!(&take[40..72], &OPERATOR);
    assert_eq!(take[72], 0xac);

    let assertion = Assertion::new(terms(), contested(), 1_000).expect("assertion");
    let disprove = assertion.disprove_script();
    assert_eq!(disprove.len(), 103);
    assert_eq!(disprove[0], 0x20);
    assert_eq!(&disprove[1..33], &binding);
    assert_eq!(disprove[33], 0x75);
    assert_eq!(disprove[34], 0xa8);
    assert_eq!(disprove[35], 0x20);
    assert_eq!(&disprove[36..68], &terms().secret_commitment);
    assert_eq!(disprove[68], 0x88);
    assert_eq!(disprove[69], 0x20);
    assert_eq!(&disprove[70..102], &BENEFICIARY);
    assert_eq!(disprove[102], 0xac);

    // The claim leaf is a different script from either assertion leaf.
    let claim = assertion_claim_script(STATEMENT, binding, BENEFICIARY);
    assert_eq!(claim.len(), 102);
    assert_ne!(claim, assertion.disprove_script());
    assert_eq!(
        parse_assertion_claim_script(&claim),
        Some((STATEMENT, binding, BENEFICIARY))
    );
    assert_eq!(
        parse_assertion_claim_script(&assertion.disprove_script()),
        None
    );
}

#[test]
fn the_assert_transaction_is_verified_against_the_terms() {
    let terms = terms();
    let assertion = Assertion::new(terms.clone(), contested(), 1_000).expect("assertion");
    assert_eq!(assertion.value_sats(), 99_000);

    let transaction = assertion
        .transaction(Witness::from_slice(&[vec![0x01; 64]]))
        .expect("assert transaction");
    assert_eq!(transaction.input.len(), 1);
    assert_eq!(transaction.input[0].previous_output, contested().outpoint);
    assert_eq!(
        transaction.input[0].sequence,
        Sequence::ENABLE_RBF_NO_LOCKTIME
    );
    assert_eq!(transaction.output[0].value, Amount::from_sat(99_000));
    assert_eq!(
        transaction.output[0].script_pubkey,
        assertion.scriptpubkey().unwrap()
    );

    let verified = Assertion::verify(
        &transaction,
        &terms,
        contested(),
        FeeBounds::new(1_000, 1_000),
    )
    .expect("verify");
    assert_eq!(verified.binding_digest(), assertion.binding_digest());

    // A different fee range is a different authorisation.
    assert!(matches!(
        Assertion::verify(&transaction, &terms, contested(), FeeBounds::new(999, 999)),
        Err(AssertionError::MinerFeeOutOfBounds { .. })
    ));

    // Redirecting the output is refused even when the fee is unchanged.
    let mut redirected = transaction.clone();
    redirected.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
    assert!(matches!(
        Assertion::verify(
            &redirected,
            &terms,
            contested(),
            FeeBounds::new(1_000, 1_000)
        ),
        Err(AssertionError::AssertionScriptMismatch)
    ));

    // Spending another outpoint is refused.
    let mut other_input = transaction.clone();
    other_input.input[0].previous_output.vout += 1;
    assert!(matches!(
        Assertion::verify(
            &other_input,
            &terms,
            contested(),
            FeeBounds::new(1_000, 1_000)
        ),
        Err(AssertionError::TransactionInputMismatch)
    ));

    // The output value may not exceed the contested value.
    let mut overpaid = transaction;
    overpaid.output[0].value = Amount::from_sat(100_001);
    assert!(matches!(
        Assertion::verify(&overpaid, &terms, contested(), FeeBounds::new(0, 0)),
        Err(AssertionError::OutputExceedsContested { .. })
    ));
}

#[test]
fn take_is_timelocked_and_verified() {
    let assertion = Assertion::new(terms(), contested(), 1_000).expect("assertion");
    let destination = ScriptBuf::from_bytes(vec![0x51]);
    let take = TakeSpend::new(&assertion, anchor(), destination.clone(), 500).expect("take");

    let transaction = take.transaction();
    assert_eq!(transaction.version, Version::TWO);
    assert_eq!(transaction.lock_time, LockTime::ZERO);
    assert_eq!(transaction.input[0].sequence, Sequence::from_consensus(144));
    assert_eq!(transaction.output[0].value, Amount::from_sat(98_500));
    assert_eq!(transaction.output[0].script_pubkey, destination);

    // The sighash is over the Take leaf, at leaf version 0xc0 and without a code separator.
    let prevout = TxOut {
        value: Amount::from_sat(99_000),
        script_pubkey: assertion.scriptpubkey().unwrap(),
    };
    let sighash = take.signing_hash(&prevout).expect("sighash");
    let script = assertion.take_script();
    let leaf_hash = bitcoin::taproot::TapLeafHash::from_byte_array(
        cube::constructive::taproot::hash_tap_leaf(&script, 0xc0),
    );
    let expected = SighashCache::new(take.transaction())
        .taproot_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            None,
            Some((leaf_hash, 0xffff_ffff)),
            bitcoin::sighash::TapSighashType::Default,
        )
        .expect("reference sighash");
    assert_eq!(sighash, expected.to_byte_array());

    let witness = take.witness([0x77; 64]).expect("witness");
    assert_eq!(witness.len(), 3);
    assert_eq!(witness[0], [0x77; 64]);
    assert_eq!(witness[1], script);
    assert_eq!(witness[2], assertion.take_control_block().unwrap());

    let verified = TakeSpend::verify(
        &transaction,
        &assertion,
        anchor(),
        &destination,
        FeeBounds::new(500, 500),
    )
    .expect("verify take");
    assert_eq!(verified.fee_sats(), 500);

    // A Take with another sequence is a different authorisation and is refused.
    let mut wrong_sequence = transaction.clone();
    wrong_sequence.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    assert!(matches!(
        TakeSpend::verify(
            &wrong_sequence,
            &assertion,
            anchor(),
            &destination,
            FeeBounds::new(500, 500)
        ),
        Err(AssertionError::TransactionInputMismatch)
    ));

    // A Take that pays somebody else is refused.
    let mut other_destination = transaction;
    other_destination.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x52]);
    assert!(matches!(
        TakeSpend::verify(
            &other_destination,
            &assertion,
            anchor(),
            &destination,
            FeeBounds::new(500, 500)
        ),
        Err(AssertionError::DestinationMismatch)
    ));
}

#[test]
fn disprove_requires_the_committed_secret() {
    let assertion = Assertion::new(terms(), contested(), 1_000).expect("assertion");
    let destination = ScriptBuf::from_bytes(vec![0x51]);

    // The wrong secret does not open the hashlock, so no descriptor is produced.
    assert_eq!(
        DisproveSpend::new(&assertion, anchor(), OTHER_SECRET, destination.clone(), 500)
            .unwrap_err(),
        AssertionError::WrongDisclosureSecret
    );

    let disprove = DisproveSpend::new(&assertion, anchor(), SECRET, destination.clone(), 500)
        .expect("disprove");
    let transaction = disprove.transaction();
    assert_eq!(
        transaction.input[0].sequence,
        Sequence::ENABLE_RBF_NO_LOCKTIME
    );
    assert_eq!(transaction.output[0].value, Amount::from_sat(98_500));

    let witness = disprove.witness([0x77; 64]).expect("witness");
    assert_eq!(witness.len(), 4);
    assert_eq!(witness[0], [0x77; 64]);
    assert_eq!(witness[1], SECRET);
    assert_eq!(witness[2], assertion.disprove_script());
    assert_eq!(witness[3], assertion.disprove_control_block().unwrap());

    let verified = DisproveSpend::verify(
        &transaction,
        &assertion,
        anchor(),
        SECRET,
        &destination,
        FeeBounds::new(500, 500),
    )
    .expect("verify disprove");
    assert_eq!(verified.fee_sats(), 500);

    // The wrong secret is refused at verification as well.
    assert_eq!(
        DisproveSpend::verify(
            &transaction,
            &assertion,
            anchor(),
            OTHER_SECRET,
            &destination,
            FeeBounds::new(500, 500)
        )
        .unwrap_err(),
        AssertionError::WrongDisclosureSecret
    );
}

#[test]
fn the_secret_commitment_is_a_plain_sha256() {
    let commitment = disclosure_secret_commitment(&SECRET);
    assert_ne!(commitment, [0u8; 32]);
    assert_eq!(commitment, disclosure_secret_commitment(&SECRET));
    assert_ne!(commitment, disclosure_secret_commitment(&OTHER_SECRET));

    // Golden vectors shared with `crates/cube-argo/tests/garbling.rs`: both implementations of the
    // tagged hash must produce these values for the same instance and secret.
    assert_eq!(
        commitment,
        [
            0x02, 0xd4, 0x49, 0xa3, 0x1f, 0xbb, 0x26, 0x7c, 0x8f, 0x35, 0x2e, 0x99, 0x68, 0xa7,
            0x9e, 0x3e, 0x5f, 0xc9, 0x5c, 0x1b, 0xbe, 0xaa, 0x50, 0x2f, 0xd6, 0x45, 0x4e, 0xbd,
            0xe5, 0xa4, 0xbe, 0xdc,
        ]
    );
    assert_eq!(
        terms().binding_digest(),
        [
            0x52, 0xf7, 0x4a, 0x54, 0xd9, 0x4b, 0xaa, 0x62, 0x62, 0x4e, 0x47, 0x8d, 0x69, 0x59,
            0x86, 0x6b, 0x45, 0xee, 0x1a, 0xbc, 0xba, 0xd2, 0x2c, 0xac, 0x8f, 0x60, 0x11, 0x26,
            0xfa, 0xe6, 0x3e, 0xe2,
        ]
    );
}
