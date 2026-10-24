//! Tests for the `ExitRequest` role.
//!
//! The script is the only thing that reaches the chain, so these tests pin it byte for byte, pin
//! what the parser refuses, and pin that the commitment moves when any term moves.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Txid};
use cube::constructive::graph::exit_request::{
    exit_commitment, ExitRequest, ExitRequestError, ExitTerms, EXIT_MAGIC, EXIT_PREIMAGE_LEN,
    EXIT_SCRIPT_LEN,
};

/// The terms a participant would publish.
fn terms() -> ExitTerms {
    ExitTerms::new(
        OutPoint {
            txid: Txid::from_byte_array([0x71; 32]),
            vout: 3,
        },
        [0x0a; 32],
        900_000,
        [0x5b; 32],
        [0x6c; 32],
    )
}

/// A change script for the notice transaction.
fn change_script() -> ScriptBuf {
    let mut script = vec![0x00, 0x14];
    script.extend([0x42u8; 20]);
    ScriptBuf::from_bytes(script)
}

#[test]
fn the_script_layout_is_frozen_and_round_trips() {
    let request = ExitRequest::new(&terms());
    let script = request.script();

    // 1 Length and header.
    assert_eq!(script.len(), EXIT_SCRIPT_LEN);
    let bytes = script.as_bytes();
    assert_eq!(bytes[0], 0x6a, "OP_RETURN");
    assert_eq!(bytes[1], EXIT_MAGIC.len() as u8);
    assert_eq!(&bytes[2..6], &EXIT_MAGIC);
    assert_eq!(bytes[6], 32);
    assert_eq!(bytes[39], 36);

    // 2 Parsing returns the same request and the same claim locator.
    let parsed = ExitRequest::parse(bytes).expect("the script must parse");
    assert_eq!(parsed, request);
    assert_eq!(parsed.claim_outpoint(), terms().claim_outpoint);
    assert_eq!(parsed.commitment(), exit_commitment(&terms()));

    // 3 The preimage is the documented width.
    assert_eq!(terms().preimage().len(), EXIT_PREIMAGE_LEN);
}

#[test]
fn parsing_refuses_anything_that_is_not_the_frozen_layout() {
    let script = ExitRequest::new(&terms()).script();
    let bytes = script.as_bytes();

    // 1 A different opcode is not an exit request.
    let mut not_return = bytes.to_vec();
    not_return[0] = 0x51;
    assert!(ExitRequest::parse(&not_return).is_none());

    // 2 A different magic is a different protocol.
    let mut wrong_magic = bytes.to_vec();
    wrong_magic[2] = b'X';
    assert!(ExitRequest::parse(&wrong_magic).is_none());

    // 3 Extra or missing bytes are refused rather than truncated.
    let mut longer = bytes.to_vec();
    longer.push(0x00);
    assert!(ExitRequest::parse(&longer).is_none());
    assert!(ExitRequest::parse(&bytes[..bytes.len() - 1]).is_none());

    // 4 A wrong push length is refused even when the total length matches.
    let mut wrong_push = bytes.to_vec();
    wrong_push[39] = 35;
    assert!(ExitRequest::parse(&wrong_push).is_none());
}

#[test]
fn verification_accepts_the_terms_and_rejects_each_changed_field() {
    let request = ExitRequest::new(&terms());
    assert_eq!(request.verify(&terms()), Ok(()));

    // 1 The claim locator is checked directly.
    let mut other_claim = terms();
    other_claim.claim_outpoint.vout += 1;
    assert!(matches!(
        request.verify(&other_claim),
        Err(ExitRequestError::ClaimMismatch { .. })
    ));

    // 2 Every other term moves the commitment.
    let mut other_statement = terms();
    other_statement.statement_digest[0] ^= 0x01;
    assert!(matches!(
        request.verify(&other_statement),
        Err(ExitRequestError::CommitmentMismatch { .. })
    ));

    let mut other_deadline = terms();
    other_deadline.deadline_height += 1;
    assert!(matches!(
        request.verify(&other_deadline),
        Err(ExitRequestError::CommitmentMismatch { .. })
    ));

    let mut other_operation = terms();
    other_operation.operation_id[0] ^= 0x01;
    assert!(matches!(
        request.verify(&other_operation),
        Err(ExitRequestError::CommitmentMismatch { .. })
    ));

    let mut other_data = terms();
    other_data.data_descriptor_digest[0] ^= 0x01;
    assert!(matches!(
        request.verify(&other_data),
        Err(ExitRequestError::CommitmentMismatch { .. })
    ));
}

#[test]
fn the_commitment_is_bound_to_every_term() {
    let base = exit_commitment(&terms());

    let mut variants = Vec::new();

    let mut v = terms();
    v.claim_outpoint.txid = Txid::from_byte_array([0x72; 32]);
    variants.push(v);

    let mut v = terms();
    v.claim_outpoint.vout = 4;
    variants.push(v);

    let mut v = terms();
    v.statement_digest[31] ^= 0x01;
    variants.push(v);

    let mut v = terms();
    v.deadline_height += 1;
    variants.push(v);

    let mut v = terms();
    v.operation_id[31] ^= 0x01;
    variants.push(v);

    let mut v = terms();
    v.data_descriptor_digest[31] ^= 0x01;
    variants.push(v);

    for variant in variants {
        assert_ne!(exit_commitment(&variant), base);
    }
}

#[test]
fn the_notice_transaction_pays_the_notice_and_the_change_only() {
    let request = ExitRequest::new(&terms());
    let funding = OutPoint {
        txid: Txid::from_byte_array([0x33; 32]),
        vout: 1,
    };

    let transaction = request
        .transaction(funding, 50_000, change_script(), 1_000)
        .expect("the notice must build");

    assert_eq!(transaction.input.len(), 1);
    assert_eq!(transaction.input[0].previous_output, funding);
    assert_eq!(
        transaction.input[0].sequence,
        Sequence::ENABLE_RBF_NO_LOCKTIME
    );

    assert_eq!(transaction.output.len(), 2);
    assert_eq!(transaction.output[0].value, Amount::from_sat(0));
    assert_eq!(transaction.output[0].script_pubkey, request.script());
    assert_eq!(transaction.output[1].value, Amount::from_sat(49_000));
    assert_eq!(transaction.output[1].script_pubkey, change_script());

    // A fee that consumes the input is not a transaction.
    assert_eq!(
        request.transaction(funding, 50_000, change_script(), 50_000),
        Err(ExitRequestError::FeeExceedsValue {
            value_sats: 50_000,
            fee_sats: 50_000,
        })
    );
}
