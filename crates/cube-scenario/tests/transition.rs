//! Offline checks of the artifact model and the derived transition.
//!
//! The derivation is a pure function of a deposit and its options, so these tests run without a
//! node. They pin the properties a scenario relies on: the manifest is the model's, the two claim
//! bindings are distinct and non-zero, the split accounts for every satoshi, and the same deposit
//! derives the same artifacts.

use cube_scenario::artifact::{Deposit, Hex, State};
use cube_scenario::keys;
use cube_scenario::transition::{derive, TransitionOptions};

/// A synthetic funded deposit; no node is involved.
fn deposit(value_sats: u64) -> Deposit {
    Deposit {
        address: keys::liftv2_address().expect("the fixture address must exist"),
        script_pubkey: "51207a01da2f91e39ff52ffdb6c9b270820d04b0c8b6ee228b1542d7ba02d2a85d51"
            .to_string(),
        account_key: Hex::new(keys::xonly(keys::ALICE_SECRET)),
        engine_key: Hex::new(keys::xonly(keys::ENGINE_SECRET)),
        refund_delay_blocks: keys::REFUND_DELAY_BLOCKS,
        funding_txid: Hex::new([0x01; 32]),
        funding_vout: 1,
        value_sats,
    }
}

#[test]
fn the_transition_is_derived_from_the_model_and_round_trips() {
    let deposit = deposit(500_000);
    let transition = derive(&deposit, &TransitionOptions::default()).expect("derivation");

    // 1 The artifact's digest is the manifest's digest.
    let manifest = transition.manifest().expect("the manifest must decode");
    assert_eq!(manifest.statement_digest(), transition.statement_digest.0);
    assert_eq!(
        manifest.anchors,
        vec![cube_scenario::artifact::anchor_of(&deposit)]
    );

    // 2 Two claims, in manifest order, and the split accounts for every satoshi of the gross value.
    assert_eq!(transition.claims.len(), 2);
    let paid: u64 = transition
        .claims
        .iter()
        .map(|claim| claim.amount_sats)
        .sum::<u64>()
        + transition.execution_fee_sats;
    assert_eq!(paid, transition.gross_sats);
    assert_eq!(
        transition.gross_sats + transition.network_fee_reserve_sats,
        deposit.value_sats
    );

    // 3 The binding commits valid terms and is not degenerate.
    for claim in &transition.claims {
        claim
            .terms
            .to_terms()
            .validate()
            .expect("the fixture terms must be valid");
        assert_ne!(claim.binding_digest.0, [0u8; 32]);
        assert_eq!(claim.terms.binding_digest(), claim.binding_digest);
    }
    assert_ne!(
        transition.claims[0].binding_digest,
        transition.claims[1].binding_digest
    );

    // 4 Deriving again from the same deposit produces the same artifacts.
    let again = derive(&deposit, &TransitionOptions::default()).expect("second derivation");
    assert_eq!(transition.manifest, again.manifest);
    assert_eq!(transition.claims, again.claims);
}

#[test]
fn an_over_reserved_deposit_is_rejected_before_the_model_runs() {
    let error = derive(&deposit(1_000), &TransitionOptions::default()).expect_err("must reject");
    assert!(
        error.to_string().contains("exceeds the deposit"),
        "{error:#}"
    );
}

#[test]
fn the_state_file_round_trips_and_rejects_another_version() {
    let path =
        std::env::temp_dir().join(format!("cube-scenario-state-{}.json", std::process::id()));
    let mut state = State::new();
    state.wallet = "cube-cli".to_string();
    state.deposit = Some(deposit(500_000));
    state.save(&path).expect("save");

    let loaded = State::load(&path).expect("load");
    assert_eq!(loaded.deposit.expect("deposit").value_sats, 500_000);

    let mut text = std::fs::read_to_string(&path).expect("read");
    text = text.replace("\"version\": 1", "\"version\": 2");
    std::fs::write(&path, text).expect("write");
    assert!(State::load(&path).is_err());

    std::fs::remove_file(&path).expect("cleanup");
}
