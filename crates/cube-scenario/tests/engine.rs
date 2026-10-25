//! Offline checks of the composed CubeVM -> manifest path.
//!
//! The test boots the same managers and session pool the node uses, executes `fund_split` through
//! `exec_call_in_pool`, and derives the manifest from the state the VM reached. It needs no Bitcoin
//! node, but it does write to the disposable `Testbed` databases under the crate directory.
//!
//! The manager fixtures share on-disk databases, so the two cases run one at a time.

use cube_scenario::artifact::{Deposit, Hex};
use cube_scenario::engine::fund_split;
use cube_scenario::keys;
use cube_scenario::transition::{from_vm, TransitionOptions};
use std::sync::Mutex;

/// Serialises the two manager fixtures.
static ENGINE_LOCK: Mutex<()> = Mutex::new(());

/// A synthetic funded deposit.
fn deposit(value_sats: u64) -> Deposit {
    Deposit {
        address: keys::liftv2_address().expect("the fixture address must exist"),
        script_pubkey: "51207a01da2f91e39ff52ffdb6c9b270820d04b0c8b6ee228b1542d7ba02d2a85d51"
            .to_string(),
        account_key: Hex::new(keys::xonly(keys::ALICE_SECRET)),
        engine_key: Hex::new(keys::xonly(keys::ENGINE_SECRET)),
        refund_delay_blocks: keys::REFUND_DELAY_BLOCKS,
        funding_txid: Hex::new([0x09; 32]),
        funding_vout: 1,
        value_sats,
    }
}

#[test]
fn the_cubevm_funds_the_split_and_its_state_becomes_the_manifest() {
    let _guard = ENGINE_LOCK.lock().expect("the engine lock is not poisoned");

    // 1 The VM executes fund_split for the fixture amounts.
    let gross_sats = 498_000;
    let execution_fee_sats = 5_000;
    let owner_start_sats = 1_000_000;
    let vm =
        fund_split(gross_sats, execution_fee_sats, owner_start_sats).expect("the VM must fund");

    assert_eq!(vm.contract_balance_sats, gross_sats - execution_fee_sats);
    assert_eq!(vm.bob_shadow_sats, 345_100);
    assert_eq!(vm.carol_shadow_sats, 147_900);
    assert_eq!(vm.fee_balance_sats, execution_fee_sats);
    assert_eq!(vm.owner_balance_sats, owner_start_sats - gross_sats);
    assert_eq!(vm.entry_fee_sats, 0, "the flow runs with zero entry fees");

    // 2 The manifest is derived from the VM's state.
    let transition = from_vm(&deposit(500_000), &vm, &TransitionOptions::default())
        .expect("the VM state must derive a manifest");
    let manifest = transition.manifest().expect("the manifest must decode");
    assert_eq!(manifest.statement_digest(), transition.statement_digest.0);
    assert_eq!(transition.claims.len(), 2);
    assert_eq!(
        transition
            .vm
            .as_ref()
            .expect("the VM execution is recorded")
            .contract_id,
        vm.contract_id
    );
    assert_eq!(
        transition.claims[0].amount_sats
            + transition.claims[1].amount_sats
            + transition.execution_fee_sats,
        transition.gross_sats
    );
    assert_eq!(
        transition.gross_sats + transition.network_fee_reserve_sats,
        500_000
    );
}

#[test]
fn a_vm_state_that_disagrees_with_the_model_is_rejected() {
    let _guard = ENGINE_LOCK.lock().expect("the engine lock is not poisoned");

    let gross_sats = 100_000;
    let execution_fee_sats = 500;
    let mut vm = fund_split(gross_sats, execution_fee_sats, 200_000).expect("the VM must fund");

    // One satoshi of disagreement must abort before any manifest exists.
    vm.bob_shadow_sats += 1;
    let options = TransitionOptions {
        execution_fee_sats,
        ..TransitionOptions::default()
    };
    let error = from_vm(&deposit(102_000), &vm, &options).expect_err("the disagreement must abort");
    assert!(
        error
            .to_string()
            .contains("does not match the reference model"),
        "{error:#}"
    );
}
