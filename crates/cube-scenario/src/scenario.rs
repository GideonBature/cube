//! The graph steps the CLI exposes, and the composed scenarios built from them.
//!
//! Each step takes the shared [`State`], derives exactly one transaction from the artifacts earlier
//! steps produced, opens it to the node's policy check, broadcasts it, and records what it learned.
//! A step never invents a value it could read from the state: the successor's outputs come from
//! `SuccessorFunding`, the claim scripts from the recovery packages, and the assertion terms from
//! the binding that is already inside the claim.
//!
//! The scenarios are the same flows as the node-backed integration tests, but driven from JSON
//! artifacts instead of Rust fixtures:
//!
//! - `liftv2-cooperative` — `tests/liftv2_regtest.rs::composed_graph_cooperative_settlement_closes_both_claims`
//! - `liftv2-dispute` — `tests/liftv2_regtest.rs::composed_graph_dispute_and_recovery_use_no_engine_signature`
//! - `proof-take` — the `Assert`/`Take` half of `tests/proof_take_regtest.rs`
//! - `liftv2-refund` — `tests/liftv2_regtest.rs::liftv2_refund_is_rejected_before_maturity_and_accepted_after`
//!
//! `proof-take` uses fixture assertion terms: the table verdict is represented by the committed
//! authenticated-input digest. The real Groth16/Argo path is the release-mode integration test,
//! which additionally requires the proving stack; this CLI deliberately does not link it.

use crate::artifact::{
    AssertionState, Deposit, Hex, Hex32, State, Terms, Transition, Tree, TreeClaim,
};
use crate::chain::Chain;
use crate::keys;
use crate::signing;
use crate::transition::{self, TransitionOptions};
use crate::DebugContext;
use anyhow::{bail, Context, Result};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};
use cube::constructive::contracts::fixed_split_vault_v1::claim::statement_op_return_script;
use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::ClaimRecoveryPackage;
use cube::constructive::graph::assertion::{
    Assertion, AssertionAnchor, AssertionClaim, ContestedOutput, DisproveSpend, TakeSpend,
};
use cube::constructive::graph::claim_recovery::ClaimRecovery;
use cube::constructive::graph::cooperative_settle::CooperativeSettle;
use cube::constructive::graph::successor_funding::{
    DepositAnchor, FeeBounds, FundingOutput, SuccessorFunding,
};
use cube::model::fixed_split_vault_v1::manifest::{Anchor, ReleaseProfile, TransitionManifest};
use serde::Serialize;
use serde_json::json;

/// The recovery package's nominal expiry, in blocks after the claim is funded.
const PACKAGE_EXPIRY_BLOCKS: u64 = 432;

/// The recovery package's recorded fee rate, sat/vB.
const PACKAGE_FEE_RATE: u64 = 10;

/// The name and one-line description of every scenario.
pub const SCENARIOS: [(&str, &str); 7] = [
    (
        "liftv2-cooperative",
        "deposit -> successor with two v2 claims -> one cooperative settlement",
    ),
    (
        "liftv2-dispute",
        "deposit -> successor -> assert and disprove one claim, recover the other",
    ),
    (
        "proof-take",
        "deposit -> successor -> assert -> take after the challenge window",
    ),
    (
        "liftv2-refund",
        "deposit -> premature refund rejected -> mine past the timelock -> refund accepted",
    ),
    (
        "engine-cheat",
        "tampered successors, a forged assertion, a premature take, a wrong take signer and a wrong secret are all rejected; the honest path still settles",
    ),
    (
        "engine-offline",
        "a one-signer successor is rejected and the participant exits through the mature refund",
    ),
    (
        "engine-e2e",
        "the CubeVM executes fund_split, the manifest is derived from the VM's state, and Bitcoin settles the two claims",
    ),
];

/// Parameters of a composed scenario.
#[derive(Debug, Clone)]
pub struct ScenarioOptions {
    /// The deposit value.
    pub deposit_sats: u64,
    /// The execution fee the manifest declares.
    pub execution_fee_sats: u64,
    /// The relative challenge window, in blocks.
    pub challenge_blocks: u32,
    /// The optional destination every scenario payout uses. When absent, fresh wallet addresses
    /// are used.
    pub destination: Option<String>,
    /// The miner fee of an `Assert`.
    pub claim_fee_sats: u64,
    /// The miner fee of a `Take`, `Disprove` or recovery.
    pub payout_fee_sats: u64,
    /// The value of the external fee input a cooperative settlement spends.
    pub settle_fee_input_sats: u64,
}

impl Default for ScenarioOptions {
    fn default() -> Self {
        Self {
            deposit_sats: 500_000,
            execution_fee_sats: 5_000,
            challenge_blocks: 144,
            destination: None,
            claim_fee_sats: 1_000,
            payout_fee_sats: 500,
            settle_fee_input_sats: 2_000,
        }
    }
}

impl ScenarioOptions {
    /// Returns the transition options this scenario asks for.
    pub fn transition(&self) -> TransitionOptions {
        TransitionOptions {
            execution_fee_sats: self.execution_fee_sats,
            challenge_blocks: self.challenge_blocks,
            ..TransitionOptions::default()
        }
    }
}

/// One observable step of a scenario.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioStep {
    /// What the step did.
    pub step: String,
    /// The transaction it produced, when it produced one.
    pub txid: Option<Hex32>,
    /// Step-specific facts.
    pub outcome: serde_json::Value,
}

/// The result of running a scenario.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioReport {
    /// The scenario name.
    pub scenario: String,
    /// The node wallet.
    pub wallet: String,
    /// The step records, in order.
    pub steps: Vec<ScenarioStep>,
}

impl ScenarioReport {
    fn new(scenario: &str, wallet: &str) -> Self {
        Self {
            scenario: scenario.to_string(),
            wallet: wallet.to_string(),
            steps: Vec::new(),
        }
    }

    fn step(&mut self, step: impl Into<String>, txid: Option<Txid>, outcome: serde_json::Value) {
        self.steps.push(ScenarioStep {
            step: step.into(),
            txid: txid.map(|txid| Hex::new(txid.to_byte_array())),
            outcome,
        });
    }
}

/// A payout a settlement or recovery produced.
#[derive(Debug, Clone, Serialize)]
pub struct Payout {
    /// The input or claim index.
    pub index: u32,
    /// The beneficiary fixture name.
    pub beneficiary: String,
    /// The destination address.
    pub destination: String,
    /// The value the destination received.
    pub amount_sats: u64,
}

/// The result of a cooperative settlement.
#[derive(Debug, Clone, Serialize)]
pub struct SettlementOutcome {
    /// The settlement transaction.
    pub txid: Hex32,
    /// The miner fee the external input paid.
    pub miner_fee_sats: u64,
    /// The payouts, in claim order.
    pub payouts: Vec<Payout>,
}

/// The result of a claim recovery.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryOutcome {
    /// The recovery transaction.
    pub txid: Hex32,
    /// The claim index.
    pub claim_index: u32,
    /// The destination address.
    pub destination: String,
    /// The value the destination received.
    pub amount_sats: u64,
}

/// The result of an `Assert`.
#[derive(Debug, Clone, Serialize)]
pub struct AssertOutcome {
    /// The assertion transaction.
    pub txid: Hex32,
    /// The claim index.
    pub claim_index: u32,
    /// The value the assertion output holds.
    pub value_sats: u64,
}

/// The result of a `Take`.
#[derive(Debug, Clone, Serialize)]
pub struct TakeOutcome {
    /// The take transaction, when one was broadcast.
    pub txid: Option<Hex32>,
    /// Whether the transaction was accepted and broadcast.
    pub accepted: bool,
    /// The premature rejection, when the node refused it before the window.
    pub premature_rejection: Option<String>,
    /// The blocks mined to reach the window, when waiting.
    pub waited_blocks: u64,
    /// The destination address.
    pub destination: String,
    /// The value the destination received.
    pub amount_sats: u64,
}

/// The result of a `Disprove`.
#[derive(Debug, Clone, Serialize)]
pub struct DisproveOutcome {
    /// The disprove transaction.
    pub txid: Hex32,
    /// The destination address.
    pub destination: String,
    /// The value the destination received.
    pub amount_sats: u64,
}

/// The result of a refund attempt.
#[derive(Debug, Clone, Serialize)]
pub struct RefundOutcome {
    /// The refund transaction, when one was broadcast.
    pub txid: Option<Hex32>,
    /// Whether the transaction was accepted and broadcast.
    pub accepted: bool,
    /// The node's rejection, when it refused the refund.
    pub rejection: Option<String>,
    /// The blocks mined to reach maturity, when asked to.
    pub mined_blocks: u64,
    /// The destination address.
    pub destination: String,
    /// The value the destination received.
    pub amount_sats: u64,
}

// ---------------------------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------------------------

/// Funds the fixture LiftV2 address and records the deposit.
pub fn fund_deposit(chain: &Chain, state: &mut State, amount_sats: u64) -> Result<Deposit> {
    let taproot = keys::liftv2_taproot().context("the LiftV2 taproot could not be constructed")?;
    let script = ScriptBuf::from_bytes(
        taproot
            .spk()
            .context("the LiftV2 taproot has no scriptpubkey")?,
    );
    let address = Address::from_script(&script, Network::Regtest)
        .context("the LiftV2 scriptpubkey is not a valid address")?;
    let txid = chain.fund(&address.to_string(), amount_sats, true)?;
    let (vout, prevout) = chain.output_for_script(txid, &script)?;

    let deposit = Deposit {
        address: address.to_string(),
        script_pubkey: hex::encode(script.as_bytes()),
        account_key: Hex::new(keys::xonly(keys::ALICE_SECRET)),
        engine_key: Hex::new(keys::xonly(keys::ENGINE_SECRET)),
        refund_delay_blocks: keys::REFUND_DELAY_BLOCKS,
        funding_txid: Hex::new(txid.to_byte_array()),
        funding_vout: vout,
        value_sats: prevout.value.to_sat(),
    };

    state.wallet = chain.wallet().to_string();
    state.deposit = Some(deposit.clone());
    state.transition = None;
    state.tree = None;
    state.assertion = None;
    Ok(deposit)
}

/// Derives and records the transition for the funded deposit.
pub fn build_transition(state: &mut State, options: &TransitionOptions) -> Result<Transition> {
    let deposit = state.require_deposit()?.clone();
    let transition = transition::derive(&deposit, options)?;
    state.transition = Some(transition.clone());
    state.tree = None;
    state.assertion = None;
    Ok(transition)
}

/// A successor that is built and signed but not yet published.
struct PreparedSuccessor {
    transition: Transition,
    manifest: TransitionManifest,
    funding: SuccessorFunding,
    transaction: Transaction,
    statement_vout: u32,
}

/// Builds the successor, signs the deposit key path and re-runs the graph verifier.
fn prepare_successor(state: &State) -> Result<PreparedSuccessor> {
    let deposit = state.require_deposit()?.clone();
    let transition = state.require_transition()?.clone();
    let manifest = transition.manifest()?;
    let taproot = keys::liftv2_taproot().context("the LiftV2 taproot could not be constructed")?;
    let deposit_prevout = TxOut {
        value: bitcoin::Amount::from_sat(deposit.value_sats),
        script_pubkey: deposit.spk()?,
    };

    // 1 Build through the graph rule; `new_with_assertions` runs the verifier itself.
    let funding = SuccessorFunding::new_with_assertions(
        &manifest,
        DepositAnchor::new(deposit.outpoint(), deposit.value_sats),
        transition.network_fee_reserve_sats,
        Some(transition.fee_script()?),
        &transition.bindings(),
    )
    .context_debug("the successor does not fund every manifest obligation")?;
    let mut transaction = funding.transaction();

    // 2 Sign the deposit's key path with MuSig2 and self-check the aggregate.
    transaction.input[0].witness = signing::deposit_key_path_witness(
        &taproot,
        &[keys::ALICE_SECRET, keys::ENGINE_SECRET],
        &transaction,
        0,
        &deposit_prevout,
    )?;

    // 3 Re-run the graph verifier over the exact bytes that will be broadcast.
    SuccessorFunding::verify_with_assertions(
        &transaction,
        &manifest,
        deposit.outpoint(),
        deposit.value_sats,
        FeeBounds::new(
            transition.network_fee_reserve_sats,
            transition.network_fee_reserve_sats,
        ),
        &transition.bindings(),
    )
    .context_debug("the signed successor fails the graph verifier")?;

    let statement_vout = (funding.outputs().len() - 1) as u32;
    Ok(PreparedSuccessor {
        transition,
        manifest,
        funding,
        transaction,
        statement_vout,
    })
}

/// Publishes a prepared successor and records the ownership tree it created.
fn publish_prepared(chain: &Chain, state: &mut State, prepared: PreparedSuccessor) -> Result<Tree> {
    // 1 Bitcoin Core must accept it before anything is published.
    chain
        .test_mempool_accept(&prepared.transaction)?
        .require("the successor funding")?;
    let txid = chain.broadcast(&prepared.transaction, true)?;

    // 2 Record one claim per beneficiary output, with the v2 package the beneficiary can recover
    //   from without the Engine.
    let expiry_height = chain.height()? + PACKAGE_EXPIRY_BLOCKS;
    let mut claims = Vec::new();
    let mut beneficiary_index = 0u32;
    for (vout, output) in prepared.funding.outputs().iter().enumerate() {
        let FundingOutput::Claim {
            beneficiary_key,
            amount_sats,
            script_pubkey,
            ..
        } = output.clone()
        else {
            continue;
        };
        let binding = prepared
            .transition
            .claims
            .iter()
            .find(|claim| claim.beneficiary_key.0 == beneficiary_key)
            .context("the successor paid a claim the transition does not bind")?;
        let package = ClaimRecoveryPackage::new_with_assertion(
            ReleaseProfile::ArgoSplitRegtest,
            binding.claim_id.0,
            None,
            beneficiary_key,
            prepared.manifest.template_hash,
            prepared.manifest.circuit_id,
            prepared.transition.statement_digest.0,
            binding.binding_digest.0,
            amount_sats,
            Some(Anchor::new(txid.to_byte_array(), vout as u32)),
            expiry_height,
            PACKAGE_FEE_RATE,
            prepared.manifest.setup_instance_id,
            prepared.manifest.challenge_config_digest,
        )
        .context("the v2 recovery package could not be built")?;
        package
            .validate()
            .context_debug("the v2 recovery package is invalid")?;
        if package.claim_scriptpubkey().as_deref() != Some(script_pubkey.as_bytes()) {
            bail!("the recovery package does not describe the funded claim output");
        }

        claims.push(TreeClaim {
            index: beneficiary_index,
            vout: vout as u32,
            beneficiary_key: binding.beneficiary_key,
            amount_sats,
            script_pubkey: hex::encode(script_pubkey.as_bytes()),
            package: hex::encode(package.encode()),
            terms: binding.terms.clone(),
        });
        beneficiary_index += 1;
    }

    let tree = Tree {
        txid: Hex::new(txid.to_byte_array()),
        hex: serialize_hex(&prepared.transaction),
        statement_vout: prepared.statement_vout,
        claims,
    };
    state.tree = Some(tree.clone());
    state.assertion = None;
    Ok(tree)
}

/// Builds, verifies, signs and publishes the successor funding.
pub fn publish_successor(chain: &Chain, state: &mut State) -> Result<Tree> {
    let prepared = prepare_successor(state)?;
    publish_prepared(chain, state, prepared)
}

/// Re-checks the deposit artifact against the fixture address and the chain.
pub fn verify_deposit(chain: &Chain, state: &State) -> Result<serde_json::Value> {
    let deposit = state.require_deposit()?;
    let taproot = keys::liftv2_taproot().context("the LiftV2 taproot could not be constructed")?;
    let expected_script = ScriptBuf::from_bytes(
        taproot
            .spk()
            .context("the LiftV2 taproot has no scriptpubkey")?,
    );
    let expected_address = Address::from_script(&expected_script, Network::Regtest)
        .context("the fixture deposit script is not a valid address")?;

    if deposit.spk()? != expected_script {
        bail!("the recorded deposit script is not the fixture LiftV2 taproot");
    }
    if deposit.address != expected_address.to_string() {
        bail!("the recorded deposit address is not the fixture address");
    }
    if deposit.account_key.0 != keys::xonly(keys::ALICE_SECRET)
        || deposit.engine_key.0 != keys::xonly(keys::ENGINE_SECRET)
    {
        bail!("the recorded deposit keys are not the fixture keys");
    }

    let outpoint = deposit.outpoint();
    let transaction = chain.wallet_transaction(outpoint.txid)?;
    let output = transaction
        .output
        .get(outpoint.vout as usize)
        .context("the funding transaction has no output at the recorded index")?;
    if output.script_pubkey != expected_script {
        bail!("the funded output does not pay the fixture deposit script");
    }
    if output.value.to_sat() != deposit.value_sats {
        bail!("the funded output value does not match the recorded deposit value");
    }

    Ok(json!({
        "verified": true,
        "address": &deposit.address,
        "value_sats": deposit.value_sats,
        "funding_unspent": chain.unspent(outpoint.txid, outpoint.vout)?,
    }))
}

/// Re-derives the transition and checks every stored byte against the derivation.
pub fn verify_transition(state: &State) -> Result<serde_json::Value> {
    let deposit = state.require_deposit()?;
    let transition = state.require_transition()?;
    let manifest = transition.manifest()?;
    manifest
        .validate()
        .context_debug("the stored manifest is invalid")?;
    if manifest.statement_digest() != transition.statement_digest.0 {
        bail!("the stored statement digest is not the manifest's digest");
    }
    if transition.gross_sats + transition.network_fee_reserve_sats != deposit.value_sats {
        bail!("the stored gross value and fee reserve do not add up to the deposit");
    }
    if transition.execution_fee_sats >= transition.gross_sats {
        bail!("the stored execution fee is not below the gross value");
    }

    let first = transition
        .claims
        .first()
        .context("the transition has no claims")?;
    let options = TransitionOptions {
        network_fee_reserve_sats: transition.network_fee_reserve_sats,
        execution_fee_sats: transition.execution_fee_sats,
        challenge_blocks: transition.challenge_blocks,
        verifier_key_identity: Some(first.terms.verifier_key_identity.0),
        table_digest: Some(first.terms.table_digest.0),
        input_digest: Some(first.terms.input_digest.0),
    };
    let again = match &transition.vm {
        Some(vm) => transition::from_vm(deposit, vm, &options)?,
        None => transition::derive(deposit, &options)?,
    };
    if again.manifest != transition.manifest {
        bail!("the stored manifest is not the one this deposit derives");
    }
    if again.claims != transition.claims {
        bail!("the stored claim bindings are not the ones this deposit derives");
    }

    Ok(json!({
        "verified": true,
        "statement_digest": transition.statement_digest,
        "gross_sats": transition.gross_sats,
        "execution_fee_sats": transition.execution_fee_sats,
        "claims": transition.claims.iter().map(|claim| json!({
            "beneficiary": keys::name_for_xonly(claim.beneficiary_key.0).unwrap_or("unknown"),
            "amount_sats": claim.amount_sats,
            "binding_digest": claim.binding_digest,
        })).collect::<Vec<_>>(),
    }))
}

/// Re-runs the successor verifier and every claim package against the stored artifacts.
pub fn verify_successor(chain: &Chain, state: &State) -> Result<serde_json::Value> {
    let deposit = state.require_deposit()?;
    let transition = state.require_transition()?;
    let tree = state.require_tree()?;
    let manifest = transition.manifest()?;

    let raw = hex::decode(&tree.hex).context("the stored successor is not hex")?;
    let transaction: Transaction =
        bitcoin::consensus::deserialize(&raw).context("the stored successor does not decode")?;
    if transaction.compute_txid().to_byte_array() != tree.txid.0 {
        bail!("the stored successor bytes do not hash to the stored txid");
    }
    if transaction.input[0].witness.is_empty() {
        bail!("the stored successor carries no signature");
    }

    let funding = SuccessorFunding::verify_with_assertions(
        &transaction,
        &manifest,
        deposit.outpoint(),
        deposit.value_sats,
        FeeBounds::new(
            transition.network_fee_reserve_sats,
            transition.network_fee_reserve_sats,
        ),
        &transition.bindings(),
    )
    .context_debug("the stored successor fails the graph verifier")?;

    // The statement commitment must be the manifest's field-sized digest, at zero value.
    let commitment = transaction
        .output
        .get(tree.statement_vout as usize)
        .context("the successor has no statement commitment output")?;
    let expected_commitment = statement_op_return_script(manifest.statement_digest());
    if commitment.value.to_sat() != 0
        || commitment.script_pubkey.as_bytes() != expected_commitment.as_slice()
    {
        bail!("the statement commitment output is not the manifest digest");
    }

    let successor_txid = Txid::from_byte_array(tree.txid.0);
    let mut all_unspent = true;
    let mut claims = Vec::new();
    for claim in &tree.claims {
        let output = funding
            .outputs()
            .get(claim.vout as usize)
            .context("the successor has no output at a claim's index")?;
        let FundingOutput::Claim {
            beneficiary_key,
            amount_sats,
            script_pubkey,
            assertion_binding_digest,
        } = output
        else {
            bail!("successor output {} is not a claim", claim.vout);
        };
        if *beneficiary_key != claim.beneficiary_key.0 || *amount_sats != claim.amount_sats {
            bail!("claim {} does not match the successor output", claim.index);
        }
        let claim_script = claim.spk()?;
        if claim_script != *script_pubkey {
            bail!(
                "claim {} script does not match the successor output",
                claim.index
            );
        }
        let binding = claim.terms.binding_digest().0;
        if *assertion_binding_digest != Some(binding) {
            bail!(
                "claim {} binding is not the one in the successor",
                claim.index
            );
        }

        let package = claim.package()?;
        package
            .validate()
            .context_debug("a stored claim package is invalid")?;
        if package.claim_scriptpubkey().as_deref() != Some(claim_script.as_bytes()) {
            bail!("claim {} package does not describe its script", claim.index);
        }
        if package.claim_outpoint != Some(Anchor::new(tree.txid.0, claim.vout)) {
            bail!("claim {} package anchors another outpoint", claim.index);
        }
        if package.statement_digest != manifest.statement_digest() {
            bail!("claim {} package binds another statement", claim.index);
        }
        if package.assertion_binding_digest != Some(binding) {
            bail!("claim {} package carries another binding", claim.index);
        }

        let unspent = chain.unspent(successor_txid, claim.vout)?;
        all_unspent &= unspent;
        claims.push(json!({
            "index": claim.index,
            "vout": claim.vout,
            "beneficiary": keys::name_for_xonly(claim.beneficiary_key.0).unwrap_or("unknown"),
            "amount_sats": claim.amount_sats,
            "unspent": unspent,
        }));
    }

    Ok(json!({
        "verified": true,
        "successor": tree.txid,
        "statement_digest": Hex::new(manifest.statement_digest()),
        "miner_fee_sats": funding.miner_fee_sats(),
        "claims": claims,
        "all_claims_unspent": all_unspent,
    }))
}

/// Spends every claim in one cooperative settlement.
pub fn settle_claims(
    chain: &Chain,
    state: &mut State,
    destinations: Option<Vec<String>>,
    fee_input_sats: u64,
) -> Result<SettlementOutcome> {
    let tree = state.require_tree()?.clone();
    let transition = state.require_transition()?.clone();
    let manifest = transition.manifest()?;

    // 1 Decode every package from its artifact; the settlement re-checks the set.
    let packages: Vec<ClaimRecoveryPackage> = tree
        .claims
        .iter()
        .map(TreeClaim::package)
        .collect::<Result<_>>()?;

    // 2 The destinations are the beneficiaries' own; without an explicit list, fresh wallet
    //   addresses stand in for them.
    let destinations = match destinations {
        Some(destinations) => {
            if destinations.len() != tree.claims.len() {
                bail!(
                    "{} destinations were supplied for {} claims",
                    destinations.len(),
                    tree.claims.len()
                );
            }
            destinations
        }
        None => (0..tree.claims.len())
            .map(|_| chain.new_address())
            .collect::<Result<Vec<_>>>()?,
    };
    let scripts: Vec<ScriptBuf> = destinations
        .iter()
        .map(|address| chain.script(address))
        .collect::<Result<_>>()?;

    // 3 A local key-path P2TR input pays the miner fee; its whole value is the fee.
    let (fee_outpoint, fee_prevout) =
        chain.fund_p2tr(keys::xonly(keys::ALICE_SECRET), fee_input_sats)?;

    let settlement = CooperativeSettle::new(
        &manifest,
        &packages,
        scripts.clone(),
        fee_outpoint,
        &fee_prevout,
        FeeBounds::new(fee_input_sats, fee_input_sats),
    )
    .context_debug("the cooperative settlement does not cover the claim tree")?;

    // 4 Verify the unsigned bytes before installing any signature.
    let mut transaction = settlement.transaction();
    CooperativeSettle::verify(
        &transaction,
        &manifest,
        &packages,
        &scripts,
        fee_outpoint,
        &fee_prevout,
        FeeBounds::new(fee_input_sats, fee_input_sats),
    )
    .context_debug("the settlement transaction fails its own verifier")?;

    let mut prevouts = settlement
        .claim_prevouts()
        .context_debug("the settlement claim prevouts")?;
    prevouts.push(fee_prevout.clone());

    // 5 Every beneficiary signs the whole settlement, so no output can be redirected.
    for (index, claim) in tree.claims.iter().enumerate() {
        let secret = keys::secret_for_xonly(claim.beneficiary_key.0)
            .context("the claim beneficiary is not a fixture key")?;
        let sighash = settlement
            .claim_signing_hash(index, &prevouts)
            .context_debug("the settlement claim sighash")?;
        transaction.input[index].witness = settlement
            .claim_witness(index, signing::sign_digest(sighash, secret)?)
            .context_debug("the settlement claim witness")?;
    }
    let fee_index = packages.len();
    transaction.input[fee_index].witness =
        Witness::from_slice(&[signing::p2tr_key_path_signature(
            keys::ALICE_SECRET,
            &transaction,
            fee_index,
            &prevouts,
        )?
        .to_vec()]);

    // 6 Bitcoin Core decides.
    chain
        .test_mempool_accept(&transaction)?
        .require("the cooperative settlement")?;
    let txid = chain.broadcast(&transaction, true)?;

    // 7 Read the mined settlement back and check the payouts are the ones promised.
    let mined = chain.mined(txid)?;
    let mut payouts = Vec::with_capacity(tree.claims.len());
    for (index, claim) in tree.claims.iter().enumerate() {
        let output = mined
            .output
            .get(index)
            .context("the settlement is missing a payout output")?;
        if output.value.to_sat() != claim.amount_sats || output.script_pubkey != scripts[index] {
            bail!("settlement output {index} does not pay the claim's entitlement");
        }
        payouts.push(Payout {
            index: claim.index,
            beneficiary: keys::name_for_xonly(claim.beneficiary_key.0)
                .unwrap_or("unknown")
                .to_string(),
            destination: destinations[index].clone(),
            amount_sats: claim.amount_sats,
        });
    }

    Ok(SettlementOutcome {
        txid: Hex::new(txid.to_byte_array()),
        miner_fee_sats: fee_input_sats,
        payouts,
    })
}

/// Publishes an `Assert` for one claim.
pub fn assert_claim(
    chain: &Chain,
    state: &mut State,
    claim_index: usize,
    fee_sats: u64,
) -> Result<AssertOutcome> {
    let tree = state.require_tree()?.clone();
    let claim = tree.claim(claim_index)?.clone();
    let terms = claim.terms.to_terms();
    let claim_prevout = TxOut {
        value: bitcoin::Amount::from_sat(claim.amount_sats),
        script_pubkey: claim.spk()?,
    };

    let assertion = Assertion::new(
        terms.clone(),
        ContestedOutput {
            outpoint: tree.outpoint(&claim),
            value_sats: claim.amount_sats,
        },
        fee_sats,
    )
    .context_debug("the assertion does not hold")?;

    // The claim output must be the two-leaf claim these terms define.
    let assertion_claim = AssertionClaim::new(
        terms.statement_digest,
        terms.binding_digest(),
        terms.beneficiary_key,
    )
    .context_debug("the assertion claim could not be built")?;
    if assertion_claim
        .scriptpubkey()
        .context_debug("the assertion claim scriptpubkey")?
        != claim_prevout.script_pubkey
    {
        bail!("the claim output does not match the terms being asserted");
    }

    let mut transaction = assertion
        .transaction(Witness::new())
        .context_debug("the assertion transaction")?;
    let sighash = assertion_claim
        .assert_signing_hash(&transaction, &claim_prevout)
        .context_debug("the assertion sighash")?;
    let secret = keys::secret_for_xonly(terms.beneficiary_key)
        .context("the claim beneficiary is not a fixture key")?;
    transaction.input[0].witness = assertion_claim
        .assert_witness(signing::sign_digest(sighash, secret)?)
        .context_debug("the assertion witness")?;

    chain
        .test_mempool_accept(&transaction)?
        .require("the assertion")?;
    let txid = chain.broadcast(&transaction, true)?;

    let assertion_state = AssertionState {
        claim_index: claim_index as u32,
        terms: Terms::from(&terms),
        value_sats: assertion.value_sats(),
        fee_sats,
        txid: Hex::new(txid.to_byte_array()),
        hex: serialize_hex(&transaction),
    };
    state.assertion = Some(assertion_state);
    Ok(AssertOutcome {
        txid: Hex::new(txid.to_byte_array()),
        claim_index: claim_index as u32,
        value_sats: assertion.value_sats(),
    })
}

/// Rebuilds the stored assertion from its artifacts.
fn stored_assertion(state: &State) -> Result<(Assertion, AssertionState, TxOut)> {
    let stored = state.require_assertion()?.clone();
    let tree = state.require_tree()?;
    let claim = tree.claim(stored.claim_index as usize)?;
    let terms = stored.terms.to_terms();
    let assertion = Assertion::new(
        terms,
        ContestedOutput {
            outpoint: tree.outpoint(claim),
            value_sats: claim.amount_sats,
        },
        stored.fee_sats,
    )
    .context_debug("the stored assertion cannot be rebuilt")?;
    if assertion.value_sats() != stored.value_sats {
        bail!("the stored assertion value does not match its terms");
    }
    let prevout = TxOut {
        value: bitcoin::Amount::from_sat(stored.value_sats),
        script_pubkey: assertion
            .scriptpubkey()
            .context_debug("the assertion scriptpubkey")?,
    };
    Ok((assertion, stored, prevout))
}

/// Builds the `Take` transaction and reports the node's verdict.
///
/// With `wait_for_window`, a premature rejection is expected data: the helper mines the challenge
/// window and retries. Without it, the rejection is returned, not treated as a failure.
pub fn take_assertion(
    chain: &Chain,
    state: &mut State,
    destination: Option<String>,
    fee_sats: u64,
    wait_for_window: bool,
) -> Result<TakeOutcome> {
    let (assertion, stored, prevout) = stored_assertion(state)?;
    let destination = match destination {
        Some(address) => address,
        None => chain.new_address()?,
    };
    let destination_script = chain.script(&destination)?;
    let anchor = AssertionAnchor::new(
        OutPoint {
            txid: Txid::from_byte_array(stored.txid.0),
            vout: 0,
        },
        stored.value_sats,
    );
    let spend = TakeSpend::new(&assertion, anchor, destination_script, fee_sats)
        .context_debug("the take spend does not hold")?;
    let mut transaction = spend.transaction();
    let sighash = spend
        .signing_hash(&prevout)
        .context_debug("the take sighash")?;
    transaction.input[0].witness = spend
        .witness(signing::sign_digest(sighash, keys::OPERATOR_SECRET)?)
        .context_debug("the take witness")?;

    // The pre-window rejection is the timelock working; keep its reason for the report.
    let verdict = chain.test_mempool_accept(&transaction)?;
    let premature_rejection = if verdict.allowed {
        None
    } else {
        verdict.reject_reason.clone()
    };
    let mut waited_blocks = 0u64;
    let accepted = if verdict.allowed {
        true
    } else if wait_for_window {
        waited_blocks = u64::from(stored.terms.challenge_blocks);
        chain.mine(waited_blocks)?;
        let mature = chain.test_mempool_accept(&transaction)?;
        mature.require("the mature take")?;
        true
    } else {
        false
    };

    let txid = if accepted {
        Some(chain.broadcast(&transaction, true)?)
    } else {
        None
    };
    Ok(TakeOutcome {
        txid: txid.map(|txid| Hex::new(txid.to_byte_array())),
        accepted,
        premature_rejection,
        waited_blocks,
        destination,
        amount_sats: spend.output_value_sats(),
    })
}

/// Spends an assertion output with the disclosure secret.
pub fn disprove_assertion(
    chain: &Chain,
    state: &mut State,
    destination: Option<String>,
    secret: [u8; 32],
    fee_sats: u64,
) -> Result<DisproveOutcome> {
    let (assertion, stored, prevout) = stored_assertion(state)?;
    let destination = match destination {
        Some(address) => address,
        None => chain.new_address()?,
    };
    let destination_script = chain.script(&destination)?;
    let anchor = AssertionAnchor::new(
        OutPoint {
            txid: Txid::from_byte_array(stored.txid.0),
            vout: 0,
        },
        stored.value_sats,
    );
    let spend = DisproveSpend::new(&assertion, anchor, secret, destination_script, fee_sats)
        .context_debug("the disclosure secret does not open the committed hashlock")?;
    let mut transaction = spend.transaction();
    let sighash = spend
        .signing_hash(&prevout)
        .context_debug("the disprove sighash")?;
    let beneficiary = keys::secret_for_xonly(stored.terms.beneficiary_key.0)
        .context("the assertion beneficiary is not a fixture key")?;
    transaction.input[0].witness = spend
        .witness(signing::sign_digest(sighash, beneficiary)?)
        .context_debug("the disprove witness")?;

    chain
        .test_mempool_accept(&transaction)?
        .require("the disprove")?;
    let txid = chain.broadcast(&transaction, true)?;
    Ok(DisproveOutcome {
        txid: Hex::new(txid.to_byte_array()),
        destination,
        amount_sats: spend.output_value_sats(),
    })
}

/// Spends one claim through its v2 recovery package.
pub fn recover_claim(
    chain: &Chain,
    state: &mut State,
    claim_index: usize,
    destination: Option<String>,
    fee_sats: u64,
) -> Result<RecoveryOutcome> {
    let tree = state.require_tree()?.clone();
    let claim = tree.claim(claim_index)?.clone();
    let package = claim.package()?;
    let claim_prevout = TxOut {
        value: bitcoin::Amount::from_sat(claim.amount_sats),
        script_pubkey: claim.spk()?,
    };
    if package.claim_outpoint != Some(Anchor::new(tree.txid.0, claim.vout)) {
        bail!("the package does not anchor the claim the tree records");
    }

    let destination = match destination {
        Some(address) => address,
        None => chain.new_address()?,
    };
    let destination_script = chain.script(&destination)?;
    let recovery = ClaimRecovery::new(&package, &claim_prevout, destination_script, fee_sats)
        .context_debug("the claim is not recoverable from its package")?;
    let mut transaction = recovery.transaction();
    let sighash = recovery
        .signing_hash(&claim_prevout)
        .context_debug("the recovery sighash")?;
    let secret = keys::secret_for_xonly(claim.beneficiary_key.0)
        .context("the claim beneficiary is not a fixture key")?;
    transaction.input[0].witness = recovery.witness(signing::sign_digest(sighash, secret)?);

    chain
        .test_mempool_accept(&transaction)?
        .require("the claim recovery")?;
    let txid = chain.broadcast(&transaction, true)?;
    Ok(RecoveryOutcome {
        txid: Hex::new(txid.to_byte_array()),
        claim_index: claim_index as u32,
        destination,
        amount_sats: recovery.output_value_sats(),
    })
}

/// Attempts the LiftV2 script-path refund, optionally mining past the relative timelock.
pub fn refund_deposit(
    chain: &Chain,
    state: &mut State,
    destination: Option<String>,
    fee_sats: u64,
    mine_past_maturity: bool,
) -> Result<RefundOutcome> {
    let deposit = state.require_deposit()?.clone();
    let taproot = keys::liftv2_taproot().context("the LiftV2 taproot could not be constructed")?;
    let prevout = TxOut {
        value: bitcoin::Amount::from_sat(deposit.value_sats),
        script_pubkey: deposit.spk()?,
    };
    let destination = match destination {
        Some(address) => address,
        None => chain.new_address()?,
    };
    let transaction = signing::refund_transaction(
        &taproot,
        deposit.outpoint(),
        &prevout,
        chain.script(&destination)?,
        deposit.refund_delay_blocks,
        fee_sats,
        keys::ALICE_SECRET,
    )?;

    // The first attempt is expected to be non-final on a fresh deposit. That rejection is the
    // observation, not a failure.
    let verdict = chain.test_mempool_accept(&transaction)?;
    let rejection = if verdict.allowed {
        None
    } else {
        verdict.reject_reason.clone()
    };

    let mut mined_blocks = 0u64;
    let mut accepted = verdict.allowed;
    if !accepted && mine_past_maturity {
        mined_blocks = u64::from(deposit.refund_delay_blocks);
        chain.mine(mined_blocks)?;
        let mature = chain.test_mempool_accept(&transaction)?;
        mature.require("the mature refund")?;
        accepted = true;
    }

    let txid = if accepted {
        Some(chain.broadcast(&transaction, true)?)
    } else {
        None
    };
    Ok(RefundOutcome {
        txid: txid.map(|txid| Hex::new(txid.to_byte_array())),
        accepted,
        rejection,
        mined_blocks,
        destination,
        amount_sats: deposit.value_sats.saturating_sub(fee_sats),
    })
}

// ---------------------------------------------------------------------------------------------
// Composed scenarios
// ---------------------------------------------------------------------------------------------

/// Requires the node to reject `transaction`, and returns the reason.
///
/// A tampered transaction that the node accepts would mean the attack is possible, so this is a
/// hard failure rather than a report.
fn expect_rejection(chain: &Chain, transaction: &Transaction, what: &str) -> Result<String> {
    let verdict = chain.test_mempool_accept(transaction)?;
    if verdict.allowed {
        bail!("{what} was accepted by the node; that attack must not be possible");
    }
    Ok(verdict
        .reject_reason
        .unwrap_or_else(|| "rejected without a reason".to_string()))
}

/// Runs one named scenario against a fresh state.
pub fn run(
    name: &str,
    chain: &Chain,
    state: &mut State,
    options: &ScenarioOptions,
) -> Result<ScenarioReport> {
    *state = State::new();
    state.wallet = chain.wallet().to_string();
    match name {
        "liftv2-cooperative" => liftv2_cooperative(chain, state, options),
        "liftv2-dispute" => liftv2_dispute(chain, state, options),
        "proof-take" => proof_take(chain, state, options),
        "liftv2-refund" => liftv2_refund(chain, state, options),
        "engine-cheat" => engine_cheat(chain, state, options),
        "engine-offline" => engine_offline(chain, state, options),
        "engine-e2e" => engine_e2e(chain, state, options),
        other => bail!(
            "unknown scenario `{other}`; known scenarios: {}",
            SCENARIOS
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `liftv2-cooperative`: fund, publish two v2 claims, settle both in one transaction.
fn liftv2_cooperative(
    chain: &Chain,
    state: &mut State,
    options: &ScenarioOptions,
) -> Result<ScenarioReport> {
    let mut report = ScenarioReport::new("liftv2-cooperative", chain.wallet());

    let deposit = fund_deposit(chain, state, options.deposit_sats)?;
    report.step(
        "deposit",
        Some(Txid::from_byte_array(deposit.funding_txid.0)),
        json!({
            "address": deposit.address,
            "value_sats": deposit.value_sats,
            "vout": deposit.funding_vout,
        }),
    );

    let transition = build_transition(state, &options.transition())?;
    report.step(
        "transition",
        None,
        json!({
            "statement_digest": transition.statement_digest,
            "gross_sats": transition.gross_sats,
            "execution_fee_sats": transition.execution_fee_sats,
            "claims": transition.claims.iter().map(|claim| json!({
                "beneficiary": keys::name_for_xonly(claim.beneficiary_key.0).unwrap_or("unknown"),
                "amount_sats": claim.amount_sats,
                "binding_digest": claim.binding_digest,
            })).collect::<Vec<_>>(),
        }),
    );

    let tree = publish_successor(chain, state)?;
    report.step(
        "successor",
        Some(Txid::from_byte_array(tree.txid.0)),
        json!({
            "claims": tree.claims.iter().map(|claim| json!({
                "index": claim.index,
                "vout": claim.vout,
                "amount_sats": claim.amount_sats,
            })).collect::<Vec<_>>(),
            "statement_vout": tree.statement_vout,
        }),
    );

    let settlement = settle_claims(chain, state, None, options.settle_fee_input_sats)?;
    report.step(
        "settlement",
        Some(Txid::from_byte_array(settlement.txid.0)),
        json!({
            "miner_fee_sats": settlement.miner_fee_sats,
            "payouts": settlement.payouts,
        }),
    );

    Ok(report)
}

/// `engine-e2e`: the CubeVM executes the split, its state becomes the manifest, and Bitcoin settles.
///
/// This is the composed path. The value-bearing fields of the resulting state — the owner and fee
/// balances, the contract balance, both shadows and the phase — are read from the CubeVM managers
/// after `exec_call_in_pool`, and `derive_manifest` runs on that state. The reference model is
/// still executed, but as a differential guard: any disagreement aborts before a Bitcoin
/// transaction is built.
fn engine_e2e(
    chain: &Chain,
    state: &mut State,
    options: &ScenarioOptions,
) -> Result<ScenarioReport> {
    let mut report = ScenarioReport::new("engine-e2e", chain.wallet());

    let deposit = fund_deposit(chain, state, options.deposit_sats)?;
    report.step(
        "deposit",
        Some(Txid::from_byte_array(deposit.funding_txid.0)),
        json!({ "value_sats": deposit.value_sats }),
    );

    // 1 The CubeVM executes `fund_split` through the production admission path.
    let transition_options = options.transition();
    let gross_sats = deposit
        .value_sats
        .checked_sub(transition_options.network_fee_reserve_sats)
        .context("the network fee reserve exceeds the deposit")?;
    let owner_start_sats = 1_000_000u64.max(gross_sats);
    let vm = crate::engine::fund_split(gross_sats, options.execution_fee_sats, owner_start_sats)?;
    report.step(
        "vm_fund_split",
        None,
        serde_json::to_value(&vm).context("cannot encode the VM execution")?,
    );

    // 2 The manifest is derived from the state the VM reached.
    let transition = transition::from_vm(&deposit, &vm, &transition_options)?;
    state.transition = Some(transition.clone());
    state.tree = None;
    state.assertion = None;
    report.step(
        "manifest_from_vm",
        None,
        json!({
            "statement_digest": transition.statement_digest,
            "gross_sats": transition.gross_sats,
            "claims": transition.claims.iter().map(|claim| json!({
                "beneficiary": keys::name_for_xonly(claim.beneficiary_key.0).unwrap_or("unknown"),
                "amount_sats": claim.amount_sats,
                "binding_digest": claim.binding_digest,
            })).collect::<Vec<_>>(),
        }),
    );

    // 3 Re-run the VM-derived verification and the Bitcoin graph.
    report.step("verify", None, verify_transition(state)?);

    let tree = publish_successor(chain, state)?;
    report.step(
        "successor",
        Some(Txid::from_byte_array(tree.txid.0)),
        json!({ "claims": tree.claims.len() }),
    );

    let destinations = options.destination.clone().map(|address| vec![address; 2]);
    let settlement = settle_claims(chain, state, destinations, options.settle_fee_input_sats)?;
    report.step(
        "settlement",
        Some(Txid::from_byte_array(settlement.txid.0)),
        json!({
            "miner_fee_sats": settlement.miner_fee_sats,
            "payouts": settlement.payouts,
        }),
    );

    Ok(report)
}

/// `liftv2-dispute`: assert and disprove one claim, recover the other, with no Engine signature.
fn liftv2_dispute(
    chain: &Chain,
    state: &mut State,
    options: &ScenarioOptions,
) -> Result<ScenarioReport> {
    let mut report = ScenarioReport::new("liftv2-dispute", chain.wallet());

    let deposit = fund_deposit(chain, state, options.deposit_sats)?;
    report.step(
        "deposit",
        Some(Txid::from_byte_array(deposit.funding_txid.0)),
        json!({ "value_sats": deposit.value_sats }),
    );

    let transition = build_transition(state, &options.transition())?;
    report.step(
        "transition",
        None,
        json!({ "statement_digest": transition.statement_digest }),
    );
    let tree = publish_successor(chain, state)?;
    report.step(
        "successor",
        Some(Txid::from_byte_array(tree.txid.0)),
        json!({ "claims": tree.claims.len() }),
    );

    let assertion = assert_claim(chain, state, 0, options.claim_fee_sats)?;
    report.step(
        "assert",
        Some(Txid::from_byte_array(assertion.txid.0)),
        json!({
            "claim_index": assertion.claim_index,
            "value_sats": assertion.value_sats,
        }),
    );

    let disprove = disprove_assertion(
        chain,
        state,
        options.destination.clone(),
        keys::DISCLOSURE_SECRET,
        options.payout_fee_sats,
    )?;
    report.step(
        "disprove",
        Some(Txid::from_byte_array(disprove.txid.0)),
        json!({
            "destination": disprove.destination,
            "amount_sats": disprove.amount_sats,
            "engine_signature": false,
        }),
    );

    let recovery = recover_claim(
        chain,
        state,
        1,
        options.destination.clone(),
        options.payout_fee_sats,
    )?;
    report.step(
        "recovery",
        Some(Txid::from_byte_array(recovery.txid.0)),
        json!({
            "claim_index": recovery.claim_index,
            "destination": recovery.destination,
            "amount_sats": recovery.amount_sats,
            "engine_signature": false,
        }),
    );

    Ok(report)
}

/// `proof-take`: assert a proof-backed claim and take it after the challenge window.
fn proof_take(
    chain: &Chain,
    state: &mut State,
    options: &ScenarioOptions,
) -> Result<ScenarioReport> {
    let mut report = ScenarioReport::new("proof-take", chain.wallet());

    let deposit = fund_deposit(chain, state, options.deposit_sats)?;
    report.step(
        "deposit",
        Some(Txid::from_byte_array(deposit.funding_txid.0)),
        json!({ "value_sats": deposit.value_sats }),
    );
    let transition = build_transition(state, &options.transition())?;
    report.step(
        "transition",
        None,
        json!({
            "statement_digest": transition.statement_digest,
            "input_digest": transition.claims[0].terms.input_digest,
            "table_digest": transition.claims[0].terms.table_digest,
            "challenge_blocks": transition.challenge_blocks,
        }),
    );
    let tree = publish_successor(chain, state)?;
    report.step(
        "successor",
        Some(Txid::from_byte_array(tree.txid.0)),
        json!({ "claims": tree.claims.len() }),
    );

    let assertion = assert_claim(chain, state, 0, options.claim_fee_sats)?;
    report.step(
        "assert",
        Some(Txid::from_byte_array(assertion.txid.0)),
        json!({
            "claim_index": assertion.claim_index,
            "value_sats": assertion.value_sats,
        }),
    );

    let take = take_assertion(
        chain,
        state,
        options.destination.clone(),
        options.payout_fee_sats,
        true,
    )?;
    if !take.accepted || take.txid.is_none() {
        bail!("the take did not settle after the challenge window");
    }
    if take.premature_rejection.is_none() {
        bail!("the take was accepted before the challenge window; the timelock did not hold");
    }
    report.step(
        "take",
        take.txid.map(|txid| Txid::from_byte_array(txid.0)),
        json!({
            "destination": take.destination,
            "amount_sats": take.amount_sats,
            "premature_rejection": take.premature_rejection,
            "waited_blocks": take.waited_blocks,
            "engine_signature": false,
        }),
    );

    Ok(report)
}

/// `liftv2-refund`: the script path must be immature, then spendable once matured.
fn liftv2_refund(
    chain: &Chain,
    state: &mut State,
    options: &ScenarioOptions,
) -> Result<ScenarioReport> {
    let mut report = ScenarioReport::new("liftv2-refund", chain.wallet());

    let deposit = fund_deposit(chain, state, options.deposit_sats)?;
    report.step(
        "deposit",
        Some(Txid::from_byte_array(deposit.funding_txid.0)),
        json!({
            "value_sats": deposit.value_sats,
            "refund_delay_blocks": deposit.refund_delay_blocks,
        }),
    );

    let premature = refund_deposit(chain, state, None, options.payout_fee_sats, false)?;
    if premature.accepted {
        bail!("the refund was accepted before the relative timelock matured");
    }
    report.step(
        "refund_before_maturity",
        None,
        json!({
            "accepted": false,
            "rejection": premature.rejection,
        }),
    );

    let mature = refund_deposit(chain, state, None, options.payout_fee_sats, true)?;
    if !mature.accepted {
        bail!("the refund was not accepted after the relative timelock matured");
    }
    report.step(
        "refund_after_maturity",
        mature.txid.map(|txid| Txid::from_byte_array(txid.0)),
        json!({
            "accepted": true,
            "mined_blocks": mature.mined_blocks,
            "destination": mature.destination,
            "amount_sats": mature.amount_sats,
        }),
    );

    Ok(report)
}

/// `engine-cheat`: every way the operator or the Engine could try to move value it is not owed.
///
/// The honest successor is built and signed but kept in memory, so the tampered copies are tested
/// while the deposit is still unspent. That matters: once a transaction is mined,
/// `testmempoolaccept` reports `missing-inputs` before it reaches the script, which would make the
/// negative test vacuous.
fn engine_cheat(
    chain: &Chain,
    state: &mut State,
    options: &ScenarioOptions,
) -> Result<ScenarioReport> {
    let mut report = ScenarioReport::new("engine-cheat", chain.wallet());

    let deposit = fund_deposit(chain, state, options.deposit_sats)?;
    report.step(
        "deposit",
        Some(Txid::from_byte_array(deposit.funding_txid.0)),
        json!({ "value_sats": deposit.value_sats }),
    );
    let transition = build_transition(state, &options.transition())?;
    report.step(
        "transition",
        None,
        json!({ "statement_digest": transition.statement_digest }),
    );

    // 1 Prepare the honest successor without publishing it.
    let prepared = prepare_successor(state)?;
    let honest = prepared.transaction.clone();

    // 2 The Engine asks Alice to co-sign a different statement commitment.
    let mut changed_statement = honest.clone();
    let mut flipped = prepared.manifest.statement_digest();
    flipped[0] ^= 0x01;
    changed_statement.output[prepared.statement_vout as usize].script_pubkey =
        ScriptBuf::from_bytes(statement_op_return_script(flipped));
    let reason = expect_rejection(
        chain,
        &changed_statement,
        "a successor with a changed statement",
    )?;
    report.step(
        "changed_statement",
        None,
        json!({ "rejected": true, "reason": reason }),
    );

    // 3 A payout is redirected to the other beneficiary.
    let mut redirected = honest.clone();
    redirected.output[0].script_pubkey = redirected.output[1].script_pubkey.clone();
    let reason = expect_rejection(chain, &redirected, "a successor with a redirected payout")?;
    report.step(
        "redirected_payout",
        None,
        json!({ "rejected": true, "reason": reason }),
    );

    // 4 A payout is shorted by one satoshi, which would silently grow the miner fee.
    let mut shorted = honest.clone();
    let value = shorted.output[0]
        .value
        .to_sat()
        .checked_sub(1)
        .context("the claim is too small to short")?;
    shorted.output[0].value = bitcoin::Amount::from_sat(value);
    let reason = expect_rejection(chain, &shorted, "a successor with a shorted payout")?;
    report.step(
        "shorted_payout",
        None,
        json!({ "rejected": true, "reason": reason }),
    );

    // 5 Publish the honest successor, so the assertion edges have claims to attack.
    let tree = publish_prepared(chain, state, prepared)?;
    report.step(
        "successor",
        Some(Txid::from_byte_array(tree.txid.0)),
        json!({ "claims": tree.claims.len() }),
    );

    // 6 The operator signs an assertion on the beneficiary's behalf.
    let claim = tree.claim(0)?.clone();
    let terms = claim.terms.to_terms();
    let claim_prevout = TxOut {
        value: bitcoin::Amount::from_sat(claim.amount_sats),
        script_pubkey: claim.spk()?,
    };
    let forged = Assertion::new(
        terms.clone(),
        ContestedOutput {
            outpoint: tree.outpoint(&claim),
            value_sats: claim.amount_sats,
        },
        options.claim_fee_sats,
    )
    .context_debug("the forged assertion could not be built")?;
    let forged_claim = AssertionClaim::new(
        terms.statement_digest,
        terms.binding_digest(),
        terms.beneficiary_key,
    )
    .context_debug("the forged claim script could not be built")?;
    let mut forged_tx = forged
        .transaction(Witness::new())
        .context_debug("the forged assertion transaction could not be built")?;
    let sighash = forged_claim
        .assert_signing_hash(&forged_tx, &claim_prevout)
        .context_debug("the forged assertion sighash could not be computed")?;
    forged_tx.input[0].witness = forged_claim
        .assert_witness(signing::sign_digest(sighash, keys::OPERATOR_SECRET)?)
        .context_debug("the forged assertion witness could not be built")?;
    let reason = expect_rejection(chain, &forged_tx, "an assertion signed by the operator")?;
    report.step(
        "operator_assertion",
        None,
        json!({ "rejected": true, "reason": reason }),
    );

    // 7 The beneficiary publishes the honest assertion.
    let assertion = assert_claim(chain, state, 0, options.claim_fee_sats)?;
    report.step(
        "assert",
        Some(Txid::from_byte_array(assertion.txid.0)),
        json!({ "claim_index": assertion.claim_index, "value_sats": assertion.value_sats }),
    );

    // 8 The operator takes before the challenge window.
    let premature = take_assertion(
        chain,
        state,
        options.destination.clone(),
        options.payout_fee_sats,
        false,
    )?;
    if premature.accepted {
        bail!("a premature take was accepted by the node");
    }
    report.step(
        "premature_take",
        None,
        json!({ "accepted": false, "reason": premature.premature_rejection }),
    );

    // 9 Mature the assertion output, so the wrong-signer check below fails on the signature and
    //   not on the timelock.
    let (rebuilt, stored, prevout) = stored_assertion(state)?;
    let matured_blocks = u64::from(stored.terms.challenge_blocks);
    let height = chain.mine(matured_blocks)?;
    report.step(
        "challenge_window",
        None,
        json!({ "mined_blocks": matured_blocks, "height": height }),
    );

    // 10 The beneficiary signs a take, which is the operator's leaf.
    let destination = match options.destination.clone() {
        Some(address) => address,
        None => chain.new_address()?,
    };
    let destination_script = chain.script(&destination)?;
    let anchor = AssertionAnchor::new(
        OutPoint {
            txid: Txid::from_byte_array(stored.txid.0),
            vout: 0,
        },
        stored.value_sats,
    );
    let take = TakeSpend::new(
        &rebuilt,
        anchor,
        destination_script.clone(),
        options.payout_fee_sats,
    )
    .context_debug("the take could not be built")?;
    let mut wrong_signer = take.transaction();
    let sighash = take
        .signing_hash(&prevout)
        .context_debug("the take sighash could not be computed")?;
    wrong_signer.input[0].witness = take
        .witness(signing::sign_digest(sighash, keys::BOB_SECRET)?)
        .context_debug("the take witness could not be built")?;
    let reason = expect_rejection(chain, &wrong_signer, "a take signed by the beneficiary")?;
    report.step(
        "beneficiary_take",
        None,
        json!({ "rejected": true, "reason": reason }),
    );

    // 11 A wrong disclosure secret must not open the disprove hashlock.
    let refusal = match DisproveSpend::new(
        &rebuilt,
        anchor,
        [0x99; 32],
        destination_script,
        options.payout_fee_sats,
    ) {
        Ok(_) => bail!("a wrong disclosure secret opened the committed hashlock"),
        Err(error) => format!("{error:?}"),
    };
    report.step(
        "wrong_secret",
        None,
        json!({ "refused_locally": true, "reason": refusal }),
    );

    // 12 The honest operator take still settles now that the window has passed.
    let take = take_assertion(
        chain,
        state,
        options.destination.clone(),
        options.payout_fee_sats,
        false,
    )?;
    if !take.accepted {
        bail!("the honest take did not settle after the challenge window");
    }
    report.step(
        "honest_take",
        take.txid.map(|txid| Txid::from_byte_array(txid.0)),
        json!({
            "destination": take.destination,
            "amount_sats": take.amount_sats,
            "engine_signature": false,
        }),
    );

    Ok(report)
}

/// `engine-offline`: the Engine never signs, so the participant has only two choices.
///
/// The cooperative path needs both MuSig2 signers; a successor signed by the participant alone is
/// rejected. What remains is the LiftV2 refund, and only after its relative timelock matures.
fn engine_offline(
    chain: &Chain,
    state: &mut State,
    options: &ScenarioOptions,
) -> Result<ScenarioReport> {
    let mut report = ScenarioReport::new("engine-offline", chain.wallet());

    let deposit = fund_deposit(chain, state, options.deposit_sats)?;
    report.step(
        "deposit",
        Some(Txid::from_byte_array(deposit.funding_txid.0)),
        json!({
            "value_sats": deposit.value_sats,
            "refund_delay_blocks": deposit.refund_delay_blocks,
        }),
    );
    let transition = build_transition(state, &options.transition())?;
    report.step(
        "transition",
        None,
        json!({ "statement_digest": transition.statement_digest }),
    );

    // 1 A successor signed by the participant alone cannot satisfy the aggregate key.
    let manifest = transition.manifest()?;
    let funding = SuccessorFunding::new_with_assertions(
        &manifest,
        DepositAnchor::new(deposit.outpoint(), deposit.value_sats),
        transition.network_fee_reserve_sats,
        Some(transition.fee_script()?),
        &transition.bindings(),
    )
    .context_debug("the successor does not fund every manifest obligation")?;
    let mut alone = funding.transaction();
    let prevout = TxOut {
        value: bitcoin::Amount::from_sat(deposit.value_sats),
        script_pubkey: deposit.spk()?,
    };
    let digest = signing::key_path_sighash(&alone, 0, std::slice::from_ref(&prevout))?;
    alone.input[0].witness =
        Witness::from_slice(&[signing::sign_digest(digest, keys::ALICE_SECRET)?.to_vec()]);
    let reason = expect_rejection(chain, &alone, "a successor signed by the participant alone")?;

    let taproot = keys::liftv2_taproot().context("the LiftV2 taproot could not be constructed")?;
    if signing::musig_sign(&taproot, &[keys::ALICE_SECRET], digest).is_ok() {
        bail!("a single signer produced a MuSig2 aggregate signature");
    }
    report.step(
        "participant_alone",
        None,
        json!({
            "aggregate_signature": "refused locally (two signers are required)",
            "node_rejection": reason,
            "engine_signature": false,
        }),
    );

    // 2 The refund is immature.
    let premature = refund_deposit(
        chain,
        state,
        options.destination.clone(),
        options.payout_fee_sats,
        false,
    )?;
    if premature.accepted {
        bail!("the refund was accepted before the relative timelock matured");
    }
    report.step(
        "refund_before_maturity",
        None,
        json!({ "accepted": false, "rejection": premature.rejection }),
    );

    // 3 After the timelock, the participant exits alone.
    let mature = refund_deposit(
        chain,
        state,
        options.destination.clone(),
        options.payout_fee_sats,
        true,
    )?;
    if !mature.accepted {
        bail!("the refund was not accepted after the relative timelock matured");
    }
    report.step(
        "refund_after_maturity",
        mature.txid.map(|txid| Txid::from_byte_array(txid.0)),
        json!({
            "destination": mature.destination,
            "amount_sats": mature.amount_sats,
            "mined_blocks": mature.mined_blocks,
            "engine_signature": false,
        }),
    );

    Ok(report)
}

/// Returns the proof envelope of one claim: the terms a proof input binds and the scripts the
/// claim and assertion outputs commit to.
///
/// This is the artifact an external prover fills in: `terms.input_digest` must be the digest of
/// the authenticated input its table evaluated, and `terms.table_digest` must name that table.
/// The CLI's fixture values can be replaced through `transition build`.
pub fn proof_envelope(state: &State, claim_index: usize) -> Result<serde_json::Value> {
    let tree = state.require_tree()?;
    let claim = tree.claim(claim_index)?;
    let terms = claim.terms.to_terms();
    let assertion_claim = AssertionClaim::new(
        terms.statement_digest,
        terms.binding_digest(),
        terms.beneficiary_key,
    )
    .context_debug("the claim script could not be derived from the terms")?;
    let claim_script = assertion_claim
        .scriptpubkey()
        .context_debug("the claim scriptpubkey could not be derived")?;
    let assertion = Assertion::new(
        terms.clone(),
        ContestedOutput {
            outpoint: tree.outpoint(claim),
            value_sats: claim.amount_sats,
        },
        claim.amount_sats.saturating_sub(1).min(PACKAGE_FEE_RATE),
    )
    .context_debug("the assertion script could not be derived from the terms")?;
    let assertion_script = assertion
        .scriptpubkey()
        .context_debug("the assertion scriptpubkey could not be derived")?;

    Ok(json!({
        "claim_index": claim_index,
        "claim_outpoint": {
            "txid": tree.txid,
            "vout": claim.vout,
        },
        "claim_value_sats": claim.amount_sats,
        "claim_scriptpubkey": hex::encode(claim_script.as_bytes()),
        "assertion_scriptpubkey": hex::encode(assertion_script.as_bytes()),
        "binding_digest": claim.terms.binding_digest(),
        "terms": claim.terms,
        "note": "The table verdict is represented by the committed input digest. Run `cargo test --release --test proof_take_regtest -- --ignored` for the Groth16/Argo path.",
    }))
}
