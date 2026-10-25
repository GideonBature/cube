//! Deriving a transition and its claim bindings from a funded deposit.
//!
//! Two paths produce the manifest:
//!
//! - [`derive`] runs the reference model (`SplitVault`). This is the path the step-by-step CLI uses;
//!   it is deterministic and needs no Engine.
//! - [`from_vm`] takes a [`VmExecution`] produced by the real CubeVM template and derives the
//!   manifest from the state the VM actually reached, after checking it against the model. This is
//!   the composed path: the value-bearing fields come from the Engine, and the model is the
//!   differential guard rather than the source.
//!
//! In both paths the manifest itself is produced by `derive_manifest`, never hand-written.
//!
//! Everything outside the model — the network genesis hash, the template hash, the setup instance,
//! the challenge configuration, the availability commitments — is explicitly fixture context. The
//! functions derive those deterministically from the deposit outpoint so that two runs against the
//! same deposit produce the same manifest.
//!
//! The two assertion terms are the scenario's off-chain obligations: a claim id, the setup
//! instance, the verifier-key identity, the table digest, the disclosure commitment, the
//! authenticated input digest and the challenge window. The CLI uses fixture digests for the
//! proof-side values; `--input-digest`, `--table-digest` and `--verifier-key-identity` let a caller
//! substitute the values an actual prover and Argo table produced.

use crate::artifact::{ClaimBinding, Deposit, Hex, Transition};
use crate::engine::VmExecution;
use crate::keys;
use crate::DebugContext;
use anyhow::{bail, Context, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::Network;
use cube::constructive::contracts::fixed_split_vault_v1::template_hash;
use cube::constructive::graph::assertion::{disclosure_secret_commitment, AssertionTerms};
use cube::model::fixed_split_vault_v1::manifest::{
    Anchor, PayoutKind, ReleaseProfile, TransitionManifest,
};
use cube::model::fixed_split_vault_v1::{
    derive_manifest, Auth, Ledger, ManifestContext, Operation, Phase, Role, SplitDescriptor,
    SplitState, SplitVault, Transition as ModelTransition,
};
use cube::transmutative::hash::{Hash, HashTag};

/// The digest tag of the CLI's fixture claim ids.
const CLAIM_ID_TAG: &str = "CubeFixture/ClaimId/v0";

/// The canonical `SplitState` encoding length with an instance present.
const CANONICAL_STATE_LEN: usize = 343;

/// Parameters a caller may override when deriving a transition.
#[derive(Debug, Clone)]
pub struct TransitionOptions {
    /// The miner fee the successor leaves; also the deposit value minus the gross split.
    pub network_fee_reserve_sats: u64,
    /// The execution fee the manifest declares.
    pub execution_fee_sats: u64,
    /// The relative challenge window, in blocks.
    pub challenge_blocks: u32,
    /// The verifier-key identity, when a real verifying key exists.
    pub verifier_key_identity: Option<[u8; 32]>,
    /// The table digest, when a real garbling table exists.
    pub table_digest: Option<[u8; 32]>,
    /// The authenticated-input digest, when a real proof input exists.
    pub input_digest: Option<[u8; 32]>,
}

impl Default for TransitionOptions {
    fn default() -> Self {
        Self {
            network_fee_reserve_sats: 2_000,
            execution_fee_sats: 5_000,
            challenge_blocks: 144,
            verifier_key_identity: None,
            table_digest: None,
            input_digest: None,
        }
    }
}

/// Returns a tagged fixture digest over `preimage`.
fn fixture_digest(tag: &str, preimage: &[u8]) -> [u8; 32] {
    preimage.hash(Some(HashTag::CustomString(tag.to_string())))
}

/// The deposit outpoint as a stable preimage.
fn outpoint_preimage(deposit: &Deposit) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(36);
    preimage.extend(deposit.funding_txid.0);
    preimage.extend(deposit.funding_vout.to_le_bytes());
    preimage
}

/// The regtest genesis hash, so the instance is bound to this network.
fn network_genesis() -> [u8; 32] {
    bitcoin::constants::genesis_block(Network::Regtest)
        .block_hash()
        .to_byte_array()
}

/// The immutable descriptor every fixture path uses.
fn descriptor() -> SplitDescriptor {
    SplitDescriptor::new(
        network_genesis(),
        template_hash(),
        keys::xonly(keys::ALICE_SECRET),
        keys::xonly(keys::BOB_SECRET),
        keys::xonly(keys::CAROL_SECRET),
        keys::xonly(keys::FEE_KEY),
    )
}

/// Instantiates the model over `owner_start_sats` and returns the instantiated vault.
fn instantiated_model(owner_start_sats: u64) -> Result<SplitVault> {
    let mut vault = SplitVault::new(Ledger::new(owner_start_sats, 0, 0, 0));
    vault
        .instantiate(
            descriptor(),
            Auth::new(Role::Owner, 1),
            Operation::new(
                SplitVault::next_operation_id(1),
                SplitVault::payload_digest(b"instantiate"),
            ),
        )
        .context_debug("the reference model rejected the fixture instantiate")?;
    Ok(vault)
}

/// The funding operation and its authorization.
fn fund_operation() -> (Operation, Auth) {
    (
        Operation::new(
            SplitVault::next_operation_id(2),
            SplitVault::payload_digest(b"fund"),
        ),
        Auth::new(Role::Owner, 2),
    )
}

/// The fixture context the model cannot derive.
fn manifest_context(deposit: &Deposit, options: &TransitionOptions) -> (ManifestContext, [u8; 32]) {
    let outpoint = outpoint_preimage(deposit);
    let setup_instance_id = fixture_digest("CubeFixture/SetupInstance/v0", &outpoint);
    let challenge_config_digest = fixture_digest(
        "CubeFixture/ChallengeConfig/v0",
        &options.challenge_blocks.to_le_bytes(),
    );
    let context = ManifestContext {
        profile: ReleaseProfile::ArgoSplitRegtest,
        network_genesis_hash: network_genesis(),
        template_hash: template_hash(),
        circuit_id: fixture_digest("CubeFixture/Circuit/v0", &outpoint),
        verifier_key_digest: fixture_digest("CubeFixture/VerifierKey/v0", &outpoint),
        batch_sequence: 1,
        anchors: vec![Anchor::new(deposit.funding_txid.0, deposit.funding_vout)],
        entry_digest: fixture_digest("CubeFixture/Entry/v0", &outpoint),
        setup_instance_id,
        graph_template_version: 1,
        challenge_config_digest,
        recovery_package_digest: fixture_digest("CubeFixture/RecoveryPackage/v0", &outpoint),
        batch_data_digest: fixture_digest("CubeFixture/BatchData/v0", &outpoint),
        availability_descriptor_digest: fixture_digest(
            "CubeFixture/AvailabilityDescriptor/v0",
            &outpoint,
        ),
    };
    (context, setup_instance_id)
}

/// Builds the artifact and one binding per beneficiary allocation.
fn artifact(
    manifest: &TransitionManifest,
    setup_instance_id: [u8; 32],
    gross_sats: u64,
    options: &TransitionOptions,
) -> Result<Transition> {
    manifest
        .validate()
        .context_debug("the derived manifest is invalid")?;
    let statement_digest = manifest.statement_digest();
    let operator_key = keys::xonly(keys::OPERATOR_SECRET);
    let secret_commitment = disclosure_secret_commitment(&keys::DISCLOSURE_SECRET);
    let mut claims = Vec::new();

    for payout in &manifest.payouts {
        if payout.kind != PayoutKind::BeneficiaryAllocation {
            continue;
        }
        let mut preimage = Vec::with_capacity(64);
        preimage.extend(statement_digest);
        preimage.extend(payout.recipient_key);
        let claim_id = fixture_digest(CLAIM_ID_TAG, &preimage);
        let mut setup_instance = [0u8; 16];
        setup_instance.copy_from_slice(&setup_instance_id[..16]);

        let terms = AssertionTerms {
            statement_digest,
            claim_id,
            setup_instance_id: setup_instance,
            verifier_key_identity: options.verifier_key_identity.unwrap_or_else(|| {
                fixture_digest("CubeFixture/VerifierIdentity/v0", &statement_digest)
            }),
            table_digest: options
                .table_digest
                .unwrap_or_else(|| fixture_digest("CubeFixture/Table/v0", &statement_digest)),
            secret_commitment,
            input_digest: options.input_digest.unwrap_or_else(|| {
                fixture_digest("CubeFixture/AuthenticatedInput/v0", &statement_digest)
            }),
            challenge_blocks: options.challenge_blocks,
            operator_key,
            beneficiary_key: payout.recipient_key,
        };
        terms
            .validate()
            .context_debug("the fixture assertion terms are invalid")?;
        claims.push(ClaimBinding {
            claim_id: Hex::new(claim_id),
            beneficiary_key: Hex::new(payout.recipient_key),
            amount_sats: payout.amount_sats,
            binding_digest: Hex::new(terms.binding_digest()),
            terms: (&terms).into(),
        });
    }

    if claims.len() != 2 {
        bail!(
            "the fixture manifest must have two beneficiary claims, found {}",
            claims.len()
        );
    }

    // The fee output pays the key the manifest names, so the script is bound to the key rather
    // than authorised as an opaque destination.
    let fee_script = keys::p2tr_script(keys::xonly(keys::FEE_KEY));

    Ok(Transition {
        manifest: hex::encode(manifest.encode()),
        statement_digest: Hex::new(statement_digest),
        gross_sats,
        execution_fee_sats: options.execution_fee_sats,
        network_fee_reserve_sats: options.network_fee_reserve_sats,
        challenge_blocks: options.challenge_blocks,
        fee_script: hex::encode(fee_script.as_bytes()),
        vm: None,
        claims,
    })
}

/// Derives the transition by running the reference model.
pub fn derive(deposit: &Deposit, options: &TransitionOptions) -> Result<Transition> {
    // 1 The deposit must fund the successor's obligations and its miner fee.
    if options.network_fee_reserve_sats == 0 {
        bail!("the successor must leave a positive miner fee");
    }
    let gross_sats = deposit
        .value_sats
        .checked_sub(options.network_fee_reserve_sats)
        .context("the network fee reserve exceeds the deposit")?;

    // 2 Run the model: instantiate, fund, and keep the accepted transition.
    let mut vault = instantiated_model(gross_sats)?;
    let parent = vault.state();
    let (operation, auth) = fund_operation();
    let accepted: ModelTransition = vault
        .fund(gross_sats, options.execution_fee_sats, auth, operation)
        .context_debug("the reference model rejected the fixture fund")?;
    let resulting = vault.state();

    // 3 Derive the manifest and the artifact.
    let (context, setup_instance_id) = manifest_context(deposit, options);
    let manifest = derive_manifest(&context, &parent, &accepted, auth, operation, &resulting)
        .context_debug("the manifest could not be derived from the accepted transition")?;
    artifact(&manifest, setup_instance_id, gross_sats, options)
}

/// The manifest and canonical state bytes a VM execution reached.
///
/// These are the exact inputs the `FundSplit` circuit takes: the canonical manifest encoding and the
/// 343-byte previous and resulting states. They come from `plan_from_vm`, not from a model run.
#[derive(Debug, Clone)]
pub struct VmPlan {
    /// The derived manifest.
    pub manifest: TransitionManifest,
    /// The canonical previous state (the instantiated, empty vault).
    pub previous_state: Vec<u8>,
    /// The canonical resulting state, carrying the VM's values.
    pub resulting_state: Vec<u8>,
}

/// Builds the manifest and canonical state bytes from a CubeVM execution.
///
/// The canonical split ledger starts **after** the Engine's entry fee: that fee is a call fee, not a
/// split obligation, so it is excluded from the `SplitState` while the VM's actual account balance
/// still reflects it. The VM's value-bearing fields — contract balance, both shadows and the fee
/// account — are copied into the state, and every one of them is checked against the reference
/// model before the manifest is derived.
pub fn plan_from_vm(
    deposit: &Deposit,
    vm: &VmExecution,
    options: &TransitionOptions,
) -> Result<VmPlan> {
    if options.network_fee_reserve_sats == 0 {
        bail!("the successor must leave a positive miner fee");
    }
    let gross_sats = deposit
        .value_sats
        .checked_sub(options.network_fee_reserve_sats)
        .context("the network fee reserve exceeds the deposit")?;
    if vm.gross_sats != gross_sats {
        bail!(
            "the VM funded {gross_sats} sats but the deposit yields {}",
            vm.gross_sats
        );
    }
    if vm.execution_fee_sats != options.execution_fee_sats {
        bail!(
            "the VM charged an execution fee of {} but the manifest declares {}",
            vm.execution_fee_sats,
            options.execution_fee_sats
        );
    }
    if vm.phase_tag != Phase::Allocated.tag() {
        bail!("the VM vault is not in the ALLOCATED phase");
    }

    // 0 The VM's accounting must be internally consistent: start = entry fee + gross + remainder.
    let effective_owner_start = vm
        .owner_balance_sats
        .checked_add(gross_sats)
        .context("the VM's owner balance overflows")?;
    let expected_start = effective_owner_start
        .checked_add(vm.entry_fee_sats)
        .context("the VM's owner start overflows")?;
    if vm.owner_start_sats != expected_start {
        bail!(
            "the VM's balances do not add up: start {} != entry fee {} + gross {} + remainder {}",
            vm.owner_start_sats,
            vm.entry_fee_sats,
            gross_sats,
            vm.owner_balance_sats
        );
    }

    // 1 Run the model with the canonical starting balance. It is the differential oracle.
    let mut vault = instantiated_model(effective_owner_start)?;
    let parent = vault.state();
    let (operation, auth) = fund_operation();
    let accepted: ModelTransition = vault
        .fund(gross_sats, options.execution_fee_sats, auth, operation)
        .context_debug("the reference model rejected the fixture fund")?;
    let oracle = vault.state();
    let oracle_instance = oracle
        .instance
        .context("the reference model produced no instance")?;

    // 2 Every value-bearing field must agree before the VM's state is used.
    if oracle_instance.contract_balance_sats != vm.contract_balance_sats
        || oracle_instance.bob_shadow_sats != vm.bob_shadow_sats
        || oracle_instance.carol_shadow_sats != vm.carol_shadow_sats
        || oracle.ledger.owner_sats != vm.owner_balance_sats
        || oracle.ledger.fee_sats != vm.fee_balance_sats
    {
        bail!(
            "the VM's funded state does not match the reference model: \
             vm(contract={}, bob={}, carol={}, owner={}, fee={}) \
             model(contract={}, bob={}, carol={}, owner={}, fee={})",
            vm.contract_balance_sats,
            vm.bob_shadow_sats,
            vm.carol_shadow_sats,
            vm.owner_balance_sats,
            vm.fee_balance_sats,
            oracle_instance.contract_balance_sats,
            oracle_instance.bob_shadow_sats,
            oracle_instance.carol_shadow_sats,
            oracle.ledger.owner_sats,
            oracle.ledger.fee_sats,
        );
    }

    // 3 Copy the VM's values into the canonical state. The identity and sequence fields come from
    //   the model: the VM template does not write the canonical instance identity or the caller
    //   sequences yet. That representation gap is documented in docs/e2e_regtest.md.
    let mut vm_state: SplitState = oracle.clone();
    {
        let instance = vm_state
            .instance
            .as_mut()
            .context("the reference model produced no instance")?;
        instance.contract_balance_sats = vm.contract_balance_sats;
        instance.bob_shadow_sats = vm.bob_shadow_sats;
        instance.carol_shadow_sats = vm.carol_shadow_sats;
        vm_state.ledger.owner_sats = vm.owner_balance_sats;
        vm_state.ledger.fee_sats = vm.fee_balance_sats;
    }

    // 4 Derive the manifest from the VM's resulting state.
    let (context, _) = manifest_context(deposit, options);
    let manifest = derive_manifest(&context, &parent, &accepted, auth, operation, &vm_state)
        .context_debug("the manifest could not be derived from the VM's state")?;
    if manifest.previous_state_digest != parent.digest()
        || manifest.resulting_state_digest != vm_state.digest()
    {
        bail!("the derived manifest does not commit the states it was derived from");
    }

    let previous_state = parent.encode();
    let resulting_state = vm_state.encode();
    if previous_state.len() != CANONICAL_STATE_LEN || resulting_state.len() != CANONICAL_STATE_LEN {
        bail!(
            "the canonical state encoding is not {CANONICAL_STATE_LEN} bytes: {} and {}",
            previous_state.len(),
            resulting_state.len()
        );
    }

    Ok(VmPlan {
        manifest,
        previous_state,
        resulting_state,
    })
}

/// Derives the transition artifact from the state the CubeVM actually reached.
pub fn from_vm(
    deposit: &Deposit,
    vm: &VmExecution,
    options: &TransitionOptions,
) -> Result<Transition> {
    let plan = plan_from_vm(deposit, vm, options)?;
    let (_, setup_instance_id) = manifest_context(deposit, options);
    let mut transition = artifact(&plan.manifest, setup_instance_id, vm.gross_sats, options)?;
    transition.vm = Some(vm.clone());
    Ok(transition)
}
