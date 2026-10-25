//! Deriving a transition and its claim bindings from a funded deposit.
//!
//! The manifest is **not** hand-written. It is produced by the repository's reference model
//! (`SplitVault`) and then derived by `derive_manifest` from the parent state, the accepted
//! `FundSplit` transition and the resulting state. That means the amounts, the caller sequence and
//! the state digests in the artifact are the ones the model actually committed, not values a
//! scenario author typed.
//!
//! Everything outside the model — the network genesis hash, the template hash, the setup instance,
//! the challenge configuration, the availability commitments — is explicitly fixture context. The
//! function derives those deterministically from the deposit outpoint so that two runs against the
//! same deposit produce the same manifest, and documents each one at the point it is chosen.
//!
//! The two assertion terms are the scenario's off-chain obligations: a claim id, the setup
//! instance, the verifier-key identity, the table digest, the disclosure commitment, the
//! authenticated input digest and the challenge window. The CLI uses fixture digests for the
//! proof-side values; `--input-digest`, `--table-digest` and `--verifier-key-identity` let a caller
//! substitute the values an actual prover and Arbo table produced.

use crate::artifact::{ClaimBinding, Deposit, Hex, Transition};
use crate::keys;
use crate::DebugContext;
use anyhow::{bail, Context, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::Network;
use cube::constructive::contracts::fixed_split_vault_v1::template_hash;
use cube::constructive::graph::assertion::{disclosure_secret_commitment, AssertionTerms};
use cube::model::fixed_split_vault_v1::manifest::{Anchor, PayoutKind, ReleaseProfile};
use cube::model::fixed_split_vault_v1::{
    derive_manifest, Auth, Ledger, ManifestContext, Operation, Role, SplitDescriptor, SplitVault,
    Transition as ModelTransition,
};
use cube::transmutative::hash::{Hash, HashTag};

/// The digest tag of the CLI's fixture claim ids.
const CLAIM_ID_TAG: &str = "CubeFixture/ClaimId/v0";

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

/// Derives the transition for a funded deposit.
pub fn derive(deposit: &Deposit, options: &TransitionOptions) -> Result<Transition> {
    // 1 The deposit must fund the successor's obligations and its miner fee.
    if options.network_fee_reserve_sats == 0 {
        bail!("the successor must leave a positive miner fee");
    }
    let gross_sats = deposit
        .value_sats
        .checked_sub(options.network_fee_reserve_sats)
        .context("the network fee reserve exceeds the deposit")?;

    // 2 Run the reference model: instantiate, fund, and keep the accepted transition.
    let descriptor = SplitDescriptor::new(
        network_genesis(),
        template_hash(),
        keys::xonly(keys::ALICE_SECRET),
        keys::xonly(keys::BOB_SECRET),
        keys::xonly(keys::CAROL_SECRET),
        keys::xonly(keys::FEE_KEY),
    );
    let mut vault = SplitVault::new(Ledger::new(gross_sats, 0, 0, 0));
    vault
        .instantiate(
            descriptor,
            Auth::new(Role::Owner, 1),
            Operation::new(
                SplitVault::next_operation_id(1),
                SplitVault::payload_digest(b"instantiate"),
            ),
        )
        .context_debug("the reference model rejected the fixture instantiate")?;
    let parent = vault.state();

    let operation = Operation::new(
        SplitVault::next_operation_id(2),
        SplitVault::payload_digest(b"fund"),
    );
    let auth = Auth::new(Role::Owner, 2);
    let accepted: ModelTransition = vault
        .fund(gross_sats, options.execution_fee_sats, auth, operation)
        .context_debug("the reference model rejected the fixture fund")?;
    let resulting = vault.state();

    // 3 The context the model cannot derive. Each value is a deterministic fixture, tagged so two
    //   different deposits cannot share one.
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

    let manifest = derive_manifest(&context, &parent, &accepted, auth, operation, &resulting)
        .context_debug("the manifest could not be derived from the accepted transition")?;
    manifest
        .validate()
        .context_debug("the derived manifest is invalid")?;
    let statement_digest = manifest.statement_digest();

    // 4 One binding per beneficiary allocation, in manifest order. The claim id is derived from
    //   the statement and the beneficiary, so the two claims are distinct but reproducible.
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
        let binding_digest = terms.binding_digest();
        claims.push(ClaimBinding {
            claim_id: Hex::new(claim_id),
            beneficiary_key: Hex::new(payout.recipient_key),
            amount_sats: payout.amount_sats,
            binding_digest: Hex::new(binding_digest),
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
        claims,
    })
}
