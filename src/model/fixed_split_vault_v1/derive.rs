//! Deriving a transition manifest from an accepted transition.
//!
//! A hand-written manifest can describe a transition that never happened. This module closes that
//! gap for the bounded `FixedSplitVaultV1` profile: the payouts, the state digests and the caller
//! sequence are derived from the actual accepted transition, and the derivation refuses to produce
//! a manifest when the transition and the resulting state disagree.
//!
//! # What "derived" does and does not mean here
//!
//! Derived means the manifest is a function of the parent state, the transition that was accepted,
//! and the resulting state. It does **not** mean the transition was correct. Both states are still
//! supplied by the caller; a prover that lied about the parent state would produce a manifest whose
//! digests are internally consistent and still wrong. Only a verifier, given the committed parent,
//! closes that, and no verifier exists yet.
//!
//! # Fields that cannot be derived
//!
//! Context (network, template, circuit, verifier key), the parent anchor outpoints, the entry
//! digest, the setup and challenge identifiers and the data-availability commitments come from the
//! calling environment. `ManifestContext` carries them, so the derivation is explicit about which
//! parts are evidence and which are assertion.

use crate::model::fixed_split_vault_v1::codec::SplitState;
use crate::model::fixed_split_vault_v1::manifest::{
    Anchor, ManifestError, Payout, PayoutKind, ReleaseProfile, TransitionManifest,
    MANIFEST_SCHEMA_VERSION, MAX_ANCHORS, MAX_PAYOUTS,
};
use crate::model::fixed_split_vault_v1::types::Role;
use crate::model::fixed_split_vault_v1::vault::{Auth, Operation, Transition};

/// The parts of a manifest that come from the environment rather than from the transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestContext {
    /// The release profile.
    pub profile: ReleaseProfile,
    /// The target network genesis hash.
    pub network_genesis_hash: [u8; 32],
    /// The template hash.
    pub template_hash: [u8; 32],
    /// The circuit identity.
    pub circuit_id: [u8; 32],
    /// The verifier-key digest.
    pub verifier_key_digest: [u8; 32],
    /// The stable batch sequence.
    pub batch_sequence: u64,
    /// The funding or claim anchors this transition spends.
    pub anchors: Vec<Anchor>,
    /// The digest of the entry that authorised the transition.
    pub entry_digest: [u8; 32],
    /// The setup instance the assertion will belong to.
    pub setup_instance_id: [u8; 32],
    /// The graph template version.
    pub graph_template_version: u16,
    /// The challenge and timing configuration digest.
    pub challenge_config_digest: [u8; 32],
    /// The recovery package commitment for this claim.
    pub recovery_package_digest: [u8; 32],
    /// The canonical batch data digest.
    pub batch_data_digest: [u8; 32],
    /// The availability or package descriptor commitment.
    pub availability_descriptor_digest: [u8; 32],
}

/// Deterministic rejection reasons of the derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveError {
    /// A replayed operation changes no state, so there is no transition to commit.
    NoStateChange,
    /// The parent and resulting state digests are equal.
    StatesAreIdentical,
    /// The vault has no instantiated contract.
    InstanceNotInstantiated,
    /// The caller sequence in the authorization was not the one the resulting state records.
    SequenceMismatch {
        role: Role,
        authorized: u64,
        recorded: u64,
    },
    /// The transition's amounts disagree with the state change.
    AmountMismatch {
        role: Role,
        transition_sats: u64,
        state_sats: u64,
    },
    /// `FundSplit` was derived from a parent that was not empty.
    FundedFromNonEmptyParent { phase_tag: u8 },
    /// A payout obligation could not be expressed.
    Manifest(ManifestError),
    /// The context supplies an unsupported number of anchors or payouts.
    ContextBounds {
        anchors: usize,
        max_anchors: usize,
        max_payouts: usize,
    },
}

/// Derives the manifest for one accepted `FixedSplitVaultV1` transition.
///
/// `parent` is the state before the transition, `resulting` the state after it, and `transition`
/// what the vault reported. The derivation cross-checks all three:
///
/// - `FundSplit` requires an empty parent and produces the two beneficiary allocations plus the
///   execution fee, in that order;
/// - `RedeemShare` produces exactly one native-successor payout, for the beneficiary whose shadow
///   decreased by the reported amount;
/// - the caller sequence must be the one the resulting state records as consumed.
pub fn derive_manifest(
    context: &ManifestContext,
    parent: &SplitState,
    transition: &Transition,
    auth: Auth,
    operation: Operation,
    resulting: &SplitState,
) -> Result<TransitionManifest, DeriveError> {
    // 1 A replay changes nothing, so there is no transition to commit.
    if matches!(transition, Transition::Replayed { .. }) {
        return Err(DeriveError::NoStateChange);
    }

    // 2 The two states must differ.
    let parent_digest = parent.digest();
    let resulting_digest = resulting.digest();
    if parent_digest == resulting_digest {
        return Err(DeriveError::StatesAreIdentical);
    }

    // 3 The resulting state must carry a contract.
    let instance = resulting
        .instance
        .ok_or(DeriveError::InstanceNotInstantiated)?;

    // 4 The authorization sequence must have been consumed exactly.
    let recorded_sequence = resulting.sequence_of(auth.role);
    if recorded_sequence != auth.sequence {
        return Err(DeriveError::SequenceMismatch {
            role: auth.role,
            authorized: auth.sequence,
            recorded: recorded_sequence,
        });
    }

    // 5 Derive the ordered payout obligations from the transition and the state change.
    let payouts = match transition {
        // 5.a A funding pays both beneficiaries and the fee account.
        Transition::Funded { amounts } => {
            // The parent must have been empty: funding happens exactly once.
            if let Some(parent_instance) = parent.instance {
                if parent_instance.phase != crate::model::fixed_split_vault_v1::types::Phase::Empty
                {
                    return Err(DeriveError::FundedFromNonEmptyParent {
                        phase_tag: parent_instance.phase.tag(),
                    });
                }
            }

            // The reported amounts must be the ones the state records.
            if amounts.bob_sats != instance.bob_shadow_sats {
                return Err(DeriveError::AmountMismatch {
                    role: Role::Bob,
                    transition_sats: amounts.bob_sats,
                    state_sats: instance.bob_shadow_sats,
                });
            }
            if amounts.carol_sats != instance.carol_shadow_sats {
                return Err(DeriveError::AmountMismatch {
                    role: Role::Carol,
                    transition_sats: amounts.carol_sats,
                    state_sats: instance.carol_shadow_sats,
                });
            }

            vec![
                Payout::new(
                    instance.descriptor.bob_key,
                    amounts.bob_sats,
                    PayoutKind::BeneficiaryAllocation,
                ),
                Payout::new(
                    instance.descriptor.carol_key,
                    amounts.carol_sats,
                    PayoutKind::BeneficiaryAllocation,
                ),
                Payout::new(
                    instance.descriptor.fee_key,
                    instance.execution_fee_sats,
                    PayoutKind::ExecutionFee,
                ),
            ]
        }

        // 5.b A redemption pays one native successor, for the beneficiary whose shadow went away.
        Transition::Redeemed {
            role, amount_sats, ..
        } => {
            if !role.is_beneficiary() {
                return Err(DeriveError::Manifest(ManifestError::PayoutCount {
                    count: 0,
                }));
            }

            // The shadow for that role must have decreased by exactly the reported amount.
            let parent_shadow = parent
                .instance
                .ok_or(DeriveError::InstanceNotInstantiated)?
                .shadow_sats(*role)
                .ok_or(DeriveError::InstanceNotInstantiated)?;
            let resulting_shadow = instance.shadow_sats(*role).unwrap_or(0);
            let observed_delta = parent_shadow.saturating_sub(resulting_shadow);
            if observed_delta != *amount_sats {
                return Err(DeriveError::AmountMismatch {
                    role: *role,
                    transition_sats: *amount_sats,
                    state_sats: observed_delta,
                });
            }

            vec![Payout::new(
                instance.descriptor.key(*role),
                *amount_sats,
                PayoutKind::NativeSuccessor,
            )]
        }

        // 5.c `InstantiateSplit` moves no value, so it has no payout obligations.
        Transition::Instantiated { .. } => {
            return Err(DeriveError::Manifest(ManifestError::PayoutCount {
                count: 0,
            }))
        }

        Transition::Replayed { .. } => return Err(DeriveError::NoStateChange),
    };

    // 6 The context must stay inside the frozen bounds.
    if context.anchors.is_empty() || context.anchors.len() > MAX_ANCHORS {
        return Err(DeriveError::ContextBounds {
            anchors: context.anchors.len(),
            max_anchors: MAX_ANCHORS,
            max_payouts: MAX_PAYOUTS,
        });
    }
    if payouts.len() > MAX_PAYOUTS {
        return Err(DeriveError::ContextBounds {
            anchors: context.anchors.len(),
            max_anchors: MAX_ANCHORS,
            max_payouts: MAX_PAYOUTS,
        });
    }

    // 7 Assemble and validate.
    let manifest = TransitionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        profile: context.profile,
        network_genesis_hash: context.network_genesis_hash,
        template_hash: context.template_hash,
        circuit_id: context.circuit_id,
        verifier_key_digest: context.verifier_key_digest,
        previous_state_digest: parent_digest,
        resulting_state_digest: resulting_digest,
        batch_sequence: context.batch_sequence,
        anchors: context.anchors.clone(),
        entry_digest: context.entry_digest,
        caller_key: instance.descriptor.key(auth.role),
        caller_sequence: auth.sequence,
        operation_id: operation.id,
        payouts,
        setup_instance_id: context.setup_instance_id,
        graph_template_version: context.graph_template_version,
        challenge_config_digest: context.challenge_config_digest,
        recovery_package_digest: context.recovery_package_digest,
        batch_data_digest: context.batch_data_digest,
        availability_descriptor_digest: context.availability_descriptor_digest,
    };

    manifest.validate().map_err(DeriveError::Manifest)?;

    Ok(manifest)
}
