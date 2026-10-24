//! Acceptance tests for the `FixedSplitVaultV1` reference model.
//!
//! These tests cover specification.md T-02 (split allocation), T-03 (rounding), T-04 (invalid
//! contract calls) and T-05 (redemption order), plus the state invariants INV-01, INV-02, INV-03,
//! INV-06, INV-07 and INV-10 as far as a pure model can demonstrate them.
//!
//! A passing run of this file does **not** demonstrate Bitcoin enforcement, proof soundness,
//! Argo invalidity or independent recovery. Those are separate gates (G1, G3, G4).

#[cfg(test)]
mod fixed_split_vault_tests {
    use cube::model::fixed_split_vault_v1::amounts::{carol_weight_bps, split_amounts};
    use cube::model::fixed_split_vault_v1::codec::SplitState;
    use cube::model::fixed_split_vault_v1::error::{
        InvariantViolation, SplitDecodeError, SplitVaultError,
    };
    use cube::model::fixed_split_vault_v1::instance::{SplitDescriptor, SplitInstance};
    use cube::model::fixed_split_vault_v1::types::{
        Ledger, Phase, Role, BOB_WEIGHT_BPS, BPS_DENOMINATOR, CAROL_WEIGHT_BPS, MINIMUM_CLAIM_SATS,
    };
    use cube::model::fixed_split_vault_v1::vault::{
        derive_contract_id, Auth, Operation, SplitVault, Transition,
    };

    // ---------------------------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------------------------

    /// Returns a deterministic, nonzero, seed-distinct 32-byte key.
    fn key(seed: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = seed
                .wrapping_mul(17)
                .wrapping_add(index as u8)
                .wrapping_add(1);
        }
        key
    }

    /// The network genesis hash used by every fixture. Frozen so digests are reproducible.
    const GENESIS_HASH: [u8; 32] = [0x11; 32];

    /// The template hash used by every fixture. Frozen so digests are reproducible.
    const TEMPLATE_HASH: [u8; 32] = [0x22; 32];

    /// The spec's example fixture: `G = 100000`, `E = 500`.
    const GROSS_SATS: u64 = 100_000;
    const EXECUTION_FEE_SATS: u64 = 500;

    /// Returns the immutable descriptor used by every fixture.
    fn fixture_descriptor() -> SplitDescriptor {
        SplitDescriptor::new(GENESIS_HASH, TEMPLATE_HASH, key(0), key(1), key(2), key(3))
    }

    /// Returns a deterministic operation with a distinct ID and payload.
    fn operation(seed: u8) -> Operation {
        let payload = [seed; 8];
        Operation::new(
            SplitVault::next_operation_id(seed),
            SplitVault::payload_digest(&payload),
        )
    }

    /// Returns a caller authorization.
    fn auth(role: Role, sequence: u64) -> Auth {
        Auth::new(role, sequence)
    }

    /// Returns a vault holding exactly the owner's eligible principal.
    fn funded_ledger() -> Ledger {
        Ledger::new(GROSS_SATS, 0, 0, 0)
    }

    /// Returns a vault that has accepted `InstantiateSplit`.
    fn instantiated_vault() -> SplitVault {
        let mut vault = SplitVault::new(funded_ledger());
        vault
            .instantiate(fixture_descriptor(), auth(Role::Owner, 1), operation(1))
            .expect("InstantiateSplit must be accepted");
        vault
    }

    /// Returns a vault that has accepted `InstantiateSplit` and `FundSplit`.
    fn allocated_vault() -> SplitVault {
        let mut vault = instantiated_vault();
        vault
            .fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                auth(Role::Owner, 2),
                operation(2),
            )
            .expect("FundSplit must be accepted");
        vault
    }

    // ---------------------------------------------------------------------------------------
    // T-02: split allocation
    // ---------------------------------------------------------------------------------------

    #[test]
    fn t02_exact_fixture_arithmetic() {
        let amounts = split_amounts(GROSS_SATS, EXECUTION_FEE_SATS).expect("fixture must be valid");

        assert_eq!(amounts.distributable_sats, 99_500);
        assert_eq!(amounts.bob_sats, 69_650);
        assert_eq!(amounts.carol_sats, 29_850);
        assert_eq!(amounts.bob_remainder_bps, 0);

        // No satoshi is created or lost.
        assert_eq!(
            amounts.bob_sats + amounts.carol_sats,
            amounts.distributable_sats
        );
    }

    #[test]
    fn t02_allocation_is_fully_backed_by_the_contract_balance() {
        let vault = allocated_vault();
        let instance = vault.instance.expect("instance must exist");

        assert_eq!(instance.phase, Phase::Allocated);
        assert_eq!(instance.gross_sats, GROSS_SATS);
        assert_eq!(instance.execution_fee_sats, EXECUTION_FEE_SATS);
        assert_eq!(instance.contract_balance_sats, 99_500);
        assert_eq!(instance.bob_shadow_sats, 69_650);
        assert_eq!(instance.carol_shadow_sats, 29_850);
        assert_eq!(
            instance.shadows_sum_sats(),
            instance.contract_balance_sats as u128
        );
        assert!(vault.check_invariants().is_ok());
    }

    // ---------------------------------------------------------------------------------------
    // T-03: rounding
    // ---------------------------------------------------------------------------------------

    #[test]
    fn t03_rounding_preserves_every_satoshi() {
        // Sweep every distributable amount from 1 sat up to 5_000 sats with a zero fee.
        for distributable_sats in 1u64..=5_000 {
            match split_amounts(distributable_sats, 0) {
                Ok(amounts) => {
                    // 1 Carol receives the integer remainder, so the parts re-add exactly.
                    assert_eq!(
                        amounts.bob_sats + amounts.carol_sats,
                        distributable_sats,
                        "value lost at D = {}",
                        distributable_sats
                    );

                    // 2 The circuit's quotient/remainder identity must hold exactly.
                    let left = (distributable_sats as u128) * (BOB_WEIGHT_BPS as u128);
                    let right = (amounts.bob_sats as u128) * (BPS_DENOMINATOR as u128)
                        + (amounts.bob_remainder_bps as u128);
                    assert_eq!(
                        left, right,
                        "quotient/remainder mismatch at D = {}",
                        distributable_sats
                    );

                    // 3 The remainder is a canonical basis-point residue.
                    assert!(amounts.bob_remainder_bps < BPS_DENOMINATOR);

                    // 4 Any accepted allocation respects the profile minimum on both sides.
                    assert!(amounts.bob_sats >= MINIMUM_CLAIM_SATS);
                    assert!(amounts.carol_sats >= MINIMUM_CLAIM_SATS);
                }
                Err(error) => {
                    // A rejection is only allowed when an allocation would be unrepresentable.
                    assert!(
                        matches!(
                            error,
                            SplitVaultError::ZeroBeneficiaryAllocation { .. }
                                | SplitVaultError::BelowMinimumClaim { .. }
                        ),
                        "unexpected rejection at D = {}: {:?}",
                        distributable_sats,
                        error
                    );
                }
            }
        }
    }

    #[test]
    fn t03_nondivisible_amount_assigns_the_remainder_to_carol() {
        // D = 1_001 -> Bob = floor(700.7) = 700, Carol = 301, remainder = 7_000 bps.
        let amounts = split_amounts(1_001, 0).expect("fixture must be valid");
        assert_eq!(amounts.distributable_sats, 1_001);
        assert_eq!(amounts.bob_sats, 700);
        assert_eq!(amounts.carol_sats, 301);
        assert_eq!(amounts.bob_remainder_bps, 7_000);
    }

    #[test]
    fn t03_rejections_are_frozen_and_ordered() {
        // G = 0.
        assert_eq!(split_amounts(0, 0), Err(SplitVaultError::GrossAmountIsZero));

        // E == G.
        assert_eq!(
            split_amounts(1_000, 1_000),
            Err(SplitVaultError::ExecutionFeeNotBelowGross {
                gross_sats: 1_000,
                execution_fee_sats: 1_000,
            })
        );

        // E > G.
        assert_eq!(
            split_amounts(1_000, 1_001),
            Err(SplitVaultError::ExecutionFeeNotBelowGross {
                gross_sats: 1_000,
                execution_fee_sats: 1_001,
            })
        );

        // G = 1 -> Bob = 0.
        assert_eq!(
            split_amounts(1, 0),
            Err(SplitVaultError::ZeroBeneficiaryAllocation {
                bob_sats: 0,
                carol_sats: 1,
            })
        );

        // G = 11 -> Bob = 7, Carol = 4 -> both below the 10-sat profile minimum.
        assert_eq!(
            split_amounts(11, 0),
            Err(SplitVaultError::BelowMinimumClaim {
                bob_sats: 7,
                carol_sats: 4,
                minimum_sats: MINIMUM_CLAIM_SATS,
            })
        );

        // G = 34 -> Bob = 23, Carol = 11.
        assert!(split_amounts(34, 0).is_ok());

        // The smallest accepted zero-fee amount is D = 31: Bob = 21, Carol = ceil(0.3 * 31) = 10.
        assert!(split_amounts(31, 0).is_ok());
        assert_eq!(
            split_amounts(30, 0),
            Err(SplitVaultError::BelowMinimumClaim {
                bob_sats: 21,
                carol_sats: 9,
                minimum_sats: MINIMUM_CLAIM_SATS,
            })
        );
    }

    #[test]
    fn t03_weights_sum_to_the_denominator() {
        assert_eq!(BOB_WEIGHT_BPS + carol_weight_bps(), BPS_DENOMINATOR);
        assert_eq!(BOB_WEIGHT_BPS, 7_000);
        assert_eq!(CAROL_WEIGHT_BPS, 3_000);
    }

    // ---------------------------------------------------------------------------------------
    // T-04: instantiation and descriptor validation
    // ---------------------------------------------------------------------------------------

    #[test]
    fn t04_instantiate_creates_an_empty_instance() {
        let vault = instantiated_vault();
        let instance = vault.instance.expect("instance must exist");

        assert_eq!(instance.phase, Phase::Empty);
        assert_eq!(instance.contract_balance_sats, 0);
        assert_eq!(instance.bob_shadow_sats, 0);
        assert_eq!(instance.carol_shadow_sats, 0);
        assert_eq!(instance.gross_sats, 0);
        assert_eq!(instance.execution_fee_sats, 0);
        assert_eq!(instance.instance_sequence, 1);

        // Instantiation does not lock principal.
        assert_eq!(vault.ledger.owner_sats, GROSS_SATS);
        assert!(vault.check_invariants().is_ok());
    }

    #[test]
    fn t04_contract_id_is_derived_from_descriptor_and_operation() {
        let descriptor = fixture_descriptor();
        let operation_id = SplitVault::next_operation_id(1);

        let expected = derive_contract_id(&descriptor, &operation_id);
        let vault = instantiated_vault();

        assert_eq!(vault.instance.expect("instance").contract_id, expected);

        // A different instantiation operation yields a different contract identity.
        let other = derive_contract_id(&descriptor, &SplitVault::next_operation_id(9));
        assert_ne!(expected, other);
    }

    #[test]
    fn t04_instantiate_rejects_aliased_keys() {
        let mut descriptor = fixture_descriptor();
        descriptor.bob_key = descriptor.carol_key;

        let mut vault = SplitVault::new(funded_ledger());
        assert_eq!(
            vault.instantiate(descriptor, auth(Role::Owner, 1), operation(1)),
            Err(SplitVaultError::DuplicateParticipantKey {
                first: Role::Bob,
                second: Role::Carol,
            })
        );
        assert!(vault.instance.is_none());

        // The owner may not alias a beneficiary either.
        let mut descriptor = fixture_descriptor();
        descriptor.owner_key = descriptor.fee_key;
        assert_eq!(
            vault.instantiate(descriptor, auth(Role::Owner, 1), operation(1)),
            Err(SplitVaultError::DuplicateParticipantKey {
                first: Role::Owner,
                second: Role::Fee,
            })
        );
    }

    #[test]
    fn t04_instantiate_rejects_zero_keys_and_wrong_weights() {
        let mut vault = SplitVault::new(funded_ledger());

        let mut descriptor = fixture_descriptor();
        descriptor.carol_key = [0u8; 32];
        assert_eq!(
            vault.instantiate(descriptor, auth(Role::Owner, 1), operation(1)),
            Err(SplitVaultError::ZeroParticipantKey { role: Role::Carol })
        );

        let mut descriptor = fixture_descriptor();
        descriptor.bob_weight_bps = 6_000;
        descriptor.carol_weight_bps = 4_000;
        assert_eq!(
            vault.instantiate(descriptor, auth(Role::Owner, 1), operation(1)),
            Err(SplitVaultError::UnsupportedWeights {
                bob_weight_bps: 6_000,
                carol_weight_bps: 4_000,
            })
        );
    }

    #[test]
    fn t04_only_the_owner_may_instantiate() {
        let mut vault = SplitVault::new(funded_ledger());
        assert_eq!(
            vault.instantiate(fixture_descriptor(), auth(Role::Bob, 1), operation(1)),
            Err(SplitVaultError::UnauthorizedCaller {
                required: "OWNER",
                actual: Role::Bob,
            })
        );
        assert!(vault.instance.is_none());
    }

    #[test]
    fn t04_instantiate_is_rejected_twice() {
        let mut vault = instantiated_vault();
        let contract_id = vault.instance.expect("instance").contract_id;

        assert_eq!(
            vault.instantiate(fixture_descriptor(), auth(Role::Owner, 2), operation(9)),
            Err(SplitVaultError::InstanceAlreadyInstantiated { contract_id })
        );
    }

    // ---------------------------------------------------------------------------------------
    // T-04: funding
    // ---------------------------------------------------------------------------------------

    #[test]
    fn t04_fund_moves_exactly_the_authorised_value() {
        let vault = allocated_vault();

        // Alice is fully debited; the fee account and the contract are funded.
        assert_eq!(vault.ledger.owner_sats, 0);
        assert_eq!(vault.ledger.bob_sats, 0);
        assert_eq!(vault.ledger.carol_sats, 0);
        assert_eq!(vault.ledger.fee_sats, EXECUTION_FEE_SATS);

        // Physical value is conserved across the transition.
        assert_eq!(vault.physical_value_sats(), GROSS_SATS as u128);

        // Both beneficiary entitlements exist only as shadows.
        assert_eq!(vault.instance.expect("instance").bob_shadow_sats, 69_650);
        assert_eq!(vault.instance.expect("instance").carol_shadow_sats, 29_850);
    }

    #[test]
    fn t04_fund_rejects_second_funding() {
        let mut vault = allocated_vault();

        assert!(matches!(
            vault.fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                auth(Role::Owner, 3),
                operation(3)
            ),
            Err(SplitVaultError::WrongPhase {
                required: "EMPTY",
                actual: Phase::Allocated,
            })
        ));
    }

    #[test]
    fn t04_fund_rejects_a_bad_fee_and_insufficient_funds() {
        // E == G.
        let mut vault = instantiated_vault();
        assert_eq!(
            vault.fund(1_000, 1_000, auth(Role::Owner, 2), operation(2)),
            Err(SplitVaultError::ExecutionFeeNotBelowGross {
                gross_sats: 1_000,
                execution_fee_sats: 1_000,
            })
        );

        // G above the owner's eligible balance.
        let mut vault = instantiated_vault();
        assert_eq!(
            vault.fund(
                GROSS_SATS + 1,
                EXECUTION_FEE_SATS,
                auth(Role::Owner, 2),
                operation(2)
            ),
            Err(SplitVaultError::InsufficientOwnerFunds {
                available_sats: GROSS_SATS,
                required_sats: GROSS_SATS + 1,
            })
        );
        assert_eq!(vault.ledger.owner_sats, GROSS_SATS);
    }

    #[test]
    fn t04_fund_rejects_a_non_owner_caller() {
        let mut vault = instantiated_vault();
        assert_eq!(
            vault.fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                auth(Role::Bob, 1),
                operation(2)
            ),
            Err(SplitVaultError::UnauthorizedCaller {
                required: "OWNER",
                actual: Role::Bob,
            })
        );
    }

    #[test]
    fn t04_fund_before_instantiation_is_rejected() {
        let mut vault = SplitVault::new(funded_ledger());
        assert_eq!(
            vault.fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                auth(Role::Owner, 1),
                operation(1)
            ),
            Err(SplitVaultError::InstanceNotInstantiated)
        );
    }

    // ---------------------------------------------------------------------------------------
    // T-05: redemption order
    // ---------------------------------------------------------------------------------------

    #[test]
    fn t05_redemption_order_does_not_change_the_outcome() {
        // Order one: Bob first, then Carol.
        let mut bob_first = allocated_vault();
        let bob_transition = bob_first
            .redeem(auth(Role::Bob, 1), operation(10))
            .expect("Bob's redemption must be accepted");
        assert_eq!(
            bob_transition,
            Transition::Redeemed {
                role: Role::Bob,
                amount_sats: 69_650,
                phase: Phase::PartiallyRedeemed,
            }
        );
        let carol_transition = bob_first
            .redeem(auth(Role::Carol, 1), operation(11))
            .expect("Carol's redemption must be accepted");
        assert_eq!(
            carol_transition,
            Transition::Redeemed {
                role: Role::Carol,
                amount_sats: 29_850,
                phase: Phase::Closed,
            }
        );

        // Order two: Carol first, then Bob.
        let mut carol_first = allocated_vault();
        carol_first
            .redeem(auth(Role::Carol, 1), operation(10))
            .expect("Carol's redemption must be accepted");
        carol_first
            .redeem(auth(Role::Bob, 1), operation(11))
            .expect("Bob's redemption must be accepted");

        // The committed state is identical in both runs.
        assert_eq!(bob_first.ledger, carol_first.ledger);
        assert_eq!(bob_first.state(), carol_first.state());
        assert_eq!(bob_first.state_digest(), carol_first.state_digest());
    }

    #[test]
    fn t05_partial_redemption_does_not_disturb_the_other_beneficiary() {
        let mut vault = allocated_vault();
        vault
            .redeem(auth(Role::Bob, 1), operation(10))
            .expect("Bob's redemption must be accepted");

        let instance = vault.instance.expect("instance");
        assert_eq!(instance.phase, Phase::PartiallyRedeemed);
        assert_eq!(instance.bob_shadow_sats, 0);
        assert_eq!(instance.carol_shadow_sats, 29_850);
        assert_eq!(instance.contract_balance_sats, 29_850);

        // Bob holds native value; Carol's claim is untouched and still backed.
        assert_eq!(vault.ledger.bob_sats, 69_650);
        assert_eq!(vault.ledger.carol_sats, 0);
        assert!(vault.check_invariants().is_ok());
    }

    #[test]
    fn t05_a_redeemed_share_cannot_be_redeemed_again() {
        let mut vault = allocated_vault();
        vault
            .redeem(auth(Role::Bob, 1), operation(10))
            .expect("Bob's redemption must be accepted");

        // A correctly sequenced second attempt finds no allocation left.
        assert_eq!(
            vault.redeem(auth(Role::Bob, 2), operation(11)),
            Err(SplitVaultError::NoShadowAllocation { role: Role::Bob })
        );

        // And nothing changed.
        assert_eq!(vault.ledger.bob_sats, 69_650);
    }

    #[test]
    fn t05_redeem_rejects_owner_fee_and_closed_vault() {
        let mut vault = allocated_vault();
        assert_eq!(
            vault.redeem(auth(Role::Owner, 2), operation(10)),
            Err(SplitVaultError::UnauthorizedCaller {
                required: "BOB or CAROL",
                actual: Role::Owner,
            })
        );
        assert_eq!(
            vault.redeem(auth(Role::Fee, 1), operation(10)),
            Err(SplitVaultError::UnauthorizedCaller {
                required: "BOB or CAROL",
                actual: Role::Fee,
            })
        );

        // Redeem both, then attempt one more.
        let mut vault = allocated_vault();
        vault.redeem(auth(Role::Bob, 1), operation(10)).unwrap();
        vault.redeem(auth(Role::Carol, 1), operation(11)).unwrap();
        assert_eq!(
            vault.redeem(auth(Role::Bob, 2), operation(12)),
            Err(SplitVaultError::WrongPhase {
                required: "ALLOCATED or PARTIALLY_REDEEMED",
                actual: Phase::Closed,
            })
        );
    }

    #[test]
    fn t05_final_ledger_matches_the_expected_accounting_table() {
        let mut vault = allocated_vault();
        vault.redeem(auth(Role::Bob, 1), operation(10)).unwrap();
        vault.redeem(auth(Role::Carol, 1), operation(11)).unwrap();

        // "Both redeemed" row of specification.md section 3.4.
        assert_eq!(vault.ledger.owner_sats, 0);
        assert_eq!(vault.ledger.bob_sats, 69_650);
        assert_eq!(vault.ledger.carol_sats, 29_850);
        assert_eq!(vault.ledger.fee_sats, 500);

        let instance = vault.instance.expect("instance");
        assert_eq!(instance.phase, Phase::Closed);
        assert_eq!(instance.contract_balance_sats, 0);
        assert_eq!(instance.bob_shadow_sats, 0);
        assert_eq!(instance.carol_shadow_sats, 0);

        // Value conservation: the same 100_000 sats are still accounted for exactly once.
        assert_eq!(vault.physical_value_sats(), GROSS_SATS as u128);
        assert_eq!(
            vault.ledger.bob_sats + vault.ledger.carol_sats + vault.ledger.fee_sats,
            GROSS_SATS
        );
    }

    // ---------------------------------------------------------------------------------------
    // T-04: sequences and operation IDs
    // ---------------------------------------------------------------------------------------

    #[test]
    fn t04_stale_and_future_sequences_are_rejected() {
        let mut vault = allocated_vault();

        // Stale: the owner sequence is already at 2.
        assert_eq!(
            vault.redeem(auth(Role::Bob, 0), operation(10)),
            Err(SplitVaultError::UnexpectedCallerSequence {
                expected: 1,
                actual: 0,
            })
        );

        // Future: skipping ahead is refused.
        assert_eq!(
            vault.redeem(auth(Role::Bob, 7), operation(10)),
            Err(SplitVaultError::UnexpectedCallerSequence {
                expected: 1,
                actual: 7,
            })
        );

        // Each role tracks its own sequence independently.
        vault.redeem(auth(Role::Bob, 1), operation(10)).unwrap();
        vault.redeem(auth(Role::Carol, 1), operation(11)).unwrap();
    }

    #[test]
    fn t04_identical_retry_is_an_idempotent_replay() {
        let mut vault = allocated_vault();
        let before = vault.state_digest();

        let op = operation(10);
        let first = vault.redeem(auth(Role::Bob, 1), op).unwrap();
        let after_first = vault.state_digest();
        assert_ne!(before, after_first);
        assert!(matches!(first, Transition::Redeemed { .. }));

        // The same bytes, retried with the same sequence value.
        let retry = vault.redeem(auth(Role::Bob, 1), op).unwrap();
        assert_eq!(
            retry,
            Transition::Replayed {
                operation_id: op.id
            }
        );

        // The retry changed nothing: one redemption, one credit.
        assert_eq!(vault.state_digest(), after_first);
        assert_eq!(vault.ledger.bob_sats, 69_650);
    }

    #[test]
    fn t04_same_operation_id_with_different_bytes_is_a_conflict() {
        let mut vault = allocated_vault();

        let op = operation(10);
        vault.redeem(auth(Role::Bob, 1), op).unwrap();

        // Same ID, different payload digest.
        let conflicting = Operation::new(op.id, SplitVault::payload_digest(b"a different payload"));
        assert_eq!(
            vault.redeem(auth(Role::Carol, 1), conflicting),
            Err(SplitVaultError::OperationIdConflict {
                operation_id: op.id,
            })
        );

        // Carol's claim is untouched.
        assert_eq!(vault.instance.expect("instance").carol_shadow_sats, 29_850);
    }

    #[test]
    fn t04_a_different_caller_cannot_replay_a_known_operation() {
        let mut vault = allocated_vault();

        // Bob redeems with operation `op`.
        let op = operation(10);
        vault.redeem(auth(Role::Bob, 1), op).unwrap();
        let after_bob = vault.state_digest();

        // Carol presents the same ID with the same bytes but as herself.
        assert_eq!(
            vault.redeem(auth(Role::Carol, 1), op),
            Err(SplitVaultError::OperationIdConflict {
                operation_id: op.id,
            })
        );

        // The replay attempt did not consume Carol's claim or change the state.
        assert_eq!(vault.instance.expect("instance").carol_shadow_sats, 29_850);
        assert_eq!(vault.state_digest(), after_bob);
    }

    // ---------------------------------------------------------------------------------------
    // INV-10: a rejected entry leaves the state byte-for-byte unchanged
    // ---------------------------------------------------------------------------------------

    #[test]
    fn inv10_every_rejection_leaves_the_encoding_identical() {
        let mut vault = allocated_vault();
        let snapshot = vault.state().encode();

        // A battery of rejected operations, each asserted against the canonical bytes.
        let attempts: Vec<(&str, Result<Transition, SplitVaultError>)> = vec![
            (
                "second funding",
                vault.fund(GROSS_SATS, 0, auth(Role::Owner, 3), operation(20)),
            ),
            (
                "owner redeems",
                vault.redeem(auth(Role::Owner, 3), operation(21)),
            ),
            (
                "fee redeems",
                vault.redeem(auth(Role::Fee, 1), operation(22)),
            ),
            (
                "stale sequence",
                vault.redeem(auth(Role::Bob, 0), operation(23)),
            ),
            (
                "future sequence",
                vault.redeem(auth(Role::Bob, 5), operation(24)),
            ),
            (
                "second instantiation",
                vault.instantiate(fixture_descriptor(), auth(Role::Owner, 3), operation(25)),
            ),
        ];

        for (label, result) in attempts {
            assert!(result.is_err(), "{} must be rejected", label);
            assert_eq!(
                vault.state().encode(),
                snapshot,
                "{} mutated the canonical state",
                label
            );
        }

        // A failed redemption after a successful one must not double-credit either.
        vault.redeem(auth(Role::Bob, 1), operation(30)).unwrap();
        let after_bob = vault.state().encode();
        assert!(vault.redeem(auth(Role::Bob, 2), operation(31)).is_err());
        assert_eq!(vault.state().encode(), after_bob);
        assert_eq!(vault.ledger.bob_sats, 69_650);
    }

    // ---------------------------------------------------------------------------------------
    // Invariants across the lifecycle
    // ---------------------------------------------------------------------------------------

    #[test]
    fn invariants_hold_at_every_lifecycle_step() {
        let mut vault = SplitVault::new(funded_ledger());
        assert!(vault.check_invariants().is_ok());

        vault
            .instantiate(fixture_descriptor(), auth(Role::Owner, 1), operation(1))
            .unwrap();
        assert!(vault.check_invariants().is_ok());

        vault
            .fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                auth(Role::Owner, 2),
                operation(2),
            )
            .unwrap();
        assert!(vault.check_invariants().is_ok());

        vault.redeem(auth(Role::Bob, 1), operation(3)).unwrap();
        assert!(vault.check_invariants().is_ok());

        vault.redeem(auth(Role::Carol, 1), operation(4)).unwrap();
        assert!(vault.check_invariants().is_ok());

        // The invariant checker is not vacuous: it rejects a forged state.
        let mut forged = vault.clone();
        if let Some(instance) = forged.instance.as_mut() {
            instance.bob_shadow_sats = 1;
        }
        assert_eq!(
            forged.check_invariants(),
            Err(InvariantViolation::ShadowExceedsContractBalance {
                shadows_sats: 1,
                contract_balance_sats: 0,
            })
        );

        // And it rejects a phase that contradicts an otherwise backed balance.
        let mut forged = vault.clone();
        if let Some(instance) = forged.instance.as_mut() {
            instance.phase = Phase::Allocated;
        }
        assert_eq!(
            forged.check_invariants(),
            Err(InvariantViolation::PhaseBalanceMismatch {
                phase: Phase::Allocated,
                contract_balance_sats: 0,
                bob_shadow_sats: 0,
                carol_shadow_sats: 0,
            })
        );
    }

    // ---------------------------------------------------------------------------------------
    // Canonical encoding
    // ---------------------------------------------------------------------------------------

    #[test]
    fn encoding_round_trips_at_every_lifecycle_step() {
        let mut vault = SplitVault::new(funded_ledger());
        assert_round_trip(&vault);

        vault
            .instantiate(fixture_descriptor(), auth(Role::Owner, 1), operation(1))
            .unwrap();
        assert_round_trip(&vault);

        vault
            .fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                auth(Role::Owner, 2),
                operation(2),
            )
            .unwrap();
        assert_round_trip(&vault);

        vault.redeem(auth(Role::Bob, 1), operation(3)).unwrap();
        assert_round_trip(&vault);

        vault.redeem(auth(Role::Carol, 1), operation(4)).unwrap();
        assert_round_trip(&vault);
    }

    /// Asserts that one state survives an encode/decode round trip with an identical digest.
    fn assert_round_trip(vault: &SplitVault) {
        let state = vault.state();
        let bytes = state.encode();
        let decoded = SplitState::decode(&bytes).expect("canonical bytes must decode");
        assert_eq!(decoded, state);
        assert_eq!(decoded.digest(), vault.state_digest());
    }

    #[test]
    fn encoding_has_a_frozen_length_per_lifecycle_state() {
        // Not instantiated: header + four balances + four sequences.
        assert_eq!(SplitVault::new(funded_ledger()).state().encode().len(), 66);

        // Instantiated: header + 277-byte instance block + four balances + four sequences.
        assert_eq!(instantiated_vault().state().encode().len(), 343);
        assert_eq!(allocated_vault().state().encode().len(), 343);
    }

    #[test]
    fn decoder_rejects_truncated_and_trailing_bytes() {
        let bytes = allocated_vault().state().encode();

        // Truncated.
        assert!(matches!(
            SplitState::decode(&bytes[..bytes.len() - 1]),
            Err(SplitDecodeError::Truncated { .. })
        ));

        // Trailing bytes.
        let mut extended = bytes.clone();
        extended.push(0x00);
        assert_eq!(
            SplitState::decode(&extended),
            Err(SplitDecodeError::TrailingBytes {
                decoded: bytes.len(),
                actual: bytes.len() + 1,
            })
        );
    }

    #[test]
    fn decoder_rejects_unknown_versions_flags_and_phases() {
        let bytes = allocated_vault().state().encode();

        // Unknown schema version.
        let mut wrong_version = bytes.clone();
        wrong_version[0] = 0x02;
        assert_eq!(
            SplitState::decode(&wrong_version),
            Err(SplitDecodeError::UnknownSchemaVersion {
                expected: 1,
                actual: 2,
            })
        );

        // Unknown instance presence flag.
        let mut wrong_presence = bytes.clone();
        wrong_presence[1] = 0x02;
        assert_eq!(
            SplitState::decode(&wrong_presence),
            Err(SplitDecodeError::UnknownInstancePresenceFlag(2))
        );

        // Unknown phase tag: the phase byte sits at 2 + 196 + 32 + 8 + 8 = 246.
        let mut wrong_phase = bytes.clone();
        wrong_phase[246] = 0x09;
        assert_eq!(
            SplitState::decode(&wrong_phase),
            Err(SplitDecodeError::UnknownPhaseTag(9))
        );
    }

    #[test]
    fn decoder_rejects_a_state_no_transition_could_produce() {
        // Claim CLOSED while a shadow allocation is still live.
        let mut forged = allocated_vault().state();
        if let Some(instance) = forged.instance.as_mut() {
            instance.phase = Phase::Closed;
        }
        assert_eq!(
            SplitState::decode(&forged.encode()),
            Err(SplitDecodeError::InconsistentState {
                reason: "CLOSED instance carries a nonzero balance or allocation",
            })
        );

        // Claim ALLOCATED with unbacked shadows.
        let mut forged = allocated_vault().state();
        if let Some(instance) = forged.instance.as_mut() {
            instance.contract_balance_sats -= 1;
        }
        assert_eq!(
            SplitState::decode(&forged.encode()),
            Err(SplitDecodeError::InconsistentState {
                reason: "ALLOCATED instance shadows do not equal the contract balance",
            })
        );
    }

    #[test]
    fn descriptor_and_instance_sizes_are_frozen() {
        assert_eq!(fixture_descriptor().encode().len(), 196);

        let instance: SplitInstance = instantiated_vault().instance.expect("instance");
        let mut buffer = Vec::<u8>::new();
        instance.encode_into(&mut buffer);
        assert_eq!(buffer.len(), 277);
    }

    // ---------------------------------------------------------------------------------------
    // Golden vectors
    // ---------------------------------------------------------------------------------------

    /// Prints the canonical digests of every lifecycle state.
    ///
    /// This test exists so the vectors below can be regenerated deliberately rather than guessed.
    /// It asserts only internal consistency; the frozen hex literals live in
    /// `golden_vectors_are_frozen`.
    #[test]
    fn golden_vectors_printer() {
        let mut vault = SplitVault::new(funded_ledger());
        println!(
            "state_digest/uninstantiated = {}",
            hex::encode(vault.state_digest())
        );

        vault
            .instantiate(fixture_descriptor(), auth(Role::Owner, 1), operation(1))
            .unwrap();
        println!(
            "contract_id                = {}",
            hex::encode(vault.instance.expect("instance").contract_id)
        );
        println!(
            "state_digest/instantiated   = {}",
            hex::encode(vault.state_digest())
        );

        vault
            .fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                auth(Role::Owner, 2),
                operation(2),
            )
            .unwrap();
        println!(
            "state_digest/allocated      = {}",
            hex::encode(vault.state_digest())
        );

        vault.redeem(auth(Role::Bob, 1), operation(3)).unwrap();
        println!(
            "state_digest/bob_redeemed   = {}",
            hex::encode(vault.state_digest())
        );

        vault.redeem(auth(Role::Carol, 1), operation(4)).unwrap();
        println!(
            "state_digest/closed         = {}",
            hex::encode(vault.state_digest())
        );

        println!(
            "state_encoding/allocated    = {}",
            hex::encode(allocated_vault().state().encode())
        );
    }

    /// The frozen `cube-v1-fixed-v0` vectors.
    ///
    /// These literals were produced by `golden_vectors_printer` from the fixtures above and are
    /// now the compatibility contract: changing the descriptor layout, the phase tags, the field
    /// order or the tagged-hash tags breaks this test on purpose. A second implementation must
    /// reproduce them byte for byte before any interoperability claim is made.
    #[test]
    fn golden_vectors_are_frozen() {
        // 1 The contract identity binds the canonical descriptor and the instantiation operation.
        assert_eq!(
            hex::encode(instantiated_vault().instance.expect("instance").contract_id),
            "250bad69700b90dbbb12a975f59b53f0ba2699a4ca90fe8987e0a158ff4f9452"
        );

        // 2 The canonical state digest at each lifecycle step.
        let mut vault = SplitVault::new(funded_ledger());
        assert_eq!(
            hex::encode(vault.state_digest()),
            "eb19257baeb1d64358e5d2be7177880e5b59c73ffd4b35237669f48be34b0334"
        );

        vault
            .instantiate(fixture_descriptor(), auth(Role::Owner, 1), operation(1))
            .unwrap();
        assert_eq!(
            hex::encode(vault.state_digest()),
            "ade5eebc13f2efc75fca9df9e40b9236a02343aafcce4e0fe9becdf1533af2ff"
        );

        vault
            .fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS,
                auth(Role::Owner, 2),
                operation(2),
            )
            .unwrap();
        assert_eq!(
            hex::encode(vault.state_digest()),
            "dd313a0d6780a9ab3db00d3cc4c058f231771570115225442b6474c44512d40c"
        );

        vault.redeem(auth(Role::Bob, 1), operation(3)).unwrap();
        assert_eq!(
            hex::encode(vault.state_digest()),
            "b3c9bd6a8e52e4733ca98d832a610f08bf42e236fbb150ae6c4840509e38f59a"
        );

        vault.redeem(auth(Role::Carol, 1), operation(4)).unwrap();
        assert_eq!(
            hex::encode(vault.state_digest()),
            "4aee119e64a77ea3643383c68d1443cdcd3d336277dfe31a63e2ba580c713f36"
        );

        // 3 The complete canonical encoding of the ALLOCATED state.
        //
        // Field by field: schema 0x01, presence 0x01, network 0x11*32, template 0x22*32,
        // owner/bob/carol/fee sequential keys, weights 0x1b58 / 0x0bb8, contract id,
        // G = 0x000186a0, E = 0x000001f4, phase 0x01, balance 0x000184ac,
        // Bob 0x00011012, Carol 0x0000749a, instance sequence 2, ledger 0/0/0/500,
        // sequences 2/0/0/0.
        assert_eq!(
            hex::encode(allocated_vault().state().encode()),
            concat!(
                "0101",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                "12131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
                "232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142",
                "3435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50515253",
                "581bb80b",
                "250bad69700b90dbbb12a975f59b53f0ba2699a4ca90fe8987e0a158ff4f9452",
                "a086010000000000",
                "f401000000000000",
                "01",
                "ac84010000000000",
                "1210010000000000",
                "9a74000000000000",
                "0200000000000000",
                "0000000000000000",
                "0000000000000000",
                "0000000000000000",
                "f401000000000000",
                "0200000000000000",
                "0000000000000000",
                "0000000000000000",
                "0000000000000000"
            )
        );
    }
}
