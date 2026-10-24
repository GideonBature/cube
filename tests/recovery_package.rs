//! Tests for the claim recovery package.
//!
//! The package is what a fresh client holds after the Engine is gone. These tests check that it is
//! self-describing, that it refuses to describe a claim that does not exist, and that its integrity
//! identifier moves with every field that matters.
//!
//! Recovery *from* a package on a live chain is covered by `liftv2_regtest.rs`.

#[cfg(test)]
mod recovery_package_tests {
    use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::{
        ClaimRecoveryPackage, DischargeState, PackageError, PACKAGE_SCHEMA_VERSION,
    };
    use cube::constructive::contracts::fixed_split_vault_v1::{claim_script, claim_scriptpubkey};
    use cube::model::fixed_split_vault_v1::manifest::Anchor;
    use cube::model::fixed_split_vault_v1::ReleaseProfile;

    const STATEMENT_DIGEST: [u8; 32] = [0x4a; 32];
    const BENEFICIARY_KEY: [u8; 32] = [0x21; 32];
    const CLAIM_ID: [u8; 32] = [0x71; 32];
    const PREDECESSOR_CLAIM_ID: [u8; 32] = [0x72; 32];
    const TEMPLATE_HASH: [u8; 32] = [0x22; 32];
    const CIRCUIT_ID: [u8; 32] = [0x33; 32];
    const SETUP_INSTANCE_ID: [u8; 32] = [0x77; 32];
    const CHALLENGE_CONFIG_DIGEST: [u8; 32] = [0x88; 32];
    const CLAIM_TXID: [u8; 32] = [0xcc; 32];

    /// One labelled mutation of a package.
    type Mutation = (&'static str, Box<dyn Fn(&mut ClaimRecoveryPackage)>);

    /// One labelled invalid case with its expected rejection.
    type InvalidCase = (
        &'static str,
        Box<dyn Fn(&mut ClaimRecoveryPackage)>,
        PackageError,
    );

    const ENTITLEMENT_SATS: u64 = 34_995_100;
    const EXPIRY_HEIGHT: u64 = 432;
    const FEE_RATE_SAT_PER_VB: u64 = 10;

    /// Returns a valid package for Bob's claim.
    fn fixture() -> ClaimRecoveryPackage {
        ClaimRecoveryPackage::new(
            ReleaseProfile::ArgoSplitRegtest,
            CLAIM_ID,
            Some(PREDECESSOR_CLAIM_ID),
            BENEFICIARY_KEY,
            TEMPLATE_HASH,
            CIRCUIT_ID,
            STATEMENT_DIGEST,
            ENTITLEMENT_SATS,
            Some(Anchor::new(CLAIM_TXID, 0)),
            EXPIRY_HEIGHT,
            FEE_RATE_SAT_PER_VB,
            SETUP_INSTANCE_ID,
            CHALLENGE_CONFIG_DIGEST,
        )
        .expect("the fixture package must construct")
    }

    #[test]
    fn package_round_trips_and_is_self_describing() {
        let package = fixture();
        package.validate().expect("the fixture must be valid");

        let bytes = package.encode();
        let decoded = ClaimRecoveryPackage::decode(&bytes).expect("canonical bytes must decode");

        assert_eq!(decoded, package);
        assert_eq!(decoded.encode(), bytes, "the encoding must be canonical");
        assert_eq!(decoded.digest(), package.digest());

        // 1 The package carries the spend material, not a promise to derive it.
        assert_eq!(
            decoded.claim_script,
            claim_script(STATEMENT_DIGEST, BENEFICIARY_KEY)
        );
        assert_eq!(decoded.control_block.len(), 33);

        // 2 The scriptpubkey it recovers is the one the statement and key imply.
        assert_eq!(
            decoded.claim_scriptpubkey(),
            claim_scriptpubkey(STATEMENT_DIGEST, BENEFICIARY_KEY)
        );

        // 3 It knows whether it still needs recovering.
        assert!(decoded.is_recoverable());
        assert!(!decoded.is_stale_at(EXPIRY_HEIGHT - 1));
        assert!(decoded.is_stale_at(EXPIRY_HEIGHT));
    }

    #[test]
    fn package_without_a_predecessor_or_outpoint_round_trips() {
        // A package can exist before the claim is funded, and a first claim has no predecessor.
        let mut package = fixture();
        package.predecessor_claim_id = None;
        package.claim_outpoint = None;
        package.validate().expect("must be valid");

        let decoded = ClaimRecoveryPackage::decode(&package.encode()).expect("round trip");
        assert_eq!(decoded.predecessor_claim_id, None);
        assert_eq!(decoded.claim_outpoint, None);
        // Without an outpoint there is nothing to recover yet.
        assert!(!decoded.is_recoverable());
    }

    #[test]
    fn package_digest_moves_with_every_bound_field() {
        let package = fixture();
        let reference = package.digest();

        let mutations: Vec<Mutation> = vec![
            (
                "claim id",
                Box::new(|p: &mut ClaimRecoveryPackage| p.claim_id[0] ^= 1),
            ),
            (
                "predecessor",
                Box::new(|p: &mut ClaimRecoveryPackage| p.predecessor_claim_id = None),
            ),
            (
                "beneficiary",
                Box::new(|p: &mut ClaimRecoveryPackage| p.beneficiary_key[0] ^= 1),
            ),
            (
                "template",
                Box::new(|p: &mut ClaimRecoveryPackage| p.template_hash[0] ^= 1),
            ),
            (
                "circuit",
                Box::new(|p: &mut ClaimRecoveryPackage| p.circuit_id[0] ^= 1),
            ),
            (
                "statement",
                Box::new(|p: &mut ClaimRecoveryPackage| p.statement_digest[0] ^= 1),
            ),
            (
                "entitlement",
                Box::new(|p: &mut ClaimRecoveryPackage| p.entitlement_sats += 1),
            ),
            (
                "discharge",
                Box::new(|p: &mut ClaimRecoveryPackage| p.discharge = DischargeState::Discharged),
            ),
            (
                "outpoint",
                Box::new(|p: &mut ClaimRecoveryPackage| {
                    p.claim_outpoint = Some(Anchor::new(CLAIM_TXID, 1))
                }),
            ),
            (
                "expiry",
                Box::new(|p: &mut ClaimRecoveryPackage| p.expiry_height += 1),
            ),
            (
                "fee rate",
                Box::new(|p: &mut ClaimRecoveryPackage| p.fee_rate_sat_per_vb += 1),
            ),
            (
                "setup",
                Box::new(|p: &mut ClaimRecoveryPackage| p.setup_instance_id[0] ^= 1),
            ),
            (
                "challenge",
                Box::new(|p: &mut ClaimRecoveryPackage| p.challenge_config_digest[0] ^= 1),
            ),
            (
                "profile",
                Box::new(|p: &mut ClaimRecoveryPackage| p.profile = ReleaseProfile::PaymentsV1),
            ),
        ];

        for (label, mutate) in mutations {
            let mut mutated = package.clone();
            mutate(&mut mutated);
            assert_ne!(
                mutated.digest(),
                reference,
                "the package digest did not change when {label} changed"
            );
        }
    }

    #[test]
    fn package_rejects_invalid_terms() {
        let cases: Vec<InvalidCase> = vec![
            (
                "schema",
                Box::new(|p: &mut ClaimRecoveryPackage| p.schema_version = 2),
                PackageError::UnsupportedSchemaVersion { actual: 2 },
            ),
            (
                "zero entitlement",
                Box::new(|p: &mut ClaimRecoveryPackage| p.entitlement_sats = 0),
                PackageError::ZeroEntitlement,
            ),
            (
                "zero fee rate",
                Box::new(|p: &mut ClaimRecoveryPackage| p.fee_rate_sat_per_vb = 0),
                PackageError::ZeroFeeRate,
            ),
            (
                "zero expiry",
                Box::new(|p: &mut ClaimRecoveryPackage| p.expiry_height = 0),
                PackageError::ZeroExpiryHeight,
            ),
            (
                "zero beneficiary",
                Box::new(|p: &mut ClaimRecoveryPackage| p.beneficiary_key = [0u8; 32]),
                PackageError::ZeroBeneficiaryKey,
            ),
            (
                "discharged without outpoint",
                Box::new(|p: &mut ClaimRecoveryPackage| {
                    p.discharge = DischargeState::Discharged;
                    p.claim_outpoint = None;
                    p.claim_script = claim_script(p.statement_digest, p.beneficiary_key);
                }),
                PackageError::DischargedWithoutOutpoint,
            ),
        ];

        for (label, mutate, expected) in cases {
            let mut package = fixture();
            mutate(&mut package);
            assert_eq!(package.validate(), Err(expected), "case: {label}");
        }
    }

    #[test]
    fn package_rejects_inconsistent_spend_material() {
        // 1 A script that does not commit to the carried statement.
        let mut package = fixture();
        package.statement_digest[0] ^= 1;
        assert_eq!(package.validate(), Err(PackageError::ClaimScriptMismatch));

        // 2 A script that commits to a different beneficiary.
        let mut package = fixture();
        package.beneficiary_key[0] ^= 1;
        assert_eq!(package.validate(), Err(PackageError::ClaimScriptMismatch));

        // 3 A well-formed script from a different claim.
        let mut package = fixture();
        package.claim_script = claim_script([0x99; 32], BENEFICIARY_KEY);
        assert_eq!(package.validate(), Err(PackageError::ClaimScriptMismatch));

        // 4 A control block that does not decode, and one that decodes but does not commit.
        let mut package = fixture();
        package.control_block = vec![0xc0; 10];
        assert_eq!(package.validate(), Err(PackageError::InvalidControlBlock));

        // Flipping the parity bit keeps the control block decodable but breaks the commitment,
        // which is the case that matters: an attacker-supplied block that still parses.
        let mut package = fixture();
        let mut control_block = package.control_block.clone();
        control_block[0] ^= 0x01;
        package.control_block = control_block;
        assert_eq!(
            package.validate(),
            Err(PackageError::ControlBlockDoesNotCommit)
        );
    }

    #[test]
    fn decoder_rejects_malformed_bytes() {
        let bytes = fixture().encode();

        // Truncation.
        assert!(matches!(
            ClaimRecoveryPackage::decode(&bytes[..bytes.len() - 1]),
            Err(PackageError::Truncated { .. })
        ));

        // Trailing bytes.
        let mut extended = bytes.clone();
        extended.push(0);
        assert_eq!(
            ClaimRecoveryPackage::decode(&extended),
            Err(PackageError::TrailingBytes {
                decoded: bytes.len(),
                actual: bytes.len() + 1,
            })
        );

        // Unknown profile tag.
        let mut wrong_profile = bytes.clone();
        wrong_profile[1] = 0x7f;
        assert_eq!(
            ClaimRecoveryPackage::decode(&wrong_profile),
            Err(PackageError::UnknownProfileTag(0x7f))
        );

        // A structurally valid package with a tampered digest must fail validation, not decode.
        let mut tampered = fixture();
        tampered.statement_digest[0] ^= 1;
        assert_eq!(
            ClaimRecoveryPackage::decode(&tampered.encode()),
            Err(PackageError::ClaimScriptMismatch)
        );
    }

    #[test]
    fn schema_version_is_the_frozen_one() {
        assert_eq!(PACKAGE_SCHEMA_VERSION, 1);
        assert_eq!(fixture().schema_version, PACKAGE_SCHEMA_VERSION);
    }
}
