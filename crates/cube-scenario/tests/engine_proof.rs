//! The composed proof path: a VM-derived manifest, a real Groth16 proof, Argo's verdict, and a
//! Bitcoin `Take`.
//!
//! This is the test the `proof` feature exists for. It runs the CubeVM, takes the state the VM
//! reached, derives the manifest from it, proves that manifest, evaluates the proof through a real
//! garbled Argo table, binds the authenticated input and table digests into the assertion terms,
//! and settles the claim on regtest.
//!
//! Groth16 setup/proving and Argo garbling are only practical in release, so the test is ignored by
//! default:
//!
//! ```text
//! CUBE_REGTEST_RPC_URL=http://127.0.0.1:18443 \
//! CUBE_REGTEST_RPC_USER=cube CUBE_REGTEST_RPC_PASSWORD=cube \
//! cargo test --release -p cube-scenario --features proof \
//!   --test engine_proof -- --ignored --nocapture
//! ```
//!
//! The setup is a single-party **trusted test setup**. It proves the composition and the settlement
//! path, not a deployment setup.

#![cfg(feature = "proof")]

mod engine_proof {
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use cube::constructive::graph::assertion::disclosure_secret_commitment;
    use cube_argo::{
        statement_public_input, GarbledVerifier, GarblingConfig, Groth16Proof as ArgoProof,
        Groth16VerifyingKey, PreparedVerifierKey, VerifierOutcome, RECOMMENDED_SETUP_STACK_BYTES,
    };
    use cube_proof::fund_split::FundSplitCircuit;
    use cube_proof::groth16::{prove, setup, verify};
    use cube_scenario::artifact::State;
    use cube_scenario::chain::Chain;
    use cube_scenario::rpc::RpcConfig;
    use cube_scenario::transition::{from_vm, plan_from_vm, TransitionOptions};
    use cube_scenario::{engine, keys, scenario};

    /// The fixture amounts, matching the runbook.
    const DEPOSIT_SATS: u64 = 500_000;
    const EXECUTION_FEE_SATS: u64 = 5_000;
    const OWNER_START_SATS: u64 = 1_000_000;
    const CHALLENGE_BLOCKS: u32 = 10;

    #[test]
    #[ignore = "Groth16 setup/proving and Argo garbling are slow; run in release with --ignored"]
    fn a_vm_derived_manifest_is_proven_and_taken_on_regtest() {
        std::thread::Builder::new()
            .name("engine-proof".to_string())
            .stack_size(RECOMMENDED_SETUP_STACK_BYTES)
            .spawn(scenario)
            .expect("spawn")
            .join()
            .expect("the scenario must not panic");
    }

    fn scenario() {
        // 1 Skip before the expensive cryptography when no node is configured.
        let config = RpcConfig::from_env();
        if config.url.is_none() && config.datadir.is_none() && config.user.is_none() {
            println!("SKIPPED: set CUBE_REGTEST_RPC_URL or CUBE_REGTEST_DATADIR to run this test");
            return;
        }
        let chain = Chain::open(&config, "cube-cli-engine-proof").expect("the node must open");
        let mut state = State::new();
        let deposit = scenario::fund_deposit(&chain, &mut state, DEPOSIT_SATS)
            .expect("the deposit must fund");

        // 2 The CubeVM executes fund_split and yields the canonical state bytes.
        let options = TransitionOptions {
            challenge_blocks: CHALLENGE_BLOCKS,
            ..TransitionOptions::default()
        };
        let gross_sats = DEPOSIT_SATS - options.network_fee_reserve_sats;
        let vm = engine::fund_split(gross_sats, EXECUTION_FEE_SATS, OWNER_START_SATS)
            .expect("the VM must fund the split");
        let plan = plan_from_vm(&deposit, &vm, &options).expect("the VM state must derive a plan");
        assert_eq!(plan.previous_state.len(), 343);
        assert_eq!(plan.resulting_state.len(), 343);

        // 3 Prove the VM-derived manifest.
        let circuit = FundSplitCircuit::from_parts(
            plan.manifest.encode(),
            plan.previous_state.clone(),
            plan.resulting_state.clone(),
            0,
        );
        let statement = circuit.statement;
        let statement_digest = plan.manifest.statement_digest();
        assert_eq!(
            statement_public_input(statement_digest).expect("field-sized digest"),
            statement,
            "the circuit statement and the field-sized digest must agree"
        );

        let mut rng = StdRng::seed_from_u64(0xc0ff_ee00_1234_5678);
        let proving_key = setup(circuit.clone(), &mut rng).expect("setup");
        let proof = prove(circuit, &proving_key, &mut rng).expect("prove");
        assert!(
            verify(&proving_key.vk, statement, &proof).expect("verify"),
            "the honest proof must verify"
        );

        // 4 The same key in Argo's equation, and the table's verdict on the real proof.
        let verifier_key = Groth16VerifyingKey {
            alpha_g1: proving_key.vk.alpha_g1,
            beta_g2: proving_key.vk.beta_g2,
            gamma_g2: proving_key.vk.gamma_g2,
            delta_g2: proving_key.vk.delta_g2,
            gamma_abc_g1: proving_key.vk.gamma_abc_g1.clone(),
        };
        let prepared =
            PreparedVerifierKey::from_groth16_verifying_key(&verifier_key).expect("convert");
        let garbling = GarblingConfig {
            rng_seed: 0x5eed_5eed_5eed_5eed,
            disclosure_secret: keys::DISCLOSURE_SECRET.to_vec(),
        };
        let verifier = GarbledVerifier::setup(&garbling, &prepared, [0x11; 16]).expect("garble");

        let input = ArgoProof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
            x: statement,
        };
        let authenticated = verifier.authenticate(&input).expect("authenticate");
        assert_eq!(
            authenticated.public_input().expect("public input"),
            statement
        );
        assert_eq!(
            verifier
                .evaluate_authenticated(&authenticated)
                .expect("evaluate"),
            VerifierOutcome::Accepted,
            "a valid proof must not disclose"
        );
        assert_eq!(
            verifier.disclosure_secret_commitment(),
            disclosure_secret_commitment(&keys::DISCLOSURE_SECRET),
            "the table and the assertion terms must commit the same disclosure secret"
        );

        // 5 Bind the real proof into the assertion terms and settle on Bitcoin.
        let options = TransitionOptions {
            challenge_blocks: CHALLENGE_BLOCKS,
            input_digest: Some(authenticated.digest()),
            table_digest: Some(verifier.table_digest()),
            verifier_key_identity: Some(prepared.identity()),
            ..TransitionOptions::default()
        };
        let transition = from_vm(&deposit, &vm, &options).expect("the transition must derive");
        assert_eq!(
            transition.statement_digest.0, statement_digest,
            "the artifact must commit the proved statement"
        );
        state.transition = Some(transition);

        let tree = scenario::publish_successor(&chain, &mut state).expect("the successor");
        let assertion =
            scenario::assert_claim(&chain, &mut state, 0, 1_000).expect("the assertion");
        let take = scenario::take_assertion(&chain, &mut state, None, 500, true).expect("the take");
        assert!(take.accepted, "the proof-backed assertion must be taken");

        println!(
            "VM-derived proof taken: successor {}, assertion {}, take {:?}, paid {} sats",
            tree.txid, assertion.txid, take.txid, take.amount_sats
        );
    }
}
