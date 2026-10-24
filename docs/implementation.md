# Cube v1 implementation plan

**Version:** 0.2.0-draft  
**Date:** 24 October 2026  
**Target:** payments and recovery plus an Argo-backed FixedSplitVaultV1 pilot on regtest  
**Normative companion:** [specification.md](specification.md)

## 1. Intended result

Build and demonstrate this complete path:

1. Alice funds a recoverable Bitcoin deposit and safely lifts it into Cube.
2. Alice instantiates and funds the allowlisted split vault through the actual Cube `Call` acceptance path.
3. The vault records Bob's and Carol's exact, fully backed Shadow allocations and the disclosed execution fee.
4. A fixed-key Groth16 proof is generated from that real transition and bound to its state, inputs and payout obligations.
5. Argo and the selected projective/malicious-security construction protect the corresponding Bitcoin assertion.
6. Bob and Carol redeem their allocations normally, or independently recover their rightful BTC after the Engine disappears.
7. A deliberately invalid assertion is defeated through the actual Bitcoin transaction graph, not merely detected in Rust.
8. A restored wallet can repeat the recovery without the original device or Engine-only data.

Use a 70/30 split after an explicit execution fee as the first bounded program. It exercises Cube's original execution/Shadowing/redemption relationship while avoiding contract-specific deadlines, price feeds and ambiguous conditional ownership. Refundable/hashlocked escrow is the next pilot, not a prerequisite for the first one.

This plan includes Argo as required work for the requested programmable regtest target. It does not claim that Argo is a full BitVM3 implementation or that the Cube-specific custody/dispute composition is already solved. The concrete graph and cryptographic adapter are design deliverables with explicit gates.

## 2. Starting point and source-backed gaps

Pinned starting revisions retrieved on 24 October 2026:

```text
Cube: 6dd4a09a3b6bcc7759110a4dc5e666aca1ae1938
Argo: aa28ba884f9af3d41265774a882d4efd9f4d9b95
```

These are source-review baselines, not a tested compatible dependency pair. Argo uses Rust edition 2024 and arkworks 0.5 dependencies at this revision; Cube's edition/dependencies differ. Pin a toolchain supporting the complete workspace and isolate incompatible library types behind byte-level adapters. Do not pass different curve/field types through unchecked conversions.

| Existing source location | Observed issue / relevant component | Required work |
|---|---|---|
| `src/constructive/txout_types/lift/lift_versions/liftv1/liftv1.rs` | Trusted Engine-only Lift placeholder | Keep out of the self-custody funded profile |
| `src/constructive/txout_types/lift/lift_versions/liftv2/liftv2.rs` | Cooperative aggregate key and user-delay branch construction exists | Complete signing, spending, refund and handover tests |
| `src/constructive/bitcoiny/batch_txn/signed_batch_txn/signed_batch_txn.rs` | Rejects LiftV2; incomplete Projector witness path | Implement the selected graph/witness integration, not just remove the error |
| `src/operative/tasks/engine_session/session_pool/session_pool.rs` | `new_projector = None` and expiry placeholders | Implement reviewed ownership lifecycle and checked signing obligations |
| `src/executive/exec_ctx/exec_ctx.rs` | Batch dispatch lacks `Call`; fallback panic; multi-manager application | Deterministic Call support and atomic/recoverable commits |
| `src/executive/vm/program_execution/exec.rs` | Existing method executor/opcode dispatch and unfinished payable work | Integrate bounded methods, funding validation and atomic rollback |
| `src/inscriptive/coin_manager/coin_manager.rs` | Native/contract accounting and Shadow methods | Enforce integer invariants and real discharge/redemption linkage |
| `src/executive/vm/opcodes/opcodes/shadowing/` | Shadow allocation/update primitives | Use explicit per-beneficiary updates, with tests across the complete transition |
| Cube manifest / accepted execution path | No integrated Argo/Groth16 dispute pipeline identified | Add prover, authenticated verifier inputs, Bitcoin graph and monitor integration |
| Argo `src/garble/groth16_verifier/mod.rs` | Verifier implementation; cache/output/randomness concerns | Reproduce, fix or justify issues before treating it as a custody dependency |

The current code has useful components. Existing entry names, opcodes, network flags and examples are not evidence that a protected contract call or mainnet exit works.

## 3. Architecture and module boundaries

The following module names and APIs are proposed additions, not files or commands that already exist in the upstream repository. Equivalent organization is acceptable if the responsibilities and evidence stay explicit.

```text
crates/
  cube-protocol/       canonical entries, manifests, state types, IDs, errors
  cube-model/          independent pure reference state transition model
  cube-contracts/      allowlisted template and real CubeVM integration
  cube-proof/          witness builder, Groth16 relation/prover/key handling
  cube-argo/           pinned Argo adapter, setup transcripts, evaluator
  cube-settlement/     reviewed graph descriptors, signing, tx validation
  cube-store/          journal, atomic acceptance, packages, nonce history
  cube-client/         participant checks, backup, normal/recovery operations
  cube-challenger/     independent scanner/evaluator/dispute broadcaster
  cube-regtest/        isolated Bitcoin-node integration and fault injection
```

Do not rewrite Cube into this layout before behavior warrants it. Start with modules around the current crate; separate crates where dependency or testing boundaries help. Keep cryptographic prototype code out of the funded default execution path.

### 3.1 Proposed typed interfaces

```rust
// Interface sketches; not compilable upstream APIs.
validate_entry(state, entry, authorization, frozen_config) -> CheckedEntry
execute_checked(state, checked_entry) -> TransitionDelta
derive_manifest(parent_anchor, state, delta, obligations, setup) -> Manifest
prepare_witness(state, checked_entry, delta, manifest) -> ExecutionWitness
prove_transition(proving_key, witness, expected_public_input) -> ProofBundle
verify_bundle(verifier_key, manifest, proof_bundle) -> VerificationResult
prepare_assertion(graph, setup, manifest, proof_bundle) -> BoundAssertion
evaluate_assertion(public_setup, assertion) -> Valid | DisproofEvidence | Error
validate_package(expected_entitlement, package, bitcoin_view) -> CheckedPackage
plan_recovery(checked_package, bitcoin_view, approved_fee_policy) -> RecoveryPlan
```

Validation errors are typed and deterministic. A failed proof, missing package or malformed message cannot mutate accepted balances. Separate parse, semantic validation, authorization, execution, package validation, signing and broadcast so fault injection can address each boundary.

### 3.2 Separate state from observations

Maintain three explicit categories:

- **Execution state:** committed balances, contract storage/phase, shadows, sequences and consumption.
- **Safety records:** signed authorizations, nonces, prepared commitments, predecessor/recovery packages and reservations; never casually rolled back.
- **Bitcoin observations:** mempool/chain status, block hashes, confirmations and maturity; can change under reorg.

This prevents a reorg from accidentally erasing the fact that a signature was already issued. The Engine and client must make the same distinction.

## 4. Work package P0: reproducible and isolated foundation

**Depends on:** no implementation assumptions.  
**Closes:** G0.

1. Preserve the original source checkout; create a separate development branch/worktree and record both baseline commits.
2. Inspect repository instructions and existing tests before execution. Use disposable paths for tests that erase or recreate databases.
3. Pin Rust/toolchain, Cargo lockfile, Bitcoin Core binary/container digest and operating environment. Record CPU architecture, cores and RAM for measurements.
4. Compile/check the unmodified baseline first where possible. Record pre-existing failures separately from changes introduced by this work.
5. Build a local regtest controller using a dedicated temporary datadir and RPC bound to loopback. Refuse to run against any chain other than regtest.
6. Create miner, Alice, Bob and Carol test wallets and independent Engine/challenger databases. Mature coinbase funds before using them. Give the challenger independent fee funds; it must not need participant signing secrets.
7. Define the initial bounded profile and golden serialization fixture directory.

Example node bootstrap, after installing a deliberately pinned Bitcoin Core build:

```bash
export CUBE_TEST_DATADIR="$(mktemp -d /tmp/cube-v1-regtest.XXXXXX)"
bitcoind -regtest -datadir="$CUBE_TEST_DATADIR" -daemon \
  -server=1 -listen=0 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1
bitcoin-cli -regtest -datadir="$CUBE_TEST_DATADIR" -rpcwait getblockchaininfo
bitcoin-cli -regtest -datadir="$CUBE_TEST_DATADIR" createwallet "miner"
bitcoin-cli -regtest -datadir="$CUBE_TEST_DATADIR" -rpcwallet=miner getnewaddress
```

Choose nonconflicting ports when running multiple nodes. Mine 101 blocks to the returned miner address before funding tests. Do not reuse a personal Bitcoin datadir or expose RPC externally. Exact wallet creation/descriptors must be covered by the harness version pin.

**Artifacts:** baseline report, environment lock, source digests, regtest config, empty test databases and basic funding/confirmation test logs.  
**Done when:** the same fresh environment reproduces the baseline and refuses non-regtest operation. No contract or Argo claim is yet made.

## 5. Work package P1: ownership and dispute graph design

**Depends on:** P0; can proceed alongside the pure model in P2.  
**Closes:** G1, GRAPH-01, BIND-01, SHADOW-EXIT-01 and the bounded part of PROJECTOR-01/CHAIN-01.

This is the highest-leverage design task. Do it before treating a proof demo as a protected BTC implementation.

### 5.1 Freeze the finite graph

For one vault and the three participant roles, enumerate each live entitlement before lifting, after allocation, after either redemption, after refresh and during recovery. Design the concrete successor/timeout tree and dispute branches for these states.

For each logical transaction in specification section 9, produce a descriptor with:

```text
transaction role and template version
exact inputs and their values / parent dependencies
output scripts, amounts, recipients and fee commitments
complete witness and control-block templates
required signers and when each signature is acquired
sighash, version, sequence and locktime
state/manifest/setup binding and label-disclosure obligations
conflicting transaction / spent output that prevents an invalid Take
remaining recovery route after each valid or adversarial action
relay requirements and permitted fee sponsorship/bumping
```

Model withholding of every Engine message. A participant must not authorize destruction of the only existing recovery path before a valid successor is secured. Distinguish a graph requiring the beneficiary to be online at creation from one supporting asynchronous receipt; do not promise both without implementation.

### 5.2 Decide how Projector is used

If retaining the whitepaper's Projector, implement its exact ordered key/value projection and compatibility with full transaction verification, MuSig2 nonce protection and the selected graph. A signer must not approve arbitrary transactions after checking only its inclusion or a value tweak.

If a simpler explicitly presigned graph is used for the finite regtest pilot, label it a scoped settlement adapter, state the architectural difference and prove participant-controlled recovery. It does not establish the general whitepaper Projector or hosted-box claims. Never add a custodial key-deletion committee silently.

### 5.3 Bind the malicious path

Demonstrate why an Engine cannot submit an otherwise valid proof for a different parent state, recipient, outpoint or instance and still spend the challenged output incorrectly. The actual assertion labels/public input and payout scripts must be bound on the enforceable path. Honest-wallet preflight checks alone do not prevent a malicious unilateral publication.

For the exit-ladder/Connector design, enumerate what transaction linkage proves and what canonical-chain verification still requires. If an interim regtest fixture trusts a harness checkpoint, record that assumption and keep CHAIN-01 open for the stronger profile.

**Artifacts:** raw/PSBT transaction fixtures, descriptor manifest, signing transcript rules, threat analysis, hashlock/label adapter design, maturity/conflict tests and recovery map for every entitlement.  
**Done when:** Bitcoin Core accepts the intended paths and rejects premature/unauthorized/conflicting ones; Alice, Bob and Carol each retain the specified recovery rights. An isolated collateral hashlock with no effect on the wrong payout fails this gate.

## 6. Work package P2: reference contract model and canonical schema

**Depends on:** P0.  
**Covers:** T-02–T-05, foundation for T-20.

Implement FixedSplitVaultV1 first as a pure reference model with no networking, database or Bitcoin RPC. Use checked integers, explicit immutable descriptors and complete rollback on error. This model must be simple enough to inspect independently of the existing CoinManager implementation.

### 6.1 Required transition tests

- Exact `100000 -> 69650 + 29850 + 500` fixture.
- Nondivisible distributable amounts; verify remainder belongs to Carol and no satoshi disappears.
- Reject `E >= G`, zero beneficiary shares, overflow, insufficient funds and unsupported dust/resource cases.
- Reject aliased participant keys in the initial profile, altered weights, second funding, second redemption and wrong caller.
- Compare Bob-first and Carol-first redemption; verify remaining beneficiary backing is unaffected.
- Retry identical operation IDs; reject conflicting payloads under one ID and stale caller sequences.
- Verify that a failed transition leaves the entire state byte-for-byte unchanged.

Instantiate the deterministic full-state serialization, manifest encoding, tagged hashes and sequence rules from the specification. Publish golden vectors for keys, outpoints, enum tags, bytes, signed messages, state digests and manifest/public-input mapping. Specify every bounded length before accepting untrusted messages.

**Artifacts:** reference state machine, schema registry, arithmetic vectors, rejection vectors and invariant checks.  
**Done when:** generated sequences preserve INV-01–INV-03/INV-06–INV-07/INV-10, and a second implementation can reproduce the serialized fixtures.

## 7. Work package P3: real CubeVM Call and Shadowing integration

**Depends on:** P2; settlement interfaces from P1.

### 7.1 Complete the execution entry path

Add explicit `Entry::Call` handling to `ExecCtx::execute_batch`; replace unsupported-input panics with deterministic rejection at the relevant boundary. Do not accept every existing opcode or deployment type merely because Call now dispatches.

Register one compiled allowlisted FixedSplitVaultV1 template. Freeze its executable hash, supported method indices, argument layouts and bounded operation budget. Unknown programs and unsupported methods are rejected. If instantiation uses the existing Deploy representation, restrict it to that exact template/hash; arbitrary deployment is not enabled.

Map the specification's `InstantiateSplit`, `FundSplit` and `RedeemShare` to actual executable methods and entry authorization. Record the mapping explicitly in the schema. Do not invent bytecode sequences from opcode names; inspect their real stack argument order and CoinManager behavior.

### 7.2 Implement atomic value movement

Complete the payable branch so Alice's debit, contract credit, fee credit and both allocations are one atomic transition. Review any existing balance-check TODOs or commented allocation writes. Validate every output and amount before signing; application-level balance checks are not authorization.

For allocations, use the existing per-account Shadow primitives where appropriate, with bound-checked amount/key arguments. Avoid proportional `_ALL` operations in the first template; exact 70/30 arithmetic and the remainder rule are explicit. On redemption, decrease the caller's shadow and contract balance and create one same-owner native successor obligation atomically.

Prevent reentrancy and internal calls by rejecting them in this profile. Freeze execution budget and failure behavior. Unsupported or failed calls cannot be silently dropped while their native debits or fees remain applied.

### 7.3 Differential evidence

For the same generated input, compare the pure model and actual CubeVM entry path: returned error, phase, balances, shadows, caller sequence and resulting canonical digest. Include randomized valid and invalid sequences and failure injection between individual internal changes. Only supported opcodes need to be proven, but every accepted opcode/branch needs explicit semantics.

**Artifacts:** template source/compiled executable, accepted method registry, Call integration, atomicity implementation, differential logs and malicious-call tests.  
**Done when:** actual accepted calls match the reference and produce the exact entitlement obligations expected by the graph/proof adapters. This demonstrates contract execution, not yet Bitcoin-enforced correctness.

## 8. Work package P4: real execution proofs

**Depends on:** P2/P3 and the statement obligations from P1.  
**Closes:** proof portion of G3 and CRYPTO-01.

### 8.1 Choose and pin the relation backend

Start with a direct bounded BN254 Groth16 relation because it matches the inspected Argo verifier. An arkworks-compatible implementation is a candidate; pin and test the actual library/prover versions rather than assuming all similarly named dependencies are compatible. A zkVM followed by recursive/compressed wrapping can be evaluated later; it adds a different proving pipeline and cannot be treated as already available.

Use one fixed relation covering instantiation, funding and full-share redemption with an action selector. Constrain inactive action branches and padding. Exposing one selector does not permit unconstrained branches or arbitrary bytecode. Freeze the template/circuit ID and verification-key digest before generating correctness evidence.

The witness builder collects actual prestate, entry, authorization and resulting state from the accepted execution path. The prover and independent verifier must reconstruct the expected public input from the same manifest. The circuit recomputes state/entry/manifest commitments, transition semantics and integer constraints.

### 8.2 Authorization and foreign-field work

BIP-340 authorization inside a BN254 relation is not supplied by Argo. Implement/reuse a reviewed gadget with exact secp256k1, x-only parity, scalar/range, challenge-hash and signature-verification behavior, or document and prove an equivalent authorization mechanism enforced by the concrete Bitcoin graph. Do not pass `signature_valid = true` from Rust as an unconstrained witness.

Benchmark this work explicitly; a tiny state transition does not imply a tiny SHA256/signature circuit. Do not introduce an alternate application key scheme without updating the protocol, recovery identity mapping and review. Check BLS coexistence separately if retained Cube infrastructure still depends on it.

### 8.3 Setup and verifier conversion

Distinguish development deterministic fixtures from production randomness. Create the actual Groth16 proving/verifying key using the fixed relation. A test key generated in a single local process may be useful for regtest, but is labeled trusted test setup until the required participant-scoped setup procedure is implemented and reviewed.

Convert the real Groth16 verifier key into Argo's equation form with an independently checked adapter: the single public scalar contribution becomes the expected G1 linear term, fixed input terms enter the verifier constant, and pairing signs/order must match. Compare ordinary Groth16 verification and Argo's underlying equation on valid and mutated proofs. Do not select a new constant to make a random tuple verify and call that an execution proof.

The initial public-input compression proposal must be tested for exact byte order, quotient/range handling and manifest reconstruction. Record its security assessment; if a multi-input verifier replaces it, update the Argo adapter, serialization, circuit ID and tests together.

### 8.4 Proof-negative cases

Test altered beneficiary/amount, changed fee, wrong state root, wrong input anchor, wrong network and stale operation. Include valid proofs generated for another manifest; these are essential tests of binding rather than pairing invalidity. Corrupt proofs for the real manifest and verify rejection. Attempt invalid state transitions with the honest prover and confirm no accepted proof is generated.

Separate two failure classes: malformed/invalid proofs and valid proofs of an incorrectly specified relation. Argo addresses verifier invalidity; independent relation review and model equivalence address circuit bugs.

**Artifacts:** relation source, compiler/dependency lock, proving/verifying-key fingerprints, setup transcripts/assumptions, real proof fixtures, conversion vectors, witness constraints inventory and proving measurements.  
**Done when:** T-06/T-07/T-20 pass with actual supported execution and a fixed verifier. Host-verified-only authorization or an unresolved public-input adapter keeps CRYPTO-01 open.

## 9. Work package P5: Argo integration and hardening

**Depends on:** P4 for real proofs; standalone adapter tests may start earlier.  
**Closes:** garbling/setup portion of G3.

### 9.1 Pin and reproduce upstream behavior

Vendor or pin the inspected source revision; record any local patches and preserve its license. First inspect upstream test side effects and build constraints. In the isolated checkout, run the README's `cargo test --release` and relevant benchmarks. Capture actual hardware and command outputs; a pass at one seed is not a security audit.

Build an adapter separating Cube manifests and canonical bytes from Argo's field/curve representation. Test ordinary valid proofs, invalid proofs, serialization, evaluator independence and regenerated setup instances. Match actual code parameters rather than replacing them with paper parameters without analysis.

### 9.2 Required source concerns

| Concern | Implementation action | Regression evidence |
|---|---|---|
| Global preprocessed verifier cache | Make preprocessing instance-owned or key by the relevant complete verifier-key identity; address concurrent generation | Interleave two distinct keys and concurrent tasks; neither uses the other's precomputation |
| Input-validity result discarded | Propagate the extracted evidence correctly through the public evaluator and assertion adapter | Malformed coordinate/curve/subgroup cases reach the intended full dispute outcome |
| u64-seeded convenience API | Use a full-entropy cryptographic RNG for deployed setup; isolate deterministic test-only constructors | Repeated fixture generation is explicit; production entry points cannot silently use fixture seeds |
| Secret encoding / success sentinel | Define canonical secret bytes, commitment and nonzero/success discrimination | Valid result, extracted secret, wrong secret and malformed bytes are not confused |
| One-time material reuse | Enforce instance lifecycle and durable retirement rules | Restart/retry cannot expose a second incompatible label set under one instance |

Treat zero as reserved if the selected API uses zero to represent no disclosure; production setup must reject zero secrets under that convention. The Bitcoin adapter checks the exact canonical secret commitment rather than interpreting any nonzero output as valid evidence.

The input-validity issue is a correctness/composition concern observed in source, not a claimed exploit. Implement a reproducer before changing behavior, and validate the changed result against the actual cryptographic contract.

### 9.3 Implement adaptive and malicious security

Select the required projective encoding and encrypted-material adaptive transformation. Record what is encrypted, which key is revealed at assertion, how its digest is authenticated and how all decoders reconstruct identical material.

Implement the selected malicious-security setup. If Mosaic is used, freeze its source/version, transcript checks, number of instances and cut-and-choose parameters, authenticated correlation/signature procedures and malformed-message behavior. Do not choose a repetition count solely because a small number is convenient. Statistical/computational security targets require explicit analysis; label reduced-security fixtures as such.

Require each protected participant's setup verification according to the selected trust model. Corrupt one table, alter commitments, withhold material, equivocate labels, reuse IDs and interrupt setup. An incomplete setup cannot authorize dependent funding.

**Artifacts:** adapter, upstream patch set, regression tests, setup transcript format, instance registry, serialized material measurements and independent evaluator logs.  
**Done when:** T-08–T-10 pass under the documented setup assumptions, and different-key/malformed-input paths are covered. An honest-setup microbenchmark is labeled as a microbenchmark, not the complete protocol.

## 10. Work package P6: Bitcoin assertion, dispute and recovery integration

**Depends on:** reviewed P1 graph plus P4/P5.

### 10.1 Wire actual transactions

Implement the graph's transaction builders, signature checks, maturity calculations and package validators. Integrate LiftV2 or the explicitly selected recoverable deposit path. Implement every required parent/branch/leaf/Projector witness; do not bypass unsupported branches through hardcoded Engine-only signatures.

Check all inputs/outputs, fee bounds, sighashes, scripts and relevant commitments before participant signing. Persist the complete signing session and consumed nonces. Refuse to release a funding authorization if required successor protection is missing.

Integrate the actual BitVM3-style input-label authentication/disclosure adapter with Argo. Its correctness is a required implementation artifact: a proof object and a table in local memory do not supply Bitcoin-authenticated proof bits automatically.

### 10.2 Demonstrate the malicious path

Submit an invalid proof through an assertion that follows the actual input-label commitment rules. An independent challenger obtains the material, recovers the committed evidence, constructs the real `Disprove` and confirms it. Attempt the competing invalid `Take` and record why Bitcoin rejects or conflicts it. Then recover the rightful entitlement to the correct participant output.

Repeat with a valid proof for an incorrect manifest. The adapter must prevent the wrong payout through actual binding, not by allowing the test controller to veto it. Test withheld labels/setup data under the graph's specified timeout/recovery response.

An actual node may reject an invalid transaction for a simple script/signature reason before Argo is involved. That is useful coverage but does not demonstrate Argo-based dispute enforcement. Test evidence must identify which mechanism rejected which attempted spend.

### 10.3 Exercise contract-held allocations

Stop the Engine after allocation while neither recipient has redeemed. Bob must independently recover only his share, with Carol's claim still protected. Run Carol's recovery as well. Repeat after Bob has redeemed to a native successor, after a refresh and during an interrupted cooperative withdrawal.

Reconcile old/new claim consumption, proof-instance retention and fee sources. Ensure no release path enables Alice or the Engine to take beneficiary principal. Recovery must not require the original contract method to execute cooperatively after the Engine is gone.

**Artifacts:** actual raw transactions/PSBTs, script and mempool-validation results, block inclusion evidence, invalid-Take conflict evidence, final output ownership/value checks and multi-recipient recovery transcript.  
**Done when:** T-11–T-13 pass and GRAPH-01/BIND-01/SHADOW-EXIT-01 are closed for the bounded profile. A missing concrete transaction branch remains a failed milestone, not an assumed implementation detail.

## 11. Work package P7: durable wallet, Engine and independent challenger

**Depends on:** P3 and graph/package schemas; complete integration uses P6.

### 11.1 Persist recoverable state

Implement a single atomic store or a documented write-ahead journal around the existing managers. Store operation ID, original canonical request, reservations, sequence/nonce history, expected parent, prepared graph, proof/setup IDs and package completeness before issuing dependent acknowledgements/signatures.

The accepted-state transaction must atomically include balance/storage changes and package inventory, or journal enough information to reconcile each partial boundary without conflicting authorizations. An async function performing several writes is not itself an atomic transaction.

Suggested records:

| Record | Important contents |
|---|---|
| `operations` | Immutable request digest, actor, state, reservations, response/evidence references |
| `authorizations` | Sequence, signed digest, nonce/session ID, consumed status |
| `claims` | Entitlement ID, predecessor/successor, owner/value, backend and discharge state |
| `packages` | Content digests, local availability, exact schema/version and integrity state |
| `setup_instances` | Key/table/secret commitments, verified participants, lifecycle and retention deadline |
| `chain_observations` | Tx/block hashes, depth, conflicts and graph-node maturity |
| `acceptance_journal` | Prepared/applied/acknowledged markers and deterministic reconciliation inputs |

These are proposed record types, not a mandatory choice of SQL versus Sled. Use one clear consistency model and prove crash behavior.

### 11.2 Recovery and backup UX

Provide CLI-first participant workflows before building elaborate UI. Distinguish deposit pending, authorized, proof-checked, challenge pending, settled, refresh needed, disputed, recovering and recovered. Display actual recipient, amount, fees, network and deadlines before signing.

Export encrypted, versioned recovery packages and verify them by restoring to a clean process. Validate every downloaded artifact by digest and semantic context. A missing artifact blocks dependent finalization; an Engine receipt does not fill the gap. Keep private keys, nonces and disclosure secrets out of diagnostics.

### 11.3 Independent challenger

Run a separate process with its own Bitcoin connection, fee wallet and public challenge data. It watches bound assertions and their deadlines, verifies setup/artifact identity, evaluates proofs and submits disputes. It must work after the Engine's network endpoint and disk are unavailable.

Record retrieval, decoding, evaluation, construction and confirmation latencies separately. Alert before a configured safety margin is exhausted. Do not claim an online monitoring obligation is removed because the evaluator is permissionless.

### 11.4 Data availability and chain handling

Implement the selected batch publication protocol and identify its exact data bytes. If early tests distribute blobs locally, label that mode explicitly; it does not establish Bitcoin DA. Add an acceptance test that removes the Engine and proves the required material is still obtainable.

On reorg, compare block identity as well as height; handle same-height replacement. Reconcile spent parents, unconfirmed children, reverted settlements and open disputes. Preserve all historical signing/replay safety records. If chain attestation is outside the current prototype, keep the stronger profile blocked rather than trusting a harness assertion silently.

**Artifacts:** durable journal/store, restart reconciler, package exporter/importer, independent monitor and backup/restore evidence.  
**Done when:** T-14/T-15/T-17/T-19 pass, no required recovery depends on Engine-only state, and DA-01 is closed for the declared availability profile.

## 12. Work package P8: complete deterministic regtest demonstration

**Depends on:** P1–P7.  
**Closes:** G4.

Run each scenario from fresh controlled state. Planned scenario names below are test-harness targets to implement; they are not existing Cube CLI commands.

| Scenario | Required steps and output |
|---|---|
| `baseline_journey` | Fund/refund test; lift; ordinary recipient payment; refresh; swapout; correct final BTC outputs |
| `split_happy` | Instantiate; fund 100000/500; assert/protect transition; Bob and Carol redeem in both orders; withdraw |
| `split_rounding` | Generated supported amounts, including nondivisible D; exact remainder and no lost sats |
| `invalid_assertion` | Authentic invalid assertion; independent Argo evaluation; confirmed dispute; wrong Take blocked; correct BTC recovery |
| `valid_wrong_context` | Proof verifies for another manifest; malicious adapter attempt cannot release incorrect funds |
| `engine_loss_allocated` | Kill Engine and data service; independently recover Bob/Carol directly from remaining shadows |
| `engine_loss_native` | Recover ordinary recipient and redeemed successor claims after total Engine loss |
| `crash_matrix` | Inject crashes at every selected persistence/signing/broadcast boundary; restart and reconcile |
| `chain_races` | Reorg, same-height replacement, competing recovery, deadline boundaries and stale fork attempts |
| `restore_all` | Restore on a clean replacement client with original client/Engine unavailable; recover confirmed outputs |
| `resource_pressure` | Fee scenarios, supported concurrent disputes, bounded data and admission failures |

### 12.1 Exact example checkpoints

1. Alice's eligible native principal is 100000 sats; network fee reserves are separately tracked.
2. After settled funding: contract 99500, Bob shadow 69650, Carol shadow 29850, F native 500; Alice's debited principal is zero.
3. After Bob's settled redemption: Bob native 69650, contract/Carol shadow 29850, Bob shadow zero.
4. After Carol's settled redemption: contract/shadows zero, Bob native 69650, Carol native 29850 and F native 500.
5. After authorized network fees and final withdrawals/recovery: check actual output values and reconcile the same principal, without double-counting shadows or fee reserves.

Always inspect real outpoints and ownership; the ledger checkpoint alone cannot pass recovery acceptance.

### 12.2 Boundary and resource matrices

Exercise maturity one block before, at the Core-defined boundary and after it. Reuse the exact block-based fixture values from the specification and record parent confirmation heights. Test overlapping refresh, redemption and exit with all supported race orders.

Measure costs per path and per protected participant. Withhold artifacts, corrupt backups, return mismatched proof/table/key IDs, duplicate messages, exceed resource bounds and consume fee funds. A recovery failure must identify the exact remaining safe action instead of marking value settled or disappearing.

### 12.3 Proposed evidence directory

```text
evidence/<release-config-digest>/<scenario-id>/
  environment.json
  configuration.json
  source-lock.json
  events.jsonl
  expected-state.json
  observed-state.json
  manifest.json
  proof-public.json
  transactions.json
  bitcoin-validation.json
  measurements.json
  result.json
```

Private witness/key/setup secrets belong in protected fixture storage, not this diagnostic directory. Evidence records digests/references where publication would expose secrets. Include actual commands, transaction hex, block hashes and assertion/dispute linkage sufficient for independent replay, subject to the declared data model.

**Done when:** all applicable T-01–T-20 pass reproducibly, each failed-gate item is resolved or the profile remains incomplete, and a fresh operator can run the scenarios from documented setup. No test result is pre-filled as passing.

## 13. Work package P9: Signet, review and mainnet preparation

**Depends on:** G4.  
**Closes:** G5/G6 only with actual evidence.

1. Move the same frozen logic to Signet with distinct keys, data paths and configuration. Remove regtest-only shortcuts and reduced-security setup fixtures before claiming the production profile.
2. Validate ordinary relay and fee-bumping behavior through independent nodes, not only direct controlled mining. Measure outages and artifact distribution.
3. Specify mainnet chain-verification/attestation and difficulty assumptions. Public-network tests do not prove censorship resistance or worst-case inclusion bounds.
4. Freeze full setup trust, public-input binding, script graph, signing obligations, DA and multi-recipient exit semantics for independent review.
5. Review the executor/circuit equivalence, native/BIP-340 integration, Argo adapter and modifications, malicious-security setup and operational custody composition.
6. Resolve findings and rerun affected tests. Freeze all quantitative limits from measurements: amounts, dust, claims, graph depth, instance retention, concurrent exits, fees, collateral/liquidity, memory and data sizes.
7. Publish monitoring, backup, incident, admission-pause, legacy recovery and upgrade procedures. Use measured exposure limits; no staffing, budget, calendar or launch-date promise is implied.
8. Keep mainnet deposits disabled until G6 passes for the exact release. A verified payment-only profile and an Argo-enabled profile have different evidence requirements and must be identifiable by configuration.

## 14. Measurements and acceptance record

### 14.1 Required measurements

| Area | Record |
|---|---|
| Prover | Circuit/constraint size, setup/proof time, proof size, peak memory, signature/hash contribution |
| Argo | Per-instance and complete setup time, serialized table/material size, evaluation, CPU/RAM and parallelism |
| Storage | Setup copies, outstanding claims, retained versions, package/witness bytes and garbage-collection safety |
| Network | Material distribution/retrieval, cold restore, monitor lag and retry behavior |
| Bitcoin | Every transaction's weight/vsize, complete path dependencies, fee rate and approved fee-bump behavior |
| Economics | Execution fees, network fees, challenger reserves, locked capital and operator liquidity separately |
| Recovery | Required broadcasts, maturity and confirmation conditions, value reaching the intended owner |
| Failure | Expected/observed rejection mechanism, remaining entitlement and recovery evidence |

Do not substitute paper figures for these measurements. Do not quote a standalone disproof size as the total recovery cost. Different fee scenarios are test inputs, not predictions of future Bitcoin fees.

### 14.2 Requirement traceability

| Work | Specification coverage | Main test IDs |
|---|---|---|
| P0 | Profiles, provenance, bounded config | Environment portion of every test |
| P1 | §§2, 9, 15 and INV-04/05/08/09/12 | T-07/T-11–T-13/T-15/T-16 |
| P2 | §§3, 5, 6 | T-02–T-05/T-20 |
| P3 | §§3–6 and execution relation | T-02–T-05/T-14/T-20 |
| P4 | §7 and CRYPTO-01 | T-06/T-07/T-20 |
| P5 | §8 | T-08–T-10/T-18 |
| P6 | §9 and complete BTC enforcement | T-01/T-07/T-11–T-13/T-16 |
| P7 | §§10–11 | T-12/T-14/T-15/T-17/T-19 |
| P8 | §§12–14 | All T-01–T-20 |
| P9 | G5/G6 and all remaining open decisions | Public-network/review evidence and affected regressions |

The release acceptance record should list each requirement, exact implementation revision, test evidence, review status and unresolved issue. A source file's existence is not a passing criterion. Any substitution of a mock, trusted harness oracle or manual signature must be visible in the profile and cannot close a stronger gate.

## 15. Second pilot implementation: fixed hashlocked/refundable escrow

**The next pilot after FixedSplitVaultV1 is a fixed hashlocked/refundable escrow, named FixedHashlockEscrowV1.** Include it in the v1 development plan as the second regtest profile after the splitter passes G4. Specification section 16 defines its behavior, EUSD stories and E-T tests.

### 15.1 E1: reference model and conditional recovery graph

Freeze Alice/Bob identities, SHA256 of exactly 32 secret bytes, absolute block-height refund condition, G/E/P, instance sequence and approved fees before funding. Build the pure model for InstantiateEscrow, FundEscrow, ClaimEscrow, RefundEscrow and RedeemEscrow, with EMPTY/OPEN/CLAIMED/REFUNDED/CLOSED states and atomic rejection.

Add a versioned conditional entitlement descriptor and concrete graph. OPEN principal must not appear as two independently spendable shadows or an unprotected Engine balance. Both outcomes consume/conflict over the same principal. Design Bob's authorized preimage claim and Alice's mature refund, stale-state invalidation, safe signing order and complete independent recovery packages.

Use the specified race semantics: refund maturity enables Alice's branch without automatically disabling Bob's branch. Freeze exact locktime type, nLockTime, sequence and canonical settlement rules; do not use Engine wall-clock time or first API receipt as final arbitration.

**Deliverables:** model, schema/vectors, claim/refund descriptors, conditional accounting and timing/conflict analysis. **Gate:** E-G1 requires actual Bitcoin-node evidence; unresolved graph or conditional-ownership work stays explicit.

### 15.2 E2: CubeVM and real proof relation

Register a new exact allowlisted escrow template. Implement atomic funding and one funding fee, Bob-authenticated correct-preimage claim, Alice-authenticated mature refund and same-owner redemption. Separate pending requests from settled outcomes and retain replay/rollback safety records.

Create a new circuit/verifier version. Constrain SHA256 computation and exact preimage length, BIP-340 authorization, terms, phase, sequences, state roots, amounts and payout obligations. Establish maturity through the reviewed relation/Bitcoin graph composition, not an unconstrained current_height witness.

Generate actual escrow execution proofs and run reference-model/VM/witness differential tests. A proof for the splitter or another escrow cannot authorize this instance. Verify ordinary Groth16 and Argo equation conversion against the same fixed key and manifest.

**Deliverables:** compiled template/method registry, circuit/witness source, fixed-key fixtures and negative vectors. **Gate:** execution/proof portion of E-G2.

### 15.3 E3: Argo and independent outcome recovery

Create fresh garbling/setup instances for the new relation, retaining the selected adaptive/malicious-security construction. Bind escrow ID, hash, height, parties, principal, parent anchor and exact outcome to assertion labels and payout paths.

Keep Bob's application preimage, Argo invalidity-disclosure secret and adaptive-material key distinct. Treat preimage publication as an irreversible information exposure, including unconfirmed or later-reorganized transactions. Persist exposure history across restart; UI cancellation cannot restore secrecy.

Demonstrate an independent challenger defeating an invalid escrow assertion through the real Bitcoin graph, followed by the rightful recovery outcome. Separately restore Bob's conditional-claim and Alice's mature-refund packages with the Engine/data endpoint and original device unavailable.

A standalone ordinary Bitcoin HTLC can be a control test; it does not demonstrate the CubeVM/proof/Argo integration.

**Deliverables:** setup/assertion/dispute transcripts, complete packages and node-verified payout/recovery paths. **Gate:** complete E-G2.

### 15.4 E4: integrated regtest scenarios

| Scenario | Acceptance focus |
|---|---|
| escrow_claim | Real funding, correct preimage/Bob authorization and final beneficiary BTC: E-T01 |
| escrow_bad_claim | Wrong secret/length/key, changed terms, duplicate funding and replay rejection: E-T02 |
| escrow_refund_boundary | Premature rejection and exact Core-defined maturity behavior: E-T03 |
| escrow_race | Both post-maturity claim/refund orders, one principal and one outcome: E-T04 |
| escrow_engine_loss | Independent claim and mature refund in fresh runs, with restoration: E-T05 |
| escrow_invalid_assertion | Actual execution proof, invalid/context-substitution assertions, real Argo dispute: E-T06 |
| escrow_reorg_crash | Reorg, restart after preimage exposure and stale claims cannot double-spend: E-T07 |
| escrow_data_fees | Withheld/corrupt packages, setup mismatch and insufficient/escalating fees: E-T08 |

Use deterministic secrets only in disposable fixtures; real application preimages require appropriate entropy and protected retention until disclosure. Derive a test refund height from a recorded regtest anchor plus a documented gap accommodating the complete settlement/dispute schedule. Record both heights, and never copy a bare test height to another network.

Extend evidence records with escrow ID, hash identifier, refund height, exposure status and winning outcome. Keep undisclosed preimages out of normal diagnostics. Repeat EUSD-01–EUSD-06 and affected signing, backup, crash, fee and version tests.

**Gate:** E-G3 requires E-T01–E-T08 and affected baseline regressions. Signet and independent review must cover the escrow's graph, conditional ownership and timing before that profile is enabled with funded mainnet.

### 15.5 Sequencing and traceability

| Work | Specification coverage | Evidence |
|---|---|---|
| E1 | §§16.1–16.3 | E-G1, pure model and actual conditional graph |
| E2 | §§16.2–16.4 | Real VM/proof equivalence and execution vectors |
| E3 | §16.4 and core §§7–11 | E-G2, bound Argo and independent outcome recovery |
| E4 | §§16.5–16.6 | E-G3, EUSD-01–EUSD-06, E-T01–E-T08 and affected regressions |

These gates do not change the splitter's P0–P9 acceptance results. They add a distinct second-pilot evidence record. AMMs, arbitrary deployment, lending and oracle-dependent programs remain outside this expansion.

## 16. Immediate implementation sequence

Start P0 and the independent model P2, while doing the concrete graph design P1. Then integrate real CubeVM calls P3, build the actual relation P4 and harden/integrate Argo P5. Only join those parts into the protected Bitcoin workflow P6 after their interfaces and assumptions agree. Complete durable recovery/monitoring P7 and run the adversarial suite P8 before Signet/review P9.

The earliest useful review checkpoint is the graph and reference model, not a new UI. The decisive PoC result is: **a real Cube contract transition is proven, its invalid alternative is defeated on Bitcoin, and both beneficiaries can recover their correct shares after Engine loss.**

## 17. Source references and limits

Use the full source register in [specification.md](specification.md#17-sources-and-provenance). Relevant pinned implementation links:

- [Cube batch executor](https://github.com/cube-btc/cube/blob/6dd4a09a3b6bcc7759110a4dc5e666aca1ae1938/src/executive/exec_ctx/exec_ctx.rs)
- [Cube program executor](https://github.com/cube-btc/cube/blob/6dd4a09a3b6bcc7759110a4dc5e666aca1ae1938/src/executive/vm/program_execution/exec.rs)
- [CoinManager](https://github.com/cube-btc/cube/blob/6dd4a09a3b6bcc7759110a4dc5e666aca1ae1938/src/inscriptive/coin_manager/coin_manager.rs)
- [Signed batch construction](https://github.com/cube-btc/cube/blob/6dd4a09a3b6bcc7759110a4dc5e666aca1ae1938/src/constructive/bitcoiny/batch_txn/signed_batch_txn/signed_batch_txn.rs)
- [Engine session pool](https://github.com/cube-btc/cube/blob/6dd4a09a3b6bcc7759110a4dc5e666aca1ae1938/src/operative/tasks/engine_session/session_pool/session_pool.rs)
- [Argo verifier](https://github.com/idealgroup/argo/blob/aa28ba884f9af3d41265774a882d4efd9f4d9b95/src/garble/groth16_verifier/mod.rs)
- [Argo input-validity component](https://github.com/idealgroup/argo/blob/aa28ba884f9af3d41265774a882d4efd9f4d9b95/src/garble/groth16_verifier/input_validity.rs)

This document is an implementation plan. No repository changes, Rust/Bitcoin integration tests, proofs, benchmark runs or mainnet deployment were performed to author it. File consistency and illustrative arithmetic can be checked separately without implying those implementation tests passed.
