# Cube v1 end-to-end regtest runbook

This document is the sequential acceptance run for everything the repository can exercise against
a real Bitcoin Core regtest node, plus the in-process suites for the parts the node cannot see.

Two commands reproduce the whole document:

```sh
./scripts/regtest.sh cli   # the seven Bitcoin-graph scenarios (about 3 minutes)
./scripts/regtest.sh all   # the node-backed test files plus the release proof test
```

The sections below are the long form: every stage, the exact commands, the values to expect, and
the negative cases. Run them in order against one fresh chain; each stage uses its own state file so
a failure does not poison the next one.

---

## 0. Scope: the Engine, this test driver, and what is still missing

**The Engine is implemented in this repository.** `src/operative` starts the runner, the session
pool and the managers. `SessionPool::exec_deploy_in_pool`, `exec_liftup_in_pool`,
`exec_call_in_pool` and `exec_move_in_pool` admit BLS-signed entries; `ExecCtx::execute_batch`
executes the CubeVM; the managers own balances, registry, contract state, privileges, flame and the
graveyard; `BatchContainer` carries an aggregate-signed batch towards Bitcoin.
`tests/split_vault_template.rs`, `tests/call_entry.rs` and `tests/simul.rs` drive that production
admission path, not a test-only shim: the template is registered, then funded, redeemed and
rejected through `exec_call_in_pool`, and `simul.rs` runs a liftup through `exec_liftup_in_pool`
and executes the resulting batch container.

**`cube-cli` is a test driver for the Bitcoin ownership graph, and it now also boots the Engine's
execution components in-process for the composed run.** It does not boot `runner::run`, because
that runtime is an interactive operator process with chain sync, a key holder and a run
configuration. Printing "the CLI does not start an Engine session" therefore says nothing about
whether the Engine exists; it only says which runtime this driver starts. `scenario run engine-e2e`
boots the managers and the session pool, executes `fund_split` through `exec_call_in_pool`, and
continues into the Bitcoin graph.

The table is deliberately blunt.

| Area | Exercised by | Status |
|---|---|---|
| LiftV2 deposit, refund boundary, MuSig2 key path | CLI stages 2 and 10, `liftv2_regtest` | implemented, regtested |
| Split transition and manifest derivation | CLI stage 3, `fixed_split_vault`, `transition_manifest` | implemented, regtested |
| Successor funding with two v2 claims | CLI stage 4, `liftv2_regtest` | implemented, regtested |
| Claim recovery without the Engine | CLI stage 7, `liftv2_regtest` | implemented, regtested |
| Cooperative settlement of the whole tree | CLI stage 6, `cooperative_settle_regtest` | implemented, regtested |
| `Assert`, `Take`, `Disprove` | CLI stages 8 and 9 | implemented, regtested |
| A real Groth16 proof evaluated by Argo's table | `tests/proof_take_regtest.rs` (release, ignored) | implemented, regtested |
| Cheating operator/Engine attempts | `scenario run engine-cheat` | implemented, regtested |
| Engine unavailable before the successor | `scenario run engine-offline` | implemented, regtested |
| CubeVM contract execution (template, entry, call) | `fixed_split_vault`, `split_vault_template`, `call_entry` | implemented, in-process suite |
| State manager persistence and garbage collection | `state_manager`, `graveyard` | implemented, in-process suite |
| Batch atomicity and rollback | `batch_atomicity` | implemented, in-process suite |
| **VM state -> manifest -> Bitcoin settlement in one run** | `scenario run engine-e2e` | implemented, regtested (Engine fees excluded from the canonical ledger) |
| **Per-step Bitcoin cost visibility** | `cost` in `assert`/`take`/`disprove`/`recover`/`refund` | implemented |
| **VM-derived manifest -> real Groth16 proof -> Argo -> Bitcoin** | `tests/engine_proof.rs` (`--features proof`, release) | implemented, regtested |
| **Engine-scanned LiftV2 outputs** | `V2_LIFT_ENABLED = true`, `tests/liftv2_scan.rs` | implemented, scan tested |
| V2 liftup through the interactive node CLI | none | **not rehearsed** |
| BIP-340 inside the proof relation | none | **not implemented** (`BIND-01`) |
| Unilateral operator assertion without the beneficiary | none | **not implemented** (`BIND-01`) |
| Data availability of the table and authenticated input | none | **commitments only** (`DA-01`) |
| Crash during `apply_changes`, restart reconciliation | `tests/commit_recovery.rs` | implemented, in-process suite |
| Reorg below the finalized tip | `sync_manager` unit tests; chain sync halt | implemented (halt, not rollback) |
| Fee policy from a fee rate | `--fee-rate` on `assert`/`take`/`disprove`/`recover`/`refund`/`settle` | implemented, vsize-derived |

### What the composed run settles, and what is still open

`scenario run engine-e2e` closes the value path:

1. it boots the same managers and session pool the node uses;
2. it executes `fund_split` through `exec_call_in_pool` with the protocol's default entry fees;
3. it reads the owner and fee balances, the contract balance, both shadows and the phase back from
   the managers;
4. it checks every value against the reference model and aborts on a one-satoshi disagreement;
5. it derives the manifest from that VM state (`transition::from_vm`) and records the execution in
   the artifact;
6. it publishes the successor and settles both claims on Bitcoin.

A second, release-only test closes the cryptographic composition:
`tests/engine_proof.rs` proves the VM-derived manifest with Groth16, evaluates the real proof
through Argo's garbled table, binds the authenticated input and table digests into the assertion
terms, and takes the claim on Bitcoin. It lives behind the `proof` feature so the default CLI build
does not link the proving stack.

What is still open:

- **The canonical-state adapter.** `SplitState`'s contract identity and caller sequences are graph
  metadata; the template does not write them. The state digests therefore combine VM values with
  model identity and sequence fields.
- **Entry fees are excluded by definition.** The canonical ledger starts after the Engine's call
  fee: the VM's raw owner balance includes it, the state handed to the circuit does not. That is
  the documented boundary, not a zero-fee fixture. If the specification wants Engine fees inside
  the committed state, it is a schema and circuit change.
- **V2 liftup through the node CLI.** The scan switch is on and the scan is tested, but the
  interactive `liftup` path has not been rehearsed end to end against the node CLI. Every scenario
  still funds the deposit externally.

These are representation and harness tasks on top of implemented components.

### The genuine research and operational gaps

- **The participant-scoped assertion is signed by the beneficiary.** `Take` and `Disprove` are
  real, but an operator cannot publish an `Assert` alone. A stronger unilateral profile needs a
  public input-label opening Argo does not expose; see `docs/bind_01.md` (`BIND-01`).
- **In-circuit BIP-340** is not implemented; authorization is graph-enforced (specification §8.2).
- **Data availability** of the table and the authenticated input is not implemented; the chain
  carries commitments only (`DA-01`).
- **Production setup, admission limits and reorg healing** are open. A reorg below the
  finalized tip halts the runtime instead of un-applying committed Cube batches.

Everything in stages 1–11 is executed by the CLI against Bitcoin Core. Nothing is a paper claim.

---

## 1. Setup

Requirements: Docker Desktop running, a Rust toolchain, `jq`.

```sh
cd /path/to/cube
./scripts/regtest.sh up

export CUBE_REGTEST_RPC_URL=http://127.0.0.1:18443
export CUBE_REGTEST_RPC_USER=cube
export CUBE_REGTEST_RPC_PASSWORD=cube

mkdir -p target/e2e

cube() { cargo run -q -p cube-cli -- "$@"; }
btc() {
  docker compose -p cube-regtest -f docker/regtest/docker-compose.yml exec -T bitcoind \
    bitcoin-cli -regtest -rpcuser=cube -rpcpassword=cube "$@"
}
```

`cube` prints one JSON object per command on stdout. Progress and errors go to stderr. Read-only
commands work without a node; everything that touches the chain needs the three environment
variables above.

`./scripts/regtest.sh up` recreates the volume, so every run starts at height 0 with a full subsidy.
That matters: regtest halves the subsidy every 150 blocks, and stages 9–10 mine about 26,000 blocks
between them.

Fixture amounts used throughout (5,000,000,000 sats are mined to the wallet):

| Value | Sats |
|---|---|
| deposit | 500,000 |
| successor miner fee (reserve) | 2,000 |
| gross split | 498,000 |
| execution fee | 5,000 |
| Bob's claim (70% of 493,000) | 345,100 |
| Carol's claim (remainder) | 147,900 |

Stop the node when finished:

```sh
./scripts/regtest.sh down
```

---

## 2. Stage 1 — Fixtures and node health

```sh
cube keys | jq -e '.keys | length == 6'
cube keys | jq -r '.deposit_address'
cube node status
```

Expected: six fixtures, the deposit address `bcrt1p0gqa5tu3uw0l2tlakmymyuyzp5ztpj9kac3gk92z67aq954gt4gsu26qxk`,
height 101, balance 5,000,000,000 sats. The deposit address is the LiftV2 taproot: a MuSig2
aggregate of Alice and the Engine as the key path, and Alice after a 12,960-block CSV as the script
path. Alice cannot move it alone before the timelock; the Engine cannot move it at all without Alice.

The keys are public test fixtures and the CLI is regtest-only.

---

## 3. Stage 2 — Onboarding: fund the LiftV2 deposit

```sh
cube --state target/e2e/deposit.json deposit fund --sats 500000 \
  | jq -e '.value_sats == 500000 and .refund_delay_blocks == 12960'

cube --state target/e2e/deposit.json deposit verify \
  | jq -e '.verified == true and .funding_unspent == true'

cube --state target/e2e/deposit.json deposit show | jq '{address, funding_txid, funding_vout, value_sats}'
```

What this proves:

- the funded script is the taproot the fixture keys define, not an address the CLI invented;
- the output exists at the recorded outpoint with exactly the recorded value;
- the outpoint is confirmed and unspent.

Independent check with the node itself:

```sh
TXID=$(cube --state target/e2e/deposit.json deposit show | jq -r '.funding_txid')
VOUT=$(cube --state target/e2e/deposit.json deposit show | jq -r '.funding_vout')
btc gettxout "$TXID" "$VOUT" | jq -e '.value == 0.005'
```

### Negative: a deposit that cannot fund the successor

```sh
cube --state target/e2e/tiny.json deposit fund --sats 1000 >/dev/null
cube --state target/e2e/tiny.json transition build
```

Expected error: `the network fee reserve exceeds the deposit`. The successor must leave a 2,000-sat
miner fee, so a 1,000-sat deposit is rejected before any manifest is derived.

This stage does **not** create a Cube root account or run a liftup. That is a CubeVM entry path,
covered in stage 13; the CLI begins at the Bitcoin ownership layer.

---

## 4. Stage 3 — Contract state: derive and verify the transition

The manifest is not authored by hand. The CLI runs the reference model (`SplitVault`), then derives
the manifest from the accepted `FundSplit` transition:

```sh
cube --state target/e2e/deposit.json transition build --challenge-blocks 144 \
  | jq -e '.gross_sats == 498000 and .execution_fee_sats == 5000'

cube --state target/e2e/deposit.json transition verify \
  | jq -e '.verified == true and .claims[0].amount_sats == 345100 and .claims[1].amount_sats == 147900'

cube --state target/e2e/deposit.json transition show \
  | jq '{statement_digest, gross_sats, execution_fee_sats, challenge_blocks, claims: [.claims[] | {beneficiary_key, amount_sats, binding_digest}]}'
```

`transition verify` re-derives the transition from the deposit and compares the manifest **and** the
claim bindings byte for byte. That is the check to run before treating a stored state as settleable.

The statement digest is field-sized: its most significant byte is at most `0x1f`, so Argo receives
one unambiguous scalar. Inspect it:

```sh
cube --state target/e2e/deposit.json transition show | jq -r '.statement_digest' | cut -c1-2
```

Expected first byte between `00` and `1f`.

### Negative: tampered contract state

```sh
jq '.transition.gross_sats = 1' target/e2e/deposit.json > target/e2e/bad-gross.json
cube --state target/e2e/bad-gross.json transition verify
# error: the stored gross value and fee reserve do not add up to the deposit

jq '.transition.claims[0].amount_sats = 1' target/e2e/deposit.json > target/e2e/bad-amount.json
cube --state target/e2e/bad-amount.json transition verify
# error: the stored claim bindings are not the ones this deposit derives
```

Both commands exit non-zero and leave the state file untouched.

### Negative: a state file that does not parse

```sh
printf '{ not json' > target/e2e/broken.json
cube --state target/e2e/broken.json transition verify
# error: cannot parse target/e2e/broken.json
```

State writes are atomic (temporary file plus rename), so a failed command never leaves a half-written
artifact.

---

## 5. Stage 4 — Ownership tree: publish and verify the successor

```sh
cube --state target/e2e/deposit.json successor publish \
  | jq -e '.claims | length == 2'

cube --state target/e2e/deposit.json successor verify \
  | jq -e '.verified == true and .miner_fee_sats == 2000 and .all_claims_unspent == true'

cube --state target/e2e/deposit.json claim list \
  | jq -e '.claims[0].beneficiary == "bob" and .claims[1].beneficiary == "carol"'
```

What `successor verify` proves, independently of the publish step:

- the transaction bytes hash to the stored txid and carry a signature;
- `SuccessorFunding::verify_with_assertions` re-derives every obligation from the manifest: one
  output per payout, in order, exact values, the fee output, and the zero-value `OP_RETURN`;
- the `OP_RETURN` commits exactly the manifest's statement digest;
- each claim output is the two-leaf v2 claim for its binding;
- each v2 recovery package validates, anchors the funded outpoint, and carries the same statement
  and binding;
- the miner fee is exactly the reserve.

The transaction is one input, the deposit key path signed by Alice and the Engine together, and the
signature covers every output — so no committed byte can change after signing. The keys are only
used here; every later stage uses participant keys.

Check the claims are confirmed and unspent:

```sh
TXID=$(cube --state target/e2e/deposit.json successor show | jq -r '.txid')
btc gettxout "$TXID" 0 | jq -e '.value == 0.003451'
btc gettxout "$TXID" 1 | jq -e '.value == 0.001479'
```

### Negative: a tampered claim in the stored tree

```sh
jq '.tree.claims[0].script_pubkey = .tree.claims[1].script_pubkey' \
  target/e2e/deposit.json > target/e2e/bad-tree.json
cube --state target/e2e/bad-tree.json successor verify
# error: claim 0 script does not match the successor output
```

The suite also proves the signature, not just the descriptor: `scenario run engine-cheat` (stage 9)
tampers with the statement commitment, a recipient and an amount, and Bitcoin Core rejects each one
with `Invalid Schnorr signature`.

The deposit itself is now spent, so `deposit verify` reports `funding_unspent: false` — a fact, not
an error. The artifact still describes the output correctly.

---

## 6. Stage 5 — Settlement validity: the proof envelope

Before any exit, inspect what a claim commits and what a proof input must satisfy:

```sh
cube --state target/e2e/deposit.json proof envelope 0 \
  | jq '{claim_outpoint, claim_value_sats, binding_digest, terms: {input_digest: .terms.input_digest, table_digest: .terms.table_digest, challenge_blocks: .terms.challenge_blocks}}'
```

The envelope prints the claim script, the assertion output script, the full 277-byte terms and the
binding digest. `input_digest` and `table_digest` are fixture values by default. To bind a real
proof, rebuild the transition with the values the prover and the table produced:

```sh
cube --state target/e2e/deposit.json transition build \
  --input-digest <32-byte hex> \
  --table-digest <32-byte hex> \
  --verifier-key-identity <32-byte hex>
```

That rebuild resets the ownership tree and the assertion, so republish the successor afterwards.

The real Groth16/Argo path is `tests/proof_take_regtest.rs`:

```sh
CUBE_REGTEST_RPC_URL=$CUBE_REGTEST_RPC_URL \
CUBE_REGTEST_RPC_USER=$CUBE_REGTEST_RPC_USER \
CUBE_REGTEST_RPC_PASSWORD=$CUBE_REGTEST_RPC_PASSWORD \
cargo test --release --test proof_take_regtest -- --ignored --nocapture
```

It generates a real proof, evaluates it through Argo's garbled table (`Accepted`), binds the
authenticated input to a claim, asserts it, and takes the valid claim after the challenge window. A
proof for another statement returns `Disclosed`.

---

## 7. Stage 6 — Cooperative exit

Both claims leave in one transaction, each paid its full entitlement. A separate key-path P2TR input
pays the miner fee, so the entitlements stay exact:

```sh
cube --state target/e2e/deposit.json claim settle \
  | tee target/e2e/settlement.json \
  | jq -e '.miner_fee_sats == 2000
           and .payouts[0].beneficiary == "bob"
           and .payouts[0].amount_sats == 345100
           and .payouts[1].beneficiary == "carol"
           and .payouts[1].amount_sats == 147900'
```

Every beneficiary signs the whole settlement (`SIGHASH_ALL`), so redirecting one output invalidates
the other signature. The settlement spends every claim, so nothing is left for a second settlement.

`claim settle --fee-rate <sat/vB>` measures the signed settlement and funds the external fee input
with exactly `ceil(rate * vsize)`. The input must be at least 330 sats (the P2TR dust threshold), so
a very low rate is refused with a clear message; use `--fee-input-sats` for a fixed value.

Confirm the tree is gone:

```sh
cube --state target/e2e/deposit.json successor verify \
  | jq -e '.all_claims_unspent == false and ([.claims[].unspent] | all(. == false))'
```

### Negative: a settlement that omits a beneficiary

```sh
ADDR=$(btc getnewaddress)
cube --state target/e2e/deposit.json claim settle --to "$ADDR"
# error: 1 destinations were supplied for 2 claims
```

### Negative: replay after settlement

```sh
cube --state target/e2e/deposit.json claim recover 0
# error: the claim recovery was rejected by the node: missing-inputs
```

The claim is spent; consensus refuses it. This is the double-spend check for the exit path.

---

## 8. Stage 7 — Unilateral exit without the Engine

A new flow. After the successor exists, the Engine is never needed again: the claim leaf names the
beneficiary.

```sh
cube --state target/e2e/unilateral.json deposit fund --sats 500000 >/dev/null
cube --state target/e2e/unilateral.json transition build >/dev/null
cube --state target/e2e/unilateral.json successor publish >/dev/null

cube --state target/e2e/unilateral.json claim recover 0 \
  | jq -e '.claim_index == 0 and .amount_sats == 344100'

cube --state target/e2e/unilateral.json successor verify \
  | jq -e '.claims[0].unspent == false and .claims[1].unspent == true'
```

Alice, the Engine and the operator are not asked for anything: the recovery witness is
`[Bob's signature, claim script, control block]`, and the script itself names Bob. Carol's claim is
still recoverable by Carol alone.

Repeat the recovery to observe the double-spend refusal:

```sh
cube --state target/e2e/unilateral.json claim recover 0
# error: the claim recovery was rejected by the node: missing-inputs
```

---

## 9. Stage 8 — Dispute: valid take and invalid claim

Two separate flows; one ends in a valid `Take`, the other in a `Disprove`.

### 8.1 A valid claim is taken after the challenge window

Use a short window (10 blocks) so the timelock is observable in seconds.

```sh
cube --state target/e2e/take.json deposit fund --sats 500000 >/dev/null
cube --state target/e2e/take.json transition build --challenge-blocks 10 >/dev/null
cube --state target/e2e/take.json successor publish >/dev/null

cube --state target/e2e/take.json assertion assert 0 --fee-sats 1000 \
  | jq -e '.value_sats == 344100 and .cost.gross_value_sats == 345100 and .cost.miner_fee_sats == 1000'

cube --state target/e2e/take.json assertion take --fee-sats 500 \
  | jq -e '.accepted == false and .premature_rejection == "non-BIP68-final"'

cube --state target/e2e/take.json assertion take --fee-sats 500 --wait \
  | jq -e '.accepted == true and .waited_blocks == 10 and .amount_sats == 343600
           and .cost.miner_fee_sats == 500 and .cost.net_payout_sats == 343600'
```

`assertion take` without `--wait` reports the node's rejection instead of broadcasting: a premature
take is data, not a crash. `--wait` mines the window and retries.

### 8.2 An invalid claim is disproved with the disclosure secret

```sh
cube --state target/e2e/disprove.json deposit fund --sats 500000 >/dev/null
cube --state target/e2e/disprove.json transition build --challenge-blocks 10 >/dev/null
cube --state target/e2e/disprove.json successor publish >/dev/null

cube --state target/e2e/disprove.json assertion assert 1 --fee-sats 1000 \
  | jq -e '.value_sats == 146900 and .cost.miner_fee_sats == 1000'

cube --state target/e2e/disprove.json assertion disprove --fee-sats 500 \
  | jq -e '.amount_sats == 146400 and .cost.gross_value_sats == 146900
           and .cost.miner_fee_sats == 500'
```

The default secret is the fixture `0x11…11`, which is exactly what the terms commit (a plain
SHA-256, because `OP_SHA256` is all the leaf can compute). A wrong secret is refused locally before
the node sees anything — this is a pure library check, so the claim does not have to be unspent:

```sh
cube --state target/e2e/disprove.json assertion disprove \
  --secret 9999999999999999999999999999999999999999999999999999999999999999
# error: the disclosure secret does not open the committed hashlock: WrongDisclosureSecret
```

This is the participant-scoped model: Bob signs the `Assert` because Bob's value is at stake. The
`Disprove` leaf is the backstop for a wrong assertion or a setup later shown unsound. A fully
unilateral operator assertion is the open `BIND-01` gap.

### What a dispute costs

Every assertion-path response carries a `cost` block: the gross value the step spent, the miner
fee, the net payout, the transaction virtual size and the realised fee rate. For the fixture:

| Step | Gross | Miner fee | Net | vsize | sat/vB |
|---|---|---|---|---|---|
| `Assert` claim 1 | 147,900 | 1,000 | 146,900 | 154 | 6.49 |
| `Disprove` | 146,900 | 500 | 146,400 | 150 | 3.33 |
| `Take` claim 0 | 344,100 | 500 | 343,600 | 134 | 3.73 |

```json
{
  "amount_sats": 146400,
  "cost": {
    "gross_value_sats": 146900,
    "miner_fee_sats": 500,
    "net_payout_sats": 146400,
    "vsize_vbytes": 150,
    "fee_rate_sat_per_vb": 3.3333333333333335
  }
}
```

The fee is a caller-supplied satoshi amount; `fee_rate_sat_per_vb` is the *realised* rate. With
`--fee-rate`, the CLI derives the amount from the signed vsize instead.

**Rate-based fees.** Every step also accepts `--fee-rate` instead of `--fee-sats`. The CLI builds
and signs the transaction, measures its vsize, and sets the fee to `ceil(rate * vsize)`:

```sh
cube --state target/e2e/rate.json deposit fund --sats 500000 >/dev/null
cube --state target/e2e/rate.json transition build --challenge-blocks 10 >/dev/null
cube --state target/e2e/rate.json successor publish >/dev/null

cube --state target/e2e/rate.json assertion assert 1 --fee-rate 2.0 \
  | jq -e '.cost.miner_fee_sats == 308 and .cost.fee_rate_sat_per_vb == 2.0'
cube --state target/e2e/rate.json assertion disprove --fee-rate 1.5 \
  | jq -e '.cost.miner_fee_sats == 225 and .cost.fee_rate_sat_per_vb == 1.5'
cube --state target/e2e/rate.json claim recover 0 --fee-rate 3.0 \
  | jq -e '.cost.miner_fee_sats == 399 and .cost.fee_rate_sat_per_vb == 3.0'
```

A settlement needs both claims unspent, so run it on a fresh flow:

```sh
cube --state target/e2e/rate-settle.json deposit fund --sats 500000 >/dev/null
cube --state target/e2e/rate-settle.json transition build >/dev/null
cube --state target/e2e/rate-settle.json successor publish >/dev/null
cube --state target/e2e/rate-settle.json claim settle --fee-rate 2.0 \
  | jq -e '.miner_fee_sats == 626 and .vsize_vbytes == 313'
```

The measured values are the fixture's: 154 vB for `Assert`, 150 vB for `Disprove`, 133 vB for a
recovery and 313 vB for the two-claim settlement. `--fee-rate` overrides the satoshi option; a
non-positive rate is rejected before anything is built.

**GC and the graveyard.** `Disprove` is a Bitcoin script spend. It does not call the graveyard, and
the graveyard does not charge this transaction: the graveyard is a CubeVM manager that buries Cube
accounts and records redemption amounts at the Engine layer. The only on-chain cost of this dispute
is the miner fee plus the assertion fee paid earlier. If the design should make cleanup costly — a
dispute bond, a penalty, or a graveyard redemption fee — that must be added to `AssertionTerms` and
the graph, or to the graveyard accounting. It is not implicit in the current path; `ECON-01` covers
it and is open.

---

## 10. Stage 9 — The Engine/operator cheating matrix

One command runs seven attacks and then the honest path:

```sh
cube --state target/e2e/cheat.json scenario run engine-cheat --challenge-blocks 10
```

Observed output (reasons verbatim):

| Attack | Result |
|---|---|
| The Engine changes the statement commitment | `mandatory-script-verify-flag-failed (Invalid Schnorr signature)` |
| A payout is redirected to the other beneficiary | `mandatory-script-verify-flag-failed (Invalid Schnorr signature)` |
| A payout is shorted by one satoshi | `mandatory-script-verify-flag-failed (Invalid Schnorr signature)` |
| The operator asserts on the beneficiary's behalf | `mandatory-script-verify-flag-failed (Invalid Schnorr signature)` |
| The operator takes before the challenge window | `non-BIP68-final` |
| The beneficiary signs the operator's `Take` leaf | `mandatory-script-verify-flag-failed (Invalid Schnorr signature)` |
| A wrong disclosure secret tries to disprove | refused locally: `WrongDisclosureSecret` |
| The honest operator takes after the window | accepted, 343,600 sats paid |

Why the tampered successors are tested before broadcasting: once an input is spent,
`testmempoolaccept` reports `missing-inputs` before it runs the script, and a negative test that
never reaches the script proves nothing. The scenario keeps the honest successor in memory, tests
the mutations, then publishes it.

---

## 11. Stage 10 — Engine offline

```sh
cube --state target/e2e/offline.json scenario run engine-offline
```

Expected steps:

1. `participant_alone` — a successor signed by Alice's key alone is rejected
   (`Invalid Schnorr signature`), and `musig_sign` refuses to aggregate with one signer at all.
2. `refund_before_maturity` — the script-path refund is rejected (`non-BIP68-final`).
3. `refund_after_maturity` — after mining 12,960 blocks the refund is accepted and pays 499,500 sats.

This is the pre-successor Engine failure: without the Engine there is no cooperative deposit spend
and no claim tree; the participant's only exit is the mature refund. After a successor, the Engine
is irrelevant (stage 7). The scenario takes about 45 seconds because of the 12,960 blocks.

Manual equivalent for the refund boundary:

```sh
cube --state target/e2e/refund.json deposit fund --sats 500000 >/dev/null
cube --state target/e2e/refund.json refund --fee-sats 500
# accepted: false, rejection: non-BIP68-final
cube --state target/e2e/refund.json refund --fee-sats 500 --mine-past-maturity
# accepted: true, mined_blocks: 12960
```

---

## 12. Stage 11b — The composed CubeVM run (`engine-e2e`)

This is the run that joins the Engine and the Bitcoin graph. It boots the managers and the session
pool in-process, executes `fund_split` through `exec_call_in_pool`, reads the value-bearing state
back from the managers, derives the manifest from that state, and settles the two claims on Bitcoin.

```sh
cube --state target/e2e/engine.json scenario run engine-e2e \
  | jq -e '(.steps | length) == 6 and .steps[1].outcome.entry_fee_sats > 0'
```

Expected:

| Step | What it proves | Values |
|---|---|---|
| `deposit` | the Bitcoin deposit exists | 500,000 sats |
| `vm_fund_split` | the CubeVM executed the call | contract 493,000; Bob 345,100; Carol 147,900; fee 5,000; owner 501,878; entry fee 122 |
| `manifest_from_vm` | the manifest comes from the VM state | statement digest and both bindings |
| `verify` | `transition verify` re-runs the VM-derived path | `verified: true` |
| `successor` | the manifest is funded into two v2 claims | 2 claims |
| `settlement` | both claims leave in one transaction | 345,100 + 147,900 |

The `vm` section of the state file records the execution, so `transition verify` re-runs
`transition::from_vm` instead of the model-only derivation.

Why the entry fee is not in the canonical state: the VM charges the protocol's default call fee
(122 sats for this call) to Alice. The canonical `SplitState` starts **after** that fee — its owner
balance is 999,878 at the start of the split, not 1,000,000. `transition::from_vm` checks the
accounting (`start = entry fee + gross + remainder`) before deriving the manifest. Engine fees are
settled outside the split; if the specification wants them inside the committed state, it is a
schema and circuit change.

The composed run aborts before any Bitcoin transaction if a single VM value disagrees with the
reference model. That check is what makes the manifest a statement about the VM's execution rather
than a second model run.

### The VM-derived proof

```sh
cargo test --release -p cube-scenario --features proof \
  --test engine_proof -- --ignored --nocapture
```

This test takes the same VM-derived plan, proves it with Groth16, converts the verifying key into
Argo's equation, garbles a table, evaluates the real proof (`Accepted`), binds the authenticated
input digest, table digest and verifier identity into the assertion terms, publishes the successor,
asserts, and takes the claim. It is release-only and feature-gated so the default CLI does not link
the proving stack. Measured: about 13 s of test time in release.

---

## 13. Stage 12 — State integrity, atomicity and garbage collection

`cube-cli` checks the Bitcoin-side state (stages 2–5) and boots the managers and session pool for
the composed run (stage 11b). It still does not boot `runner::run`; the graveyard and manager suites
are run directly below:

```sh
cargo test --test state_manager      # register a contract, insert two keys, apply, reload
cargo test --test graveyard          # bury accounts, read redemption amounts, persistence
cargo test --test batch_atomicity    # a corrupt aggregate signature leaves no delta; retry works
cargo test --test commit_recovery    # crash mid-commit, replay the archive, fail-stop on pending
cargo test -p cube --lib sync_manager::tests   # reorg detector and tip persistence
cargo test --test exec               # opcode execution
cargo test --test simul              # liftup simulation
cargo test --test fixed_split_vault  # 36 reference-model cases
cargo test --test split_vault_template
cargo test --test call_entry
cargo test --test template_allowlist
cargo test --test deploy_allowlist
```

Observed: all pass (`fixed_split_vault` 36, `template_allowlist` 3, one each elsewhere).

### The state-issue scenario

`batch_atomicity` is the executable "something went wrong in the state" case. It builds an APE
batch, corrupts one aggregate-signature byte, submits it, and asserts:

- the batch fails with `AggregateBLSSignatureVerificationError`;
- the account balance is unchanged;
- the same batch retried afterwards succeeds.

That is the rollback guarantee: validation failure leaves no delta behind.

`state_manager` covers the other half: a registered contract, inserted keys, `apply_changes`, and a
fresh manager reading the values back from sled. `graveyard` does the same for burial and redemption
accounting. Those are the garbage-collection and death paths at the manager level.

### Crash and reorg boundaries

A batch commit touches six independent Sled stores, which cannot share a transaction
(specification §11.2 says so explicitly). `ExecCtx::apply_changes` therefore writes a durable
intent to `storage/<chain>/commit_journal` before the first manager changes, archives the batch
before that, and closes the intent only after the tips and the utxo removal. If the process stops
in between, the next start finds the intent and `reconcile_pending_commit`:

1. reads the in-flight record from the journal and every earlier record from the archival store;
2. resets the Cube tips (the Bitcoin scan tip and the chain-derived utxo set survive);
3. erases the batch-derived managers and re-executes the records in order in replay mode;
4. checks that each replayed record reproduces the archived txid, payload and entry ids;
5. restores the lift outpoints the replay consumes, archives the in-flight record if needed, and
   closes the intent.

`tests/commit_recovery.rs` builds two real liftup batches, executes them cleanly, repeats the run
with an injected fault after the coin manager applied, drops every store handle (the crash),
reconciles, and compares the reopened managers with the clean run. A second test proves that a
pending intent makes `execute_batch` return `UnreconciledCommit(height)` instead of applying on top
of a torn commit. The failpoint is a `#[doc(hidden)]` atomic and does nothing unless a test sets it.

Recovery is O(history) and requires archival storage; a pruned node refuses to start with
`MissingArchivedRecord` instead of guessing which stores committed.

The reorg policy is deliberately narrower: the sync manager records the height and hash of the last
scanned block, and chain sync refuses to extend the scan when the node's active chain no longer
contains that block. It prints `Reorg below the finalized tip` and exits with status 2. It does not
un-apply committed Cube batches; doing that safely is a protocol decision, not a storage repair.

Power-loss durability remains sled's fsync policy rather than a per-manager `flush()`. The fault
injection simulates a process stop, which is the boundary this code claims.

The VM and Bitcoin halves are composed for the value path by stage 11b, and the VM-derived manifest
is proved in `tests/engine_proof.rs`. What remains is the canonical-state representation adapter
(identity and sequences) and the interactive V2 liftup rehearsal (section 0).

---

## 14. Stage 13 — Full regression

```sh
# offline artifact, derivation and composed-Engine tests
cargo test -p cube-scenario

# the node's LiftV2 scan switch
cargo test --test liftv2_scan

# seven scenarios, fresh chain per run
./scripts/regtest.sh cli

# node-backed test files plus the model-derived release proof test
./scripts/regtest.sh all

# the VM-derived manifest through Groth16, Argo and Bitcoin (release, ignored)
cargo test --release -p cube-scenario --features proof \
  --test engine_proof -- --ignored --nocapture
```

Expected: `cube-scenario` 5 passed; `liftv2_scan` 1 passed; `cli` exit 0 with seven scenario
reports; `all` exit 0 with every node-backed file green and `proof_take_regtest` reporting
`valid proof taken`; `engine_proof` 1 passed with a taken claim.

`./scripts/regtest.sh cli` takes about 3 minutes. It runs, in order: `liftv2-cooperative`,
`liftv2-dispute`, `proof-take`, `engine-e2e`, `engine-cheat`, `engine-offline`, `liftv2-refund`.
The last two mine 12,960 blocks each.

---

## Appendix A — Failure strings and what they mean

| Message | Meaning |
|---|---|
| `non-BIP68-final` | The input's sequence is a relative timelock that has not matured. |
| `mandatory-script-verify-flag-failed (Invalid Schnorr signature)` | The signature does not match the output key for the exact bytes. Every tamper path lands here. |
| `missing-inputs` | The outpoint is already spent (or unknown). This is the replay/double-spend refusal. |
| `WrongDisclosureSecret` | `DisproveSpend::new` checked the revealed preimage against the committed SHA-256. |
| `1 destinations were supplied for 2 claims` | The settlement must cover every claim exactly once. |
| `the stored gross value and fee reserve do not add up to the deposit` | Tampered or stale transition artifact. |
| `claim 0 script does not match the successor output` | Tampered claim in the stored tree. |
| `the network fee reserve exceeds the deposit` | The deposit cannot pay the successor's miner fee. |
| `the fee rate must be a positive sat/vB value` | `--fee-rate` was zero or negative. |
| `... below the 330-sat P2TR dust threshold ...` | A rate-based settlement fee is too small to fund as a standalone P2TR input; raise the rate or use `--fee-input-sats`. |

## Appendix B — Artifact inventory

One `--state` file carries one flow. Sections appear as the flow advances:

| Section | Written by | Contains |
|---|---|---|
| `deposit` | `deposit fund` | fixture keys, address, script, outpoint, value |
| `transition` | `transition build` | canonical manifest, statement digest, gross/fee, challenge window, one binding per beneficiary |
| `tree` | `successor publish` | successor txid and bytes, statement output index, one claim per beneficiary with its v2 package |
| `assertion` | `assertion assert` | contested claim, terms, assertion txid and bytes, value and fee |

`deposit verify`, `transition verify`, `successor verify` and `proof envelope` are read-only: they
re-derive and compare, and never mutate the file. Nothing is auto-deleted; a spent claim stays in
the artifact so the history remains inspectable.

## Appendix C — Traceability to the specification

| Specification area | Evidence |
|---|---|
| INV-12 (no beneficiary erased while another exits) | stage 6: one settlement spends every claim |
| §7.2 field-sized statement | stage 3, `transition verify` |
| §8.2 graph-enforced authorization | stages 4, 8, 9: MuSig2 over the successor, beneficiary-signed assertions, node rejections |
| §9.2 roles: SuccessorFunding, Recovery, Assert/Take/Disprove, CooperativeSettle | stages 4–11 |
| Binding construction | stage 5 and `docs/bind_01.md` |
| VM state -> manifest -> Bitcoin settlement | stage 11b |
| VM-derived manifest proved with Groth16 and Argo | stage 11b, `tests/engine_proof.rs` |
| LiftV2 output discovery by the node | `tests/liftv2_scan.rs` |
| State/GC and rollback | stage 13 |
| Remaining gaps | section 0 and `docs/implementation.md` |
