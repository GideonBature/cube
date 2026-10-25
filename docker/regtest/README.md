# Docker regtest node

A single Bitcoin Core regtest node for the node-backed integration tests. The tests themselves run
on the host: the Rust test binaries are the artifact under test, and rebuilding them inside a
container only adds time.

## Usage

```sh
./scripts/regtest.sh all
```

This runs every node-backed test, each file on a **fresh chain**: the named volume is recreated
before each file. That is required because regtest halves the block subsidy every 150 blocks and the
LiftV2 refund fixture mines about 13,000 blocks, which would leave later wallets with zero-value
coinbases. It also isolates wallets and failures. `KEEP=1` leaves the last node running for
inspection. Individual steps:

```sh
./scripts/regtest.sh up
./scripts/regtest.sh test
./scripts/regtest.sh down
```

The tests use the same environment against a local `bitcoind`:

```sh
export CUBE_REGTEST_RPC_URL=http://127.0.0.1:18443
export CUBE_REGTEST_RPC_USER=cube
export CUBE_REGTEST_RPC_PASSWORD=cube
```

Cookie authentication remains supported for a local node with
`CUBE_REGTEST_DATADIR=/path/to/datadir`.

## What runs

- `liftv2_regtest`: the LiftV2 deposit, refund, MuSig2 successor, and the two composed
  deposit -> successor -> settle/dispute/recover scenarios. Its refund fixture mines 12,960 blocks,
  which is why the runner gives each file a fresh chain.
- `assertion_regtest`: the Assert/Take/Disprove mechanics and the v2 recovery path.
- `successor_v2_regtest`: a successor with two v2 claims, an assertion, a disprove and a recovery.
- `cooperative_settle_regtest`: both claims settled in one transaction.
- `proof_take_regtest` (release, ignored by default): a real Groth16 proof, Argo's table verdict, the
  beneficiary-signed assertion, and a valid `Take` after the challenge window.

The node uses `-fallbackfee=0.0002` so wallet-funded fixtures work, and no `-txindex`: the tests read
mined transactions from their blocks.
