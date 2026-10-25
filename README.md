![Cube](https://i.ibb.co/KjnGsD7L/cube-text-logo.png)
Cube is a four-elemental, fire-sampled virtual execution environment for Bitcoin.

## Installation

Ensure you have [Rust](https://www.rust-lang.org/tools/install) installed. Clone the repository and navigate into the project directory:

```sh
git clone https://github.com/cube-btc/cube
cd cube
```

## Generating a Secret Key

If you don't already have a secret key, you can optionally generate a new one by running:

```sh
cargo run gensec
```

This will generate a random secret key and print it as an nsec string, which you'll need when running the program.

Cube abides by the [NIP-19](https://nips.nostr.com/19) format for secret keys, which uses bech32-encoded `nsec` strings for private keys.

## Usage

Run the program with the following command:

```sh
cargo run <resource-mode> <chain> <kind> <rpc-url> <rpc-user> <rpc-password> <syncinflight?>
```

### Parameters:

- `<resource-mode>`: Whether to run in pruned or archival mode. Supported values:
  - `pruned`: For running in pruned mode.
  - `archival`: For running in archival mode.
- `<chain>`: The Bitcoin network to use. Supported values:
  - `signet`
  - `mainnet`
- `<kind>`: The kind of operating entity. Supported values:
  - `node`: For running a Cube node.
  - `engine`: For the network operator.
- `<rpc-url>`: The RPC URL of the Bitcoin node.
- `<rpc-user>`: The RPC username of the Bitcoin node.
- `<rpc-password>`: The RPC password of the Bitcoin node.
- `<syncinflight?>`: Whether to sync in-flight unconfirmed executions.
  - `true`: For syncing in-flight executions.
  - `false`: For syncing confirmed-executions-only.

### Example:

```sh
cargo run pruned signet node http://127.0.0.1:38332 user password true
```

## Regtest scenarios (`cube-cli`)

`cube-cli` drives the ownership graph against a Bitcoin Core regtest node and prints one JSON
artifact per command. Every command is one step over a state file (`--state`, `cube-state.json` by
default), so shell scripts can inspect, resume or replay a flow:

```sh
./scripts/regtest.sh up
export CUBE_REGTEST_RPC_URL=http://127.0.0.1:18443 \
       CUBE_REGTEST_RPC_USER=cube CUBE_REGTEST_RPC_PASSWORD=cube

cargo run -p cube-cli -- keys
cargo run -p cube-cli -- deposit fund --sats 500000
cargo run -p cube-cli -- transition build
cargo run -p cube-cli -- successor publish
cargo run -p cube-cli -- claim list
cargo run -p cube-cli -- claim recover 0
```

The composed scenarios match the node-backed integration tests:

```sh
cargo run -p cube-cli -- scenario list
cargo run -p cube-cli -- scenario run liftv2-cooperative
cargo run -p cube-cli -- scenario run liftv2-dispute
cargo run -p cube-cli -- scenario run proof-take
cargo run -p cube-cli -- scenario run engine-cheat
cargo run -p cube-cli -- scenario run engine-offline
cargo run -p cube-cli -- scenario run liftv2-refund   # mines ~13,000 blocks
```

`./scripts/regtest.sh cli` starts a fresh node and runs every scenario. All keys are public test
fixtures and the CLI is regtest-only. The full sequential acceptance run, including the negative
cases and the state/garbage-collection suites, is [docs/e2e_regtest.md](docs/e2e_regtest.md).

## License

This project is licensed under the CC0 1.0 Universal License. See the `LICENSE` file for details.
