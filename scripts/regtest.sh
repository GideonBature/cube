#!/usr/bin/env bash
# Runs the node-backed integration tests against a containerised Bitcoin Core regtest node.
#
#   ./scripts/regtest.sh up      start the node and print the environment
#   ./scripts/regtest.sh test    run every node-backed test (node must be up)
#   ./scripts/regtest.sh cli     run every cube-cli scenario on a fresh chain
#   ./scripts/regtest.sh down    stop the node and remove its volume
#   ./scripts/regtest.sh all     start, test, stop (KEEP=1 leaves the node running)
#
# The tests use RPC user/password authentication, so no cookie file has to cross the
# container boundary. The same variables work against a local node.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose_file="$root/docker/regtest/docker-compose.yml"
project="cube-regtest"
rpc_port="${CUBE_REGTEST_RPC_PORT:-18443}"

compose() {
  docker compose -p "$project" -f "$compose_file" "$@"
}

export_env() {
  export CUBE_REGTEST_RPC_URL="http://127.0.0.1:${rpc_port}"
  export CUBE_REGTEST_RPC_USER="cube"
  export CUBE_REGTEST_RPC_PASSWORD="cube"
}

start() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is not running; start Docker Desktop or another daemon first." >&2
    exit 1
  fi

  # A fresh chain per run: the named volume is scoped to this compose project.
  compose down -v >/dev/null 2>&1 || true
  compose up -d --wait
  export_env
}

show_env() {
  echo "regtest node ready at ${CUBE_REGTEST_RPC_URL}"
  echo "export CUBE_REGTEST_RPC_URL=${CUBE_REGTEST_RPC_URL}"
  echo "export CUBE_REGTEST_RPC_USER=${CUBE_REGTEST_RPC_USER}"
  echo "export CUBE_REGTEST_RPC_PASSWORD=${CUBE_REGTEST_RPC_PASSWORD}"
}

# Regtest halves the block subsidy every 150 blocks. The LiftV2 refund fixture mines ~13,000
# blocks, which exhausts it, so every test file gets a fresh chain. This also isolates wallets
# and keeps a failing file from poisoning the next one.
run_test_file() {
  start
  "$@"
}

stop() {
  compose down -v
}

run_tests() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is not running; start Docker Desktop or another daemon first." >&2
    exit 1
  fi
  cd "$root"

  run_test_file cargo test --test liftv2_regtest -- --test-threads=1
  run_test_file cargo test --test assertion_regtest -- --test-threads=1
  run_test_file cargo test --test successor_v2_regtest -- --test-threads=1
  run_test_file cargo test --test cooperative_settle_regtest -- --test-threads=1

  # Groth16 setup/proving and Argo garbling are only practical in release.
  run_test_file cargo test --release --test proof_take_regtest -- --ignored --nocapture
}

# Runs the cube-cli scenarios on one fresh chain. The refund scenario mines ~13,000 blocks, which
# exhausts the regtest subsidy, so it runs last.
run_cli_scenarios() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is not running; start Docker Desktop or another daemon first." >&2
    exit 1
  fi
  cd "$root"
  start
  show_env

  cargo run -q -p cube-cli -- --state target/cube-cli-cooperative.json scenario run liftv2-cooperative
  cargo run -q -p cube-cli -- --state target/cube-cli-dispute.json scenario run liftv2-dispute
  cargo run -q -p cube-cli -- --state target/cube-cli-proof.json scenario run proof-take --challenge-blocks 10
  cargo run -q -p cube-cli -- --state target/cube-cli-engine.json scenario run engine-e2e
  cargo run -q -p cube-cli -- --state target/cube-cli-cheat.json scenario run engine-cheat --challenge-blocks 10
  cargo run -q -p cube-cli -- --state target/cube-cli-offline.json scenario run engine-offline
  cargo run -q -p cube-cli -- --state target/cube-cli-refund.json scenario run liftv2-refund
}

case "${1:-all}" in
  up)
    start
    show_env
    ;;
  down)
    stop
    ;;
  cli)
    if [[ "${KEEP:-0}" != "1" ]]; then
      trap 'stop' EXIT
    fi
    run_cli_scenarios
    if [[ "${KEEP:-0}" == "1" ]]; then
      echo "KEEP=1: leaving the node running"
    fi
    ;;
  test|all)
    if [[ "${KEEP:-0}" != "1" ]]; then
      trap 'stop' EXIT
    fi
    run_tests
    if [[ "${KEEP:-0}" == "1" ]]; then
      echo "KEEP=1: leaving the last node running"
      show_env
    fi
    ;;
  *)
    echo "usage: $0 {up|test|cli|down|all}" >&2
    exit 2
    ;;
esac
