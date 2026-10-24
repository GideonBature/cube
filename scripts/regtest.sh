#!/usr/bin/env bash
# Runs the node-backed integration tests against a containerised Bitcoin Core regtest node.
#
#   ./scripts/regtest.sh up      start the node and print the environment
#   ./scripts/regtest.sh test    run every node-backed test (node must be up)
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
  echo "regtest node ready at ${CUBE_REGTEST_RPC_URL}"
  echo "export CUBE_REGTEST_RPC_URL=${CUBE_REGTEST_RPC_URL}"
  echo "export CUBE_REGTEST_RPC_USER=${CUBE_REGTEST_RPC_USER}"
  echo "export CUBE_REGTEST_RPC_PASSWORD=${CUBE_REGTEST_RPC_PASSWORD}"
}

stop() {
  compose down -v
}

run_tests() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is not running; start Docker Desktop or another daemon first." >&2
    exit 1
  fi
  export_env
  cd "$root"

  # The LiftV2 test uses the unscoped node client, so it runs first on a fresh node. The other
  # tests use wallet-scoped clients and can create their own wallets afterwards.
  cargo test --test liftv2_regtest -- --test-threads=1
  cargo test --test assertion_regtest -- --test-threads=1
  cargo test --test successor_v2_regtest -- --test-threads=1
  cargo test --test cooperative_settle_regtest -- --test-threads=1

  # Groth16 setup/proving and Argo garbling are only practical in release.
  cargo test --release --test proof_take_regtest -- --ignored --nocapture
}

case "${1:-all}" in
  up)
    start
    ;;
  down)
    stop
    ;;
  test)
    run_tests
    ;;
  all)
    start
    if [[ "${KEEP:-0}" == "1" ]]; then
      run_tests
      echo "KEEP=1: leaving the node running"
    else
      trap 'stop' EXIT
      run_tests
    fi
    ;;
  *)
    echo "usage: $0 {up|test|down|all}" >&2
    exit 2
    ;;
esac
