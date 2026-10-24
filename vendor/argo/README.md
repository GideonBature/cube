# Argo: Arithmetic Garbling for SNARK Verifiers

Argo implements arithmetic garbling for a Groth16 verifier over BN254 in Rust. Given authenticated proof inputs, the garbled verifier is designed to reveal a committed secret when verification fails.

Run tests:

```sh
cargo test --release
```

Run benchmarks:

```sh
cargo bench
```

See the [verifier implementation](https://github.com/idealgroup/argo/tree/main/src/garble/groth16_verifier) and [benchmarks](https://github.com/idealgroup/argo/tree/main/benches) for usage examples.
