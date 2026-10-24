# Model Files
Independent reference state-transition models.

These modules describe what a contract accepts and what state it produces, using only the Rust
standard library plus `transmutative::hash`. They intentionally do not import `CoinManager`,
`Registry`, `StateManager`, `sled`, `tokio` or `bitcoin`, so that:

1. the contract's arithmetic and lifecycle can be reviewed without the Engine, and
2. the real CubeVM entry path can be compared byte-for-byte against a second implementation.

A model is a specification artifact. Passing a model test demonstrates neither Bitcoin
enforcement, nor proof soundness, nor recovery. Those remain separate release gates.

## Contents

- `fixed_split_vault_v1`: the bounded `FixedSplitVaultV1` pilot from specification.md section 3.
