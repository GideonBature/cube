//! Independent reference state-transition models.
//!
//! The modules under `model` are deliberately free of the Engine managers: no `CoinManager`,
//! no `Registry`, no Sled database, no Bitcoin RPC and no async. They exist so that a contract's
//! accepted behaviour can be reviewed and re-implemented independently of the production
//! execution path, and so that the real CubeVM path can later be compared against a second
//! implementation (implementation.md P2, differential evidence in P3.3).
//!
//! A model in this layer is a specification artifact. Matching the model does not demonstrate
//! Bitcoin enforcement, proof soundness or recovery; those are separate gates.

pub mod fixed_split_vault_v1;
