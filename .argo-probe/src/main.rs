//! Feasibility probe: can a Rust 2021 crate depend on Argo at its pinned revision, and what does
//! the dependency tree look like?
//!
//! This does not exercise the garbling. It answers two questions:
//!
//! 1. Does an edition-2024 / arkworks-0.5 dependency resolve and compile from an edition-2021
//!    crate?
//! 2. Which arkworks versions end up in the lockfile, i.e. is the tree duplicated next to Cube's
//!    existing arkworks 0.4?
//!
//! The crate is deliberately empty of Argo calls: naming a type here would prove more than
//! resolution, so the follow-up is to name `argo::garble::groth16_verifier::VerifierKey` once a
//! Groth16 verifying key exists.

fn main() {
    println!("argo probe: dependency resolved and linked");
}
