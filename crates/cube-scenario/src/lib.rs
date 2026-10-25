//! Scriptable regtest scenarios over the Cube ownership graph.
//!
//! The crate is the library half of `cube-cli`. It owns three things:
//!
//! - a typed, JSON-serialisable state of artifacts ([`State`]), so one command can consume what
//!   another produced without re-deriving it;
//! - the signing and chain plumbing the graph edges need ([`signing`], [`chain`]);
//! - the graph steps and the composed scenarios ([`scenario`]).
//!
//! Every fixture is deterministic and every secret in [`keys`] is a test value. Nothing in this
//! crate is safe for a network with value.

pub mod artifact;
pub mod chain;
pub mod engine;
pub mod keys;
pub mod rpc;
pub mod scenario;
pub mod signing;
pub mod transition;

pub use artifact::State;
pub use chain::Chain;
pub use rpc::RpcConfig;

/// Adds context to results whose error type is a repository enum.
///
/// The graph and model errors are frozen `Debug` enums without a `Display`/`Error`
/// implementation, so `anyhow::Context` does not apply to them. This trait keeps the call sites
/// uniform and preserves the variant in the message.
pub trait DebugContext<T> {
    /// Wraps the error with `what` and the error's `Debug` form.
    fn context_debug(self, what: &str) -> anyhow::Result<T>;
}

impl<T, E: std::fmt::Debug> DebugContext<T> for std::result::Result<T, E> {
    fn context_debug(self, what: &str) -> anyhow::Result<T> {
        self.map_err(|error| anyhow::anyhow!("{what}: {error:?}"))
    }
}
