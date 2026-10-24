//! Shared regtest RPC client for the node-backed integration tests.
//!
//! Cookie authentication is the default, matching a local `bitcoind` started with a datadir:
//!
//! ```text
//! CUBE_REGTEST_DATADIR=/path/to/datadir CUBE_REGTEST_RPC_PORT=18443 cargo test ...
//! ```
//!
//! A container or remote node can instead expose its RPC endpoint and credentials:
//!
//! ```text
//! CUBE_REGTEST_RPC_URL=http://127.0.0.1:18443 \
//! CUBE_REGTEST_RPC_USER=cube CUBE_REGTEST_RPC_PASSWORD=cube cargo test ...
//! ```
//!
//! The tests use `client(None)` when they only call node RPCs and `client(Some("wallet"))`
//! when they call wallet RPCs. A wallet-scoped path makes several test wallets coexist on one node.

#![allow(dead_code)]

use bitcoincore_rpc::{Auth, Client};
use std::path::PathBuf;

/// Returns a client for the configured regtest node, or `None` when no endpoint is configured.
pub fn client(wallet: Option<&str>) -> Option<Client> {
    let port = std::env::var("CUBE_REGTEST_RPC_PORT").unwrap_or_else(|_| "18443".to_string());
    let datadir = std::env::var("CUBE_REGTEST_DATADIR")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let user = std::env::var("CUBE_REGTEST_RPC_USER")
        .ok()
        .filter(|value| !value.is_empty());
    let password = std::env::var("CUBE_REGTEST_RPC_PASSWORD").ok();

    let base_url = std::env::var("CUBE_REGTEST_RPC_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| datadir.as_ref().map(|_| format!("http://127.0.0.1:{port}")))
        .or_else(|| user.as_ref().map(|_| format!("http://127.0.0.1:{port}")))?;
    let base_url = base_url.trim_end_matches('/');

    let auth = match (user, password) {
        (Some(user), Some(password)) => Auth::UserPass(user, password),
        _ => {
            let datadir = datadir?;
            Auth::CookieFile(PathBuf::from(datadir).join("regtest/.cookie"))
        }
    };

    let path = wallet
        .map(|name| format!("/wallet/{name}"))
        .unwrap_or_default();
    Client::new(&format!("{base_url}{path}"), auth).ok()
}
