//! Node access for the scenario CLI and its tests.
//!
//! Configuration is explicit so the CLI can override the environment:
//!
//! ```text
//! CUBE_REGTEST_RPC_URL=http://127.0.0.1:18443
//! CUBE_REGTEST_RPC_USER=cube
//! CUBE_REGTEST_RPC_PASSWORD=cube
//! ```
//!
//! Cookie authentication remains available through `CUBE_REGTEST_DATADIR`.

use anyhow::{anyhow, bail, Context, Result};
use bitcoin::{Address, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;
use std::path::PathBuf;

/// How to reach the regtest node.
#[derive(Debug, Clone, Default)]
pub struct RpcConfig {
    /// Full RPC URL, e.g. `http://127.0.0.1:18443`.
    pub url: Option<String>,
    /// RPC user, when user/password authentication is used.
    pub user: Option<String>,
    /// RPC password.
    pub password: Option<String>,
    /// Bitcoin datadir, for cookie authentication.
    pub datadir: Option<String>,
    /// RPC port used when only the datadir or credentials are supplied.
    pub port: u16,
}

impl RpcConfig {
    /// Reads the environment used by the integration tests.
    pub fn from_env() -> Self {
        Self {
            url: std::env::var("CUBE_REGTEST_RPC_URL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            user: std::env::var("CUBE_REGTEST_RPC_USER")
                .ok()
                .filter(|value| !value.is_empty()),
            password: std::env::var("CUBE_REGTEST_RPC_PASSWORD").ok(),
            datadir: std::env::var("CUBE_REGTEST_DATADIR")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            port: std::env::var("CUBE_REGTEST_RPC_PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(18443),
        }
    }

    /// Returns a client for the node, optionally scoped to a wallet.
    pub fn client(&self, wallet: Option<&str>) -> Result<Client> {
        let base_url = self
            .url
            .clone()
            .or_else(|| {
                self.datadir
                    .as_ref()
                    .map(|_| format!("http://127.0.0.1:{}", self.port))
            })
            .or_else(|| {
                self.user
                    .as_ref()
                    .map(|_| format!("http://127.0.0.1:{}", self.port))
            })
            .ok_or_else(|| {
                anyhow!("no regtest endpoint: set CUBE_REGTEST_RPC_URL or CUBE_REGTEST_DATADIR")
            })?;
        let base_url = base_url.trim_end_matches('/');

        let auth = match (self.user.clone(), self.password.clone()) {
            (Some(user), Some(password)) => Auth::UserPass(user, password),
            _ => {
                let datadir = self
                    .datadir
                    .as_ref()
                    .ok_or_else(|| anyhow!("cookie authentication needs CUBE_REGTEST_DATADIR"))?;
                Auth::CookieFile(PathBuf::from(datadir).join("regtest/.cookie"))
            }
        };

        let path = wallet
            .map(|name| format!("/wallet/{name}"))
            .unwrap_or_default();
        Client::new(&format!("{base_url}{path}"), auth)
            .map_err(|error| anyhow!("cannot build RPC client: {error}"))
    }

    /// Creates or loads `wallet`, mines 101 blocks to it and returns the wallet client.
    pub fn node_wallet(&self, wallet: &str) -> Result<(Client, String)> {
        let base = self.client(None)?;
        if let Err(create_error) = base.call::<serde_json::Value>("createwallet", &[json!(wallet)])
        {
            base.call::<serde_json::Value>("loadwallet", &[json!(wallet)])
                .map_err(|load_error| {
                    anyhow!(
                        "cannot create or load wallet {wallet}: create={create_error}; load={load_error}"
                    )
                })?;
        }

        let rpc = self.client(Some(wallet))?;
        let mining_address: String = rpc
            .call("getnewaddress", &[])
            .context("getnewaddress for the scenario wallet")?;
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(101), json!(mining_address)])
            .context("mine mature coinbase")?;
        Ok((rpc, mining_address))
    }
}

/// Parses a node address into its scriptpubkey.
pub fn address_to_script(address: &str) -> Result<ScriptBuf> {
    use std::str::FromStr;
    Ok(Address::from_str(address)
        .context("invalid address")?
        .assume_checked()
        .script_pubkey())
}

/// Finds the first output of `txid` worth `value_sats`.
pub fn wallet_output(rpc: &Client, txid: &str, value_sats: u64) -> Result<(OutPoint, TxOut)> {
    let wallet_tx: serde_json::Value = rpc
        .call("gettransaction", &[json!(txid), json!(true)])
        .context("gettransaction")?;
    let tx: Transaction = bitcoin::consensus::deserialize(
        &hex::decode(wallet_tx["hex"].as_str().context("transaction hex")?)
            .context("hex decode")?,
    )
    .context("transaction decode")?;
    let parsed_txid: Txid = txid.parse().context("txid parse")?;
    for (vout, output) in tx.output.iter().enumerate() {
        if output.value.to_sat() == value_sats {
            return Ok((
                OutPoint {
                    txid: parsed_txid,
                    vout: vout as u32,
                },
                output.clone(),
            ));
        }
    }
    bail!("the transaction has no output worth {value_sats} sats");
}

/// Reads a mined transaction from its block, so the node does not need a txindex.
pub fn mined_transaction(rpc: &Client, txid: Txid) -> Result<Transaction> {
    let height: u64 = rpc.call("getblockcount", &[]).context("getblockcount")?;
    let block_hash: String = rpc
        .call("getblockhash", &[json!(height)])
        .context("getblockhash")?;
    let block: serde_json::Value = rpc
        .call("getblock", &[json!(block_hash), json!(2)])
        .context("getblock")?;
    let tx = block["tx"]
        .as_array()
        .context("block tx array")?
        .iter()
        .find(|tx| tx["txid"] == json!(txid))
        .context("the transaction must be in the tip block")?;
    bitcoin::consensus::deserialize(
        &hex::decode(tx["hex"].as_str().context("transaction hex")?).context("hex decode")?,
    )
    .context("transaction decode")
}
