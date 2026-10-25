//! A thin, failure-attributing wrapper over the regtest node.
//!
//! The wrapper exists so the scenarios read as graph steps instead of RPC plumbing. It also hides
//! the two node details that make regtest fixtures awkward:
//!
//! - a wallet is created once and then loaded, because both `createwallet` and `loadwallet` fail on
//!   a second call;
//! - blocks are mined in batches of 100 with a retry, because a single large `generatetoaddress`
//!   call can exceed the RPC read timeout, and a timed-out batch may still have mined.
//!
//! Nothing here is cached: every read asks the node, so a scenario can be interrupted and the state
//! file replayed against the chain that actually exists.

use crate::artifact::Hex32;
use crate::rpc::{address_to_script, mined_transaction, wallet_output, RpcConfig};
use anyhow::{anyhow, bail, Context, Result};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::{Address, Network, ScriptBuf, Transaction, TxOut, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use serde::Serialize;
use serde_json::json;

/// The most blocks one `generatetoaddress` call requests.
const MINE_BATCH: u64 = 100;

/// What the node's mempool policy said about a transaction.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// Whether the transaction would be accepted.
    pub allowed: bool,
    /// The reject reason, when it would not.
    pub reject_reason: Option<String>,
    /// The reject details, when the node supplies them.
    pub reject_details: Option<String>,
    /// The virtual size, when the node reports it.
    pub vsize: Option<u64>,
}

impl Verdict {
    /// Returns an error carrying the node's reason unless the transaction is acceptable.
    pub fn require(&self, what: &str) -> Result<()> {
        if self.allowed {
            return Ok(());
        }
        bail!(
            "{what} was rejected by the node: {}",
            self.reject_reason
                .as_deref()
                .unwrap_or("no reason reported")
        )
    }
}

/// A wallet-backed handle on the regtest node.
pub struct Chain {
    rpc: Client,
    wallet: String,
    mining_address: String,
}

impl Chain {
    /// Creates or loads `wallet`, and mines mature coins only when the wallet lacks them.
    ///
    /// Mining 101 blocks on every command would make a scripted sequence unusably slow, while not
    /// mining at all would fail on a fresh node. The check keeps both costs where they belong.
    pub fn open(config: &RpcConfig, wallet: &str) -> Result<Self> {
        let base = config.client(None)?;
        if base
            .call::<serde_json::Value>("createwallet", &[json!(wallet)])
            .is_err()
        {
            // A wallet that already exists and is loaded rejects `loadwallet`; that is fine, the
            // next call proves whether it is usable.
            let _ = base.call::<serde_json::Value>("loadwallet", &[json!(wallet)]);
        }

        let rpc = config.client(Some(wallet))?;
        let mining_address: String = rpc
            .call("getnewaddress", &[])
            .context("getnewaddress for the scenario wallet")?;
        let chain = Self {
            rpc,
            wallet: wallet.to_string(),
            mining_address,
        };

        if chain.height()? < 101 || chain.balance_sats()? < 1_000_000_000 {
            chain.mine(101)?;
        }
        Ok(chain)
    }

    /// The RPC client, for calls this wrapper does not model.
    pub fn rpc(&self) -> &Client {
        &self.rpc
    }

    /// The wallet name.
    pub fn wallet(&self) -> &str {
        &self.wallet
    }

    /// The address new blocks are mined to.
    pub fn mining_address(&self) -> &str {
        &self.mining_address
    }

    /// The current chain height.
    pub fn height(&self) -> Result<u64> {
        self.rpc.call("getblockcount", &[]).context("getblockcount")
    }

    /// The wallet balance in satoshis.
    pub fn balance_sats(&self) -> Result<u64> {
        let balance: f64 = self.rpc.call("getbalance", &[]).context("getbalance")?;
        Ok((balance * 100_000_000.0).round() as u64)
    }

    /// Mines `blocks` blocks to the wallet's mining address and returns the new height.
    pub fn mine(&self, blocks: u64) -> Result<u64> {
        let mut mined = 0u64;
        while mined < blocks {
            let batch = (blocks - mined).min(MINE_BATCH);
            let mut attempts = 0u32;
            loop {
                match self.rpc.call::<Vec<String>>(
                    "generatetoaddress",
                    &[json!(batch), json!(self.mining_address)],
                ) {
                    Ok(_) => break,
                    Err(error) if attempts < 5 => {
                        attempts += 1;
                        eprintln!("retrying block batch after transport error: {error}");
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    Err(error) => return Err(error).context("generatetoaddress"),
                }
            }
            mined += batch;
        }
        self.height()
    }

    /// Returns a fresh wallet address.
    pub fn new_address(&self) -> Result<String> {
        self.rpc.call("getnewaddress", &[]).context("getnewaddress")
    }

    /// Parses an address into its scriptpubkey.
    pub fn script(&self, address: &str) -> Result<ScriptBuf> {
        address_to_script(address)
    }

    /// Parses a bech32m address and returns both the address and its script.
    pub fn destination(&self, address: &str) -> Result<(String, ScriptBuf)> {
        let script = address_to_script(address)?;
        Ok((address.to_string(), script))
    }

    /// Funds `address` from the wallet and optionally confirms it.
    pub fn fund(&self, address: &str, sats: u64, confirm: bool) -> Result<Txid> {
        // Regtest halves the subsidy every 150 blocks. After about 9,600 blocks the coinbase is
        // worth nothing, so a chain reused past the refund scenario cannot fund a fixture. Say so
        // here instead of letting `sendtoaddress` fail on an unexplained balance.
        let balance = self.balance_sats()?;
        if balance < sats {
            bail!(
                "the wallet holds {balance} sats but {sats} are needed; if this chain has mined \
                 past its subsidy, restart the node with `./scripts/regtest.sh up`"
            );
        }

        let txid: String = self
            .rpc
            .call(
                "sendtoaddress",
                &[json!(address), json!(sats as f64 / 100_000_000.0)],
            )
            .with_context(|| format!("sendtoaddress {sats} sats to {address}"))?;
        if confirm {
            self.mine(1)?;
        }
        txid.parse().context("the node returned an invalid txid")
    }

    /// Funds a key-path-only P2TR output and returns its outpoint and prevout.
    pub fn fund_p2tr(&self, key: [u8; 32], sats: u64) -> Result<(bitcoin::OutPoint, TxOut)> {
        let script = crate::keys::p2tr_script(key);
        let address = Address::from_script(&script, Network::Regtest)
            .context("the fixture P2TR script is not a valid address")?;
        let txid = self.fund(&address.to_string(), sats, true)?;
        // Locate the output by its script, not by its value: a change output could coincidentally
        // be worth the same amount.
        let (vout, prevout) = self.output_for_script(txid, &script)?;
        Ok((bitcoin::OutPoint { txid, vout }, prevout))
    }

    /// Finds the first output of `txid` that pays `script`.
    pub fn output_for_script(&self, txid: Txid, script: &ScriptBuf) -> Result<(u32, TxOut)> {
        let transaction = self.wallet_transaction(txid)?;
        transaction
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| &output.script_pubkey == script)
            .map(|(vout, output)| (vout as u32, output.clone()))
            .with_context(|| format!("{txid} has no output paying the expected script"))
    }

    /// Finds the first output of `txid` worth exactly `sats`.
    pub fn output_by_value(&self, txid: Txid, sats: u64) -> Result<(bitcoin::OutPoint, TxOut)> {
        wallet_output(&self.rpc, &txid.to_string(), sats)
    }

    /// Reads a wallet transaction.
    pub fn wallet_transaction(&self, txid: Txid) -> Result<Transaction> {
        let wallet_tx: serde_json::Value = self
            .rpc
            .call("gettransaction", &[json!(txid), json!(true)])
            .context("gettransaction")?;
        let raw = wallet_tx["hex"]
            .as_str()
            .context("the wallet transaction has no hex")?;
        bitcoin::consensus::deserialize(&hex::decode(raw).context("transaction hex")?)
            .context("transaction decode")
    }

    /// Asks the node what it would do with this transaction, without broadcasting it.
    pub fn test_mempool_accept(&self, transaction: &Transaction) -> Result<Verdict> {
        let result: serde_json::Value = self
            .rpc
            .call("testmempoolaccept", &[json!([serialize_hex(transaction)])])
            .context("testmempoolaccept")?;
        let entry = result
            .as_array()
            .and_then(|entries| entries.first())
            .context("testmempoolaccept returned no entry")?;
        Ok(Verdict {
            allowed: entry["allowed"].as_bool().unwrap_or(false),
            reject_reason: entry["reject-reason"].as_str().map(str::to_string),
            reject_details: entry["reject-details"].as_str().map(str::to_string),
            vsize: entry["vsize"].as_u64(),
        })
    }

    /// Broadcasts a transaction and optionally confirms it in the next block.
    pub fn broadcast(&self, transaction: &Transaction, confirm: bool) -> Result<Txid> {
        let txid: String = self
            .rpc
            .call("sendrawtransaction", &[json!(serialize_hex(transaction))])
            .context("sendrawtransaction")?;
        let txid: Txid = txid.parse().context("the node returned an invalid txid")?;
        if confirm {
            self.mine(1)?;
        }
        Ok(txid)
    }

    /// Reads a confirmed transaction back from the tip block.
    pub fn mined(&self, txid: Txid) -> Result<Transaction> {
        mined_transaction(&self.rpc, txid)
    }

    /// Returns whether `txid:vout` is confirmed and still unspent.
    pub fn unspent(&self, txid: Txid, vout: u32) -> Result<bool> {
        let output: serde_json::Value = self
            .rpc
            .call("gettxout", &[json!(txid), json!(vout)])
            .context("gettxout")?;
        Ok(!output.is_null())
    }

    /// Returns the first spendable wallet UTXO with at least one confirmation.
    pub fn spendable(&self) -> Result<(bitcoin::OutPoint, TxOut)> {
        let unspent: serde_json::Value = self.rpc.call("listunspent", &[json!(1)])?;
        let entry = unspent
            .as_array()
            .and_then(|entries| entries.first())
            .ok_or_else(|| anyhow!("the wallet has no spendable output"))?;
        let txid: Txid = entry["txid"]
            .as_str()
            .context("listunspent txid")?
            .parse()
            .context("listunspent txid")?;
        let vout = entry["vout"].as_u64().context("listunspent vout")? as u32;
        let transaction = self.wallet_transaction(txid)?;
        let prevout = transaction
            .output
            .get(vout as usize)
            .cloned()
            .context("listunspent vout is not in the transaction")?;
        Ok((bitcoin::OutPoint { txid, vout }, prevout))
    }

    /// Reports the node and wallet status as a JSON-friendly value.
    pub fn status(&self) -> Result<serde_json::Value> {
        Ok(json!({
            "height": self.height()?,
            "wallet": self.wallet,
            "mining_address": self.mining_address,
            "balance_sats": self.balance_sats()?,
        }))
    }
}

/// Returns the JSON form of a transaction id, for reports.
pub fn txid_hex(txid: Txid) -> Hex32 {
    Hex32::new(txid.to_byte_array())
}
