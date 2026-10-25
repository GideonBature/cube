//! The JSON artifacts the CLI reads and writes.
//!
//! Every command is a pure step over one [`State`] file: it loads the artifacts earlier steps
//! produced, derives its transaction from them, and writes the artifacts it learned back. That is
//! what makes the CLI scriptable — a shell script can chain `deposit fund`, `transition build`,
//! `successor publish` and `claim recover` without passing a dozen hex values on the command line,
//! and a failed step leaves the previous state untouched.
//!
//! Fixed-width values are hex strings on the wire, not JSON arrays of 255 numbers. The canonical
//! encodings the repository already freezes — the manifest, the recovery package, a transaction —
//! travel as hex of the encoded bytes, so the artifact never becomes a second, drifting schema.

use crate::engine::VmExecution;
use crate::DebugContext;
use anyhow::{bail, Context, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::{OutPoint, ScriptBuf};
use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::ClaimRecoveryPackage;
use cube::constructive::graph::assertion::AssertionTerms;
use cube::model::fixed_split_vault_v1::manifest::{Anchor, TransitionManifest};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::io::ErrorKind;
use std::path::Path;

/// The schema version of the state file.
pub const STATE_VERSION: u8 = 1;

/// The network these artifacts describe. The CLI only speaks regtest.
pub const NETWORK: &str = "regtest";

/// A fixed-width byte string serialised as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hex<const N: usize>(pub [u8; N]);

/// A 32-byte digest, key or transaction id.
pub type Hex32 = Hex<32>;
/// A 16-byte setup instance.
pub type Hex16 = Hex<16>;
/// A 64-byte BIP-340 signature.
pub type Hex64 = Hex<64>;

impl<const N: usize> Hex<N> {
    /// Wraps raw bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub fn bytes(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> fmt::Debug for Hex<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl<const N: usize> fmt::Display for Hex<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl<const N: usize> std::str::FromStr for Hex<N> {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim().strip_prefix("0x").unwrap_or(text.trim());
        let bytes = hex::decode(text).map_err(|error| error.to_string())?;
        let array: [u8; N] = bytes
            .try_into()
            .map_err(|_| format!("expected {N} bytes"))?;
        Ok(Self(array))
    }
}

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(text.trim()).map_err(serde::de::Error::custom)?;
        let array: [u8; N] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes")))?;
        Ok(Self(array))
    }
}

/// The frozen assertion terms, with hex fields so they can be inspected in a JSON artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terms {
    /// The statement digest the claim commits.
    pub statement_digest: Hex32,
    /// The stable claim identity.
    pub claim_id: Hex32,
    /// The setup instance the table belongs to.
    pub setup_instance_id: Hex16,
    /// The verifier key identity.
    pub verifier_key_identity: Hex32,
    /// The digest of the garbling table.
    pub table_digest: Hex32,
    /// The commitment the `Disprove` hashlock checks.
    pub secret_commitment: Hex32,
    /// The digest of the published authenticated input.
    pub input_digest: Hex32,
    /// The relative timelock before `Take` is valid.
    pub challenge_blocks: u32,
    /// The only key that can `Take`.
    pub operator_key: Hex32,
    /// The only key that can `Disprove`.
    pub beneficiary_key: Hex32,
}

impl Terms {
    /// Converts to the executable terms.
    pub fn to_terms(&self) -> AssertionTerms {
        AssertionTerms {
            statement_digest: self.statement_digest.0,
            claim_id: self.claim_id.0,
            setup_instance_id: self.setup_instance_id.0,
            verifier_key_identity: self.verifier_key_identity.0,
            table_digest: self.table_digest.0,
            secret_commitment: self.secret_commitment.0,
            input_digest: self.input_digest.0,
            challenge_blocks: self.challenge_blocks,
            operator_key: self.operator_key.0,
            beneficiary_key: self.beneficiary_key.0,
        }
    }

    /// Returns the tagged binding digest embedded in the claim and the assertion output.
    pub fn binding_digest(&self) -> Hex32 {
        Hex::new(self.to_terms().binding_digest())
    }
}

impl From<&AssertionTerms> for Terms {
    fn from(terms: &AssertionTerms) -> Self {
        Self {
            statement_digest: Hex::new(terms.statement_digest),
            claim_id: Hex::new(terms.claim_id),
            setup_instance_id: Hex::new(terms.setup_instance_id),
            verifier_key_identity: Hex::new(terms.verifier_key_identity),
            table_digest: Hex::new(terms.table_digest),
            secret_commitment: Hex::new(terms.secret_commitment),
            input_digest: Hex::new(terms.input_digest),
            challenge_blocks: terms.challenge_blocks,
            operator_key: Hex::new(terms.operator_key),
            beneficiary_key: Hex::new(terms.beneficiary_key),
        }
    }
}

/// A funded LiftV2 deposit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deposit {
    /// The Base58/bech32m address the deposit pays to.
    pub address: String,
    /// The taproot scriptpubkey, hex.
    pub script_pubkey: String,
    /// The participant key in the MuSig2 aggregate.
    pub account_key: Hex32,
    /// The Engine key in the MuSig2 aggregate.
    pub engine_key: Hex32,
    /// The relative timelock of the refund leaf, in blocks.
    pub refund_delay_blocks: u16,
    /// The funding transaction.
    pub funding_txid: Hex32,
    /// The deposit output index.
    pub funding_vout: u32,
    /// The deposit value in satoshis.
    pub value_sats: u64,
}

impl Deposit {
    /// Returns the deposit scriptpubkey.
    pub fn spk(&self) -> Result<ScriptBuf> {
        Ok(ScriptBuf::from_bytes(
            hex::decode(&self.script_pubkey).context("deposit scriptpubkey is not hex")?,
        ))
    }

    /// Returns the deposit outpoint.
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_byte_array(self.funding_txid.0),
            vout: self.funding_vout,
        }
    }
}

/// Returns the manifest anchor a deposit occupies.
pub fn anchor_of(deposit: &Deposit) -> Anchor {
    Anchor::new(deposit.funding_txid.0, deposit.funding_vout)
}

/// One beneficiary claim of the transition, in manifest order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimBinding {
    /// The stable claim identity.
    pub claim_id: Hex32,
    /// The beneficiary key the claim pays.
    pub beneficiary_key: Hex32,
    /// The allocation in satoshis.
    pub amount_sats: u64,
    /// The tagged assertion binding digest embedded in the claim.
    pub binding_digest: Hex32,
    /// The full assertion terms the binding commits.
    pub terms: Terms,
}

/// A derived transition: the manifest and the two claim bindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    /// The canonical manifest encoding, hex.
    pub manifest: String,
    /// The field-sized statement digest the manifest commits.
    pub statement_digest: Hex32,
    /// The deposit value minus the successor miner fee.
    pub gross_sats: u64,
    /// The execution fee the manifest declares.
    pub execution_fee_sats: u64,
    /// The miner fee the successor leaves.
    pub network_fee_reserve_sats: u64,
    /// The relative challenge window, in blocks.
    pub challenge_blocks: u32,
    /// The script the successor pays the execution fee to, hex.
    pub fee_script: String,
    /// The CubeVM execution the manifest was derived from, when this transition is VM-derived.
    #[serde(default)]
    pub vm: Option<VmExecution>,
    /// One binding per beneficiary allocation, in manifest order.
    pub claims: Vec<ClaimBinding>,
}

impl Transition {
    /// Decodes the manifest.
    pub fn manifest(&self) -> Result<TransitionManifest> {
        let bytes = hex::decode(&self.manifest).context("manifest is not hex")?;
        TransitionManifest::decode(&bytes).context_debug("manifest does not decode")
    }

    /// Returns the claim binding at `index`.
    pub fn claim(&self, index: usize) -> Result<&ClaimBinding> {
        self.claims.get(index).with_context(|| {
            format!(
                "claim {index} does not exist; the transition has {} claims",
                self.claims.len()
            )
        })
    }

    /// Returns the beneficiary bindings in manifest order.
    pub fn bindings(&self) -> Vec<[u8; 32]> {
        self.claims
            .iter()
            .map(|claim| claim.binding_digest.0)
            .collect()
    }

    /// Returns the execution-fee output script.
    pub fn fee_script(&self) -> Result<ScriptBuf> {
        Ok(ScriptBuf::from_bytes(
            hex::decode(&self.fee_script).context("fee script is not hex")?,
        ))
    }
}

/// One funded claim of a published successor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeClaim {
    /// The claim's position in the transition.
    pub index: u32,
    /// The claim's position in the successor transaction.
    pub vout: u32,
    /// The beneficiary key the claim pays.
    pub beneficiary_key: Hex32,
    /// The allocation in satoshis.
    pub amount_sats: u64,
    /// The claim scriptpubkey, hex.
    pub script_pubkey: String,
    /// The v2 recovery package, hex.
    pub package: String,
    /// The assertion terms embedded in the claim.
    pub terms: Terms,
}

impl TreeClaim {
    /// Decodes the recovery package.
    pub fn package(&self) -> Result<ClaimRecoveryPackage> {
        ClaimRecoveryPackage::decode(&hex::decode(&self.package).context("package is not hex")?)
            .context_debug("package does not decode")
    }

    /// Returns the claim scriptpubkey.
    pub fn spk(&self) -> Result<ScriptBuf> {
        Ok(ScriptBuf::from_bytes(
            hex::decode(&self.script_pubkey).context("claim scriptpubkey is not hex")?,
        ))
    }
}

/// A published successor funding and the claims it created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tree {
    /// The successor transaction id.
    pub txid: Hex32,
    /// The signed successor transaction, hex.
    pub hex: String,
    /// The `OP_RETURN` statement commitment output index.
    pub statement_vout: u32,
    /// One claim per beneficiary allocation, in manifest order.
    pub claims: Vec<TreeClaim>,
}

impl Tree {
    /// Returns the claim at `index`.
    pub fn claim(&self, index: usize) -> Result<&TreeClaim> {
        self.claims.get(index).with_context(|| {
            format!(
                "claim {index} does not exist; the tree has {} claims",
                self.claims.len()
            )
        })
    }

    /// Returns a claim outpoint.
    pub fn outpoint(&self, claim: &TreeClaim) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_byte_array(self.txid.0),
            vout: claim.vout,
        }
    }
}

/// A published assertion output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionState {
    /// The claim the assertion contested.
    pub claim_index: u32,
    /// The terms the assertion output commits.
    pub terms: Terms,
    /// The value the assertion output holds.
    pub value_sats: u64,
    /// The miner fee the `Assert` transaction left.
    pub fee_sats: u64,
    /// The assertion transaction id.
    pub txid: Hex32,
    /// The signed assertion transaction, hex.
    pub hex: String,
}

/// The artifact file the CLI mutates step by step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// The schema version.
    pub version: u8,
    /// The network name.
    pub network: String,
    /// The node wallet used by the commands.
    pub wallet: String,
    /// The funded deposit, if any.
    pub deposit: Option<Deposit>,
    /// The derived transition, if any.
    pub transition: Option<Transition>,
    /// The published successor, if any.
    pub tree: Option<Tree>,
    /// The published assertion, if any.
    pub assertion: Option<AssertionState>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// Returns an empty state.
    pub fn new() -> Self {
        Self {
            version: STATE_VERSION,
            network: NETWORK.to_string(),
            wallet: String::new(),
            deposit: None,
            transition: None,
            tree: None,
            assertion: None,
        }
    }

    /// Loads a state file, or returns an empty state when the file does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Self::new()),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()))
            }
        };
        let state: Self = serde_json::from_str(&text)
            .with_context(|| format!("cannot parse {}", path.display()))?;
        if state.version != STATE_VERSION {
            bail!(
                "{} has state version {}, expected {}",
                path.display(),
                state.version,
                STATE_VERSION
            );
        }
        Ok(state)
    }

    /// Writes the state file atomically, so a failed command never leaves a half-written artifact.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
        }
        let mut text = serde_json::to_string_pretty(self).context("cannot encode the state")?;
        text.push('\n');
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, text)
            .with_context(|| format!("cannot write {}", temporary.display()))?;
        std::fs::rename(&temporary, path)
            .with_context(|| format!("cannot replace {}", path.display()))?;
        Ok(())
    }

    /// Returns the deposit or explains which command creates it.
    pub fn require_deposit(&self) -> Result<&Deposit> {
        self.deposit
            .as_ref()
            .context("no deposit in the state; run `cube-cli deposit fund` first")
    }

    /// Returns the transition or explains which command creates it.
    pub fn require_transition(&self) -> Result<&Transition> {
        self.transition
            .as_ref()
            .context("no transition in the state; run `cube-cli transition build` first")
    }

    /// Returns the published tree or explains which command creates it.
    pub fn require_tree(&self) -> Result<&Tree> {
        self.tree
            .as_ref()
            .context("no published successor in the state; run `cube-cli successor publish` first")
    }

    /// Returns the assertion or explains which command creates it.
    pub fn require_assertion(&self) -> Result<&AssertionState> {
        self.assertion
            .as_ref()
            .context("no assertion in the state; run `cube-cli assertion assert` first")
    }
}
