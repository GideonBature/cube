//! The command-line surface.
//!
//! Every command prints one JSON object to stdout; progress and diagnostics go to stderr. That
//! split is what makes the tool scriptable: `cube-cli successor publish | jq -r .txid` composes,
//! while the human still sees what happened.
//!
//! Multi-step commands share one artifact file (`--state`, `cube-state.json` by default) instead of
//! long argument lists. A command loads it, applies one step, and writes it back atomically.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Scriptable regtest scenarios for the Cube ownership graph.
#[derive(Debug, Parser)]
#[command(
    name = "cube-cli",
    version,
    about = "Scriptable regtest scenarios for the Cube ownership graph",
    long_about = "Runs deposits, successors, claims, assertions and the composed scenarios against a \
                  Bitcoin Core regtest node. Every command prints one JSON object to stdout. All \
                  keys are public test fixtures; never point this at a network with value."
)]
pub struct Cli {
    /// Full RPC URL, e.g. `http://127.0.0.1:18443`.
    #[arg(long, global = true, env = "CUBE_REGTEST_RPC_URL")]
    pub rpc_url: Option<String>,
    /// RPC user, when user/password authentication is used.
    #[arg(long, global = true, env = "CUBE_REGTEST_RPC_USER")]
    pub rpc_user: Option<String>,
    /// RPC password.
    #[arg(
        long,
        global = true,
        env = "CUBE_REGTEST_RPC_PASSWORD",
        hide_env_values = true
    )]
    pub rpc_password: Option<String>,
    /// Bitcoin datadir, for cookie authentication.
    #[arg(long, global = true, env = "CUBE_REGTEST_DATADIR")]
    pub datadir: Option<String>,
    /// RPC port, when only a datadir or credentials are configured.
    #[arg(
        long,
        global = true,
        env = "CUBE_REGTEST_RPC_PORT",
        default_value_t = 18_443
    )]
    pub rpc_port: u16,
    /// The node wallet the commands use.
    #[arg(long, global = true, default_value = "cube-cli")]
    pub wallet: String,
    /// The artifact file the steps read and write.
    #[arg(long, global = true, default_value = "cube-state.json")]
    pub state: PathBuf,
    /// The step to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect or operate the regtest node.
    Node {
        /// The node operation.
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Print the deterministic test fixtures.
    Keys,
    /// Fund and inspect the LiftV2 deposit.
    Deposit {
        /// The deposit operation.
        #[command(subcommand)]
        command: DepositCommand,
    },
    /// Derive and inspect the transition manifest.
    Transition {
        /// The transition operation.
        #[command(subcommand)]
        command: TransitionCommand,
    },
    /// Publish and inspect the successor funding.
    Successor {
        /// The successor operation.
        #[command(subcommand)]
        command: SuccessorCommand,
    },
    /// List, recover or settle claims.
    Claim {
        /// The claim operation.
        #[command(subcommand)]
        command: ClaimCommand,
    },
    /// Assert, take or disprove a claim.
    Assertion {
        /// The assertion operation.
        #[command(subcommand)]
        command: AssertionCommand,
    },
    /// Inspect the proof input a claim binds.
    Proof {
        /// The proof operation.
        #[command(subcommand)]
        command: ProofCommand,
    },
    /// Attempt the LiftV2 script-path refund.
    Refund(RefundArgs),
    /// List or run composed scenarios.
    Scenario {
        /// The scenario operation.
        #[command(subcommand)]
        command: ScenarioCommand,
    },
}

/// Node operations.
#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Report the height, wallet and balance.
    Status,
    /// Mine blocks to the wallet.
    Mine {
        /// The number of blocks.
        #[arg(default_value_t = 1)]
        blocks: u64,
    },
    /// Fund an address from the wallet and confirm it.
    Fund {
        /// The destination address.
        address: String,
        /// The value in satoshis.
        sats: u64,
    },
}

/// Deposit operations.
#[derive(Debug, Subcommand)]
pub enum DepositCommand {
    /// Fund the fixture LiftV2 address and record the deposit.
    Fund {
        /// The deposit value in satoshis.
        #[arg(long, default_value_t = 500_000)]
        sats: u64,
    },
    /// Print the recorded deposit.
    Show,
    /// Re-check the deposit against the fixture address and the chain.
    Verify,
}

/// Transition operations.
#[derive(Debug, Subcommand)]
pub enum TransitionCommand {
    /// Run the reference model and derive the manifest.
    Build(TransitionArgs),
    /// Print the recorded transition.
    Show,
    /// Re-derive the transition and compare every stored byte.
    Verify,
}

/// Parameters of the derived transition.
#[derive(Debug, Args)]
pub struct TransitionArgs {
    /// The miner fee the successor leaves.
    #[arg(long, default_value_t = 2_000)]
    pub network_fee_reserve_sats: u64,
    /// The execution fee the manifest declares.
    #[arg(long, default_value_t = 5_000)]
    pub execution_fee_sats: u64,
    /// The relative challenge window, in blocks.
    #[arg(long, default_value_t = 144)]
    pub challenge_blocks: u32,
    /// The authenticated-input digest a real proof produced, hex.
    #[arg(long)]
    pub input_digest: Option<String>,
    /// The garbling-table digest a real table produced, hex.
    #[arg(long)]
    pub table_digest: Option<String>,
    /// The verifier-key identity a real verifying key produced, hex.
    #[arg(long)]
    pub verifier_key_identity: Option<String>,
}

/// Successor operations.
#[derive(Debug, Subcommand)]
pub enum SuccessorCommand {
    /// Build, verify, sign and publish the successor.
    Publish,
    /// Print the recorded successor.
    Show,
    /// Re-run the successor verifier and every claim package.
    Verify,
}

/// Claim operations.
#[derive(Debug, Subcommand)]
pub enum ClaimCommand {
    /// List the claims the successor funded.
    List,
    /// Spend one claim through its v2 recovery package.
    Recover(RecoverArgs),
    /// Spend every claim in one cooperative settlement.
    Settle(SettleArgs),
}

/// Parameters of a claim recovery.
#[derive(Debug, Args)]
pub struct RecoverArgs {
    /// The claim index.
    #[arg(default_value_t = 0)]
    pub index: usize,
    /// The destination address; a fresh wallet address when absent.
    #[arg(long)]
    pub to: Option<String>,
    /// The miner fee in satoshis.
    #[arg(long, default_value_t = 1_000)]
    pub fee_sats: u64,
}

/// Parameters of a cooperative settlement.
#[derive(Debug, Args)]
pub struct SettleArgs {
    /// One destination per claim, in claim order; fresh wallet addresses when absent.
    #[arg(long = "to", num_args = 1..)]
    pub to: Vec<String>,
    /// The value of the external fee input, which becomes the miner fee.
    #[arg(long, default_value_t = 2_000)]
    pub fee_input_sats: u64,
}

/// Assertion operations.
#[derive(Debug, Subcommand)]
pub enum AssertionCommand {
    /// Publish an assertion for one claim.
    Assert(AssertArgs),
    /// Spend the assertion output after the challenge window.
    Take(TakeArgs),
    /// Spend the assertion output with the disclosure secret.
    Disprove(DisproveArgs),
}

/// Parameters of an assertion.
#[derive(Debug, Args)]
pub struct AssertArgs {
    /// The claim index.
    #[arg(default_value_t = 0)]
    pub index: usize,
    /// The miner fee in satoshis.
    #[arg(long, default_value_t = 1_000)]
    pub fee_sats: u64,
}

/// Parameters of a take.
#[derive(Debug, Args)]
pub struct TakeArgs {
    /// The destination address; a fresh wallet address when absent.
    #[arg(long)]
    pub to: Option<String>,
    /// The miner fee in satoshis.
    #[arg(long, default_value_t = 500)]
    pub fee_sats: u64,
    /// Mine the challenge window instead of reporting the premature rejection.
    #[arg(long)]
    pub wait: bool,
}

/// Parameters of a disprove.
#[derive(Debug, Args)]
pub struct DisproveArgs {
    /// The destination address; a fresh wallet address when absent.
    #[arg(long)]
    pub to: Option<String>,
    /// The miner fee in satoshis.
    #[arg(long, default_value_t = 500)]
    pub fee_sats: u64,
    /// The disclosure secret, hex. Defaults to the fixture committed by the terms.
    #[arg(long)]
    pub secret: Option<String>,
}

/// Proof operations.
#[derive(Debug, Subcommand)]
pub enum ProofCommand {
    /// Print the assertion terms and the scripts a proof input binds.
    Envelope(EnvelopeArgs),
}

/// Parameters of the proof envelope.
#[derive(Debug, Args)]
pub struct EnvelopeArgs {
    /// The claim index.
    #[arg(default_value_t = 0)]
    pub index: usize,
}

/// Parameters of a refund.
#[derive(Debug, Args)]
pub struct RefundArgs {
    /// The destination address; a fresh wallet address when absent.
    #[arg(long)]
    pub to: Option<String>,
    /// The miner fee in satoshis.
    #[arg(long, default_value_t = 500)]
    pub fee_sats: u64,
    /// Mine past the relative timelock and publish the mature refund.
    #[arg(long)]
    pub mine_past_maturity: bool,
}

/// Scenario operations.
#[derive(Debug, Subcommand)]
pub enum ScenarioCommand {
    /// List the scenarios and what they exercise.
    List,
    /// Run one scenario against a fresh deposit.
    Run(ScenarioRunArgs),
}

/// Parameters of a scenario run.
#[derive(Debug, Args)]
pub struct ScenarioRunArgs {
    /// The scenario name.
    pub name: String,
    /// The deposit value in satoshis.
    #[arg(long, default_value_t = 500_000)]
    pub sats: u64,
    /// The execution fee the manifest declares.
    #[arg(long, default_value_t = 5_000)]
    pub execution_fee_sats: u64,
    /// The relative challenge window, in blocks.
    #[arg(long, default_value_t = 144)]
    pub challenge_blocks: u32,
    /// The destination every payout uses; fresh wallet addresses when absent.
    #[arg(long)]
    pub to: Option<String>,
    /// The miner fee of an assertion.
    #[arg(long, default_value_t = 1_000)]
    pub claim_fee_sats: u64,
    /// The miner fee of a take, disprove or recovery.
    #[arg(long, default_value_t = 500)]
    pub payout_fee_sats: u64,
    /// The value of the external fee input a settlement spends.
    #[arg(long, default_value_t = 2_000)]
    pub settle_fee_input_sats: u64,
}
