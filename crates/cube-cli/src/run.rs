//! Command dispatch.
//!
//! Read-only commands never open the node, so an artifact can be inspected on a machine without
//! Bitcoin Core. Every mutating command loads the state file, applies exactly one step, and writes
//! the file back only after the step succeeded.

use crate::cli::{
    ClaimCommand, Cli, Command, DepositCommand, DisproveArgs, NodeCommand, ProofCommand,
    RecoverArgs, RefundArgs, ScenarioCommand, ScenarioRunArgs, SuccessorCommand, TakeArgs,
    TransitionArgs, TransitionCommand,
};
use anyhow::{Context, Result};
use cube_scenario::artifact::{Hex32, State};
use cube_scenario::chain::Chain;
use cube_scenario::rpc::RpcConfig;
use cube_scenario::{keys, scenario};
use serde_json::{json, Value};
use std::path::Path;

/// Runs the requested command and returns its JSON artifact.
pub fn dispatch(cli: Cli) -> Result<Value> {
    // 1 Commands that only read the state file.
    match &cli.command {
        Command::Keys => return keys_report(),
        Command::Deposit {
            command: DepositCommand::Show,
        } => return show_deposit(&cli.state),
        Command::Transition {
            command: TransitionCommand::Show,
        } => return show_transition(&cli.state),
        Command::Successor {
            command: SuccessorCommand::Show,
        } => return show_successor(&cli.state),
        Command::Claim {
            command: ClaimCommand::List,
        } => return list_claims(&cli.state),
        Command::Proof {
            command: ProofCommand::Envelope(args),
        } => {
            let state = State::load(&cli.state)?;
            return scenario::proof_envelope(&state, args.index);
        }
        Command::Scenario {
            command: ScenarioCommand::List,
        } => return Ok(scenario_list()),
        _ => {}
    }

    // 2 Everything else needs the node.
    let mut state = State::load(&cli.state)?;
    if state.wallet.is_empty() {
        state.wallet = cli.wallet.clone();
    }
    let chain = Chain::open(&rpc_config(&cli), &cli.wallet)?;

    let value = match &cli.command {
        Command::Node { command } => match command {
            NodeCommand::Status => chain.status()?,
            NodeCommand::Mine { blocks } => {
                let height = chain.mine(*blocks)?;
                json!({ "mined": blocks, "height": height })
            }
            NodeCommand::Fund { address, sats } => {
                let txid = chain.fund(address, *sats, true)?;
                json!({ "txid": txid.to_string(), "address": address, "sats": sats })
            }
        },
        Command::Deposit { command } => match command {
            DepositCommand::Fund { sats } => {
                let deposit = scenario::fund_deposit(&chain, &mut state, *sats)?;
                state.wallet = cli.wallet.clone();
                state.save(&cli.state)?;
                serde_json::to_value(&deposit)?
            }
            DepositCommand::Show => unreachable!("handled before the node is opened"),
        },
        Command::Transition { command } => match command {
            TransitionCommand::Build(args) => {
                let options = transition_options(args)?;
                let transition = scenario::build_transition(&mut state, &options)?;
                state.wallet = cli.wallet.clone();
                state.save(&cli.state)?;
                serde_json::to_value(&transition)?
            }
            TransitionCommand::Show => unreachable!("handled before the node is opened"),
        },
        Command::Successor { command } => match command {
            SuccessorCommand::Publish => {
                let tree = scenario::publish_successor(&chain, &mut state)?;
                state.wallet = cli.wallet.clone();
                state.save(&cli.state)?;
                serde_json::to_value(&tree)?
            }
            SuccessorCommand::Show => unreachable!("handled before the node is opened"),
        },
        Command::Claim { command } => match command {
            ClaimCommand::List => unreachable!("handled before the node is opened"),
            ClaimCommand::Recover(args) => {
                let outcome = recover(&chain, &mut state, args)?;
                state.save(&cli.state)?;
                outcome
            }
            ClaimCommand::Settle(args) => {
                let destinations = if args.to.is_empty() {
                    None
                } else {
                    Some(args.to.clone())
                };
                let outcome =
                    scenario::settle_claims(&chain, &mut state, destinations, args.fee_input_sats)?;
                state.save(&cli.state)?;
                serde_json::to_value(&outcome)?
            }
        },
        Command::Assertion { command } => match command {
            crate::cli::AssertionCommand::Assert(args) => {
                let outcome =
                    scenario::assert_claim(&chain, &mut state, args.index, args.fee_sats)?;
                state.save(&cli.state)?;
                json!({
                    "txid": outcome.txid,
                    "claim_index": outcome.claim_index,
                    "value_sats": outcome.value_sats,
                    "assertion": state.assertion,
                })
            }
            crate::cli::AssertionCommand::Take(args) => {
                let outcome = take(&chain, &mut state, args)?;
                state.save(&cli.state)?;
                outcome
            }
            crate::cli::AssertionCommand::Disprove(args) => {
                let outcome = disprove(&chain, &mut state, args)?;
                state.save(&cli.state)?;
                outcome
            }
        },
        Command::Proof { command } => match command {
            ProofCommand::Envelope(_) => unreachable!("handled before the node is opened"),
        },
        Command::Refund(args) => {
            let outcome = refund(&chain, &mut state, args)?;
            state.save(&cli.state)?;
            outcome
        }
        Command::Scenario { command } => match command {
            ScenarioCommand::List => unreachable!("handled before the node is opened"),
            ScenarioCommand::Run(args) => {
                let options = scenario_options(args);
                let report = scenario::run(&args.name, &chain, &mut state, &options)?;
                state.wallet = cli.wallet.clone();
                state.save(&cli.state)?;
                serde_json::to_value(&report)?
            }
        },
        Command::Keys => unreachable!("handled before the node is opened"),
    };

    Ok(value)
}

/// Builds the node configuration from the global flags.
fn rpc_config(cli: &Cli) -> RpcConfig {
    RpcConfig {
        url: cli.rpc_url.clone(),
        user: cli.rpc_user.clone(),
        password: cli.rpc_password.clone(),
        datadir: cli.datadir.clone(),
        port: cli.rpc_port,
    }
}

/// Returns the fixture report.
fn keys_report() -> Result<Value> {
    let fixtures = keys::FIXTURES
        .iter()
        .map(|(name, role, secret)| {
            json!({
                "name": name,
                "role": role,
                "secret": hex::encode(secret),
                "xonly": hex::encode(keys::xonly(*secret)),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "warning": "Deterministic regtest fixtures. Never use these keys on a network with value.",
        "deposit_address": keys::liftv2_address(),
        "refund_delay_blocks": keys::REFUND_DELAY_BLOCKS,
        "keys": fixtures,
    }))
}

/// Prints the recorded deposit.
fn show_deposit(path: &Path) -> Result<Value> {
    let state = State::load(path)?;
    Ok(serde_json::to_value(state.require_deposit()?)?)
}

/// Prints the recorded transition.
fn show_transition(path: &Path) -> Result<Value> {
    let state = State::load(path)?;
    Ok(serde_json::to_value(state.require_transition()?)?)
}

/// Prints the recorded successor.
fn show_successor(path: &Path) -> Result<Value> {
    let state = State::load(path)?;
    Ok(serde_json::to_value(state.require_tree()?)?)
}

/// Lists the claims the successor funded.
fn list_claims(path: &Path) -> Result<Value> {
    let state = State::load(path)?;
    let tree = state.require_tree()?;
    let claims = tree
        .claims
        .iter()
        .map(|claim| {
            json!({
                "index": claim.index,
                "vout": claim.vout,
                "beneficiary": keys::name_for_xonly(claim.beneficiary_key.0).unwrap_or("unknown"),
                "beneficiary_key": claim.beneficiary_key,
                "amount_sats": claim.amount_sats,
                "binding_digest": claim.terms.binding_digest(),
                "challenge_blocks": claim.terms.challenge_blocks,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "successor": tree.txid,
        "statement_vout": tree.statement_vout,
        "claims": claims,
    }))
}

/// Lists the scenarios.
fn scenario_list() -> Value {
    let scenarios = scenario::SCENARIOS
        .iter()
        .map(|(name, description)| json!({ "name": name, "description": description }))
        .collect::<Vec<_>>();
    json!({ "scenarios": scenarios })
}

/// Parses the optional digest overrides.
fn parse_digest(value: &Option<String>) -> Result<Option<[u8; 32]>> {
    value
        .as_deref()
        .map(|text| -> Result<[u8; 32]> {
            Ok(text
                .parse::<Hex32>()
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("`{text}` is not a 32-byte hex digest"))?
                .bytes())
        })
        .transpose()
}

/// Builds transition options from the command line.
fn transition_options(
    args: &TransitionArgs,
) -> Result<cube_scenario::transition::TransitionOptions> {
    Ok(cube_scenario::transition::TransitionOptions {
        network_fee_reserve_sats: args.network_fee_reserve_sats,
        execution_fee_sats: args.execution_fee_sats,
        challenge_blocks: args.challenge_blocks,
        verifier_key_identity: parse_digest(&args.verifier_key_identity)?,
        table_digest: parse_digest(&args.table_digest)?,
        input_digest: parse_digest(&args.input_digest)?,
    })
}

/// Builds scenario options from the command line.
fn scenario_options(args: &ScenarioRunArgs) -> scenario::ScenarioOptions {
    scenario::ScenarioOptions {
        deposit_sats: args.sats,
        execution_fee_sats: args.execution_fee_sats,
        challenge_blocks: args.challenge_blocks,
        destination: args.to.clone(),
        claim_fee_sats: args.claim_fee_sats,
        payout_fee_sats: args.payout_fee_sats,
        settle_fee_input_sats: args.settle_fee_input_sats,
    }
}

/// Recovers one claim.
fn recover(chain: &Chain, state: &mut State, args: &RecoverArgs) -> Result<Value> {
    let outcome =
        scenario::recover_claim(chain, state, args.index, args.to.clone(), args.fee_sats)?;
    Ok(serde_json::to_value(&outcome)?)
}

/// Takes the stored assertion.
fn take(chain: &Chain, state: &mut State, args: &TakeArgs) -> Result<Value> {
    let outcome =
        scenario::take_assertion(chain, state, args.to.clone(), args.fee_sats, args.wait)?;
    Ok(serde_json::to_value(&outcome)?)
}

/// Disproves the stored assertion.
fn disprove(chain: &Chain, state: &mut State, args: &DisproveArgs) -> Result<Value> {
    let secret = match args.secret.as_deref() {
        Some(text) => text
            .parse::<Hex32>()
            .map_err(anyhow::Error::msg)
            .context("the disclosure secret must be 32 bytes of hex")?
            .bytes(),
        None => keys::DISCLOSURE_SECRET,
    };
    let outcome =
        scenario::disprove_assertion(chain, state, args.to.clone(), secret, args.fee_sats)?;
    Ok(serde_json::to_value(&outcome)?)
}

/// Attempts the refund.
fn refund(chain: &Chain, state: &mut State, args: &RefundArgs) -> Result<Value> {
    let outcome = scenario::refund_deposit(
        chain,
        state,
        args.to.clone(),
        args.fee_sats,
        args.mine_past_maturity,
    )?;
    Ok(serde_json::to_value(&outcome)?)
}
