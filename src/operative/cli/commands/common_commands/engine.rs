use crate::communicative::peer::manager::engine_key;
use crate::operative::run_args::chain::Chain;

/// Prints the well-known engine public key (hex) for the active chain.
pub fn engine_command(chain: Chain) {
    println!("{}", hex::encode(engine_key(chain)));
}
