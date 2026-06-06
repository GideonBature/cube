use std::fmt;

/// Chain type.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Chain {
    // For local tests (./tests/) involving db operations.
    Testbed,
    // For signet.
    Signet,
    // For mainnet.
    Mainnet,
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Chain::Testbed => "testbed",
            Chain::Signet => "signet",
            Chain::Mainnet => "mainnet",
        })
    }
}
