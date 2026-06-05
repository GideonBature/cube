use std::fmt;

/// Operating kind type.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum OperatingKind {
    Node,
    Engine,
}

impl fmt::Display for OperatingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OperatingKind::Node => "node",
            OperatingKind::Engine => "engine",
        })
    }
}
