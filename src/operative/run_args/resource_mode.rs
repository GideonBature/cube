use std::fmt;

/// Operating mode type.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ResourceMode {
    Pruned,
    Archival,
}

impl fmt::Display for ResourceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ResourceMode::Pruned => "pruned",
            ResourceMode::Archival => "archival",
        })
    }
}
