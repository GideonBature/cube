use std::fmt;

/// Sync inflight type.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SyncMode {
    InFlight,
    ConfirmedOnly,
}

impl fmt::Display for SyncMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SyncMode::InFlight => "in-flight",
            SyncMode::ConfirmedOnly => "confirmed-only",
        })
    }
}
