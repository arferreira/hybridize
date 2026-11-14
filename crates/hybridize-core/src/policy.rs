//! Target policies for migration plans.

use std::fmt;
use std::str::FromStr;

/// The policy a migration plan targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// General and commercial systems: hybrid groups such as X25519MLKEM768.
    General,
    /// NSA CNSA 2.0 for National Security Systems.
    Cnsa2,
    /// Executive Order 14412 timelines for federal systems.
    Eo14412,
}

impl Policy {
    pub const ALL: [Policy; 3] = [Policy::General, Policy::Cnsa2, Policy::Eo14412];

    pub fn as_str(self) -> &'static str {
        match self {
            Policy::General => "general",
            Policy::Cnsa2 => "cnsa2",
            Policy::Eo14412 => "eo14412",
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Policy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Policy::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| {
                let valid: Vec<_> = Policy::ALL.iter().map(|p| p.as_str()).collect();
                format!(
                    "unknown policy `{s}` (expected one of: {})",
                    valid.join(", ")
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_policy() {
        for p in Policy::ALL {
            assert_eq!(p.as_str().parse::<Policy>(), Ok(p));
        }
    }

    #[test]
    fn rejects_unknown_policy() {
        assert!("hybrid".parse::<Policy>().is_err());
    }
}
