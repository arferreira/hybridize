//! What hybridize reports: where a key-exchange configuration is, what it contains,
//! and how sure the analysis is.

use std::ops::Range;
use std::path::PathBuf;

use crate::group::Group;

/// Where a finding is in the source tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub file: PathBuf,
    /// Byte range of the configuration value. Patches edit exactly this range,
    /// so the rest of the file keeps its formatting.
    pub byte_range: Range<usize>,
    /// 1-based line, for humans.
    pub line: u32,
}

/// A value the analyzer either worked out or explicitly could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved<T> {
    Known(T),
    Unresolved(UnresolvedReason),
}

/// Why a value could not be resolved. Unresolved findings are reported, never patched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// Read from an environment variable.
    EnvVar(String),
    /// Comes from a config file, flag or other runtime input.
    RuntimeInput,
    /// Built through more calls than the analysis follows.
    CallDepthExceeded,
    /// Anything else, described in words.
    Other(String),
}

/// How sure the analysis is about a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// A runtime version such as Go 1.24 or OpenSSL 3.5.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuntimeVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl RuntimeVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// An explicitly configured list of TLS key-exchange groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable rule identifier, e.g. `go/curve-preferences`
    pub rule_id: &'static str,
    pub location: Location,
    /// The configured groups, in order, or why they could not be determined.
    pub groups: Resolved<Vec<Group>>,
    /// The runtime version in the code targets, if known (from `go.mod`, a Dockerfile, ....).
    pub runtime: Option<RuntimeVersion>,
    pub confidence: Confidence,
}

impl Finding {
    /// Whether the configured list leaves out every post-quantum group.
    /// `None` when the list is unresolved: hybridize does not guess.
    pub fn excludes_post_quantum(&self) -> Option<bool> {
        match &self.groups {
            Resolved::Known(groups) => Some(!groups.iter().any(Group::is_post_quantum)),
            Resolved::Unresolved(_) => None,
        }
    }

    /// Whether this finding is safe to turn into a patch.
    pub fn is_patchable(&self) -> bool {
        matches!(self.groups, Resolved::Known(_)) && self.confidence == Confidence::High
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(groups: Resolved<Vec<Group>>, confidence: Confidence) -> Finding {
        Finding {
            rule_id: "go/curve-preferences",
            location: Location {
                file: "server.go".into(),
                byte_range: 120..170,
                line: 12,
            },
            groups,
            runtime: Some(RuntimeVersion::new(1, 22, 0)),
            confidence,
        }
    }

    #[test]
    fn classical_only_list_excludes_post_quantum() {
        let f = finding(
            Resolved::Known(vec![Group::X25519, Group::P256]),
            Confidence::High,
        );
        assert_eq!(f.excludes_post_quantum(), Some(true));
        assert!(f.is_patchable());
    }

    #[test]
    fn list_with_hybrid_group_does_not_exclude_post_quantum() {
        let f = finding(
            Resolved::Known(vec![Group::X25519MlKem768, Group::X25519]),
            Confidence::High,
        );
        assert_eq!(f.excludes_post_quantum(), Some(false));
    }

    #[test]
    fn unresolved_list_is_reported_but_never_patched() {
        let f = finding(
            Resolved::Unresolved(UnresolvedReason::EnvVar("TLS_CURVES".into())),
            Confidence::High,
        );
        assert_eq!(f.excludes_post_quantum(), None);
        assert!(!f.is_patchable());
    }

    #[test]
    fn low_confidence_is_not_patched() {
        let f = finding(Resolved::Known(vec![Group::X25519]), Confidence::Medium);
        assert!(!f.is_patchable());
    }

    #[test]
    fn runtime_versions_order_correctly() {
        assert!(RuntimeVersion::new(1, 22, 0) < RuntimeVersion::new(1, 24, 0));
        assert!(RuntimeVersion::new(3, 5, 0) > RuntimeVersion::new(3, 0, 17));
    }
}
