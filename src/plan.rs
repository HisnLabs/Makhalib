//! The keystone: [`ScanPlan`] is the declarative, reviewable artifact that the
//! NL brain compiles intent into and the engine executes. It is the contract
//! that makes the tool "no code" — targets, probes, detectors and the harness
//! are all named/configured here as data, never written as code.
//!
//! A plan is the unit of reproducibility: the LLM authors it, a human reviews
//! and may hand-edit it, and re-running the same plan is deterministic.

use serde::{Deserialize, Serialize};

/// Authorization gate. Execution MUST refuse unless `authorized` is true; `scope`
/// records the operator's attestation of what they are permitted to test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub authorized: bool,
    #[serde(default)]
    pub scope: String,
}

impl Default for Authorization {
    fn default() -> Self {
        Self { authorized: false, scope: String::new() }
    }
}

/// Declarative target config: a `kind` (preset or `rest`) plus a free-form config
/// map the matching generator factory parses. No code to add a target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetSpec {
    pub kind: String,
    #[serde(default)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

/// Declarative harness/strategy config. `kind` is e.g. `probewise` or `multiturn`;
/// `config` carries strategy parameters (attacker/judge model, max turns, …).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HarnessSpec {
    pub kind: String,
    #[serde(default)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

impl Default for HarnessSpec {
    fn default() -> Self {
        Self { kind: "probewise".into(), config: serde_json::Map::new() }
    }
}

fn default_concurrency() -> usize {
    8
}

fn default_version() -> String {
    "1".into()
}

/// A complete, executable red-teaming plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanPlan {
    #[serde(default = "default_version")]
    pub version: String,
    pub authorization: Authorization,
    pub target: TargetSpec,
    #[serde(default)]
    pub probes: Vec<String>,
    #[serde(default)]
    pub detectors: Vec<String>,
    #[serde(default)]
    pub buffs: Vec<String>,
    #[serde(default)]
    pub harness: HarnessSpec,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("plan is not authorized: set authorization.authorized=true to run (authorized testing only)")]
    Unauthorized,
    #[error("plan has no target.kind")]
    MissingTarget,
    #[error("plan selects no probes")]
    NoProbes,
    #[error("concurrency must be >= 1")]
    ZeroConcurrency,
}

impl ScanPlan {
    /// Validate a plan is safe and runnable. The authorization gate is checked
    /// first — an unauthorized plan is rejected regardless of other fields.
    pub fn validate(&self) -> Result<(), PlanError> {
        if !self.authorization.authorized {
            return Err(PlanError::Unauthorized);
        }
        if self.target.kind.trim().is_empty() {
            return Err(PlanError::MissingTarget);
        }
        if self.probes.is_empty() {
            return Err(PlanError::NoProbes);
        }
        if self.concurrency == 0 {
            return Err(PlanError::ZeroConcurrency);
        }
        Ok(())
    }

    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(s)
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized_plan() -> ScanPlan {
        ScanPlan {
            version: "1".into(),
            authorization: Authorization { authorized: true, scope: "my own ollama".into() },
            target: TargetSpec { kind: "ollama".into(), config: serde_json::Map::new() },
            probes: vec!["dan.Dan_11_0".into()],
            detectors: vec![],
            buffs: vec![],
            harness: HarnessSpec::default(),
            concurrency: 4,
        }
    }

    #[test]
    fn valid_plan_passes() {
        assert!(authorized_plan().validate().is_ok());
    }

    #[test]
    fn unauthorized_plan_is_rejected_first() {
        let mut p = authorized_plan();
        p.authorization.authorized = false;
        p.probes.clear(); // also invalid, but auth must be the reported error
        assert_eq!(p.validate(), Err(PlanError::Unauthorized));
    }

    #[test]
    fn plan_without_probes_is_rejected() {
        let mut p = authorized_plan();
        p.probes.clear();
        assert_eq!(p.validate(), Err(PlanError::NoProbes));
    }

    #[test]
    fn zero_concurrency_is_rejected() {
        let mut p = authorized_plan();
        p.concurrency = 0;
        assert_eq!(p.validate(), Err(PlanError::ZeroConcurrency));
    }

    #[test]
    fn missing_target_is_rejected() {
        let mut p = authorized_plan();
        p.target.kind = "  ".into();
        assert_eq!(p.validate(), Err(PlanError::MissingTarget));
    }

    #[test]
    fn yaml_round_trips() {
        let p = authorized_plan();
        let yaml = p.to_yaml().unwrap();
        let back = ScanPlan::from_yaml(&yaml).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn defaults_apply_from_minimal_yaml() {
        // No version, harness, or concurrency given → defaults fill in.
        let yaml = r#"
authorization:
  authorized: true
  scope: lab
target:
  kind: mock
probes:
  - test.Blank
"#;
        let p = ScanPlan::from_yaml(yaml).unwrap();
        assert_eq!(p.version, "1");
        assert_eq!(p.concurrency, 8);
        assert_eq!(p.harness.kind, "probewise");
        assert!(p.validate().is_ok());
    }
}
