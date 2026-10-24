//! Port of augustus `patterns.Patterns` (Apache-2.0, praetorian-inc/augustus).
//!
//! Regex pattern detector with three combination modes:
//! - `any`: the highest severity among matching patterns (0 if none match)
//! - `all`: the highest severity, but only if every pattern matches (else 0)
//! - `weighted`: the average severity of the matching patterns (0 if none match)
//!
//! Each pattern carries a severity in [0, 1]. Scoring logic only; the patterns
//! are supplied by configuration.

use std::sync::Arc;

use async_trait::async_trait;
use regex::Regex;

use crate::core::Attempt;
use crate::registry::{Config, Registry};
use crate::traits::Detector;
use crate::Result;

/// How the pattern results are combined into one score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Any,
    All,
    Weighted,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "any" => Ok(Mode::Any),
            "all" => Ok(Mode::All),
            "weighted" => Ok(Mode::Weighted),
            other => Err(format!("invalid mode: {other:?} (must be any, all or weighted)").into()),
        }
    }
}

/// One named regex with its severity.
#[derive(Debug, Clone)]
pub struct Pattern {
    pub name: String,
    pub regex: Regex,
    pub severity: f64,
}

/// Pattern detector ported from augustus `patterns.Patterns`.
#[derive(Debug, Clone)]
pub struct PatternsDetector {
    pub name: String,
    pub patterns: Vec<Pattern>,
    pub mode: Mode,
}

impl PatternsDetector {
    /// Scores one output. Returns a value in [0, 1].
    pub fn score(&self, output: &str) -> f64 {
        if self.patterns.is_empty() {
            return 0.0;
        }
        let hits: Vec<&Pattern> = self.patterns.iter().filter(|p| p.regex.is_match(output)).collect();
        match self.mode {
            Mode::Any => hits.iter().map(|p| p.severity).fold(0.0, f64::max),
            Mode::All => {
                if hits.len() == self.patterns.len() {
                    hits.iter().map(|p| p.severity).fold(0.0, f64::max)
                } else {
                    0.0
                }
            }
            Mode::Weighted => {
                if hits.is_empty() {
                    0.0
                } else {
                    hits.iter().map(|p| p.severity).sum::<f64>() / hits.len() as f64
                }
            }
        }
        .clamp(0.0, 1.0)
    }
}

#[async_trait]
impl Detector for PatternsDetector {
    async fn detect(&self, a: &Attempt) -> Result<Vec<f64>> {
        Ok(a.outputs.iter().map(|o| self.score(o)).collect())
    }
    fn name(&self) -> &str {
        &self.name
    }
}

/// Builds the pattern list from a registry config (`patterns: [{name, regex, severity}]`).
fn patterns_from(cfg: &Config) -> Result<Vec<Pattern>> {
    let Some(arr) = cfg.get("patterns").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    arr.iter()
        .enumerate()
        .map(|(i, p)| {
            let name = p.get("name").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| format!("pattern_{i}"));
            let re = p
                .get("regex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("pattern {name:?} missing 'regex'"))?;
            let severity = p.get("severity").and_then(|v| v.as_f64()).unwrap_or(1.0);
            Ok(Pattern { name, regex: Regex::new(re)?, severity })
        })
        .collect()
}

/// Registers `patterns.Patterns` in the registry.
pub fn register(reg: &Registry<Arc<dyn Detector>>) {
    reg.register("patterns.Patterns", |cfg| {
        let mode = match cfg.get("mode").and_then(|v| v.as_str()) {
            Some(m) => Mode::parse(m)?,
            None => Mode::Any,
        };
        Ok(Arc::new(PatternsDetector {
            name: "patterns.Patterns".into(),
            patterns: patterns_from(cfg)?,
            mode,
        }) as Arc<dyn Detector>)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(mode: Mode, pats: &[(&str, &str, f64)]) -> PatternsDetector {
        PatternsDetector {
            name: "t".into(),
            patterns: pats
                .iter()
                .map(|(n, r, s)| Pattern { name: n.to_string(), regex: Regex::new(r).unwrap(), severity: *s })
                .collect(),
            mode,
        }
    }

    #[test]
    fn any_takes_highest_matching_severity() {
        let d = det(Mode::Any, &[("a", "alpha", 0.4), ("b", "beta", 0.9)]);
        assert_eq!(d.score("alpha and beta"), 0.9);
        assert_eq!(d.score("alpha only"), 0.4);
        assert_eq!(d.score("nothing"), 0.0);
    }

    #[test]
    fn all_requires_every_pattern() {
        let d = det(Mode::All, &[("a", "alpha", 0.5), ("b", "beta", 0.8)]);
        assert_eq!(d.score("alpha and beta"), 0.8);
        assert_eq!(d.score("alpha only"), 0.0);
    }

    #[test]
    fn weighted_averages_matches() {
        let d = det(Mode::Weighted, &[("a", "alpha", 0.2), ("b", "beta", 0.6), ("c", "gamma", 1.0)]);
        assert!((d.score("alpha beta") - 0.4).abs() < 1e-9);
        assert_eq!(d.score("none"), 0.0);
    }

    #[test]
    fn empty_pattern_list_scores_zero() {
        assert_eq!(det(Mode::Any, &[]).score("anything"), 0.0);
    }

    #[test]
    fn parse_rejects_unknown_mode() {
        assert!(Mode::parse("sometimes").is_err());
    }

    #[test]
    fn registry_builds_and_rejects_missing_regex() {
        let reg: Registry<Arc<dyn Detector>> = Registry::new("detectors");
        register(&reg);
        let ok: Config = serde_json::json!({"patterns":[{"name":"x","regex":"x+","severity":0.5}],"mode":"weighted"})
            .as_object().unwrap().clone();
        assert!(reg.create("patterns.Patterns", &ok).is_ok());
        let bad: Config = serde_json::json!({"patterns":[{"name":"x"}]}).as_object().unwrap().clone();
        assert!(reg.create("patterns.Patterns", &bad).is_err());
    }
}
