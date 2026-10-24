//! Port of augustus `base.StringDetector` (Apache-2.0, praetorian-inc/augustus).
//!
//! Scores each output 1.0 when any configured substring matches, else 0.0.
//! Match types: `str` (substring), `word` (whole-word, via `\b`) and `startswith`.
//! Case-insensitive by default. This is scoring logic only; the substrings are
//! supplied by the caller's configuration.

use std::sync::Arc;

use async_trait::async_trait;
use regex::Regex;

use crate::core::Attempt;
use crate::registry::{Config, Registry};
use crate::traits::Detector;
use crate::Result;

/// How a substring is matched against an output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    Str,
    Word,
    StartsWith,
}

impl MatchType {
    /// Parses the augustus config value (`str`, `word`, `startswith`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "str" => Ok(MatchType::Str),
            "word" => Ok(MatchType::Word),
            "startswith" => Ok(MatchType::StartsWith),
            other => Err(format!("unknown matchtype: {other}").into()),
        }
    }
}

/// Substring detector ported from augustus `base.StringDetector`.
#[derive(Debug, Clone)]
pub struct StringDetector {
    pub name: String,
    pub substrings: Vec<String>,
    pub match_type: MatchType,
    pub case_sensitive: bool,
}

impl StringDetector {
    pub fn new(name: impl Into<String>, substrings: Vec<String>, match_type: MatchType, case_sensitive: bool) -> Self {
        Self { name: name.into(), substrings, match_type, case_sensitive }
    }

    /// True if any substring matches the output.
    pub fn matches_any(&self, output: &str) -> Result<bool> {
        for s in &self.substrings {
            if self.matches_one(s, output)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn matches_one(&self, substring: &str, output: &str) -> Result<bool> {
        let (needle, hay) = if self.case_sensitive {
            (substring.to_string(), output.to_string())
        } else {
            (substring.to_lowercase(), output.to_lowercase())
        };
        Ok(match self.match_type {
            MatchType::Str => hay.contains(&needle),
            MatchType::StartsWith => hay.starts_with(&needle),
            MatchType::Word => {
                let pattern = format!(r"\b{}\b", regex::escape(&needle));
                Regex::new(&pattern)?.is_match(&hay)
            }
        })
    }
}

#[async_trait]
impl Detector for StringDetector {
    async fn detect(&self, a: &Attempt) -> Result<Vec<f64>> {
        a.outputs
            .iter()
            .map(|o| self.matches_any(o).map(|m| if m { 1.0 } else { 0.0 }))
            .collect()
    }
    fn name(&self) -> &str {
        &self.name
    }
}

/// Parses the `substrings` list from a registry config.
fn substrings_from(cfg: &Config) -> Result<Vec<String>> {
    let arr = cfg
        .get("substrings")
        .and_then(|v| v.as_array())
        .ok_or("base.StringDetector: 'substrings' (list) is required")?;
    arr.iter()
        .map(|v| v.as_str().map(str::to_string).ok_or_else(|| "substrings must be strings".into()))
        .collect()
}

/// Registers `base.StringDetector` in the given registry.
pub fn register(reg: &Registry<Arc<dyn Detector>>) {
    reg.register("base.StringDetector", |cfg| {
        let substrings = substrings_from(cfg)?;
        let mt = match cfg.get("matchtype").and_then(|v| v.as_str()) {
            Some(s) => MatchType::parse(s)?,
            None => MatchType::Str,
        };
        let cs = cfg.get("case_sensitive").and_then(|v| v.as_bool()).unwrap_or(false);
        Ok(Arc::new(StringDetector::new("base.StringDetector", substrings, mt, cs)) as Arc<dyn Detector>)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn att(outs: &[&str]) -> Attempt {
        let mut a = Attempt::new("p");
        a.outputs = outs.iter().map(|s| s.to_string()).collect();
        a
    }

    #[tokio::test]
    async fn str_match_is_case_insensitive_by_default() {
        let d = StringDetector::new("t", vec!["marker".into()], MatchType::Str, false);
        assert_eq!(d.detect(&att(&["a MARKER b", "none"])).await.unwrap(), vec![1.0, 0.0]);
    }

    #[tokio::test]
    async fn case_sensitive_respects_case() {
        let d = StringDetector::new("t", vec!["marker".into()], MatchType::Str, true);
        assert_eq!(d.detect(&att(&["MARKER"])).await.unwrap(), vec![0.0]);
    }

    #[tokio::test]
    async fn word_match_requires_boundaries() {
        let d = StringDetector::new("t", vec!["cat".into()], MatchType::Word, false);
        assert_eq!(d.detect(&att(&["a cat sat", "concatenate"])).await.unwrap(), vec![1.0, 0.0]);
    }

    #[tokio::test]
    async fn startswith_match() {
        let d = StringDetector::new("t", vec!["hello".into()], MatchType::StartsWith, false);
        assert_eq!(d.detect(&att(&["Hello there", "say hello"])).await.unwrap(), vec![1.0, 0.0]);
    }

    #[test]
    fn unknown_match_type_is_an_error() {
        assert!(MatchType::parse("regexish").is_err());
    }

    #[test]
    fn registry_builds_from_config() {
        let reg: Registry<Arc<dyn Detector>> = Registry::new("detectors");
        register(&reg);
        let cfg: Config = json!({"substrings": ["x"], "matchtype": "word"}).as_object().unwrap().clone();
        assert!(reg.create("base.StringDetector", &cfg).is_ok());
        let missing: Config = Config::new();
        assert!(reg.create("base.StringDetector", &missing).is_err());
    }
}
