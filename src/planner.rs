//! The NL planner (roadmap P2): turns a natural-language request into a
//! validated [`ScanPlan`] by asking a provider-agnostic [`LlmClient`] to author
//! the plan as JSON. The model only names existing probes/buffs; it never writes
//! payloads. The authorization gate in [`ScanPlan::validate`] is always applied.

use crate::llm::LlmClient;
use crate::plan::ScanPlan;
use crate::Result;

/// System prompt that constrains the model to emit a single ScanPlan JSON object.
pub const PLANNER_SYSTEM: &str = r#"You are the planning module of an LLM guardrail red-teaming tool used only for authorized testing of the operator's own systems.
Convert the user's request into a scan plan. Reply with ONLY one JSON object, no prose, no code fences, matching this schema:
{
  "version": "1",
  "authorization": {"authorized": bool, "scope": string},
  "target": {"kind": string, "config": object},
  "probes": [string],
  "detectors": [string],
  "buffs": [string],
  "harness": {"kind": string, "config": object},
  "concurrency": integer >= 1
}
Rules:
- Set authorization.authorized to false unless the user text explicitly attests they are authorized to test the target. When true, record their attestation in authorization.scope.
- target.kind must be one of: guardrail, inspect, ollama, mock.
- Reference probes and detectors only by their existing names; never write attack payloads or prompts yourself.
- buffs may only use these names: base64, rot13, leetspeak, homoglyph, zero_width, reverse, case, spaced, payload_split, wrap.
- harness.kind defaults to "probewise". Omit nothing you are unsure of; use empty arrays or objects instead."#;

/// Find the first balanced `{...}` object in a model reply, tolerating
/// surrounding prose and ```json fences. Braces inside JSON strings are ignored.
pub fn extract_json(text: &str) -> Option<&str> {
    text.match_indices('{')
        .find_map(|(start, _)| balanced_end(&text[start..]).map(|end| &text[start..start + end]))
}

/// Byte length of the balanced object starting at the first char of `s` (`{`).
fn balanced_end(s: &str) -> Option<usize> {
    let (mut depth, mut in_str, mut escaped) = (0usize, false, false);
    for (i, c) in s.char_indices() {
        if in_str {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse a model reply into a [`ScanPlan`] and validate it.
pub fn parse_plan(text: &str) -> Result<ScanPlan> {
    let json = extract_json(text).ok_or("planner: no JSON object found in model reply")?;
    let plan = ScanPlan::from_json(json).map_err(|e| format!("planner: invalid plan JSON: {e}"))?;
    plan.validate().map_err(|e| format!("planner: plan failed validation: {e}"))?;
    check_allowed(&plan)?;
    Ok(plan)
}

/// Target kinds the planner may choose. The prompt asks for these, and this
/// check enforces them in code, so a model that ignores the prompt cannot
/// select an unknown target.
pub const ALLOWED_TARGETS: &[&str] = &["guardrail", "inspect", "ollama", "mock"];

/// Buff names the planner may choose.
pub const ALLOWED_BUFFS: &[&str] = &[
    "base64", "rot13", "leetspeak", "homoglyph", "zero_width",
    "reverse", "case", "spaced", "payload_split", "wrap",
];

/// Built-in probe names the planner may choose (no catalog loader yet).
pub const ALLOWED_PROBES: &[&str] = &["test.Blank", "test.Hello", "guardrail.seeds"];

/// Detector names registered in the crate.
pub const ALLOWED_DETECTORS: &[&str] = &[
    "keyword.Keyword", "regex.Regex", "refusal.Refusal", "secrets.Secrets",
    "secrets.Gitleaks", "pii.PII", "guardrail.Bypass", "inspect.Bypass",
];

/// Rejects target kinds, probes, detectors and buffs that do not exist in the crate.
pub fn check_allowed(plan: &ScanPlan) -> Result<()> {
    for p in &plan.probes {
        if !ALLOWED_PROBES.contains(&p.as_str()) {
            return Err(format!("planner: probe '{p}' is not a known probe").into());
        }
    }
    for d in &plan.detectors {
        if !ALLOWED_DETECTORS.contains(&d.as_str()) {
            return Err(format!("planner: detector '{d}' is not a known detector").into());
        }
    }
    if !ALLOWED_TARGETS.contains(&plan.target.kind.as_str()) {
        return Err(format!("planner: target kind '{}' is not allowed", plan.target.kind).into());
    }
    for b in &plan.buffs {
        if !ALLOWED_BUFFS.contains(&b.as_str()) {
            return Err(format!("planner: buff '{b}' is not allowed").into());
        }
    }
    Ok(())
}

/// Ask `brain` to plan `request`, then parse and validate the result.
pub async fn plan_from_request(brain: &dyn LlmClient, request: &str) -> Result<ScanPlan> {
    let reply = brain.chat(Some(PLANNER_SYSTEM), request).await?;
    parse_plan(&reply)
}

/// Render a plan as reviewable YAML.
pub fn render_plan_yaml(plan: &ScanPlan) -> Result<String> {
    Ok(plan.to_yaml()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    const GOOD: &str = r#"{"authorization":{"authorized":true,"scope":"my own mock"},"target":{"kind":"mock"},"probes":["test.Blank"]}"#;

    struct Fake(&'static str);

    #[async_trait]
    impl LlmClient for Fake {
        async fn chat(&self, system: Option<&str>, _user: &str) -> Result<String> {
            assert_eq!(system, Some(PLANNER_SYSTEM));
            Ok(self.0.to_string())
        }
        fn name(&self) -> &str {
            "fake"
        }
    }

    #[test]
    fn system_prompt_lists_kinds_and_buffs() {
        for w in ["guardrail", "inspect", "ollama", "mock", "base64", "rot13", "leetspeak",
            "homoglyph", "zero_width", "reverse", "case", "spaced", "payload_split", "wrap"]
        {
            assert!(PLANNER_SYSTEM.contains(w), "missing {w}");
        }
    }

    #[test]
    fn extract_handles_prose_fences_and_nesting() {
        assert_eq!(extract_json("sure: {\"a\":{\"b\":1}} done"), Some("{\"a\":{\"b\":1}}"));
        assert_eq!(extract_json("```json\n{\"a\":1}\n```"), Some("{\"a\":1}"));
        assert_eq!(extract_json(r#"x {"a":"}{\"}"} y"#), Some(r#"{"a":"}{\"}"}"#));
        assert_eq!(extract_json("no braces"), None);
        assert_eq!(extract_json("{ unbalanced"), None);
    }

    #[test]
    fn parses_good_prose_and_fenced() {
        assert_eq!(parse_plan(GOOD).unwrap().probes, vec!["test.Blank"]);
        assert!(parse_plan(&format!("Here you go: {GOOD} enjoy")).is_ok());
        assert!(parse_plan(&format!("```json\n{GOOD}\n```")).is_ok());
    }

    #[test]
    fn defaults_apply() {
        let p = parse_plan(GOOD).unwrap();
        assert_eq!(p.version, "1");
        assert_eq!(p.concurrency, 8);
        assert_eq!(p.harness.kind, "probewise");
        assert!(p.buffs.is_empty());
    }

    #[test]
    fn missing_required_fields_error() {
        let e = parse_plan(r#"{"probes":["x"]}"#).unwrap_err().to_string();
        assert!(e.contains("invalid plan JSON"), "{e}");
    }

    #[test]
    fn unauthorized_parses_but_fails_validation() {
        let raw = r#"{"authorization":{"authorized":false},"target":{"kind":"mock"},"probes":["test.Blank"]}"#;
        assert!(ScanPlan::from_json(raw).is_ok());
        let e = parse_plan(raw).unwrap_err().to_string();
        assert!(e.contains("validation") && e.contains("not authorized"), "{e}");
    }

    #[test]
    fn garbage_errors() {
        assert!(parse_plan("I cannot help with that").is_err());
        assert!(parse_plan("{not json}").is_err());
    }

    #[tokio::test]
    async fn plan_from_request_ok() {
        let p = plan_from_request(&Fake(GOOD), "scan my mock, I am authorized").await.unwrap();
        assert_eq!(p.target.kind, "mock");
    }

    #[tokio::test]
    async fn plan_from_request_garbage_is_clean_err() {
        assert!(plan_from_request(&Fake("lol no"), "scan").await.is_err());
    }

    #[test]
    fn yaml_round_trips() {
        let p = parse_plan(GOOD).unwrap();
        let y = render_plan_yaml(&p).unwrap();
        assert_eq!(ScanPlan::from_yaml(&y).unwrap(), p);
    }
}

#[cfg(test)]
mod allow_tests {
    use super::*;

    #[test]
    fn rejects_unknown_target_kind() {
        let r = parse_plan(r#"{"authorization":{"authorized":true,"scope":"x"},"target":{"kind":"evil"},"probes":["test.Blank"]}"#);
        assert!(r.unwrap_err().to_string().contains("target kind 'evil'"));
    }

    #[test]
    fn rejects_unknown_buff() {
        let r = parse_plan(r#"{"authorization":{"authorized":true,"scope":"x"},"target":{"kind":"mock"},"probes":["test.Blank"],"buffs":["nope"]}"#);
        assert!(r.unwrap_err().to_string().contains("buff 'nope'"));
    }

    #[test]
    fn rejects_invented_probe_and_detector() {
        let r = parse_plan(r#"{"authorization":{"authorized":true,"scope":"x"},"target":{"kind":"mock"},"probes":["bypass_probe"]}"#);
        assert!(r.unwrap_err().to_string().contains("probe 'bypass_probe'"));
        let r = parse_plan(r#"{"authorization":{"authorized":true,"scope":"x"},"target":{"kind":"mock"},"probes":["test.Hello"],"detectors":["made_up.Det"]}"#);
        assert!(r.unwrap_err().to_string().contains("detector 'made_up.Det'"));
    }

    #[test]
    fn accepts_allowed_target_and_buffs() {
        let r = parse_plan(r#"{"authorization":{"authorized":true,"scope":"x"},"target":{"kind":"guardrail"},"probes":["test.Blank"],"buffs":["rot13","reverse"]}"#);
        assert!(r.is_ok());
    }
}
