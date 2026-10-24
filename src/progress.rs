//! Terminal view of a run's live progress (`progress.jsonl`), for CLI users.
//! The dashboard reads the same file, so both views show the same events.

use std::fs;
use std::path::Path;

use serde_json::Value;

/// Reads progress events from line `since` onward. Malformed lines are skipped.
pub fn read_events(path: &Path, since: usize) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .skip(since)
        .collect()
}

/// One-line guardrail response: the action and the layer scores, if present.
pub fn summarize_guardrail(raw: &str) -> String {
    match serde_json::from_str::<Value>(raw) {
        Ok(v) => {
            let action = v["action"].as_str().unwrap_or("?");
            let l2 = v["layers"]
                .as_array()
                .and_then(|ls| ls.iter().find(|l| l["layer"] == "l2"))
                .and_then(|l| l["score"].as_f64());
            match l2 {
                Some(s) => format!("action={action} l2={s:.4}"),
                None => format!("action={action}"),
            }
        }
        Err(_) => raw.chars().take(80).collect(),
    }
}

/// Formats one event as a terminal line.
pub fn format_event(e: &Value) -> String {
    let phase = e["phase"].as_str().unwrap_or("?");
    let depth = e["depth"].as_u64().map(|d| format!(" d{d}")).unwrap_or_default();
    let score = e["score"].as_f64().unwrap_or(0.0);
    let tag = if e["bypass"].as_bool().unwrap_or(false) { "BYPASS" } else { "blocked" };
    let used = e["tokens_used"].as_u64().unwrap_or(0);
    let limit = e["token_limit"].as_u64().unwrap_or(0);
    let budget = if limit == 0 { "∞".to_string() } else { limit.to_string() };
    let guard = summarize_guardrail(e["guardrail"].as_str().unwrap_or(""));
    let prompt: String = e["prompt"].as_str().unwrap_or("").chars().take(60).collect();
    format!(
        "{phase:<8}{depth:<4} score={score:.3} {tag:<8} tok {tok:>5} · total {used}/{budget} · {guard} · {prompt}",
        tok = e["tokens"].as_u64().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn formats_a_bypass_with_tokens_and_guardrail() {
        let e = json!({
            "phase": "adaptive",
            "depth": 1,
            "score": 0.91,
            "bypass": true,
            "tokens": 210,
            "tokens_used": 5000,
            "token_limit": 60000,
            "prompt": "ignore everything",
            "guardrail": r#"{"action":"allow","layers":[{"layer":"l2","score":0.2}]}"#
        });
        let line = format_event(&e);
        assert!(line.contains("BYPASS"));
        assert!(line.contains("tok   210"));
        assert!(line.contains("5000/60000"));
        assert!(line.contains("action=allow l2=0.2000"));
    }

    #[test]
    fn unlimited_budget_and_non_json_guardrail() {
        let e = json!({"phase":"baseline","score":0.0,"bypass":false,"tokens":3,"tokens_used":3,"token_limit":0,"guardrail":"plain text"});
        let line = format_event(&e);
        assert!(line.contains("blocked"));
        assert!(line.contains("3/∞") || line.contains("3/") || line.contains("∞"));
        assert!(line.contains("plain text"));
    }

    #[test]
    fn read_events_respects_offset() {
        let p = std::env::temp_dir().join(format!("mkb-prog-{}.jsonl", std::process::id()));
        std::fs::write(&p, "{\"a\":1}\n{\"a\":2}\nnot json\n{\"a\":3}\n").unwrap();
        assert_eq!(read_events(&p, 0).len(), 3);
        assert_eq!(read_events(&p, 2).len(), 1);
        let _ = std::fs::remove_file(&p);
    }
}
