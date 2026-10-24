//! Framework mapping: Makhalib finding categories to OWASP LLM Top 10 (2025)
//! and MITRE ATLAS technique IDs, plus a simple coverage model.

use serde::Serialize;

/// A mapping from a Makhalib category to external framework identifiers.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Mapping {
    /// OWASP LLM Top 10 (2025) identifier, e.g. `LLM01`.
    pub owasp: &'static str,
    /// MITRE ATLAS technique identifier, e.g. `AML.T0051`.
    pub atlas: &'static str,
    /// Human-readable title of the mapped risk.
    pub title: &'static str,
}

/// Map a finding category to its framework identifiers; `None` if unknown.
pub fn map_category(category: &str) -> Option<Mapping> {
    match category {
        "direct_injection" => Some(Mapping {
            owasp: "LLM01",
            atlas: "AML.T0051",
            title: "Prompt Injection",
        }),
        "indirect_injection" => Some(Mapping {
            owasp: "LLM01",
            atlas: "AML.T0051.001",
            title: "Prompt Injection (Indirect)",
        }),
        // AML.T0056 is ATLAS "LLM Meta Prompt Extraction", the technique for
        // recovering a system/meta prompt. AML.T0048 is not a fit (it covers
        // external harms), so it is deliberately not used.
        "prompt_extraction" => Some(Mapping {
            owasp: "LLM07",
            atlas: "AML.T0056",
            title: "System Prompt Leakage",
        }),
        _ => None,
    }
}

/// The full OWASP LLM Top 10 (2025) as `(id, title)` pairs.
pub fn owasp_catalogue() -> Vec<(&'static str, &'static str)> {
    vec![
        ("LLM01", "Prompt Injection"),
        ("LLM02", "Sensitive Information Disclosure"),
        ("LLM03", "Supply Chain"),
        ("LLM04", "Data and Model Poisoning"),
        ("LLM05", "Improper Output Handling"),
        ("LLM06", "Excessive Agency"),
        ("LLM07", "System Prompt Leakage"),
        ("LLM08", "Vector and Embedding Weaknesses"),
        ("LLM09", "Misinformation"),
        ("LLM10", "Unbounded Consumption"),
    ]
}

/// OWASP coverage achieved by a set of tested categories.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Coverage {
    /// OWASP ids covered by at least one tested category.
    pub covered: Vec<String>,
    /// OWASP ids with no tested category.
    pub not_covered: Vec<String>,
    /// Covered share of the catalogue, 0.0 to 100.0.
    pub percent: f64,
}

/// Compute OWASP coverage for the given tested categories.
pub fn coverage(tested_categories: &[&str]) -> Coverage {
    let hit: Vec<&str> = tested_categories
        .iter()
        .filter_map(|c| map_category(c))
        .map(|m| m.owasp)
        .collect();
    let (mut covered, mut not_covered) = (Vec::new(), Vec::new());
    let catalogue = owasp_catalogue();
    for (id, _) in &catalogue {
        if hit.contains(id) {
            covered.push(id.to_string());
        } else {
            not_covered.push(id.to_string());
        }
    }
    let percent = covered.len() as f64 / catalogue.len() as f64 * 100.0;
    Coverage { covered, not_covered, percent }
}

/// JSON annotation `{"owasp","atlas","title"}` for a report row, or null.
pub fn annotate(category: &str) -> serde_json::Value {
    match map_category(category) {
        Some(m) => serde_json::json!({"owasp": m.owasp, "atlas": m.atlas, "title": m.title}),
        None => serde_json::Value::Null,
    }
}

/// Render a Markdown framework table: id, title, status and a note.
pub fn markdown_table(tested_categories: &[&str]) -> String {
    let cov = coverage(tested_categories);
    let mut out = String::from("| OWASP | Title | Status | Note |\n|---|---|---|---|\n");
    for (id, title) in owasp_catalogue() {
        let tested = cov.covered.iter().any(|c| c == id);
        let (status, note) = if tested {
            let cats: Vec<&str> = tested_categories
                .iter()
                .copied()
                .filter(|c| map_category(c).is_some_and(|m| m.owasp == id))
                .collect();
            ("Tested", format!("Covered by {}", cats.join(", ")))
        } else {
            ("Not tested", "No Makhalib probes for this risk".to_string())
        };
        out.push_str(&format!("| {id} | {title} | {status} | {note} |\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [&str; 3] = ["direct_injection", "indirect_injection", "prompt_extraction"];

    #[test]
    fn maps_known_categories() {
        assert_eq!(map_category("direct_injection").unwrap().atlas, "AML.T0051");
        assert_eq!(map_category("indirect_injection").unwrap().atlas, "AML.T0051.001");
        assert_eq!(map_category("prompt_extraction").unwrap().owasp, "LLM07");
        assert_eq!(map_category("indirect_injection").unwrap().owasp, "LLM01");
    }

    #[test]
    fn unknown_is_none() {
        assert!(map_category("nope").is_none());
        assert!(annotate("nope").is_null());
    }

    #[test]
    fn catalogue_has_ten() {
        let c = owasp_catalogue();
        assert_eq!(c.len(), 10);
        assert_eq!(c[0].0, "LLM01");
        assert_eq!(c[9].1, "Unbounded Consumption");
    }

    #[test]
    fn coverage_empty_is_zero() {
        let c = coverage(&[]);
        assert_eq!(c.percent, 0.0);
        assert!(c.covered.is_empty());
        assert_eq!(c.not_covered.len(), 10);
    }

    #[test]
    fn coverage_all_three() {
        let c = coverage(&ALL);
        assert_eq!(c.covered, vec!["LLM01", "LLM07"]);
        assert_eq!(c.not_covered.len(), 8);
        assert!((c.percent - 20.0).abs() < 1e-9);
    }

    #[test]
    fn coverage_ignores_unknown_and_dedups() {
        let c = coverage(&["direct_injection", "indirect_injection", "bogus"]);
        assert_eq!(c.covered, vec!["LLM01"]);
        assert!((c.percent - 10.0).abs() < 1e-9);
    }

    #[test]
    fn annotate_shape() {
        let v = annotate("direct_injection");
        assert_eq!(v["owasp"], "LLM01");
        assert_eq!(v["atlas"], "AML.T0051");
        assert_eq!(v["title"], "Prompt Injection");
    }

    #[test]
    fn table_contents() {
        let t = markdown_table(&ALL);
        assert!(t.contains("LLM01"));
        assert!(t.contains("Tested"));
        assert!(t.contains("Not tested"));
        assert_eq!(t.lines().count(), 12);
        assert!(!markdown_table(&[]).contains("| Tested |"));
    }
}
