//! Finding deduplication and triage (P5). Many findings are the same technique
//! applied to different seeds. Grouping them by a technique signature shows the
//! review list as distinct issues, ranked by severity and then by how often each
//! technique worked.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::core::Attempt;

/// One deduplicated issue: a technique signature and the findings that share it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Issue {
    /// Signature: category plus the sorted obfuscation names.
    pub signature: String,
    pub category: String,
    pub mutations: Vec<String>,
    pub count: usize,
    pub severity_rank: u8,
    pub example_id: String,
}

/// Severity order used for ranking (lower is more severe).
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

fn signature(category: &str, mutations: &[String]) -> String {
    let mut m = mutations.to_vec();
    m.sort();
    format!("{category}|{}", m.join("+"))
}

/// Groups bypass findings by technique signature and ranks the groups.
/// Non-bypass attempts are ignored.
pub fn triage(findings: &[Attempt]) -> Vec<Issue> {
    let mut groups: BTreeMap<String, Issue> = BTreeMap::new();
    for a in findings {
        let is_bypass = a.metadata.get("bypass").and_then(|v| v.as_bool()).unwrap_or(false);
        if !is_bypass {
            continue;
        }
        let category = a.metadata.get("category").and_then(|v| v.as_str()).unwrap_or("uncategorized").to_string();
        let mutations: Vec<String> = a
            .metadata
            .get("mutations")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let sig = signature(&category, &mutations);
        let sev = crate::report::severity(
            a.metadata.get("success_rate").and_then(|v| v.as_f64()).unwrap_or(1.0),
            true,
        );
        let entry = groups.entry(sig.clone()).or_insert_with(|| Issue {
            signature: sig,
            category: category.clone(),
            mutations: mutations.clone(),
            count: 0,
            severity_rank: severity_rank(sev),
            example_id: a.id.clone(),
        });
        entry.count += 1;
        entry.severity_rank = entry.severity_rank.min(severity_rank(sev));
    }
    let mut issues: Vec<Issue> = groups.into_values().collect();
    // Most severe first, then most frequent, then stable by signature.
    issues.sort_by(|a, b| {
        a.severity_rank
            .cmp(&b.severity_rank)
            .then(b.count.cmp(&a.count))
            .then(a.signature.cmp(&b.signature))
    });
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bypass(category: &str, mutations: &[&str], rate: f64) -> Attempt {
        let mut a = Attempt::new("p");
        a.metadata.insert("bypass".into(), json!(true));
        a.metadata.insert("category".into(), json!(category));
        a.metadata.insert("mutations".into(), json!(mutations));
        a.metadata.insert("success_rate".into(), json!(rate));
        a
    }

    #[test]
    fn same_technique_groups_together_regardless_of_mutation_order() {
        let f = vec![
            bypass("direct_injection", &["rot13", "reverse"], 1.0),
            bypass("direct_injection", &["reverse", "rot13"], 1.0),
            bypass("direct_injection", &["rot13", "reverse"], 1.0),
        ];
        let issues = triage(&f);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].count, 3);
    }

    #[test]
    fn non_bypass_attempts_are_ignored() {
        let mut blocked = bypass("direct_injection", &["rot13"], 0.0);
        blocked.metadata.insert("bypass".into(), json!(false));
        assert!(triage(&[blocked]).is_empty());
    }

    #[test]
    fn ranks_by_severity_then_frequency() {
        let f = vec![
            bypass("prompt_extraction", &["case"], 0.02), // Rare -> Medium
            bypass("direct_injection", &["rot13"], 1.0),  // Reliable -> Critical
            bypass("direct_injection", &["rot13"], 1.0),
        ];
        let issues = triage(&f);
        assert_eq!(issues[0].category, "direct_injection");
        assert_eq!(issues[0].count, 2);
        assert_eq!(issues[1].category, "prompt_extraction");
    }
}
