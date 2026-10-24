//! Threat-intel feed ingestion (roadmap P13).
//!
//! Takes a curated JSON feed of published attack-technique *metadata*
//! (id, title, source URL, date, category, and references to existing
//! buff names) and produces validated, normalized catalog entries.
//! This module performs no network I/O and holds no attack text.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Allowed technique categories.
const CATEGORIES: &[&str] = &[
    "direct_injection",
    "indirect_injection",
    "prompt_extraction",
    "multimodal",
    "agent_tool",
    "encoding",
];

/// Names of existing buffs an entry may reference.
const BUFFS: &[&str] = &[
    "base64",
    "rot13",
    "leetspeak",
    "homoglyph",
    "zero_width",
    "reverse",
    "case",
    "spaced",
    "payload_split",
    "wrap",
    "emoji_smuggle",
    "bidi",
    "unicode_tags",
];

/// One metadata record describing a published attack technique.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct IntelEntry {
    /// Stable identifier, 1-64 chars of `[A-Za-z0-9._-]`.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// `https://` URL of the publication.
    pub source_url: String,
    /// Publication date, `YYYY-MM-DD`.
    pub published: String,
    /// One of the allowed categories.
    pub category: String,
    /// Names of existing buffs this entry maps to (non-empty).
    pub buff_refs: Vec<String>,
    /// Optional free-form notes.
    #[serde(default)]
    pub notes: String,
}

/// Result of ingesting a feed: accepted entries and `(id or "?", reason)` rejections.
#[derive(Serialize, Debug)]
pub struct IngestReport {
    /// Entries that passed validation (first occurrence of each id).
    pub accepted: Vec<IntelEntry>,
    /// Rejected entries as `(id or "?", reason)`.
    pub rejected: Vec<(String, String)>,
}

/// Parse a JSON array of entries. Returns an error string on malformed JSON
/// or a schema mismatch. Does not validate field contents; see [`validate`].
pub fn parse_feed(json: &str) -> Result<Vec<IntelEntry>, String> {
    serde_json::from_str(json).map_err(|e| format!("invalid feed JSON: {e}"))
}

/// Parse `YYYY-MM-DD` into `(year, month, day)` with month 01-12 and day 01-31.
fn parse_date(s: &str) -> Option<(i64, i64, i64)> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    if !(digits(0..4) && digits(5..7) && digits(8..10)) {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let m: i64 = s[5..7].parse().ok()?;
    let d: i64 = s[8..10].parse().ok()?;
    if (1..=12).contains(&m) && (1..=31).contains(&d) {
        Some((y, m, d))
    } else {
        None
    }
}

/// Validate a single entry against the feed rules.
pub fn validate(entry: &IntelEntry) -> Result<(), String> {
    let id_ok = !entry.id.is_empty()
        && entry.id.len() <= 64
        && entry
            .id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    if !id_ok {
        return Err("invalid id".into());
    }
    if !entry.source_url.starts_with("https://")
        || entry.source_url.len() == "https://".len()
        || entry.source_url.chars().any(char::is_whitespace)
    {
        return Err("invalid source_url".into());
    }
    if parse_date(&entry.published).is_none() {
        return Err("invalid published date".into());
    }
    if !CATEGORIES.contains(&entry.category.as_str()) {
        return Err(format!("unknown category: {}", entry.category));
    }
    if entry.buff_refs.is_empty() {
        return Err("buff_refs must not be empty".into());
    }
    if let Some(bad) = entry.buff_refs.iter().find(|b| !BUFFS.contains(&b.as_str())) {
        return Err(format!("unknown buff ref: {bad}"));
    }
    Ok(())
}

/// Ingest a feed, validating each entry independently. Duplicate ids keep the
/// first occurrence; later ones are rejected with "duplicate id". A feed that
/// is not a JSON array yields an empty report with a single `("?", reason)`
/// rejection; an element that does not fit the schema is rejected on its own.
pub fn ingest(json: &str) -> IngestReport {
    let mut report = IngestReport { accepted: Vec::new(), rejected: Vec::new() };
    let items: Vec<serde_json::Value> = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            report.rejected.push(("?".into(), format!("invalid feed JSON: {e}")));
            return report;
        }
    };
    let mut seen: HashSet<String> = HashSet::new();
    for item in items {
        let id_hint = item
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let entry: IntelEntry = match serde_json::from_value(item) {
            Ok(e) => e,
            Err(e) => {
                report.rejected.push((id_hint, format!("malformed entry: {e}")));
                continue;
            }
        };
        if let Err(reason) = validate(&entry) {
            report.rejected.push((entry.id.clone(), reason));
        } else if !seen.insert(entry.id.clone()) {
            report.rejected.push((entry.id.clone(), "duplicate id".into()));
        } else {
            report.accepted.push(entry);
        }
    }
    report
}

/// Union of `existing` and `incoming` by id; `existing` wins on conflict.
/// Result is sorted by `published` descending, then `id` ascending.
pub fn merge_into_catalog(existing: &[IntelEntry], incoming: &[IntelEntry]) -> Vec<IntelEntry> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut out: Vec<IntelEntry> = existing
        .iter()
        .chain(incoming)
        .filter(|e| seen.insert(e.id.as_str()))
        .cloned()
        .collect();
    out.sort_by(|a, b| b.published.cmp(&a.published).then_with(|| a.id.cmp(&b.id)));
    out
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// True when the entry is more than `max_age_days` older than `today`
/// (`YYYY-MM-DD`). An entry exactly `max_age_days` old is not stale. If either
/// date cannot be parsed the entry is conservatively reported stale.
pub fn is_stale(entry: &IntelEntry, today: &str, max_age_days: i64) -> bool {
    match (parse_date(&entry.published), parse_date(today)) {
        (Some((py, pm, pd)), Some((ty, tm, td))) => {
            days_from_civil(ty, tm, td) - days_from_civil(py, pm, pd) > max_age_days
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, published: &str) -> IntelEntry {
        IntelEntry {
            id: id.into(),
            title: "Example technique A".into(),
            source_url: "https://example.org/a".into(),
            published: published.into(),
            category: "encoding".into(),
            buff_refs: vec!["base64".into()],
            notes: String::new(),
        }
    }

    fn feed_item(id: &str) -> String {
        format!(
            r#"{{"id":"{id}","title":"Example technique B","source_url":"https://example.org/b","published":"2025-03-01","category":"multimodal","buff_refs":["rot13","bidi"]}}"#
        )
    }

    #[test]
    fn valid_feed_accepted() {
        let r = ingest(&format!("[{},{}]", feed_item("a-1"), feed_item("b.2")));
        assert_eq!(r.accepted.len(), 2);
        assert!(r.rejected.is_empty());
        assert_eq!(r.accepted[0].notes, "");
    }

    #[test]
    fn parse_feed_ok_and_bad_json() {
        assert_eq!(parse_feed(&format!("[{}]", feed_item("x"))).unwrap().len(), 1);
        assert!(parse_feed("not json").is_err());
        assert!(parse_feed("{}").is_err());
        let r = ingest("not json");
        assert!(r.accepted.is_empty());
        assert_eq!(r.rejected.len(), 1);
    }

    #[test]
    fn baseline_entry_is_valid() {
        assert_eq!(validate(&entry("ok_1", "2025-01-31")), Ok(()));
    }

    #[test]
    fn rejects_bad_id() {
        for id in ["", "has space", "bad/slash", &"x".repeat(65), "ünï"] {
            assert!(validate(&entry(id, "2025-01-01")).is_err(), "{id:?}");
        }
        assert!(validate(&entry(&"x".repeat(64), "2025-01-01")).is_ok());
    }

    #[test]
    fn rejects_bad_url() {
        for u in ["http://example.org", "https://a b", "ftp://x", "https://", "https://x\ty"] {
            let mut e = entry("a", "2025-01-01");
            e.source_url = u.into();
            assert!(validate(&e).is_err(), "{u:?}");
        }
    }

    #[test]
    fn rejects_bad_date() {
        for d in ["2025-13-01", "2025-00-10", "2025-01-00", "2025-01-32", "25-01-01", "2025/01/01", "2025-1-01", "abcd-ef-gh", ""] {
            assert!(validate(&entry("a", d)).is_err(), "{d:?}");
        }
    }

    #[test]
    fn rejects_bad_category() {
        let mut e = entry("a", "2025-01-01");
        e.category = "other".into();
        assert!(validate(&e).is_err());
    }

    #[test]
    fn rejects_bad_buff_refs() {
        let mut e = entry("a", "2025-01-01");
        e.buff_refs = vec![];
        assert!(validate(&e).is_err());
        e.buff_refs = vec!["base64".into(), "nonexistent".into()];
        assert!(validate(&e).unwrap_err().contains("nonexistent"));
    }

    #[test]
    fn duplicate_id_keeps_first() {
        let r = ingest(&format!("[{},{}]", feed_item("dup"), feed_item("dup")));
        assert_eq!(r.accepted.len(), 1);
        assert_eq!(r.rejected, vec![("dup".to_string(), "duplicate id".to_string())]);
    }

    #[test]
    fn one_bad_one_good() {
        let bad = r#"{"id":"bad","title":"t","source_url":"http://x","published":"2025-03-01","category":"encoding","buff_refs":["base64"]}"#;
        let r = ingest(&format!("[{bad},{}]", feed_item("good")));
        assert_eq!(r.accepted.len(), 1);
        assert_eq!(r.accepted[0].id, "good");
        assert_eq!(r.rejected.len(), 1);
        assert_eq!(r.rejected[0].0, "bad");
    }

    #[test]
    fn malformed_element_rejected_alone() {
        let r = ingest(&format!(r#"[{{"id":"half"}},{}]"#, feed_item("good")));
        assert_eq!(r.accepted.len(), 1);
        assert_eq!(r.rejected[0].0, "half");
        let r = ingest("[42]");
        assert_eq!(r.rejected[0].0, "?");
    }

    #[test]
    fn merge_precedence_and_ordering() {
        let mut old = entry("same", "2024-01-01");
        old.title = "Existing wins".into();
        let mut new = entry("same", "2026-01-01");
        new.title = "Incoming loses".into();
        let merged = merge_into_catalog(
            &[old, entry("b", "2025-05-05")],
            &[new, entry("a", "2025-05-05"), entry("z", "2026-02-02")],
        );
        let ids: Vec<&str> = merged.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["z", "a", "b", "same"]);
        assert_eq!(merged[3].title, "Existing wins");
    }

    #[test]
    fn days_from_civil_known_values() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(2024, 3, 1) - days_from_civil(2024, 2, 28), 2);
    }

    #[test]
    fn staleness_boundary() {
        let e = entry("a", "2025-01-01");
        assert!(!is_stale(&e, "2025-01-31", 30));
        assert!(is_stale(&e, "2025-02-01", 30));
        assert!(!is_stale(&e, "2025-01-01", 0));
        assert!(!is_stale(&e, "2024-12-01", 0), "future-dated is not stale");
        assert!(is_stale(&e, "garbage", 30));
    }
}
