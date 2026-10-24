//! Probe catalog loader (P5). Reads augustus-format YAML probe specs from a
//! directory the operator supplies (for example a checkout of the augustus
//! project, Apache-2.0). The payload text is never copied into this repository;
//! it stays in the operator's own copy, and the source attribution is kept.
//!
//! Only the fields the framework needs are read: `id`, `info` (name, goal,
//! detector, severity, tags, owasp) and `prompts`. Unknown fields are ignored.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct RawTemplate {
    id: String,
    #[serde(default)]
    info: RawInfo,
    #[serde(default)]
    prompts: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    goal: String,
    #[serde(default)]
    detector: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    owasp: Vec<String>,
}

/// One catalog entry. `prompts` are the operator's own copies of the probe text.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CatalogEntry {
    pub id: String,
    pub name: String,
    pub goal: String,
    pub detector: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub owasp: Vec<String>,
    pub prompts: Vec<String>,
    /// Where the entry was loaded from, for provenance in reports.
    pub source: String,
}

/// Parses one template document. Entries with no id or no prompts are rejected.
pub fn parse_template(yaml: &str, source: &str) -> Result<CatalogEntry, String> {
    let raw: RawTemplate = serde_yaml::from_str(yaml).map_err(|e| format!("{source}: {e}"))?;
    if raw.id.trim().is_empty() {
        return Err(format!("{source}: missing id"));
    }
    if raw.prompts.is_empty() {
        return Err(format!("{source}: no prompts"));
    }
    Ok(CatalogEntry {
        id: raw.id,
        name: raw.info.name,
        goal: raw.info.goal,
        detector: raw.info.detector,
        severity: raw.info.severity,
        tags: raw.info.tags,
        owasp: raw.info.owasp,
        prompts: raw.prompts,
        source: source.to_string(),
    })
}

/// Loads every `.yaml` / `.yml` file under `dir` (recursively). Returns the valid
/// entries and a list of (file, reason) for the ones rejected.
pub fn load_dir(dir: &Path) -> (Vec<CatalogEntry>, Vec<(String, String)>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let is_yaml = matches!(p.extension().and_then(|x| x.to_str()), Some("yaml") | Some("yml"));
            if !is_yaml {
                continue;
            }
            let name = p.display().to_string();
            match fs::read_to_string(&p) {
                Ok(text) => match parse_template(&text, &name) {
                    Ok(entry) => ok.push(entry),
                    Err(reason) => bad.push((name, reason)),
                },
                Err(e) => bad.push((name, e.to_string())),
            }
        }
    }
    ok.sort_by(|a, b| a.id.cmp(&b.id));
    (ok, bad)
}

/// Converts a catalog entry into Makhalib's native probe spec YAML, which
/// `probes::ProbeSpec::from_yaml` loads. The output is the operator's local copy.
pub fn to_probe_spec_yaml(entry: &CatalogEntry) -> Result<String, String> {
    let spec = crate::probes::ProbeSpec {
        name: entry.id.clone(),
        description: if entry.name.is_empty() { entry.id.clone() } else { entry.name.clone() },
        goal: entry.goal.clone(),
        prompts: entry.prompts.clone(),
        detector: if entry.detector.is_empty() { None } else { Some(entry.detector.clone()) },
    };
    serde_yaml::to_string(&spec).map_err(|e| format!("{}: {e}", entry.id))
}

/// Converts every entry under `from` into a probe spec file under `out`.
/// Returns the written paths and any rejected source files.
pub fn convert_dir(from: &Path, out: &Path) -> Result<(Vec<std::path::PathBuf>, Vec<(String, String)>), String> {
    let (entries, rejected) = load_dir(from);
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let mut written = Vec::new();
    for e in &entries {
        let yaml = to_probe_spec_yaml(e)?;
        let file = out.join(format!("{}.yaml", e.id.replace(['/', '\\'], "_")));
        fs::write(&file, yaml).map_err(|e| e.to_string())?;
        written.push(file);
    }
    Ok((written, rejected))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
id: example.Placeholder
info:
  name: Placeholder probe
  goal: check the guardrail flags a placeholder
  detector: refusal.Refusal
  severity: low
  tags: [demo]
  owasp: ["LLM01"]
prompts:
  - "Placeholder prompt A"
  - "Placeholder prompt B"
"#;

    #[test]
    fn parses_augustus_style_template() {
        let e = parse_template(SAMPLE, "fixture.yaml").unwrap();
        assert_eq!(e.id, "example.Placeholder");
        assert_eq!(e.detector, "refusal.Refusal");
        assert_eq!(e.prompts.len(), 2);
        assert_eq!(e.owasp, vec!["LLM01".to_string()]);
        assert_eq!(e.source, "fixture.yaml");
    }

    #[test]
    fn rejects_missing_id_and_empty_prompts() {
        assert!(parse_template("info: {}\nprompts: [\"x\"]\n", "a.yaml").is_err());
        assert!(parse_template("id: a.B\nprompts: []\n", "b.yaml").is_err());
    }

    #[test]
    fn load_dir_is_recursive_and_reports_rejects() {
        let root = std::env::temp_dir().join(format!("mkb-cat-{}", std::process::id()));
        let nested = root.join("sub");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("ok.yaml"), SAMPLE).unwrap();
        fs::write(root.join("bad.yml"), "id: \nprompts: []\n").unwrap();
        fs::write(root.join("ignored.txt"), "not yaml").unwrap();
        let (ok, bad) = load_dir(&root);
        assert_eq!(ok.len(), 1);
        assert_eq!(bad.len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn converted_spec_loads_as_native_probe() {
        let e = parse_template(SAMPLE, "fixture.yaml").unwrap();
        let yaml = to_probe_spec_yaml(&e).unwrap();
        let spec = crate::probes::ProbeSpec::from_yaml(&yaml).unwrap();
        assert_eq!(spec.name, "example.Placeholder");
        assert_eq!(spec.detector.as_deref(), Some("refusal.Refusal"));
        assert_eq!(spec.prompts.len(), 2);
    }

    #[test]
    fn convert_dir_writes_one_spec_per_entry() {
        let root = std::env::temp_dir().join(format!("mkb-conv-{}", std::process::id()));
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("ok.yaml"), SAMPLE).unwrap();
        let out = root.join("out");
        let (written, rejected) = convert_dir(&src, &out).unwrap();
        assert_eq!(written.len(), 1);
        assert!(rejected.is_empty());
        let _ = fs::remove_dir_all(&root);
    }
}
