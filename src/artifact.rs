//! Static scanner for model artifacts.
//!
//! Inspects the raw bytes of a model file WITHOUT deserializing, importing or
//! executing anything, and flags risky constructs (pickle code-execution
//! opcodes, deny-listed modules, malformed safetensors headers). All checks
//! are heuristic: a clean report does NOT prove a file is safe.

use serde::Serialize;

/// Largest safetensors header length accepted (100 MB).
const MAX_HEADER_LEN: u64 = 100_000_000;
/// Cap on findings emitted by the pickle scanner, to bound report size.
const MAX_PICKLE_FINDINGS: usize = 10_000;
/// Module names that are suspicious inside a model file.
const DENY_MODULES: &[&str] = &[
    "os", "posix", "nt", "subprocess", "builtins", "__builtin__", "sys", "socket", "shutil",
    "pty", "runpy",
];

/// Container format guessed from the leading bytes.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub enum Format {
    /// Raw pickle stream (protocol marker 0x80).
    Pickle,
    /// Safetensors: u64 LE header length followed by a JSON header.
    Safetensors,
    /// Zip archive (PyTorch `.pt` / `.bin`).
    Zip,
    /// Anything else.
    Unknown,
}

/// A single suspicious construct found by a scanner.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Stable rule identifier, e.g. `pickle.global`.
    pub rule: &'static str,
    /// `"high"` or `"medium"`.
    pub severity: &'static str,
    /// Byte offset of the construct (0 when not applicable).
    pub offset: usize,
    /// Human-readable description.
    pub detail: String,
}

/// Result of scanning one file.
#[derive(Serialize)]
pub struct ScanReport {
    /// Detected format.
    pub format: Format,
    /// All findings.
    pub findings: Vec<Finding>,
    /// `"reject"`, `"review"` or `"clean-heuristic"`.
    pub verdict: &'static str,
}

fn safetensors_header_len(bytes: &[u8]) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    let n = u64::from_le_bytes(raw);
    (n <= MAX_HEADER_LEN).then_some(n)
}

/// Guess the file format from its leading bytes. Never panics.
pub fn detect_format(bytes: &[u8]) -> Format {
    if bytes.first() == Some(&0x80) {
        return Format::Pickle;
    }
    if let Some(n) = safetensors_header_len(bytes) {
        if bytes.get(8) == Some(&b'{') && (n as usize).checked_add(8).is_some_and(|e| e <= bytes.len())
        {
            return Format::Safetensors;
        }
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return Format::Zip;
    }
    Format::Unknown
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Heuristically scan a pickle stream for code-execution opcodes and
/// deny-listed module names.
///
/// This is a byte-level heuristic, not a pickle disassembler: every byte equal
/// to a dangerous opcode letter is reported, so false positives are expected
/// inside string data. A clean scan does NOT prove the file is safe.
pub fn scan_pickle(bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        let (rule, sev, name) = match b {
            b'c' => ("pickle.global", "high", "GLOBAL"),
            0x93 => ("pickle.stack_global", "high", "STACK_GLOBAL"),
            b'R' => ("pickle.reduce", "high", "REDUCE"),
            b'i' => ("pickle.inst", "high", "INST"),
            b'o' => ("pickle.obj", "high", "OBJ"),
            0x92 => ("pickle.newobj_ex", "high", "NEWOBJ_EX"),
            0x81 => ("pickle.newobj", "medium", "NEWOBJ"),
            b'b' => ("pickle.build", "medium", "BUILD"),
            _ => continue,
        };
        if out.len() >= MAX_PICKLE_FINDINGS {
            break;
        }
        out.push(Finding { rule, severity: sev, offset: i, detail: format!("opcode {name} (0x{b:02x})") });
    }
    for name in DENY_MODULES {
        let n = name.as_bytes();
        if bytes.len() < n.len() {
            continue;
        }
        for i in 0..=bytes.len() - n.len() {
            if &bytes[i..i + n.len()] != n {
                continue;
            }
            let after_ok = bytes.get(i + n.len()).is_none_or(|&c| !is_ident(c));
            // Preceded by a non-identifier byte, or by a GLOBAL/INST opcode letter.
            let before_ok = i == 0
                || !is_ident(bytes[i - 1])
                || (matches!(bytes[i - 1], b'c' | b'i') && (i == 1 || !is_ident(bytes[i - 2])));
            if after_ok && before_ok {
                out.push(Finding {
                    rule: "pickle.denied_module",
                    severity: "high",
                    offset: i,
                    detail: format!("deny-listed module name `{name}`"),
                });
            }
        }
    }
    out
}

fn finding(rule: &'static str, severity: &'static str, detail: String) -> Finding {
    Finding { rule, severity, offset: 0, detail }
}

/// Validate a safetensors header and check tensor offsets and metadata.
/// Operates on parsed JSON only; nothing is executed. Heuristic.
pub fn scan_safetensors(bytes: &[u8]) -> Vec<Finding> {
    let bad = |d: &str| vec![finding("safetensors.bad_header", "high", d.to_string())];
    let Some(n) = safetensors_header_len(bytes) else {
        return bad("missing or oversized header length");
    };
    let n = n as usize;
    let Some(end) = n.checked_add(8).filter(|&e| e <= bytes.len()) else {
        return bad("header length exceeds file size");
    };
    let header: serde_json::Value = match serde_json::from_slice(&bytes[8..end]) {
        Ok(v) => v,
        Err(e) => return bad(&format!("header is not valid JSON: {e}")),
    };
    let Some(map) = header.as_object() else {
        return bad("header is not a JSON object");
    };
    let data_len = (bytes.len() - end) as u64;
    let mut out = Vec::new();
    for (name, entry) in map {
        if name == "__metadata__" {
            if let Some(meta) = entry.as_object() {
                for key in meta.keys() {
                    let k = key.to_ascii_lowercase();
                    if k.contains("pickle") || k.contains("code") {
                        out.push(finding(
                            "safetensors.metadata_code",
                            "medium",
                            format!("metadata key `{key}` suggests embedded code"),
                        ));
                    }
                }
            }
            continue;
        }
        let offs = entry.get("data_offsets").and_then(|v| v.as_array());
        let pair = offs.and_then(|a| match a.as_slice() {
            [s, e] => Some((s.as_u64()?, e.as_u64()?)),
            _ => None,
        });
        match pair {
            Some((s, e)) if s <= e && e <= data_len => {}
            Some((s, e)) => out.push(finding(
                "safetensors.out_of_bounds",
                "high",
                format!("tensor `{name}` offsets [{s}, {e}] exceed data section of {data_len} bytes"),
            )),
            None => out.push(finding(
                "safetensors.bad_header",
                "high",
                format!("tensor `{name}` has no valid data_offsets"),
            )),
        }
    }
    out
}

/// Detect the format, run the matching scanner and compute a verdict.
///
/// Zip archives are not unpacked (their embedded pickle is not inspected);
/// they yield a medium `zip.unscanned` finding. A `clean-heuristic` verdict
/// does NOT prove safety.
pub fn scan(bytes: &[u8]) -> ScanReport {
    let format = detect_format(bytes);
    let findings = match format {
        Format::Pickle => scan_pickle(bytes),
        Format::Safetensors => scan_safetensors(bytes),
        Format::Zip => vec![finding(
            "zip.unscanned",
            "medium",
            "zip archive (likely PyTorch); embedded pickle not inspected".into(),
        )],
        Format::Unknown => vec![finding("format.unknown", "medium", "unrecognized format".into())],
    };
    let verdict = if findings.iter().any(|f| f.severity == "high") {
        "reject"
    } else if findings.iter().any(|f| f.severity == "medium") {
        "review"
    } else {
        "clean-heuristic"
    };
    ScanReport { format, findings, verdict }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(header: &str, data_len: usize) -> Vec<u8> {
        let mut v = (header.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(header.as_bytes());
        v.extend(vec![0u8; data_len]);
        v
    }
    const GOOD: &str = r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#;

    fn pickle_global() -> Vec<u8> {
        let mut v = vec![0x80, 2, b'c'];
        v.extend_from_slice(b"builtins\nprint\n.");
        v
    }

    #[test]
    fn detects_formats() {
        assert_eq!(detect_format(&[0x80, 2]), Format::Pickle);
        assert_eq!(detect_format(&st(GOOD, 8)), Format::Safetensors);
        assert_eq!(detect_format(b"PK\x03\x04rest"), Format::Zip);
        assert_eq!(detect_format(b"hello"), Format::Unknown);
        assert_eq!(detect_format(&[]), Format::Unknown);
    }

    #[test]
    fn pickle_global_high() {
        let f = scan_pickle(&pickle_global());
        assert!(f.iter().any(|x| x.rule == "pickle.global" && x.severity == "high" && x.offset == 2));
    }

    #[test]
    fn pickle_medium_opcodes() {
        let f = scan_pickle(&[0x80, 2, 0x81, b'.']);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "medium");
    }

    #[test]
    fn deny_listed_module_flagged() {
        let f = scan_pickle(&pickle_global());
        assert!(f.iter().any(|x| x.rule == "pickle.denied_module" && x.detail.contains("builtins")));
        let f = scan_pickle(b"\x80\x02\x8c\x06subprocess");
        assert!(f.iter().any(|x| x.detail.contains("subprocess")));
    }

    #[test]
    fn safetensors_valid_is_clean() {
        assert!(scan_safetensors(&st(GOOD, 8)).is_empty());
    }

    #[test]
    fn safetensors_out_of_bounds() {
        let f = scan_safetensors(&st(GOOD, 4));
        assert!(f.iter().any(|x| x.rule == "safetensors.out_of_bounds" && x.severity == "high"));
    }

    #[test]
    fn safetensors_bad_json() {
        let f = scan_safetensors(&st("{not json", 0));
        assert!(f.iter().any(|x| x.rule == "safetensors.bad_header"));
    }

    #[test]
    fn safetensors_metadata_code() {
        let h = r#"{"__metadata__":{"pickle_blob":"x"},"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let f = scan_safetensors(&st(h, 4));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "safetensors.metadata_code");
        assert_eq!(f[0].severity, "medium");
    }

    #[test]
    fn verdict_mapping() {
        assert_eq!(scan(&pickle_global()).verdict, "reject");
        assert_eq!(scan(&[0x80, 2, 0x81, b'.']).verdict, "review");
        assert_eq!(scan(&st(GOOD, 8)).verdict, "clean-heuristic");
        let r = scan(b"garbage");
        assert_eq!(r.verdict, "review");
        assert_eq!(r.findings[0].rule, "format.unknown");
    }

    #[test]
    fn truncated_inputs_never_panic() {
        for sample in [pickle_global(), st(GOOD, 8), b"PK\x03\x04abcdef".to_vec()] {
            for i in 0..=sample.len() {
                let _ = scan(&sample[..i]);
                let _ = scan_safetensors(&sample[..i]);
                let _ = scan_pickle(&sample[..i]);
            }
        }
    }
}
