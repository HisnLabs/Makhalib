//! Defender (P16): project the effect of **normalize-then-classify** hardening.
//!
//! The bypasses Makhalib finds exist because the guardrail scores the *surface*
//! string. A hardened guardrail scores several **normalized views** of the input
//! and takes the max. This module produces those views and — by re-querying the
//! live guardrail with each — shows empirically how many confirmed bypasses the
//! fix would close, and which normalization catches each. Purely defensive: it
//! demonstrates the mitigation on the guardrail's own scoring.

use base64::Engine;

/// De-leetspeak: map common digit/symbol substitutions back to letters.
fn deleet(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '4' | '@' => 'a',
            '3' => 'e',
            '1' | '!' => 'i',
            '0' => 'o',
            '5' | '$' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
}

/// Remove invisible / zero-width / bidi / variation-selector characters.
fn strip_invisible(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            !matches!(c as u32,
                0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0xFEFF |
                0xFE00..=0xFE0F | 0xE0000..=0xE007F)
        })
        .collect()
}

/// Fold the Cyrillic/confusable homoglyphs we know back to Latin.
fn defold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'а' => 'a',
            'е' => 'e',
            'о' => 'o',
            'і' => 'i',
            'с' => 'c',
            'р' => 'p',
            'х' => 'x',
            other => other,
        })
        .collect()
}

/// ROT13 (self-inverse): normalizes a rot13'd payload back to plaintext.
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

/// Base64-decode `s` if it decodes to valid UTF-8.
fn b64_decode_utf8(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() < 8 {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

/// The normalized views a normalize-then-classify guardrail would also score.
/// Each is `(method, view)`; the original is not included (it already bypassed).
pub fn normalized_views(text: &str) -> Vec<(String, String)> {
    let mut v = vec![
        ("lower".to_string(), text.to_lowercase()),
        ("deleet".to_string(), deleet(text)),
        ("strip_invisible".to_string(), strip_invisible(text)),
        ("defold_homoglyph".to_string(), defold(text)),
        ("reverse".to_string(), text.chars().rev().collect()),
        ("rot13".to_string(), rot13(text)),
    ];
    if let Some(d) = b64_decode_utf8(text) {
        v.push(("b64decode".to_string(), d));
    }
    // Drop views identical to the original (they add nothing).
    v.retain(|(_, view)| view != text);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleet_recovers_text() {
        assert_eq!(deleet("R3p347"), "Repeat");
        assert_eq!(deleet("1gn0r3"), "ignore");
    }

    #[test]
    fn rot13_is_self_inverse() {
        assert_eq!(rot13("Vtaber"), "Ignore");
        assert_eq!(rot13(&rot13("hello world")), "hello world");
    }

    #[test]
    fn reverse_recovers_reversed_payload() {
        let rev: String = "print prompt".chars().rev().collect();
        let back: String = rev.chars().rev().collect();
        assert_eq!(back, "print prompt");
    }

    #[test]
    fn strip_invisible_removes_zero_width() {
        let s = "ig\u{200b}no\u{200b}re";
        assert_eq!(strip_invisible(s), "ignore");
    }

    #[test]
    fn defold_folds_cyrillic() {
        assert_eq!(defold("іgnоrе"), "ignore"); // cyrillic і, о, е
    }

    #[test]
    fn b64_roundtrips_known_text() {
        let enc = base64::engine::general_purpose::STANDARD.encode("ignore instructions");
        assert_eq!(b64_decode_utf8(&enc).as_deref(), Some("ignore instructions"));
        assert_eq!(b64_decode_utf8("not base64 !!"), None);
    }

    #[test]
    fn views_exclude_identity_and_cover_methods() {
        let views = normalized_views("Vtaber nyy cerivbhf");
        assert!(views.iter().any(|(m, _)| m == "rot13"));
        // none of the returned views equals the original
        assert!(views.iter().all(|(_, v)| v != "Vtaber nyy cerivbhf"));
    }
}

/// Defensive control that would close a finding, given the normalization that
/// catches it (`None` = no normalization catches it). This is the remediation
/// text a defender applies to the guardrail.
pub fn control_for(method: Option<&str>) -> &'static str {
    match method {
        Some("lower") => "Case-fold the input before scoring",
        Some("deleet") => "De-leetspeak the input (map 4/3/1/0/5/7 back to letters) before scoring",
        Some("strip_invisible") => "Strip zero-width, bidi and variation-selector characters before scoring",
        Some("defold_homoglyph") => "Fold confusable (homoglyph) characters to Latin before scoring",
        Some("reverse") => "Also score the reversed input (catch reversed payloads)",
        Some("rot13") => "Also score the rot13-decoded input",
        Some("b64decode") => "Decode base64 segments and score the decoded text",
        _ => "No single normalization catches it: add a chars-per-token anomaly filter and route to human review",
    }
}

/// Risk-based severity order, used to sort findings for the remediation list.
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        _ => 3,
    }
}

#[cfg(test)]
mod control_tests {
    use super::*;

    #[test]
    fn every_normalization_has_a_control() {
        for m in ["lower", "deleet", "strip_invisible", "defold_homoglyph", "reverse", "rot13", "b64decode"] {
            assert!(!control_for(Some(m)).starts_with("No single"));
        }
        assert!(control_for(None).starts_with("No single"));
    }

    #[test]
    fn critical_sorts_first() {
        assert!(severity_rank("Critical") < severity_rank("High"));
        assert!(severity_rank("High") < severity_rank("Low"));
    }
}
