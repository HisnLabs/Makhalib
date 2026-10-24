//! Text extraction for PNG text chunks and PDF text streams (P12). This is the
//! reading side of the canary carriers: it recovers the text a pipeline would see
//! in a document or image, so the canary tests can check whether it was read.
//! These are deliberately minimal parsers for files this tool produces and for
//! simple uncompressed PDFs. They do not decode compressed streams.

/// Text recovered from a PNG's tEXt chunks, as (keyword, text) pairs.
pub fn png_text_chunks(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if bytes.len() < 8 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
        return out;
    }
    let mut pos = 8;
    while pos + 8 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
        let kind = &bytes[pos + 4..pos + 8];
        let start = pos + 8;
        let end = match start.checked_add(len) {
            Some(e) if e <= bytes.len() => e,
            _ => break,
        };
        if kind == b"tEXt" {
            let data = &bytes[start..end];
            if let Some(nul) = data.iter().position(|&b| b == 0) {
                let key = String::from_utf8_lossy(&data[..nul]).to_string();
                let val = String::from_utf8_lossy(&data[nul + 1..]).to_string();
                out.push((key, val));
            }
        }
        pos = end + 4; // skip CRC
        if kind == b"IEND" {
            break;
        }
    }
    out
}

/// Text shown by `Tj` operators in an uncompressed PDF, in order of appearance.
pub fn pdf_text(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut rest: &str = &text;
    while let Some(tj) = rest.find(") Tj") {
        let before = &rest[..tj];
        if let Some(open) = before.rfind('(') {
            out.push(unescape_pdf(&before[open + 1..]));
        }
        rest = &rest[tj + 4..];
    }
    out
}

fn unescape_pdf(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Removes zero-width characters, as a text normalizer would before matching.
pub fn strip_zero_width(text: &str) -> String {
    text.chars().filter(|c| !matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}')).collect()
}

/// True if `needle` appears in any text the extractors recover from the bytes,
/// after zero-width characters are normalized away.
pub fn recovers(bytes: &[u8], needle: &str) -> bool {
    let raw = String::from_utf8_lossy(bytes);
    png_text_chunks(bytes).iter().any(|(_, v)| strip_zero_width(v).contains(needle))
        || pdf_text(bytes).iter().any(|t| strip_zero_width(t).contains(needle))
        || strip_zero_width(&raw).contains(needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier;

    const C: &str = "CANARY-EXTRACT-1";

    #[test]
    fn png_text_chunk_is_recovered() {
        let chunks = png_text_chunks(&carrier::png_text(C));
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, "Comment");
        assert_eq!(chunks[0].1, C);
    }

    #[test]
    fn pdf_tj_text_is_recovered() {
        let texts = pdf_text(&carrier::pdf(C));
        assert_eq!(texts, vec![C.to_string()]);
    }

    #[test]
    fn pdf_unescapes_parentheses() {
        assert_eq!(unescape_pdf(r"a\(b\)c"), "a(b)c");
    }

    #[test]
    fn non_png_yields_no_chunks_and_truncated_png_does_not_panic() {
        assert!(png_text_chunks(b"not a png").is_empty());
        let full = carrier::png_text(C);
        for n in 0..full.len() {
            let _ = png_text_chunks(&full[..n]);
        }
    }

    #[test]
    fn recovers_across_carrier_kinds() {
        for c in carrier::all_carriers(C) {
            assert!(recovers(&c.bytes, C), "not recovered: {:?}", c.kind);
        }
    }
}
