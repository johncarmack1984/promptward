//! tripwire-core: detection on the request hot path.
//!
//! `scan` runs a fixed, deterministic pipeline reflecting the current (2026)
//! attack surface, not 2024 keyword matching:
//!   1. normalize + smuggling detection (NFKC; reveal unicode-tag/zero-width/bidi)
//!   2. injection scan (source-aware) on the normalized text
//!   3. exfiltration scan (secrets/PII/markdown-exfil) on the normalized text
//!   4. decode-then-rescan (base64/hex/url/rot13) of any encoded payloads
//! Spans are mapped back to byte offsets in the ORIGINAL text for redaction.
//!
//! Everything here is pure, deterministic, and allocation-light. The optional
//! LLM-judge lives in the gateway, not here.

mod decode;
mod exfil;
mod injection;
mod normalize;
mod types;

pub use types::{Direction, Finding, Kind, Severity, Source};

// The napi boundary (cdylib addon) is compiled only under the `node` feature.
#[cfg(feature = "node")]
mod node;

/// Scan a chunk of text and return findings. Pure, deterministic, no I/O.
pub fn scan(text: &str, direction: Direction, source: Source) -> Vec<Finding> {
    let norm = normalize::analyze(text);
    let mut findings: Vec<Finding> = norm.findings.clone();

    // Primary scan on the de-smuggled, normalized text; map spans back to original.
    for f in injection::scan(&norm.text, direction, source) {
        findings.push(norm.remap(f));
    }
    for f in exfil::scan(&norm.text, direction, source) {
        findings.push(norm.remap(f));
    }

    // Decode-then-rescan: unwrap encoded payloads and scan them, attributing any
    // finding to the encoded region's span in the original text.
    for seg in decode::candidates(&norm.text) {
        let start = norm.to_original(seg.start) as u32;
        let end = norm.to_original(seg.end) as u32;
        let mut sub = injection::scan(&seg.text, direction, source);
        sub.extend(exfil::scan(&seg.text, direction, source));
        for mut f in sub {
            f.start = start;
            f.end = end;
            f.detail = Some(match f.detail {
                Some(d) => format!("decoded:{}; {d}", seg.kind),
                None => format!("decoded:{}", seg.kind),
            });
            findings.push(f);
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_is_clean_on_benign_text() {
        let findings = scan(
            "Summarize this quarterly report in three bullets.",
            Direction::Inbound,
            Source::User,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_flags_unicode_smuggling_as_obfuscation() {
        // Zero-width split keyword: the smuggling pass should flag it even before
        // the injection scanner (T4) lands.
        let findings = scan("ig\u{200b}nore previous", Direction::Inbound, Source::User);
        assert!(findings
            .iter()
            .any(|f| f.kind == Kind::Obfuscation && f.label == "zero_width"));
    }

    #[test]
    fn finding_constructor_sets_span_as_u32() {
        let f = Finding::new(
            Kind::Injection,
            "instruction_override",
            Severity::High,
            0.9,
            (5, 12),
            Source::User,
        );
        assert_eq!(f.start, 5);
        assert_eq!(f.end, 12);
        assert_eq!(f.label, "instruction_override");
        assert_eq!(f.detail, None);
    }
}
