//! Normalization + unicode-smuggling detection -- the first pass of every scan.
//!
//! Attackers hide directives from human reviewers (and naive keyword filters)
//! with invisible code points: the Unicode Tags block (U+E0000-U+E007F, which
//! encodes ASCII), zero-width characters that split keywords, and bidi controls
//! that reorder text. This pass:
//!   - emits an `Obfuscation` finding for each run of smuggling code points,
//!   - reveals tag-encoded ASCII back into the stream,
//!   - drops zero-width / bidi controls and NFKC-folds the rest (e.g. full-width
//!     letters) so the downstream injection/exfiltration scanners see the real
//!     text,
//!   - keeps a byte-offset map so findings on the normalized text can be mapped
//!     back to spans in the ORIGINAL text for redaction.

use unicode_normalization::UnicodeNormalization;

use crate::types::{Finding, Kind, Severity, Source};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Smuggle {
    ZeroWidth,
    Bidi,
    Tag,
}

fn smuggle_of(c: u32) -> Option<Smuggle> {
    match c {
        0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF => Some(Smuggle::ZeroWidth),
        0x202A..=0x202E | 0x2066..=0x2069 => Some(Smuggle::Bidi),
        0xE0000..=0xE007F => Some(Smuggle::Tag),
        _ => None,
    }
}

fn finding_for(cat: Smuggle, span: (usize, usize)) -> Finding {
    let (label, sev, score) = match cat {
        Smuggle::Tag => ("unicode_tag_smuggling", Severity::High, 0.95),
        Smuggle::Bidi => ("bidi_control", Severity::Medium, 0.70),
        Smuggle::ZeroWidth => ("zero_width", Severity::Medium, 0.60),
    };
    Finding::new(Kind::Obfuscation, label, sev, score, span, Source::User)
}

/// Result of normalizing a piece of text.
pub struct Normalized {
    /// De-smuggled, NFKC-folded text the downstream scanners run on.
    pub text: String,
    /// Smuggling findings, with spans in the ORIGINAL text.
    pub findings: Vec<Finding>,
    /// `map[i]` = original byte offset that produced normalized byte `i`.
    /// Length is `text.len() + 1`; the final entry is `original.len()`.
    map: Vec<usize>,
    orig_len: usize,
}

impl Normalized {
    /// Map a byte offset in the normalized text back to the original text.
    pub fn to_original(&self, norm_byte: usize) -> usize {
        self.map.get(norm_byte).copied().unwrap_or(self.orig_len)
    }

    /// Rewrite a finding's span from normalized coordinates to original ones.
    pub fn remap(&self, mut f: Finding) -> Finding {
        let s = self.to_original(f.start as usize);
        let e = self.to_original(f.end as usize);
        f.start = s as u32;
        f.end = e as u32;
        f
    }
}

fn push_char(text: &mut String, map: &mut Vec<usize>, nch: char, src: usize) {
    let mut buf = [0u8; 4];
    let s = nch.encode_utf8(&mut buf);
    text.push_str(s);
    for _ in 0..s.len() {
        map.push(src);
    }
}

/// Normalize `original`, detecting unicode smuggling and folding the rest.
pub fn analyze(original: &str) -> Normalized {
    let mut text = String::with_capacity(original.len());
    let mut map: Vec<usize> = Vec::with_capacity(original.len() + 1);
    let mut findings = Vec::new();
    // (category, run_start_byte, run_end_byte) in the original text.
    let mut run: Option<(Smuggle, usize, usize)> = None;

    for (i, ch) in original.char_indices() {
        let c = ch as u32;
        let end = i + ch.len_utf8();
        if let Some(cat) = smuggle_of(c) {
            match run {
                Some((rc, rs, _)) if rc == cat => run = Some((rc, rs, end)),
                Some((rc, rs, re)) => {
                    findings.push(finding_for(rc, (rs, re)));
                    run = Some((cat, i, end));
                }
                None => run = Some((cat, i, end)),
            }
            // Reveal printable tag-block characters (U+E0020..=U+E007E -> ASCII).
            if cat == Smuggle::Tag && (0xE0020..=0xE007E).contains(&c) {
                if let Some(rch) = char::from_u32(c - 0xE0000) {
                    push_char(&mut text, &mut map, rch, i);
                }
            }
        } else {
            if let Some((rc, rs, re)) = run.take() {
                findings.push(finding_for(rc, (rs, re)));
            }
            for nch in ch.nfkc() {
                push_char(&mut text, &mut map, nch, i);
            }
        }
    }
    if let Some((rc, rs, re)) = run.take() {
        findings.push(finding_for(rc, (rs, re)));
    }
    map.push(original.len());

    Normalized {
        text,
        findings,
        map,
        orig_len: original.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reveals_zero_width_split_keyword() {
        let n = analyze("ig\u{200b}nore this");
        assert!(n.text.contains("ignore this"), "got: {:?}", n.text);
        assert!(n
            .findings
            .iter()
            .any(|f| f.label == "zero_width" && f.kind == Kind::Obfuscation));
    }

    #[test]
    fn reveals_tag_smuggled_text() {
        // Tag-encode "hi": U+E0068, U+E0069.
        let s = format!("a{}{}b", '\u{E0068}', '\u{E0069}');
        let n = analyze(&s);
        assert!(n.text.contains("ahib"), "got: {:?}", n.text);
        assert!(n.findings.iter().any(|f| f.label == "unicode_tag_smuggling"));
    }

    #[test]
    fn flags_bidi_override() {
        let n = analyze("abc\u{202E}def");
        assert!(n.findings.iter().any(|f| f.label == "bidi_control"));
    }

    #[test]
    fn nfkc_folds_fullwidth() {
        // Full-width "ignore" -> ASCII "ignore".
        let n = analyze("\u{FF49}\u{FF47}\u{FF4E}\u{FF4F}\u{FF52}\u{FF45}");
        assert_eq!(n.text, "ignore");
    }

    #[test]
    fn benign_text_has_no_findings_and_is_unchanged() {
        let s = "Summarize this report in three bullets.";
        let n = analyze(s);
        assert!(n.findings.is_empty());
        assert_eq!(n.text, s);
    }

    #[test]
    fn offset_map_stays_in_bounds() {
        let s = "ig\u{200b}nore all previous";
        let n = analyze(s);
        for i in 0..=n.text.len() {
            assert!(n.to_original(i) <= s.len());
        }
    }
}
