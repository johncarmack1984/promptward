//! tripwire-core: detection on the request hot path.
//!
//! Two cheap, deterministic scanner families run before any model call:
//!   - injection: source-aware heuristics for prompt-injection / jailbreak /
//!     indirect-injection / tool-and-MCP-description poisoning.
//!   - exfiltration: secrets + PII (regex + entropy) and markdown/link exfil.
//! A normalization + smuggling pass and a decode-then-rescan pass run first so
//! invisible-unicode and encoded payloads become visible to the rest.
//!
//! Everything here is pure, deterministic, and allocation-light -- it sits in
//! front of every call. The optional LLM-judge lives in the gateway, not here.

mod types;

pub use types::{Direction, Finding, Kind, Severity, Source};

// The napi boundary (cdylib addon) is compiled only under the `node` feature.
#[cfg(feature = "node")]
mod node;

/// Scan a chunk of text and return findings. Pure, deterministic, no I/O.
///
/// T1 ships the type contract and binding with a trivial empty result; the
/// normalization, decode, injection, and exfiltration passes land in T3-T5,
/// driven by the labeled corpus (see docs/SPEC.md section 5).
pub fn scan(_text: &str, _direction: Direction, _source: Source) -> Vec<Finding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_returns_empty_for_now() {
        let findings = scan("hello world", Direction::Inbound, Source::User);
        assert!(findings.is_empty());
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
