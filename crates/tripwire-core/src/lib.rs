//! tripwire-core: detection on the request hot path.
//!
//! Two cheap, deterministic scanners run before any model call:
//!   - injection: heuristic patterns for prompt-injection / jailbreak attempts
//!   - exfiltration: secrets + PII (regex + entropy) leaving in a prompt or response
//!
//! An optional LLM-judge pass (in the gateway, not here) handles the fuzzy cases.
//! Everything here must be fast and allocation-light -- it sits in front of every call.

/// Where in the request lifecycle a scan runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// User/system text heading to the model.
    Inbound,
    /// Model text heading back to the caller.
    Outbound,
}

/// A single detection finding.
#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: Kind,
    pub label: String,
    /// 0.0..=1.0 -- deterministic scanners should be calibrated, not guessed.
    pub score: f32,
    /// Byte range in the scanned text, for redaction/highlighting.
    pub span: (usize, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Injection,
    Exfiltration,
}

/// Scan a chunk of text and return any findings. Pure, no I/O.
pub fn scan(_text: &str, _direction: Direction) -> Vec<Finding> {
    // TODO(build): implement via spec -> tests -> code (see docs/SPEC.md, evals/datasets/*.jsonl).
    // Drive this with the eval datasets: write failing tests from the labeled examples first.
    todo!("implement injection + exfiltration scanners against the eval datasets")
}
