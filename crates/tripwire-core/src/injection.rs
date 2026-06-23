//! Injection scanner: source-aware heuristics for prompt-injection, jailbreak,
//! indirect injection, and tool/MCP-description poisoning. Implemented in T4.

use crate::types::{Direction, Finding, Source};

/// Scan `text` (already normalized) for injection findings.
pub fn scan(_text: &str, _direction: Direction, _source: Source) -> Vec<Finding> {
    Vec::new()
}
