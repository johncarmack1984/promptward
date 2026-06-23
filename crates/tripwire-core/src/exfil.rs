//! Exfiltration scanner: secrets (keys/tokens/JWT/PEM), PII (email/SSN/card via
//! Luhn), entropy fallback, and markdown/link exfil on the output path.
//! Implemented in T5.

use crate::types::{Direction, Finding, Source};

/// Scan `text` (already normalized) for exfiltration findings.
pub fn scan(_text: &str, _direction: Direction, _source: Source) -> Vec<Finding> {
    Vec::new()
}
