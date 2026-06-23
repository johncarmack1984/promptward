//! napi boundary. Thin shim over the pure `scan` -- the only Rust<->TS surface.
//! @napi-rs/cli generates index.js + index.d.ts from these signatures.

use napi_derive::napi;

use crate::{scan as core_scan, Direction, Finding, Source};

/// Scan `text` for injection / exfiltration / smuggling findings.
///
/// `direction` is "Inbound" | "Outbound"; `source` defaults to `User`.
#[napi]
pub fn scan(text: String, direction: Direction, source: Option<Source>) -> Vec<Finding> {
    core_scan(&text, direction, source.unwrap_or(Source::User))
}
