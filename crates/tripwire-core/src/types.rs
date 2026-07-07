//! Shared detection types. Defined once here; under the `node` feature they are
//! also the napi boundary types, so @napi-rs/cli generates the TypeScript
//! definitions from them (single source of truth -- no hand-written TS types).

/// Where in the request lifecycle a scan runs.
#[cfg_attr(feature = "node", napi_derive::napi(string_enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Text heading to the model (user/system/tool/document input).
    Inbound,
    /// Text heading back to the caller (model output).
    Outbound,
}

/// The class of a finding -- this is what the eval scores against the label.
#[cfg_attr(feature = "node", napi_derive::napi(string_enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Instruction-injection content aimed at the model.
    Injection,
    /// Secret or PII content leaving through the response.
    Exfiltration,
    /// Obfuscation/smuggling technique (unicode tags, zero-width, encoded blobs)
    /// that carries an injection or exfiltration payload.
    Obfuscation,
}

/// Severity of a finding; drives policy actions.
#[cfg_attr(feature = "node", napi_derive::napi(string_enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Notable but not actionable on its own.
    Info,
    /// Weak signal; usually needs corroboration.
    Low,
    /// Solid signal worth flagging.
    Medium,
    /// Confident detection; act on it.
    High,
    /// Unambiguous secret/attack material; block.
    Critical,
}

/// Where the scanned text came from. Injection heuristics weight untrusted
/// sources (tool output, fetched documents, MCP tool descriptions) higher --
/// that is where 2026 indirect-injection and tool poisoning land.
#[cfg_attr(feature = "node", napi_derive::napi(string_enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A user turn.
    User,
    /// The system prompt.
    System,
    /// Tool output returned into the context (untrusted).
    Tool,
    /// Fetched or attached document content (untrusted).
    Document,
    /// A tool/MCP description string (untrusted; poisoning surface).
    McpDescription,
    /// The model's own output (exfiltration surface).
    ModelOutput,
}

/// A single detection finding. Spans are byte offsets into the ORIGINAL text
/// (before normalization) so the gateway can redact/highlight precisely.
#[cfg_attr(feature = "node", napi_derive::napi(object))]
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Which taxonomy the finding belongs to.
    pub kind: Kind,
    /// Stable machine label for the specific pattern, e.g. `unicode_tag_smuggling`,
    /// `aws_access_key`, `markdown_image_exfil`, `instruction_override`.
    pub label: String,
    /// Calibrated severity for this label.
    pub severity: Severity,
    /// 0.0..=1.0, calibrated per label (not guessed).
    pub score: f64,
    /// Byte offset of the match start in the original text.
    pub start: u32,
    /// Byte offset of the match end in the original text.
    pub end: u32,
    /// Which scanned surface produced the finding.
    pub source: Source,
    /// Optional human/debug detail (e.g. decoded payload provenance).
    pub detail: Option<String>,
}

impl Finding {
    /// Constructor used by the scanners.
    pub fn new(
        kind: Kind,
        label: impl Into<String>,
        severity: Severity,
        score: f64,
        span: (usize, usize),
        source: Source,
    ) -> Self {
        Finding {
            kind,
            label: label.into(),
            severity,
            score,
            start: span.0 as u32,
            end: span.1 as u32,
            source,
            detail: None,
        }
    }
}
