//! Markdown / link exfiltration on the OUTPUT path -- the canonical zero-tool
//! leak: a model that renders markdown leaks data through an (often invisible)
//! image or link whose URL carries the stolen content in its query or path.
//!
//! A URL to a non-allowlisted host that also carries a data-shaped payload
//! (a long base64-ish token, or an embedded secret) is the strong signal. A
//! non-allowlisted host with no payload is only a weak signal (people link out
//! legitimately), so it scores below the decision threshold.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::types::{Direction, Finding, Kind, Severity, Source};

static URL: Lazy<Regex> = Lazy::new(|| Regex::new(r"https?://[^\s)\]<>]+").unwrap());
static LONG_TOKEN: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9+/_=-]{16,}").unwrap());
static SECRET_IN_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{16,}|sk-(?:ant-)?[A-Za-z0-9]{16,}").unwrap()
});

const ALLOWED: &[&str] = &[
    "example.com",
    "github.com",
    "raw.githubusercontent.com",
    "github.io",
    "localhost",
    "127.0.0.1",
];

fn host_of(url: &str) -> Option<&str> {
    let after = url.split_once("://")?.1;
    let host = after.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next().unwrap_or(host); // strip userinfo
    let host = host.split(':').next().unwrap_or(host); // strip port
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn allowed(host: &str) -> bool {
    ALLOWED
        .iter()
        .any(|a| host == *a || host.ends_with(&format!(".{a}")))
}

/// Scan model output for URL-based exfiltration. Only runs on the output path.
pub fn scan(text: &str, direction: Direction, source: Source) -> Vec<Finding> {
    if direction != Direction::Outbound && source != Source::ModelOutput {
        return Vec::new();
    }
    let mut out = Vec::new();
    for m in URL.find_iter(text) {
        let url = m.as_str();
        let host = match host_of(url) {
            Some(h) => h,
            None => continue,
        };
        if allowed(host) {
            continue;
        }
        let after_host = url.split_once(host).map(|x| x.1).unwrap_or("");
        let data_shaped = SECRET_IN_URL.is_match(url) || LONG_TOKEN.is_match(after_host);
        let (label, score, sev) = if data_shaped {
            ("markdown_image_exfil", 0.88, Severity::High)
        } else {
            ("external_link", 0.35, Severity::Low)
        };
        out.push(Finding::new(
            Kind::Exfiltration,
            label,
            sev,
            score,
            (m.start(), m.end()),
            source,
        ));
    }
    out
}
