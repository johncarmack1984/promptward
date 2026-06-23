# Security Policy

promptward is a security tool, so its own supply chain and disclosure process are held to the same bar as the detection it ships.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in a public issue. Use GitHub's private vulnerability reporting on this repository: open the **Security** tab and choose **Report a vulnerability**. That opens a channel visible only to the maintainer.

Where you can, include the affected component (tripwire-core, gateway, dashboard, or evals), a minimal reproduction, the impact, and any suggested remediation. This is maintained by one person, so acknowledgement will come as soon as practical; please allow a reasonable window for a fix before any public disclosure.

## Scope

In scope: the detection core (`crates/tripwire-core`), the gateway proxy (`apps/gateway`), the dashboard (`apps/dashboard`), and the eval harness (`evals`). Of particular interest are detection bypasses (an injection or exfiltration payload the scanners miss), redaction that leaks the value it claims to remove, and any path that lets untrusted request content reach the provider or the event store unscanned.

Out of scope: findings that depend on a misconfigured deployment (for example, running with detection disabled), denial of service from pathologically large inputs, and vulnerabilities in third-party dependencies that are already tracked publicly upstream.

## A note on secrets in this repository

Every key, token, and PEM in the datasets and tests is a documented fake (for example, AWS's published `AKIAIOSFODNN7EXAMPLE`). No real credential is present in the working tree or its history. If you believe you have found a real secret, report it through the channel above.
