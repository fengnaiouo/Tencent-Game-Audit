# Support

## Where to ask

- **Bug reports:** use the Bug Report issue form and include the application version, Windows version, locale, command-line options, and sanitized error output.
- **Detection questions or possible false positives:** use the Detection Review issue form. Include the exact finding identifier and sanitized evidence; do not upload a full host report.
- **Feature proposals:** open a GitHub issue describing the problem, expected behavior, and security/privacy implications.
- **Game compatibility:** use the Game Compatibility issue form and include only sanitized version, region, launcher, and path details.
- **Threat intelligence:** use the Threat Intelligence Submission form for public, attributable indicators. Do not submit live malware, credentials, private samples, or unredacted reports.
- **Security vulnerabilities:** follow [SECURITY.md](SECURITY.md). Do not disclose exploitable details in public issues.

## Experimental Rust component

The `rust-core/` crate is an experimental streaming-analysis component. It is not yet part of the released Windows executable. Report Rust-core bugs with the Rust toolchain version, crate commit, sanitized reproduction, and whether the issue affects memory budgeting, chunk-boundary matching, hashing, or concurrency.

## What support does not include

This is a community utility, not a managed security service. The maintainer does not guarantee response times, incident-response availability, malware removal, or that a clean scan means a system is safe.

## Privacy

Audit reports may contain usernames, device names, local paths, command lines, installed applications, and network information. Redact sensitive values before sharing. Never post credentials, tokens, private samples, or another person's report without consent.
