# Security Policy

## Supported versions

Only the latest published release is actively maintained. The experimental `rust-core/` component is maintained on the repository's default branch but is not currently included in released binaries. Older releases may contain stale IOC data, dependency vulnerabilities, or known detection limitations. Users should upgrade to the latest release before reporting a bug.

## Reporting a vulnerability

Please do not publish exploitable details, malware samples containing live credentials, private user reports, or unredacted audit JSON in public issues. GitHub private vulnerability reporting is enabled for this repository; use [the private advisory form](https://github.com/fengnaiouo/Tencent-Game-Audit/security/advisories/new). If the form is temporarily unavailable, contact the repository maintainer privately through the contact method listed in the GitHub profile.

Please allow the maintainer a reasonable period to investigate and coordinate a fix before public disclosure. There is currently no guaranteed response or remediation SLA; this is a maintainer-led community project.

If GitHub private vulnerability reporting is enabled, use the private advisory form linked above. Public issues are not an appropriate channel for exploitable vulnerabilities, bypass techniques, live payloads, or sensitive host evidence. If the private form is unavailable, use the maintainer's private contact route from the GitHub profile and do not attach sensitive artifacts to a public discussion.

Include the affected version/commit, Windows version and locale, minimal reproduction steps, expected and actual behavior, and sanitized logs. Never include passwords, access tokens, API keys, personal identifiers, or another person's scan report without consent.

## IOC submissions

IOC contributions must cite a verifiable public source or provide a reproducible sample-analysis method. Include indicator type/value, product and region when known, confidence, dates, false-positive considerations, and redistribution/licensing terms. Clearly distinguish confirmed malicious indicators from historical or heuristic leads.

## Safe handling

Do not send full audit reports unless specifically requested through a private channel. Reports can expose hostnames, usernames, local paths, process command lines, installed software, and network metadata. Never submit passwords, access tokens, private keys, or personal information belonging to another person.
