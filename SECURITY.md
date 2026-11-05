# Security Policy

## Supported versions

Only the latest published release is actively maintained. Older releases may contain stale IOC data, dependency vulnerabilities, or known detection limitations. Users should upgrade to the latest release before reporting a bug.

## Reporting a vulnerability

Please do not publish exploitable details, malware samples containing live credentials, private user reports, or unredacted audit JSON in public issues. Use [GitHub's private vulnerability reporting](https://github.com/fengnaiouo/Tencent-Game-Audit/security/advisories/new) when available. If private reporting is unavailable, contact the repository maintainer privately through the contact method listed in the GitHub profile.

Please allow the maintainer a reasonable period to investigate and coordinate a fix before public disclosure. There is currently no guaranteed response or remediation SLA; this is a maintainer-led community project.

Include the affected version/commit, Windows version and locale, minimal reproduction steps, expected and actual behavior, and sanitized logs. Never include passwords, access tokens, API keys, personal identifiers, or another person's scan report without consent.

## IOC submissions

IOC contributions must cite a verifiable public source or provide a reproducible sample-analysis method. Include indicator type/value, product and region when known, confidence, dates, false-positive considerations, and redistribution/licensing terms. Clearly distinguish confirmed malicious indicators from historical or heuristic leads.

## Safe handling

Do not send full audit reports unless specifically requested through a private channel. Reports can expose hostnames, usernames, local paths, process command lines, installed software, and network metadata. Never submit passwords, access tokens, private keys, or personal information belonging to another person.
