# Tencent Game Audit

[![CI](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/fengnaiouo/Tencent-Game-Audit?display_name=tag)](https://github.com/fengnaiouo/Tencent-Game-Audit/releases)
[![License](https://img.shields.io/badge/license-not_yet_declared-lightgrey)](#license)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue)](#requirements)

A portable, read-only Windows security auditing tool for Tencent's game ecosystem worldwide. It inventories game and launcher locations and hunts for documented indicators of compromise (IOCs), suspicious persistence, process behavior, DLL content, signatures, and network artifacts.

**[Download the latest release](https://github.com/fengnaiouo/Tencent-Game-Audit/releases/latest) · [Report a bug](https://github.com/fengnaiouo/Tencent-Game-Audit/issues/new?template=bug_report.yml) · [Report a security issue](SECURITY.md)**

> **Scope and evidence discipline:** This project investigates Tencent-operated, controlled, published, and selected investment-related game ecosystems. A publisher or investment relationship is a discovery hint, not proof that a title is owned by Tencent or compromised. NIKKE/K2F indicators remain attributed to that documented incident unless independent evidence supports broader attribution. A clean scan is not proof of a clean system.

## Global and regional support

- Designed for Windows installations in mainland China, Taiwan, Hong Kong, Japan, Korea, Southeast Asia, Europe, the Americas, and other regions.
- Does not hard-code a country, timezone, decimal format, or installation drive. Uses Windows environment variables, mounted fixed-volume metadata, registry metadata, launcher manifests, Steam libraries, Epic manifests, and optional user-supplied paths.
- Recognizes selected Traditional Chinese and Simplified Chinese game-title and publisher aliases alongside international titles.
- JSON field names remain stable English identifiers for automation and SIEM ingestion. Timestamps use RFC 3339 with the host's local UTC offset.
- Console language can be selected with `-lang auto|en|zh-Hant|zh-Hans|ja|ko|pt-BR|fr|de|es|id|th|vi|ru|pl|tr|it`. Unsupported locales fall back to English. `auto` uses locale environment variables or the Windows user UI culture and otherwise falls back to English; explicitly set `-lang` for predictable output. Summary labels are localized; finding details and JSON identifiers remain English for stable triage and automation.
- IOC matching is region-independent. Regional game editions, publisher names, launcher paths, and custom install locations can differ; use repeatable `-root` arguments to include locations not discovered automatically.

## Requirements

- Target: Windows 10/11 x64 (the portable release does not require Go, Rust, Python, or network access).
- Recommended: run elevated for broader visibility into services, processes, registry and other users' files. Non-elevated scans remain useful but may have access limitations.
- Build: Go 1.23 or newer.

## Trust, safety and limitations

- This is a defensive, read-only triage utility, not an antivirus, EDR, incident-response service, or guarantee that a host is clean.
- Findings are evidence leads. Validate file provenance, timestamps, signatures, process context and IOC freshness before taking action.
- Historical browser artifacts do not establish a current command-and-control session. Heuristic matches may be legitimate software behavior.
- The scanner does not upload reports or samples. Treat generated reports as sensitive local data and share only sanitized copies.
- Detection coverage and known blind spots are documented in [Detection Sources](docs/DETECTION-SOURCES.md) and the [changelog](CHANGELOG.md).

## Quick start

```powershell
# Standard scan
.\Tencent-Game-Audit.exe

# Include additional game libraries (repeat -root as needed)
.\Tencent-Game-Audit.exe -root "D:\Games" -root "F:\WeGame"

# Focused scan of only the supplied paths
.\Tencent-Game-Audit.exe -root-only -root "D:\Games"

# System persistence, process and network snapshot only
.\Tencent-Game-Audit.exe -system-only

# Raise file scan budget
.\Tencent-Game-Audit.exe -full

# Choose report/console locale and a private report destination
.\Tencent-Game-Audit.exe -lang en -json "$env:TEMP\Tencent-Game-Audit.json"
.\Tencent-Game-Audit.exe -lang zh-Hant -json "$env:TEMP\Tencent-Game-Audit.json"

# Human-readable reports (JSON remains the default)
.\Tencent-Game-Audit.exe -format html -out "$env:TEMP\Tencent-Game-Audit.html"
.\Tencent-Game-Audit.exe -format csv -out "$env:TEMP\Tencent-Game-Audit.csv"
.\Tencent-Game-Audit.exe -format md -out "$env:TEMP\Tencent-Game-Audit.md"
```

The scanner is read-only: it does not delete, quarantine, repair, terminate processes, change Defender/firewall/hosts/registry settings, or contact live C2 infrastructure. Reports are available as JSON, TXT, offline HTML, CSV, and Markdown through `-format` and `-out`; the legacy `-json` option remains supported. Reports can contain usernames, computer names, file paths, process command lines, and installed-game information; review and redact them before public sharing.

## Detection coverage

- Game and launcher discovery from Windows uninstall metadata, Steam libraries, Epic manifests, Tencent/WeGame/Level Infinite/Riot paths, known game directory names, and explicit paths.
- Known K2F hashes, strings, LuaJIT structure, launcher/cache traces, persistence identifiers, DNS/hosts/named-pipe and active TCP IOC matches.
- Candidate executable, DLL, SYS and script content scanning; Authenticode status and signer enrichment for findings.
- Windows Run keys, services, scheduled tasks, Startup folders, per-user COM registrations, loaded browser persistence DLLs, Chromium cache/HSTS records, suspicious process command lines and established external TCP connections.
- Selected cross-game loader API combinations are triage leads only. Game engines, anti-cheat, DRM, overlays and modding tools may legitimately use similar APIs.

### Severity

- `CRITICAL`: a high-confidence, specifically documented IOC or persistence indicator matched.
- `WARNING`: multiple or meaningful indicators warrant investigation; not a definitive infection verdict.
- `REVIEW`: heuristic or contextual evidence requiring analyst validation.
- `INFO`: inventory, scan limits, or informational observations.

## Build from source

```powershell
cd tencent-game-audit
.\build-portable.ps1
```

The script runs uncached Go tests, `go vet`, builds Windows amd64 with CGO disabled, and creates the portable ZIP. It does not start a server. Build outputs are ignored by Git and should be attached to a tagged GitHub Release rather than committed to source history.

## Repository layout

- `tencent-game-audit/`: Go source, tests, embedded IOC CSV, and portable build script.
- `docs/`: detection source provenance and technical notes.
- `docs/PROJECT-SESSION-LOG.md`: append-only project conversation summaries, tool activity, and validation history (not a verbatim account-wide transcript).
- `README.md`: project overview and quick start.

## Contributing and responsible disclosure

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [detection source notes](docs/DETECTION-SOURCES.md). Every IOC should include a source, first/last-seen context where known, confidence, affected product/region if established, and license/redistribution notes. Do not convert rumors or a Tencent investment relationship into a confirmed compromise claim.

Project decision-making and release responsibilities are described in [GOVERNANCE.md](GOVERNANCE.md). For non-security questions, see [SUPPORT.md](SUPPORT.md).

## License

No license has been declared yet. Until a license is added by the repository owner, all rights are reserved; do not assume that public visibility grants permission to redistribute or relicense the source or bundled IOC data.
