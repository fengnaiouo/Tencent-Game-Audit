# Tencent Game Audit

[![CI](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/fengnaiouo/Tencent-Game-Audit?display_name=tag)](https://github.com/fengnaiouo/Tencent-Game-Audit/releases)
[![License](https://img.shields.io/badge/license-not_yet_declared-lightgrey)](#license)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue)](#requirements)

A portable, read-only Windows security auditing tool for Tencent's game ecosystem worldwide. It inventories game and launcher locations and hunts for documented indicators of compromise (IOCs), suspicious persistence, process behavior, DLL content, signatures, and network artifacts.

**[Download the latest release](https://github.com/fengnaiouo/Tencent-Game-Audit/releases/latest) · [Report a bug](https://github.com/fengnaiouo/Tencent-Game-Audit/issues/new?template=bug_report.yml) · [Request a feature](https://github.com/fengnaiouo/Tencent-Game-Audit/issues/new?template=feature_request.yml) · [Report a security issue](SECURITY.md)**

> **Scope and evidence discipline:** This project investigates Tencent-operated, controlled, published, and selected investment-related game ecosystems. A publisher or investment relationship is a discovery hint, not proof that a title is owned by Tencent or compromised. NIKKE/K2F indicators remain attributed to that documented incident unless independent evidence supports broader attribution. A clean scan is not proof of a clean system.

## Global and regional support

- Designed for Windows installations in mainland China, Taiwan, Hong Kong, Japan, Korea, Southeast Asia, Europe, the Americas, and other regions.
- Does not hard-code a country, timezone, decimal format, or installation drive. Uses Windows environment variables, mounted fixed-volume metadata, registry metadata, launcher manifests, Steam libraries, Epic manifests, and optional user-supplied paths.
- Recognizes selected Traditional Chinese and Simplified Chinese game-title and publisher aliases alongside international titles.
- JSON field names remain stable English identifiers for automation and SIEM ingestion. Timestamps use RFC 3339 with the host's local UTC offset.
- Console language can be selected with `-lang auto|en|zh-Hant|zh-Hans|ja|ko|pt-BR|fr|de|es|id|th|vi|ru|pl|tr|it`. Unsupported locales fall back to English. `auto` uses locale environment variables or the Windows user UI culture and otherwise falls back to English; explicitly set `-lang` for predictable output. Summary labels are localized; finding details and JSON identifiers remain English for stable triage and automation.
- IOC matching is region-independent. Regional game editions, publisher names, launcher paths, and custom install locations can differ; use repeatable `-root` arguments to include locations not discovered automatically.
- Selected roots are traversed without arbitrary global/per-root file-count caps or directory-name pruning. `-full` includes every mounted fixed volume; reports distinguish complete traversal from incomplete content analysis and count inaccessible/reparse-point entries.

## Requirements

- Target: Windows 10/11 x64 (the portable release does not require Go, Rust, Python, or network access).
- Recommended: run elevated for broader visibility into services, processes, registry and other users' files. Non-elevated scans remain useful but may have access limitations.
- Portable release: no Go, Rust, Python, or network access required.
- Build from source: Go 1.23 or newer. The experimental Rust core additionally requires the stable Rust toolchain and Cargo.

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

# Strictly scan only the supplied paths (no registry or global system snapshot)
.\Tencent-Game-Audit.exe -root-only -root "D:\Games"

# System persistence, process and network snapshot only
.\Tencent-Game-Audit.exe -system-only

# Scan every mounted fixed volume (may take many hours)
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

`-root-only` is a strict isolation mode: only explicitly supplied `-root` paths are traversed. It skips uninstall-registry/game discovery and the global Windows system snapshot (persistence, services, scheduled tasks, processes, loaded modules, network connections, DNS, hosts, named pipes and Defender status). It does not follow symbolic links/reparse points, and it does scan ordinary subdirectories such as `packages`. Every report format records the actual scan roots and whether the system snapshot was collected. Use the standard mode or `-system-only` separately when host-wide checks are required.

## Detection coverage

- Game and launcher discovery from Windows uninstall metadata, Steam libraries, Epic manifests, Tencent/WeGame/Level Infinite/Riot paths, known game directory names, and explicit paths.
- Known K2F hashes, strings, LuaJIT structure, launcher/cache traces, persistence identifiers, DNS/hosts/named-pipe and active TCP IOC matches.
- Candidate executable, DLL, SYS and script content scanning; Authenticode status and signer enrichment for findings.
- Generic LuaJIT markers are checked only as structurally plausible file-leading dumps, not as raw byte sequences anywhere inside PE machine code. Authenticode reporting separates unsigned files, untrusted roots, invalid signatures, and unknown verification errors.
- Windows Run keys, services, scheduled tasks, Startup folders, per-user COM registrations, loaded browser persistence DLLs, Chromium cache/HSTS records, suspicious process command lines and established external TCP connections.
- Selected cross-game loader API combinations are triage leads only. Game engines, anti-cheat, DRM, overlays and modding tools may legitimately use similar APIs.

### Severity

- `CRITICAL`: a high-confidence, specifically documented IOC or persistence indicator matched.
- `WARNING`: multiple or meaningful indicators warrant investigation; not a definitive infection verdict.
- `REVIEW`: heuristic or contextual evidence requiring analyst validation.
- `INFO`: inventory, coverage limitations, or informational observations.

### Log Forensics

- Enhanced Log Forensics is enabled by default for selected game/launcher roots. It inspects `.log`, rotated `.log.*`, and selected debug/service/crash text logs; `-no-logs` disables this dedicated context-analysis pass, while normal file IOC scanning remains active.
- The NIKKE profile includes the reported `Launcher/intl_service/debug.log` and `Launcher/log/tinyget/` locations through recursive discovery. Paths are not assumed to exist in every region or launcher version.
- Exact `k2f_chan registered` and `lua downloaded to log\\tinyget` markers are high-confidence incident-specific evidence. A bare `k2f_chan`, asset filename, or generic process API string is only a review lead.
- Log discovery has no global candidate-count cap; text parsing is bounded to 16 MiB per file. Current/rotated text logs support UTF-8 and UTF-16 BOMs; compressed logs and binary payloads are not parsed as text. Reports identify incomplete content analysis.
- Evidence contains line number, nearby context, timestamp text when present, SHA-256, and rule ID. Secret-like values in context are redacted. The original log is never modified or uploaded.
- A deleted or conditionally delivered payload may leave no surviving log or file. A no-hit result cannot establish that an event did not occur.

## Build from source

```powershell
cd tencent-game-audit
.\build-portable.ps1
```

The script runs uncached Go tests, `go vet`, builds Windows amd64 with CGO disabled, and creates the portable ZIP. It does not start a server. Build outputs are ignored by Git and should be attached to a tagged GitHub Release rather than committed to source history.

### Experimental Rust scanning core

The `rust-core/` directory contains an independently tested Rust library for bounded-memory streaming SHA-256 and multi-pattern IOC scanning. Its default read buffer is 4 MiB (configurable from 256 KiB to 16 MiB), and its worker-count calculation respects a configurable memory budget. Matches are aggregated per IOC pattern rather than retaining every occurrence. The implementation handles IOC patterns crossing chunk boundaries and returns per-file errors instead of silently treating partial reads as complete.

**The Rust core is experimental and is not yet linked into the production Go executable or included in release binaries.** Go remains the authoritative scanner and report generator until the Rust implementation demonstrates detection parity, resource behavior, Windows compatibility, and a maintainable integration boundary. To validate the Rust crate:

```powershell
cd rust-core
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

See [Architecture](docs/ARCHITECTURE.md) for the staged integration plan.

## Repository layout

- `tencent-game-audit/`: Go source, tests, embedded IOC CSV, and portable build script.
- `rust-core/`: experimental Rust streaming scan library and its independent tests.
- `docs/`: detection source provenance and technical notes.
- `docs/PROJECT-SESSION-LOG.md`: append-only project conversation summaries, tool activity, and validation history (not a verbatim account-wide transcript).
- `docs/NIKKE-K2F-CROSS-GAME-HUNTING.md`: NIKKE / K2F incident leads, evidence boundaries, and the defensive investigation plan for other Tencent game launchers.
- `README.md`: project overview and quick start.

## Contributing and responsible disclosure

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [detection source notes](docs/DETECTION-SOURCES.md). Every IOC should include a source, first/last-seen context where known, confidence, affected product/region if established, and license/redistribution notes. Do not convert rumors or a Tencent investment relationship into a confirmed compromise claim.

Project decision-making and release responsibilities are described in [GOVERNANCE.md](GOVERNANCE.md). For non-security questions, see [SUPPORT.md](SUPPORT.md). See [Architecture](docs/ARCHITECTURE.md) and [open project decisions](docs/OPEN-DECISIONS.md) for the Rust migration and licensing status.

Community participation follows the [Code of Conduct](CODE_OF_CONDUCT.md). Please use the issue forms for bug reports, detection reviews, feature requests, game compatibility, and sourced threat-intelligence submissions. Security vulnerabilities must be disclosed privately as described in [SECURITY.md](SECURITY.md).

## License

No license has been declared yet. Until a license is added by the repository owner, all rights are reserved; do not assume that public visibility grants permission to redistribute or relicense the source or bundled IOC data.
