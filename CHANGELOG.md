# Changelog

All notable changes to Tencent Game Audit are documented here.

## [0.9.0] - 2026-11-05

### Fixed
- Removed global and per-root file-count cutoffs from filesystem traversal and Log Forensics; scanning no longer stops at 100,000 / 1,000,000 files or 20,000 log candidates.
- Removed directory-name pruning (`Windows`, `packages`, `node_modules`, `.git`, and similar) from selected-root traversal.
- Added `-full` volume mode to scan every mounted fixed volume rather than only automatically discovered game and launcher roots. `-root-only` remains a strict explicit-root boundary and takes precedence.
- Directory/file access failures are recorded while traversal continues through other accessible entries. Symbolic links/reparse points remain un-followed and are counted as explicit scope exclusions.
- Reports now include filesystem entries, directories, unreadable entries, skipped reparse points, traversal completion, and incomplete content-analysis counts.

### Coverage notes
- File-count limits are removed, but safe per-file content limits remain: deep analysis is capped at 512 MiB per file, selected static string/IOC inspection at 64 MiB, and text-log parsing at 16 MiB. These cases are explicitly counted as incomplete content analysis and are not described as fully analyzed.
- Full-volume mode can take many hours and still does not follow reparse points or decrypt compressed/encrypted content.

## [0.8.0] - 2026-11-05

### Fixed
- Removed raw-offset matching of the generic LuaJIT `1B 4C 4A 01` marker, which could match coincidental bytes inside PE instructions such as x64 RIP-relative displacements.
- Generic LuaJIT findings now require a file-leading dump marker, valid flag bits, and a bounded non-zero first-prototype length. K2F-specific structure remains independently checked at the file-leading LuaJIT marker.
- Authenticode enrichment now distinguishes `Valid`, `NotSigned`, `UntrustedRoot`, `InvalidSignature`, `NotSupported`, and `UnknownError`; an untrusted certificate root is no longer conflated with a cryptographically invalid signature.

### Tests
- Added a regression fixture for the Epic Launcher-style x64 `LEA` displacement false positive, malformed LuaJIT dump headers, and Authenticode trust/integrity status mapping.

## [0.7.0] - 2026-11-05

### Fixed
- Made `-root-only` a strict scan boundary: it no longer queries uninstall registry inventory or collects the global Windows system snapshot.
- Strict root-only file and log traversal no longer applies broad auto-discovery directory exclusions such as `packages`; symbolic links/reparse points remain untraversed.
- Reports now include actual scan roots and explicitly state whether the global system snapshot was collected.
- Deep and ordinary content reads now use hard bounded reads to prevent file growth between metadata inspection and reading from exceeding configured memory limits.

### Changed
- Updated the scanner version to `0.7.0` and documented strict root-only behavior and its trade-off: host-wide persistence/process/network checks require a separate standard or system-only run.

## [0.6.0] - 2026-11-05

### Added
- Read-only Log Forensics discovers current and rotated text logs under selected game/launcher roots, including NIKKE `Launcher/intl_service/debug.log` and `Launcher/log/tinyget/` locations when present.
- NIKKE/K2F incident-specific log rules for `k2f_chan registered`, `lua downloaded to log\\tinyget`, `k2f.agent.state`, and reported `insightjs.com` infrastructure references; generic process/injection-related log strings remain low-confidence review leads.
- Log evidence includes rule IDs, line numbers, nearby bounded context, timestamp text, and SHA-256. Passwords, tokens, cookies, API keys, and bearer values are redacted from retained context.
- Static checks identify known payload hashes, LuaJIT/K2F structures, and MZ executable headers in files disguised with log-style names without executing them.
- Reports now include the number of analyzed log files; `-no-logs` disables the dedicated context-analysis pass while general file IOC scanning remains active.
- Recorded the NIKKE / K2F launcher and browser-persistence incident leads and a cross-game threat-hunting plan, with strict IOC provenance boundaries.

### Changed
- A bare `k2f_chan` string is now a `REVIEW` lead rather than an automatic `CRITICAL`; exact incident-specific execution/download markers retain higher severity.
- Existing NIKKE indicators remain scoped to that incident; generic cross-game log rules do not imply compromise of other Tencent titles.

## [0.4.0] - 2026-11-05

### Added
- `-deep` read-only analysis mode hashes and inspects every file type within selected roots, with explicit per-root/global budgets and size/read-error reporting.
- Deep findings include SHA-256 evidence; K2F-specific LuaJIT structure is distinguished from the generic LuaJIT bytecode header.

### Changed
- A generic `1B 4C 4A 01` LuaJIT header is now a low-confidence `REVIEW`, not a high-confidence malware `CRITICAL` finding.

## Unreleased

## [0.3.0] - 2026-11-05

### Added
- Shared-model TXT, offline HTML, CSV, and Markdown report output alongside JSON.
- `-format` and `-out` options while retaining the legacy `-json` option.
- HTML output escaping, CSV spreadsheet-formula neutralization, Unicode report coverage, and report-format tests.
- Explicit informational findings for inaccessible scan roots and filesystem entries instead of silently skipping them.
- Dynamic fixed-volume discovery through Windows logical-disk metadata rather than a hard-coded drive-letter list.
- Mounted-volume discovery is time-bounded and reports CIM/PowerShell failures as scan limitations.
- System snapshot collection failures surfaced as informational scan limitations.

## [0.2.0] - 2026-11-05

### Added
- Global locale selection and automatic locale detection for Windows user UI culture.
- Traditional/Simplified Chinese aliases for selected Tencent and Riot game titles and publisher metadata.
- Browser persistence inspection across Chrome, Edge, Brave, Vivaldi, Opera, Opera GX and Chromium user-data locations.
- Loaded-module detection for `platform_experience_helper.dll`, plus historical browser persistence directory checks.
- Chromium HSTS hashed-host IOC checks and additional K2F temporary credential/screenshot artifact detections.
- Detection source provenance, contribution/security policies, `.gitignore`, and GitHub Actions Windows release workflow.

### Changed
- Stable English JSON identifiers with localized console summary labels.
- Expanded per-user profile and launcher discovery while preserving read-only behavior.
- Corrected public scope language: Tencent portfolio discovery does not imply every title was compromised.

### Limitations
- Chromium LevelDB compressed block parsing is not implemented; raw byte scanning may miss compressed keys.
- Game portfolio discovery remains best-effort and supports explicit `-root` paths for custom regional installs.
- This remains an IOC hunter, not a full antivirus/EDR or memory-forensics product.
