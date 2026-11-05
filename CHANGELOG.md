# Changelog

All notable changes to Tencent Game Audit are documented here.

## Unreleased

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
