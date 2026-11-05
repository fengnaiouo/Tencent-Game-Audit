# AGENTS.md — Tencent Game Audit

This file defines repository-wide instructions for coding agents and automated contributors. Follow it before making changes. More specific `AGENTS.md` files in subdirectories may add constraints but must not weaken the safety and evidence rules below.

## 1. Project mission

Build and maintain a professional, portable, defensive Windows security-auditing tool for the worldwide Tencent game ecosystem. The project must cover more than NIKKE/K2F and must not assume that every Tencent-published, invested-in, partnered, or distributed game is compromised.

Keep these relationship categories distinct in code, data, reports, and documentation:

- Tencent-operated or directly controlled.
- Tencent-owned studios and subsidiaries.
- Tencent-published or regionally distributed.
- Tencent-invested or minority-owned companies.
- Third-party partners or platform integrations.

A relationship is a discovery hint, never proof of ownership, malicious activity, or compromise. Attribute an IOC only to the product, version, region, component, and incident supported by its evidence. In particular, keep NIKKE/K2F indicators scoped to their documented evidence unless independent evidence supports broader attribution.

## 2. Working-directory and tool requirements

- The repository root is the current project directory. Use absolute paths only when a tool requires them; do not hard-code this machine's user name, drive letter, or installation paths into product code, tests, scripts, or documentation.
- Use RTK to reduce command output. Start by consulting `rtk help` when its available commands or syntax are unclear.
- For PowerShell commands, invoke PowerShell through RTK, for example:

  ```powershell
  rtk pwsh -NoProfile -Command 'Get-Location'
  rtk pwsh -NoProfile -File .\scripts\check.ps1
  ```

- Prefer purpose-built RTK commands where available, such as `rtk git`, `rtk go`, `rtk test`, `rtk read`, `rtk grep`, and `rtk diff`. Use `rtk pwsh` for native PowerShell operations that do not have a dedicated RTK command.
- Do not bypass RTK merely to obtain verbose output. If full output is essential for debugging, use the appropriate RTK command's supported verbose mode or explain why a native command is required.
- Do not start a web server, development server, watcher, GUI, or long-running service unless the user explicitly requests it or a test strictly requires it. Ordinary build, test, vet, and static-analysis work must not start a server.

## 3. Autonomy and change discipline

- Complete clearly authorized work end-to-end. Do not repeatedly ask the user to approve routine implementation details or each individual file.
- Ask only when a decision is genuinely irreversible, destructive, externally visible, security-sensitive beyond the user's authorization, or materially ambiguous.
- Inspect the existing implementation, relevant documentation, tests, Git status, and all applicable `AGENTS.md` files before editing.
- Preserve unrelated user changes. Never reset, clean, checkout over, force-update, or delete user work to make a task easier.
- Do not overwrite or stage pre-existing untracked files unless the task explicitly requires it. Generated scan reports, binaries, archives, screenshots, and local evidence should remain outside source history unless explicitly intended as release assets.
- Keep changes focused and compatible with the existing architecture. Avoid unrelated refactors, gratuitous dependencies, and duplicate implementations.
- Do not commit, push, create tags, publish releases, open pull requests, or modify remote GitHub settings unless the user explicitly asks for that action.
- Before finishing, inspect `git status` and the final diff. Report changed files and validation results accurately.

## 4. Security and forensic safety — mandatory

- The product is a defensive, read-only audit and triage tool. Scanning must not delete, quarantine, repair, disable, terminate, inject into, or modify target files, processes, registry keys, services, scheduled tasks, firewall, hosts, Defender, browser profiles, or game installations.
- Never add automatic remediation or cleanup. If remediation guidance is needed, report evidence and provide separate manual guidance; do not execute it.
- Do not contact suspected command-and-control infrastructure, execute suspicious samples, load suspect DLLs, or submit user files/reports to third-party services as part of ordinary scans or tests.
- Network access must be opt-in, narrowly scoped, documented, and unnecessary for the default scan. Never silently upload telemetry, samples, reports, or machine identifiers.
- Treat scan reports and logs as sensitive. They may contain usernames, computer names, paths, command lines, process details, installed software, and security posture. Use restrictive file permissions where supported, avoid unnecessary collection, and warn before recommending public sharing.
- Handle access-denied, unavailable, malformed, locked, and unsupported evidence explicitly. Do not silently interpret an unreadable location as clean.
- A clean/no-hit result is not proof that a host is clean. Record scan scope, skipped locations, permission limitations, rule-set version, and timestamps so users can interpret coverage.
- Never present an unverified rumor, social-media allegation, game publisher relationship, generic API string, or heuristic match as confirmed malware or a confirmed compromise.

## 5. Evidence, IOC, and detection engineering

- Every IOC or detection rule must have traceable provenance: source URL or document, retrieval/review date, source reliability, confidence, first/last-seen dates when known, affected product/component/version/region when established, and redistribution/licensing notes.
- Preserve original indicators exactly where relevant, while normalizing a separate comparison value. Validate hashes, domains, paths, signatures, and metadata before adding them to production rules.
- Distinguish at least: confirmed/high-confidence match, suspicious or heuristic lead, contextual observation, informational inventory, and scan limitation. Use the existing severity model consistently (`CRITICAL`, `WARNING`, `REVIEW`, `INFO`) and document any changes.
- Generic APIs such as process injection functions, unsigned binaries, unusual paths, or uncommon publishers are not sufficient alone to label a file malicious. Correlate independent evidence and explain why a rule matched.
- Use allowlists or contextual suppression carefully; do not hide evidence globally merely because a component is common. Keep false-positive tests for game engines, anti-cheat, DRM, overlays, launchers, modding tools, and legitimate security software.
- Prefer deterministic local analysis: hashes, file metadata, Authenticode status, structural parsing, strings, documented signatures, and well-scoped YARA/rule matching. Never execute a scanned binary to identify it.
- Keep NIKKE/K2F-specific indicators and signatures clearly scoped. Shared-engine or cross-game rules require independent evidence and dedicated tests before being generalized.
- Keep IOC data machine-readable, schema-validated, deduplicated, versioned, and testable. Reject malformed or incomplete entries rather than silently weakening validation.

## 6. Global game and publisher inventory

- Design for different countries, languages, time zones, drive layouts, launchers, publishers, and regional game editions. Do not assume Taiwan, mainland China, or any single market is the default.
- Avoid hard-coded user profile paths, drive letters, locale assumptions, date formats, and case-sensitive path assumptions. Prefer Windows APIs, environment variables, registry metadata, launcher manifests, and explicit user-supplied roots.
- Model canonical game identity separately from localized title, aliases, publisher, developer, operator, owner/control relationship, distributor, region, platform, and version.
- Record provenance and confidence for ownership and publishing relationships. Minority investment, partnership, licensing, and regional publishing must not be conflated with direct ownership or operation.
- Support custom installation roots and multiple libraries. A missing default path must not prevent scanning other discovered or user-provided paths.
- Treat game catalog data as maintained evidence, not an exhaustive truth claim. Document its last review date and known coverage gaps.

## 7. Architecture and implementation conventions

- The primary scanner is Go. Keep the core portable and testable; use Windows-specific code behind clear platform boundaries and build tags where appropriate.
- Rust, Python/uv, and PowerShell may be used for justified supporting tasks, but do not introduce another runtime dependency into the portable Windows release without documenting the need and packaging impact.
- Keep the default deliverable a portable Windows x64 executable that does not require Go, Rust, Python, a server, or an internet connection on the target machine.
- Use the standard library where practical. Any new dependency must have a clear security, maintenance, licensing, and supply-chain justification; pin and review versions.
- Bound file sizes, recursion depth, scan duration, memory use, and parser work. Treat scanned content and metadata as untrusted input; avoid path traversal, symlink/reparse-point escapes, decompression bombs, and unbounded reads.
- Keep output deterministic where possible. Preserve stable machine-readable field names and schema compatibility; version breaking report-schema changes.
- Use structured errors and actionable diagnostics. Do not silently swallow errors that affect scan coverage.
- Keep comments focused on security rationale, non-obvious behavior, and limitations rather than restating code.

## 8. Reports and localization

- JSON is the stable machine-readable format. Human-readable report formats must be supported alongside it: TXT, HTML, CSV, and Markdown.
- All report formats must derive from the same canonical report model; do not implement separate detection logic per output format.
- Reports should include tool/version, scan time and timezone, host context only when necessary, scan scope, detected games and confidence, findings, severity, evidence, file paths, hashes, signature/signer data when available, rule/IOC provenance, skipped checks, limitations, and recommended next steps.
- Escape untrusted content correctly in HTML and CSV. Prevent HTML/script injection and spreadsheet formula injection. Do not embed remote scripts, fonts, trackers, or external resources in offline HTML reports.
- Keep JSON keys and enum values stable and language-neutral. Localize human-facing labels and explanations without changing the underlying evidence or severity.
- Support Unicode game names and paths, including Traditional Chinese, Simplified Chinese, Japanese, Korean, and other international scripts. Avoid locale-dependent parsing bugs.
- Do not claim complete translation coverage unless all user-facing strings, findings, errors, and help text are covered. Document fallback behavior.

## 9. Testing and validation

- Add or update tests for every behavior change, including positive, negative, malformed-input, permission/error, and false-positive cases where relevant.
- Tests must use synthetic fixtures or harmless test data. Never run real malware or contact live malicious infrastructure in tests.
- For Go changes, normally run from `tencent-game-audit/`:

  ```powershell
  rtk go test -count=1 ./...
  rtk go vet ./...
  ```

- For portable release/build changes, also run the repository's documented build script or equivalent cross-compilation checks, and inspect the resulting archive contents. Do not launch the built application against the user's machine unless the user requested an actual scan.
- Validate Windows-specific code with compile checks and mocks/fixtures when the current host cannot exercise Windows behavior. State clearly what was and was not tested.
- Test report serialization for all supported formats, Unicode, escaping, large inputs, empty results, and partial/failed scans.
- Do not claim tests passed unless the commands actually completed successfully. Report exact failures and environmental limitations.

## 10. GitHub, documentation, and release quality

- Keep README, `tencent-game-audit/README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `GOVERNANCE.md`, and `docs/` consistent with actual behavior.
- Document supported Windows versions, privileges, scan scope, limitations, report privacy, IOC provenance, build steps, and reproducible usage examples.
- Maintain CI for tests, vet/static checks, build verification, and release artifact validation. Do not weaken CI to make a failing change appear green.
- Before release, review license and redistribution rights, dependency inventory, SBOM, build provenance, artifact hashes, and code-signing status. Never invent a license or claim a binary is signed when it is not.
- Release artifacts should be reproducibly built where practical, include version and SHA256 checksums, and exclude unrelated local reports or evidence.
- Do not commit generated executables, ZIP packages, scan reports, or personal evidence into source history unless the repository's release policy explicitly calls for them.

## 11. Completion checklist

Before declaring a coding task complete:

1. Confirm the implementation matches the requested scope and preserves read-only behavior.
2. Add/update tests and documentation where behavior or user-facing claims changed.
3. Run the relevant tests, vet, build, and static checks using RTK where available.
4. Inspect the final diff and Git status; preserve unrelated and untracked user files.
5. State what changed, what was tested, what remains unverified, and any known limitations.
