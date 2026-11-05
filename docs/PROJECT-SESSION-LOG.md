# Project Conversation and Tool Activity Log

This is an append-only project activity log for the `Tencent-Game-Audit` repository. It records project-related user requests, decisions, implementation summaries, tool operations, validation outcomes, and known gaps that are available in the active project conversation context.

## Scope and completeness

- This file is not a server-side export of the ChatGPT account or a verbatim transcript of every message ever exchanged. It cannot recover conversation content or tool payloads that are not present in the active project context.
- Earlier sessions below are summarized from the project conversation history available during the 2026-11-05 session. Exact raw connector arguments and complete outputs were not available for every historical operation, so they are identified as summaries rather than reconstructed transcripts.
- From this entry onward, append dated entries with the user's request, relevant assistant decisions, tool/action names, commands or arguments when available, exit status, changed files, and validation results.
- Do not copy credentials, access tokens, private scan reports, full host identifiers, or unrelated personal data into this repository. Scan reports and local evidence remain ignored by Git.
- Tool names in this log are the user-facing integration/action identifiers where available; this log intentionally excludes hidden reasoning and internal model instructions.

## Project timeline

### 2026-10-21 — Coding-agent workflow

**User request (available wording):** “不要每次都開啟伺服器” (do not start a server every time).

**Recorded decision:** Use the existing local workspace and perform repository work without unnecessarily launching servers. This preference remains active.

### 2026-11-04 — Broaden Tencent game security coverage

**User requests (available wording):** “不要只製作NIKKE的 目前騰訊旗下的遊戲基本中招” and “直接全部製作完 不用我一個一個確認”. The user also supplied an external security-research link in that conversation; its exact URL is not present in the retained project summary and is therefore not reconstructed here.

**Recorded decisions:**
- Build a defensive, read-only Windows auditing tool for the wider Tencent game ecosystem.
- Distinguish ownership, operation, publishing, investment, and partnership; do not infer compromise from corporate affiliation.
- Keep NIKKE/K2F indicators scoped to evidence for that incident unless independent evidence justifies broader attribution.
- Preserve user changes and avoid destructive remediation, malware execution, C2 contact, and silent report uploads.

### 2026-11-05 — Global support and repository governance

**User requests (available wording):** “然後這個專案是要適配國內外不同國家的使用，然後你必須使用git 因為這是一個git公開專案，這是一個針對騰訊旗下的所有遊戲做的檢測工具”; “你的github不夠正式”; and “幫我撰寫 AGENTS.md 工具 `rtk help` powershell 可以使用 `rtk pwsh`”.

**Recorded implementation:** A repository-level `AGENTS.md` was created with RTK-first tooling guidance, PowerShell-through-RTK examples (`rtk pwsh`), global/regional support requirements, evidence and IOC provenance rules, read-only security constraints, report safety, tests, and GitHub governance expectations.

**Recorded repository state at that time:** Branch `main` was aligned with `origin/main` at commit `617e158` (`chore: establish professional GitHub project governance`). Existing untracked `k2f-iocs-reference.csv` and `riju-x-post.jpg` were explicitly preserved. No commit, push, tag, or server start was performed.

### 2026-11-05 — Complete project and add this log

**User requests:**
1. “好完成專案” — complete the project.
2. “好完成專案，然後新增一個log md 來紀錄我們的所有對話歷史跟工具調用” — complete the project and add a Markdown log of conversation history and tool calls.

**Decisions for this work:**
- Complete practical, verifiable gaps without inventing new IOC evidence or claiming every Tencent game is compromised.
- Add human-readable report formats while preserving JSON compatibility and the canonical `Report` data model.
- Record inaccessible scan roots/entries as limitations rather than silently treating them as clean.
- Maintain this file as an append-only record, subject to the completeness and privacy limits above.
- Do not scan the user's actual machine, launch a server, commit, push, tag, or publish a release.

## Tool and command ledger

### 2026-11-05 — Initial repository inspection for completion work

| Tool/action | Command or operation | Result |
|---|---|---|
| Chat On Steroids Core `update_plan` | Created a four-stage plan: inspect, implement, log, validate. | Accepted. |
| Chat On Steroids Core `exec_command` | `rtk git status --short --branch` | `main...origin/main`; pre-existing untracked `AGENTS.md`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` were visible and preserved. |
| Chat On Steroids Core `exec_command` | `rtk git log -5 --oneline --decorate` | HEAD and `origin/main` at `617e158`; prior tag `v0.2.0` at `c219b21`. |
| Chat On Steroids Core `exec_command` | `rtk tree .` | RTK rejected the invocation because its configured ignore list was interpreted as excess parameters; no files changed. |
| Chat On Steroids Core `exec_command` | `rtk read AGENTS.md` | Read the repository agent instructions. |
| Chat On Steroids Core `exec_command` | `rtk read tencent-game-audit\go.mod` | Confirmed module `tencent-game-audit`, Go 1.23. |
| Chat On Steroids Core `exec_command` | `rtk go test -count=1 ./...` from repository root | Failed because the current directory was outside the Go module. This was a working-directory error, not evidence of a source-code test failure. |
| Chat On Steroids Core `exec_command` | `rtk go vet ./...` from repository root | Reported no issues, but it was also run outside the module and is not counted as project validation. |

### 2026-11-05 — Source and documentation review

| Tool/action | Command or operation | Result |
|---|---|---|
| Chat On Steroids Core `exec_command` | `rtk pwsh -NoProfile -Command 'Get-ChildItem -Force ...'` | Confirmed repository layout and existing ignored local scan artifacts/build outputs. No artifacts were modified. |
| Chat On Steroids Core `exec_command` | `rtk read tencent-game-audit\README.md` | Reviewed supported regions, usage, K2F evidence boundaries, and documented JSON-only output. |
| Chat On Steroids Core `exec_command` | `rtk read README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md SUPPORT.md GOVERNANCE.md` | Reviewed public project and governance documentation. |
| Chat On Steroids Core `exec_command` | `rtk read .github\workflows\*.yml .github\workflows\*.yaml` | RTK wildcard syntax did not resolve those paths; later direct reads of the CI and release workflow files succeeded. |
| Chat On Steroids Core `read` | Read `main.go`, `main_test.go`, `windows_audit.go`, `build-portable.ps1`, `iocs.csv`, `portable-readme.txt`, `docs/DETECTION-SOURCES.md`, CI/release workflows, `.gitignore`, and `AGENTS.md` (selected ranges/full files). | Confirmed JSON-only writer, existing Go tests, IOC provenance notes, Windows x64 build/release workflow, and report privacy requirements. |
| Chat On Steroids Core `exec_command` | `rtk pwsh -NoProfile -Command 'Get-Content ... | Measure-Object -Line'` | Source sizes observed: `main.go` 1,024 lines, `main_test.go` 242 lines, `windows_audit.go` 167 lines. |
| Chat On Steroids Core `read` | Read `main.go` lines 90–180 and 849–1024; `main_test.go` lines 180–242; README and detection-source documentation. | Located canonical `Report` type, CLI report path, test conventions, and evidence limitations. |

### 2026-11-05 — Implementation changes

| Tool/action | File or operation | Result |
|---|---|---|
| Chat On Steroids Core `apply_patch` | Added `tencent-game-audit/report.go`. | Added JSON, TXT, offline HTML, CSV, and Markdown renderers based on the same `Report` structure; HTML uses `html/template`; CSV neutralizes formula-leading cells; report files use mode `0600` where supported. |
| Chat On Steroids Core `apply_patch` | Updated `tencent-game-audit/main.go`. | Added `-format` and `-out`; retained `-json` as a JSON-compatible legacy option; records unavailable scan roots and filesystem entries as informational findings. |
| Chat On Steroids Core `apply_patch` | Updated `tencent-game-audit/main_test.go`. | Added synthetic tests for all report formats, JSON decoding, Unicode, HTML escaping, CSV formula neutralization, fixed CSV columns, and unsupported formats. |
| Chat On Steroids Core `apply_patch` | Updated `README.md`, `tencent-game-audit/README.md`, and `CHANGELOG.md`. | Documented the new formats and CLI examples; recorded the changes under Unreleased. |
| Chat On Steroids Core `apply_patch` | Added `docs/PROJECT-SESSION-LOG.md`. | Created this append-only conversation/tool activity record. |
| Chat On Steroids Core `apply_patch` | Updated `tencent-game-audit/main.go`, `main_test.go`, `windows_audit.go`, `README.md`, and `CHANGELOG.md`. | Replaced the hard-coded C:–Z: drive list with a 10-second, fixed-volume CIM discovery query; reports discovery failure; surfaces Windows snapshot collection errors; adds malformed-volume-response coverage. |
| Chat On Steroids Core `apply_patch` | Updated `tencent-game-audit/report.go` and `main_test.go`. | Ensured every human-readable format includes the system snapshot; corrected CSV rows to a stable 19-column schema. |
| Chat On Steroids Core `apply_patch` | Updated root `README.md`. | Added a link/description for this project session log and its transcript completeness limitation. |
| Chat On Steroids Core `exec_command` | `rtk gofmt -w main.go main_test.go report.go windows_audit.go` (module directory). | Passed. |
| Chat On Steroids Core `exec_command` | `rtk go test -count=1 ./...` (module directory). | Final result: 32 tests passed, 0 failed. Earlier runs exposed CSV test-fixture/column-count defects; those were corrected before the final run. |
| Chat On Steroids Core `exec_command` | `rtk go vet ./...` (module directory). | Passed with no issues. |
| Chat On Steroids Core `exec_command` | `rtk git diff --check` | Passed. |
| Chat On Steroids Core `exec_command` + `rtk pwsh` | Cross-compiled with `GOOS=windows`, `GOARCH=amd64`, `CGO_ENABLED=0` to a temporary-directory executable. | Passed. PE machine value `34404` (`0x8664`, AMD64); size `6,492,160` bytes; SHA-256 `595AAF5EF0F05BC2D05037E7164E865100FF5755FFCDDA1DA4B027E5385C9A63`. |
| Chat On Steroids Core `exec_command` + `rtk pwsh` | Ran the temporary executable with `-version` and an invalid `-format` argument. | Version printed `Tencent Game Audit v0.2.0`; invalid format was rejected with exit code 2 before any scan. No actual host scan was run. |
| Chat On Steroids Core `exec_command` + `rtk pwsh` | Created a temporary validation ZIP and inspected its entries. | ZIP contains only `TGA-validation.exe` (6,492,160 bytes) and `portable-readme.txt` (1,179 bytes); ZIP SHA-256 `F7E068EDF23BCFC5CD7DBEB150A221836505BA411F23BA854C462BE8012DB3DD`. |
| Chat On Steroids Core `exec_command` | `rtk git diff --stat`, `rtk git diff -- ...`, `rtk git status --short --branch`, `rtk read ...` | Reviewed source/documentation changes and preserved all unrelated pre-existing untracked files. Final Git status is recorded after the last check below. |

### 2026-11-05 — Tool-call corrections and intermediate failures

- `rtk tree .` and RTK wildcard reads for `*.go` / workflow YAML did not resolve with the supplied syntax. The relevant source and workflow files were subsequently read by explicit paths; no source changes resulted from the failed reads.
- The first module test run exposed a CSV row-width defect (`record on line 2: wrong number of fields`). After fixing the CSV writer, a later test assertion still expected three rows rather than the actual header/summary/system/game/finding rows. The assertion was corrected; the final suite passed.
- Initial nested-quote attempts to set PowerShell build environment variables produced parser/quoting errors. The successful build used `rtk pwsh` with explicit process environment assignments, then verified the PE machine field as AMD64. The temporary build output was outside the repository.
- An initial root-directory `go test` and `go vet` were not counted as validation because the module is in `tencent-game-audit/`; the final validation commands were rerun from that module directory.
- Additional read operations inspected `report.go`, `PROJECT-SESSION-LOG.md`, and the final source diff. `update_plan` was used to track the four work stages; all stages were marked complete after final verification.

## Current implementation notes and remaining verification

- The scanner remains a read-only Windows IOC triage utility; K2F-specific evidence is not generalized to all Tencent titles.
- Report formats now share the canonical Go report model. The HTML report is self-contained and uses Go's contextual HTML escaping. CSV fields are protected against common spreadsheet formula prefixes.
- All human-readable formats include the system snapshot. Scan-root, filesystem-entry, system snapshot, and fixed-volume discovery errors now become visible informational findings and increment the skipped count where applicable.
- Fixed-volume discovery uses Windows logical-disk metadata with a 10-second timeout; it no longer assumes drive letters C: through Z:.
- The game catalogue and regional launcher discovery remain best-effort; custom regional installs still require explicit `-root` paths where discovery is incomplete.
- Chromium LevelDB compressed records are not fully decompressed. Historical HSTS/DNS evidence does not prove a current C2 session.
- No full historical ChatGPT transcript export is available in this project workspace. Earlier entries are summaries, not verbatim logs. Continue appending future tool operations and results here.
- Final validation: 32 Go tests passed; `go vet` and `git diff --check` passed; Windows AMD64 PE build and temporary ZIP inspection passed. The final Git status is appended below.

## Validation and close-out entries

_Append dated results here. Do not rewrite earlier entries; correct mistakes with a new dated note._

### 2026-11-05 — v0.6.0 Log Forensics implementation

**User request:** “將這板隔離並製作0.6.0” (isolate this work on a separate branch and build v0.6.0).

**Branch isolation:**
- Created `feat/v0.6.0-log-forensics` from the verified local `main` at `027943b`.
- Carried forward the pending NIKKE/K2F incident documentation changes on this feature branch. Existing unrelated untracked `a`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` remain un-staged and untouched.

**Implementation:**
- Added `tencent-game-audit/log_forensics.go` for bounded, read-only discovery of current and rotated logs, UTF-8/UTF-16 BOM decoding, timestamp/line/context evidence, SHA-256, and secret redaction.
- Added NIKKE-specific markers for `k2f_chan registered`, `lua downloaded to log\\tinyget`, `k2f.agent.state`, `insightjs.com` references, launcher asset names, and generic low-confidence process/loader technique references.
- Added static handling for MZ/LuaJIT/K2F signatures and known hashes in log-named binary payloads without executing or rendering binary content as text.
- Integrated default Log Forensics with `-no-logs` opt-out and added `log_files_scanned` to reports.
- Downgraded isolated `k2f_chan` from automatic CRITICAL to REVIEW; exact incident-specific markers retain stronger severity.
- Added synthetic tests for marker detection, redaction (including JSON/API/bearer/query secrets and private-key blocks), line/time/hash evidence, benign and rotated logs, UTF-16, binary disguised logs, K2F payloads with `.log` names, size limits, and severity boundaries.

**Validation:**
- An initial test run found a CSV row-width mismatch after adding the log count field; corrected the system-snapshot row and reran the complete suite.
- `rtk go test -count=1 ./...`: 53 tests passed.
- `rtk go vet ./...`: passed.
- `rtk git diff --check`: passed.
- Built Windows AMD64 with `GOOS=windows`, `GOARCH=amd64`, `CGO_ENABLED=0`; executable reports `Tencent Game Audit v0.6.0`. Temporary validation EXE SHA-256: `8E52715EB60DF4482D897569B976537259ACBFC7F25FFCA2F94A554AB905E01A`.
- Synthetic CLI smoke test created a temporary `Launcher/intl_service/debug.log` and a binary `.log` under `Launcher/log/tinyget/`; report showed 2 analyzed logs, detected the exact K2F marker and MZ disguise, redacted the fixture token, and did not count nested `k2f_chan` strings as an independent IOC cluster.
- No installed game directory was scanned and no actual infection assessment was performed. The smoke test did collect the scanner's normal local Windows system snapshot; no server was started and no network/C2 endpoint was contacted.
- Build outputs and synthetic fixtures were written to the OS temp directory, not over the existing root EXE, `portable-release`, or ZIP. Temporary test artifacts are removed after validation.

**Publication and release verification:**
- Pushed `feat/v0.6.0-log-forensics` and opened [PR #10](https://github.com/fengnaiouo/Tencent-Game-Audit/pull/10).
- Required GitHub check `Test and vet` passed, including hosted Go tests, vet, and Windows x64 build. Merged PR #10 at `2026-11-05T12:29:36Z`; merge commit `e753f9cb8ef40507713a0438edc59a64ecf1bec5`.
- Created and pushed annotated tag `v0.6.0` at the merge commit.
- Release workflow [42027649239](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/runs/42027649239) completed successfully; GitHub Release [v0.6.0](https://github.com/fengnaiouo/Tencent-Game-Audit/releases/tag/v0.6.0) is published.
- Release assets: `Tencent-Game-Audit-Windows-x64.zip` (1,703,681 bytes) and `SHA256SUMS.txt`. Downloaded the published ZIP, verified it against the checksum file, extracted it, and ran the executable; it printed `Tencent Game Audit v0.6.0`. Published ZIP SHA-256: `f579d82d7eec20e4119e84ca83b3626706b87586e843d970fdcc4b84aaaf8c8b`.
- Release workflow emitted a non-blocking Node.js 20 deprecation annotation for `actions/upload-artifact@v4`; the release job still succeeded. Track the artifact action upgrade separately.
- Local `main` is synchronized with `origin/main` at the release commit. Unrelated untracked files `a`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` remain untouched and un-staged. No server was started.

### 2026-11-05 — NIKKE / K2F incident leads and cross-game hunting scope

**User request (available wording):** “好先記錄，然後這關於妮姬的問題希能針對騰訊遊戲去做減查” (record the plan first, and investigate the NIKKE-related issue across Tencent games).

**User-supplied incident details recorded as unverified leads:**
- Stage 1 reportedly involved four modified Level Infinite launcher JavaScript assets (`aegis-fix.min.js`, `vue-bucket.min.js`, `images.7fec4c32.js`, `FeedList.feb647c9.js`), external loading from `insightjs.com`, conditional payload delivery, and a payload disguised as a `.log` under `Launcher/log/tinyget/`.
- Reported execution markers include `k2f_chan` in launcher `debug.log`, `k2f_chan registered`, `agent started as`, and `lua downloaded to log\\tinyget`.
- Stage 2 reportedly installed browser persistence on only a subset of hosts, with Chrome-associated DLL and per-user HKCU registry evidence.
- Reported impact includes remote command execution, file access, screenshots, browser credential/session theft, Windows/developer credentials, API tokens, wallet data, and NIKKE account data.

**Recorded decisions:**
- Treat the user's description as threat-intelligence leads, not independently verified facts. Retain source provenance and require corroboration before raising confidence.
- Keep the four launcher assets, `insightjs.com`, K2F strings/structures, tinyget artifacts, and known K2F browser-persistence artifacts scoped to the NIKKE / Level Infinite incident unless independently validated in another title.
- Expand the investigation across Tencent-operated, published, invested, and partner games by hunting for shared *techniques* and verified shared components: launcher web assets, remote script loading, service/debug logs, transient payload traces, browser persistence, and correlated file/process/registry/network timelines.
- Do not infer compromise from Tencent ownership, investment, an isolated `k2f_chan` string, a generic injection API, an unsigned file, or a browser process name.
- Keep all checks read-only; never execute samples, contact suspected C2, collect secret contents, or upload private logs. Include scan limitations and redaction.

**Files updated:**
- Added `docs/NIKKE-K2F-CROSS-GAME-HUNTING.md` with reported attack stages, IOC scope, cross-game hypotheses, severity/evidence handling, implementation plan, and safety constraints.
- Updated `docs/DETECTION-SOURCES.md` with the provenance boundary and cross-game investigation guidance.
- Updated root `README.md` with the new document link.
- Updated `CHANGELOG.md` under `Unreleased`.

**Validation/publication:** Documentation-only change. `rtk git diff --check` passed; reviewed the resulting documentation diff and confirmed the new plan is linked from the root README. No Go tests or binary build were needed because scanner code was not changed. No host scan, server start, commit, push, PR, merge, tag, or release was performed.

### 2026-11-05 — Deep file analysis mode

**User request:** “能讓他在更深入檢測檔案嗎?” (enable deeper file inspection).

**Implementation:**
- Added `-deep` to perform bounded, read-only content inspection and SHA-256 calculation for all file extensions in explicitly selected scan roots. The mode does not execute, load, unpack, or modify inspected files.
- Deep mode raises limits to 250,000 files per root and 1,000,000 total; files over 512 MiB and read failures are surfaced as scan limitations.
- Findings from deep content inspection include SHA-256 evidence. K2F-specific LuaJIT structure remains a high-confidence match, while the generic LuaJIT 2.0 header is now low-confidence `REVIEW` only. Updated the IOC catalog confidence accordingly.
- Updated the scanner version to `0.4.0`, documented deep mode, and added regression tests for generic-header severity and K2F-specific structure in an arbitrary extension.

**Tool/validation ledger:**
- Chat On Steroids Core `read`: inspected `main.go`, `main_test.go`, `report.go`, `README.md`, `iocs.csv`, build script, and current project session log.
- Chat On Steroids Core `apply_patch`: updated `tencent-game-audit/main.go`, `main_test.go`, `README.md`, `iocs.csv`, root `CHANGELOG.md`, and this log.
- `rtk gofmt -w main.go main_test.go`: passed.
- `rtk go test -count=1 ./...`: 41 tests passed.
- `rtk go vet ./...`: passed.
- `rtk git diff --check`: passed.
- `rtk pwsh -NoProfile -File .\build-portable.ps1`: passed; Windows x64 executable and portable ZIP rebuilt. Executable reports `Tencent Game Audit v0.4.0`.
- CLI smoke test scanned a synthetic `.bin` file containing only the generic LuaJIT header; it produced low-confidence `REVIEW` findings with SHA-256, not `CRITICAL`.
- Attempted a deep scan of the Delta Force path recorded in the supplied HTML report. That path is not present in the currently connected workspace environment, so the scan could not inspect the game files. No claim is made that Delta Force was rescanned.
- No commit, push, PR, merge, release, or server start was performed. Existing unrelated untracked `k2f-iocs-reference.csv` and `riju-x-post.jpg` were preserved and not staged.

**Remaining limitations:** Deep mode is static IOC/content analysis, not a sandbox, decompiler, archive unpacker, memory scanner, or antivirus. Encrypted/packed/compressed content and files outside the selected roots remain outside its visibility. The Delta Force path must be rescanned on a machine where that installation is actually mounted.

### 2026-11-05 — Final repository state

- Changed tracked files: `CHANGELOG.md`, `README.md`, `tencent-game-audit/README.md`, `tencent-game-audit/main.go`, `tencent-game-audit/main_test.go`, and `tencent-game-audit/windows_audit.go`.
- New project files: `tencent-game-audit/report.go` and `docs/PROJECT-SESSION-LOG.md`.
- Pre-existing untracked files preserved: `AGENTS.md`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg`.
- Final `rtk git status --short --branch`: `main...origin/main`; modified tracked files are the six listed above; new files are `docs/PROJECT-SESSION-LOG.md` and `tencent-game-audit/report.go`; the three pre-existing untracked files remain untouched.
- No commit, push, tag, GitHub release, server, or real-machine scan was performed. Temporary validation executable and ZIP were written outside the repository.

### 2026-11-05 — GitHub publication and main-branch protection

**User request (available wording):** “沒上傳至github? 顯示 您的主分支未受保護。防止強制推送或刪除此分支，或要求在合併前進行狀態檢查。”

**Repository inspection:**
- `rtk git status --short --branch`: local completion changes were uncommitted; remote `origin/main` still pointed to `617e158`.
- `rtk git remote -v`: origin is `https://github.com/fengnaiouo/Tencent-Game-Audit.git`.
- `rtk gh auth status`: authenticated as `fengnaiouo`; token scopes reported by gh were `gist`, `read:org`, `repo`, and `workflow` (token value intentionally not recorded).
- `rtk gh repo view fengnaiouo/Tencent-Game-Audit --json nameWithOwner,defaultBranchRef,url,visibility`: confirmed public repository and default branch `main`.
- `rtk gh api repos/fengnaiouo/Tencent-Game-Audit/branches/main/protection`: returned HTTP 404, confirming `main` had no branch protection before this operation.
- Read `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `CONTRIBUTING.md`, and `GOVERNANCE.md` to determine required check names and merge policy.

**Publication operations:**
- Created branch `chore/protect-main-and-publish-completion` with `rtk git switch -c ...`.
- Explicitly staged only `AGENTS.md`, `CHANGELOG.md`, `README.md`, `docs/PROJECT-SESSION-LOG.md`, `tencent-game-audit/README.md`, `tencent-game-audit/main.go`, `tencent-game-audit/main_test.go`, `tencent-game-audit/report.go`, and `tencent-game-audit/windows_audit.go`.
- Excluded and preserved unrelated untracked `k2f-iocs-reference.csv` and `riju-x-post.jpg`.
- The first staged `rtk git diff --cached --check` found extra blank lines at EOF in the two new Markdown files. Normalized those files to one final newline, re-staged, and the check passed.
- `rtk git commit -m "feat: complete audit reports and project logging"`: created commit `4de9667` (9 files changed; 644 insertions, 16 deletions).
- `rtk git push -u origin chore/protect-main-and-publish-completion`: succeeded; remote feature branch created.
- `rtk gh pr create ...`: created PR #6, https://github.com/fengnaiouo/Tencent-Game-Audit/pull/6, targeting `main`.

**Branch protection operations:**
- An initial `gh api ... -X PUT` attempt used object-shaped values for fields that the GitHub endpoint expects as booleans; GitHub returned HTTP 422 and made no change.
- Retried with boolean values; `rtk gh api repos/fengnaiouo/Tencent-Game-Audit/branches/main/protection -X PUT ...` succeeded.
- Enabled protection for administrators; disabled force pushes and branch deletion; required PRs; required strict status check `Test and vet`; enabled conversation resolution; set required approving reviews to 0 to allow a solo maintainer to merge after CI. Restrictions are not limited to a named push team.
- Verified the endpoint response showed `strict: true`, context `Test and vet`, `enforce_admins.enabled: true`, `allow_force_pushes.enabled: false`, `allow_deletions.enabled: false`, and `required_conversation_resolution.enabled: true`.

**GitHub Actions validation and maintenance:**
- `rtk gh pr view 6 ...`: PR was mergeable and CI was initially in progress.
- `rtk gh run watch 42011830498 --repo fengnaiouo/Tencent-Game-Audit --exit-status`: CI job `Test and vet` passed; its Test, Vet, and Windows x64 build steps all succeeded.
- The successful run warned that `actions/checkout@v4` and `actions/setup-go@v5` were running under the Node.js 24 compatibility transition. Queried latest upstream release tags using `rtk gh api repos/actions/checkout/releases/latest`, `.../setup-go/...`, and `.../softprops/action-gh-release/...`; results were `v7.0.1`, `v7.0.0`, and `v3.0.3` respectively.
- Updated `.github/workflows/ci.yml` to `actions/checkout@v7` and `actions/setup-go@v7`; updated `.github/workflows/release.yml` to those versions and `softprops/action-gh-release@v3`. This triggers a fresh PR CI run; its result must be recorded after it completes.

**Current state at this log entry:** PR #6 is published; `main` branch protection is active; the first CI run passed, and a workflow dependency update is pending a fresh CI run. No main-branch merge or GitHub Release is claimed until separately verified.

### 2026-11-05 — Publication completed and protected main verified

- `rtk gh run watch 42012097275 --repo fengnaiouo/Tencent-Game-Audit --exit-status`: second CI run passed after workflow action updates. `Test and vet`, `Test`, `Vet`, and `Build Windows x64` all completed successfully; no Node.js 20 deprecation warning appeared in this run.
- `rtk gh pr checks 6 --repo fengnaiouo/Tencent-Game-Audit`: 1 required check passed, 0 failed.
- Merged PR #6 with squash merge and branch deletion after required CI passed. Verified using `rtk gh pr view 6 --repo fengnaiouo/Tencent-Game-Audit --json state,mergedAt,mergeCommit,url`: state `MERGED`, merged at `2026-11-05T10:37:18Z`, squash commit `469f246daee7d92c0a570862a0e591f3b7dd48b9`.
- Re-queried `rtk gh api repos/fengnaiouo/Tencent-Game-Audit/branches/main/protection`: confirmed strict required check `Test and vet`; PR required; 0 required approvals; administrators included; force pushes and deletion disabled; conversation resolution required.
- Synchronized local repository with `rtk git fetch origin`, `rtk git switch main`, and `rtk git pull --ff-only origin main`. Final `rtk git status --short --branch` showed `main...origin/main` with no modified tracked files.
- `rtk git log -4 --oneline --decorate` confirmed local `main` and `origin/main` both at `469f246` (`Complete audit report formats and project activity log (#6)`).
- The two pre-existing unrelated untracked files `k2f-iocs-reference.csv` and `riju-x-post.jpg` remain untouched and excluded from GitHub.
- This log update itself is being submitted separately through a follow-up documentation PR because the newly protected `main` branch now requires pull requests and CI. The main implementation is already merged; this follow-up only appends publication/verification history.

### 2026-11-05 — Strict `-root-only` scope isolation (v0.7.0)

**User request:** The user reported that `-deep -root-only -root "D:\Delta Force"` still appeared to scan other folders and authorized the proposed correction with “好”.

**Root cause confirmed:** `main()` called `registryInventory()` and `collectWindowsSnapshot()` unconditionally. `registryInventory()` queried uninstall metadata and K2F COM persistence; the Windows snapshot enumerated global Run keys, services, scheduled tasks, Startup folders, COM registrations, processes/modules, TCP connections, DNS cache, hosts, named pipes, and Defender status. In addition, the shared `skipDir()` exclusions were applied inside explicit roots, so directories such as `packages` could be omitted from both file and log traversal.

**Implementation:**
- Added `buildScanScope()` with an early strict-root branch. With `-root-only`, only normalized, deduplicated `-root` arguments are returned; registry, Steam/Epic, fixed-volume, Tencent, launcher, profile, and TEMP discovery are not invoked.
- Strict root-only mode no longer calls `collectWindowsSnapshot()` and explicitly records that global host checks were not collected. Normal and `-system-only` modes retain their existing host snapshot behavior.
- Bypassed general auto-discovery directory exclusions inside explicit root-only roots while continuing to refuse symbolic-link/reparse-point traversal. Applied the same rule to Log Forensics.
- Added `scan_roots` and `system_snapshot_collected` to the canonical report model and all JSON/TXT/HTML/CSV/Markdown output. Reports state when the global snapshot was not collected.
- Replaced `os.ReadFile()` content paths for deep and ordinary IOC reads with `readFileBounded()` to enforce hard byte limits even if a file grows after metadata inspection.
- Updated scanner version and documentation to v0.7.0.

**Regression coverage and validation:**
- Added tests for strict scan-scope selection, bounded reads with stale metadata, nested `packages` traversal in both file scanning and Log Forensics, and scope disclosure in all five report formats.
- `rtk go test -count=1 ./...`: 64 tests passed.
- `rtk go vet ./...`: passed.
- `rtk git diff --check`: passed.
- Built a temporary Windows AMD64 executable; `-version` printed `Tencent Game Audit v0.7.0`.
- Ran a synthetic CLI smoke test using a temporary fixture containing `packages/game/asset.bin` and `packages/game/logs/debug.log`. The HTML report recorded exactly the explicit root, scanned 2 files and 1 log, and stated `System snapshot collected: false` / `Not collected`. No actual game directory or user files were scanned.
- Temporary executable, fixture, and report were removed. No server was started.

**Publication status at implementation close-out:** Feature branch `fix/root-only-scope-isolation` was ready for publication. The three pre-existing unrelated untracked files (`a`, `k2f-iocs-reference.csv`, `riju-x-post.jpg`) remained untouched and excluded from staging.

**Publication completed:**
- Staged only the nine intended source/documentation files; unrelated untracked `a`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` were not staged.
- Created commit `0f9e54b` on `fix/root-only-scope-isolation`, pushed it, and opened [PR #12](https://github.com/fengnaiouo/Tencent-Game-Audit/pull/12).
- Required CI run [42031111123](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/runs/42031111123) passed: Test, Vet, and Windows x64 build.
- Merged PR #12 at `2026-11-05T12:55:40Z`; merge commit `5133246ceaf0e08f72969b57f2d5a669581ed9ce`. Local `main` and `origin/main` are synchronized at this commit.
- Created and pushed annotated tag `v0.7.0`. Release workflow [42031318966](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/runs/42031318966) completed successfully and published [GitHub Release v0.7.0](https://github.com/fengnaiouo/Tencent-Game-Audit/releases/tag/v0.7.0).
- Published assets: `Tencent-Game-Audit-Windows-x64.zip` (1,707,057 bytes) and `SHA256SUMS.txt` (102 bytes). Downloaded the published ZIP, verified its SHA-256 against the published checksum file, extracted it, and ran the executable; it printed `Tencent Game Audit v0.7.0`. ZIP SHA-256: `794b6685cf9cb246a99e42a56f2a273e072bc0ab09bf843de585843c44cf106f`.
- Release workflow reported a non-blocking Node.js 20 deprecation annotation for `actions/upload-artifact@v4`; both build/package and publish jobs succeeded. Track upgrading that action separately.
- Re-verified `main` branch protection: required PR and `Test and vet` check, strict status checks, administrators included, force pushes/deletion disabled, and conversation resolution required.
- Final `rtk git status --short --branch`: `main...origin/main`; only the three unrelated pre-existing untracked files remain. No server was started and no real game directory was scanned.

### 2026-11-05 — LuaJIT byte-pattern false positive and Authenticode taxonomy (v0.8.0)

**User authorization:** The user accepted the proposed scanner corrections after the read-only PE review of 134 candidate files identified an Epic Games Launcher x64 `LEA` instruction whose RIP-relative displacement happened to contain `1B 4C 4A 01`.

**Implementation:**
- Removed generic LuaJIT magic-byte IOC matching at arbitrary file offsets. The same byte sequence inside unrelated PE machine code is no longer treated as a LuaJIT marker.
- Generic LuaJIT detection now requires the marker at byte offset zero, valid flag bits, and a bounded, non-zero first-prototype length. The dedicated K2F structure check remains separately scoped to a file-leading LuaJIT marker.
- Authenticode enrichment now includes the provider's status message and normalizes outcomes to `Valid`, `NotSigned`, `UntrustedRoot`, `InvalidSignature`, `NotSupported`, or `UnknownError`. An untrusted root is distinguished from a cryptographically invalid signature; unsigned status is not elevated to malicious evidence.
- Bumped the scanner to `0.8.0` and documented both behavior changes.

**Regression coverage:**
- Added a synthetic x64 `LEA` RIP-relative displacement case matching the previously observed Epic Launcher false-positive bytes.
- Added positive/negative LuaJIT header structure tests and Authenticode status-mapping tests.

**Validation:**
- `rtk go test -count=1 ./...`: 67 tests passed.
- `rtk go vet ./...`: passed.
- `rtk git diff --check`: passed.
- Cross-compiled a temporary Windows AMD64 executable with CGO disabled; `-version` printed `Tencent Game Audit v0.8.0`. Temporary executable was removed.
- No actual game directory, candidate PE, or user report was rescanned or modified; tests used synthetic bytes only.

**Publication pending:** PR/CI, merge, tag, and release verification remain to be completed.

**Publication completed:**
- Staged only the seven intended source/documentation files; pre-existing unrelated untracked `a`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` were not staged.
- Created feature commit `6800079` on `fix/luajit-signature-and-authenticode` and opened [PR #14](https://github.com/fengnaiouo/Tencent-Game-Audit/pull/14).
- Required CI run [42034700816](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/runs/42034700816) passed: Go tests, vet, and Windows x64 build.
- Merged PR #14 at `2026-11-05T13:20:07Z`; merge commit `e42713dd855f44f27213fad92378a66dfcd18135`. Local `main` and `origin/main` are synchronized at this commit.
- Created and pushed annotated tag `v0.8.0`. Release workflow [42034898065](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/runs/42034898065) completed successfully and published [GitHub Release v0.8.0](https://github.com/fengnaiouo/Tencent-Game-Audit/releases/tag/v0.8.0).
- Release assets: `Tencent-Game-Audit-Windows-x64.zip` (1,709,543 bytes) and `SHA256SUMS.txt` (102 bytes). Downloaded the published ZIP, verified it against the published checksum file, extracted it, and ran the executable; it printed `Tencent Game Audit v0.8.0`. ZIP SHA-256: `3052f5551b24b3c45a91426497ed0414e0f63197871a76b406ca74dc7d77ac08`.
- Release workflow emitted the existing non-blocking Node.js 20 deprecation annotation for `actions/upload-artifact@v4`; packaging and publication both succeeded.
- Final `rtk git status --short --branch`: `main...origin/main`; only pre-existing untracked `a`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` remain. No server was started and no actual game files were scanned.

### 2026-11-05 — Remove scan-count truncation and add full-volume mode (v0.9.0)

**User request:** The user does not want scan coverage gaps and expects a complete scan rather than stopping after a fixed number of files.

**Findings in v0.8.0:**
- Main file traversal had 100,000 files by default, 500,000 with `-full`, 1,000,000 with `-deep`, and a 25,000 / 250,000 per-root cutoff.
- Log Forensics stopped at 20,000 candidates globally and 10,000 per root.
- The default scan pruned directory names such as `Windows`, `packages`, `node_modules`, `.git`, `ProgramData`, `Users`, and `WindowsApps`.
- `-full` only raised the budget; it did not scan every fixed volume.

**Implementation:**
- Removed all global/per-root file-count caps from file and log traversal.
- Removed directory-name pruning from selected-root traversal; directories are no longer omitted solely because of their names.
- Reworked `-full` to add every mounted fixed-volume root (for example `C:\\`, `D:\\`) to scan scope. Nested explicit roots already covered by a volume are deduplicated. `-root-only` takes precedence and remains restricted to explicit roots.
- Added report coverage counters: filesystem entries visited, directories visited, unreadable entries, reparse points not followed, traversal completion, and incomplete content-analysis count.
- Access errors are recorded and the walker continues through other entries. Symlink/reparse points are not followed, including an explicitly supplied root that is itself a symlink.
- Log candidate discovery no longer has a count cutoff. The existing 16 MiB text-log limit, 64 MiB selected static-content limit, and 512 MiB deep-analysis limit remain for bounded resource use; these now contribute to explicit incomplete-content counters and findings rather than silently disappearing.
- Updated documentation and regression tests for no count truncation, previously excluded directory names, full-volume root de-duplication, and coverage fields in all report formats.

**Validation:**
- `rtk go test -count=1 ./...`: 69 tests passed.
- `rtk go vet ./...`: passed.
- `rtk git diff --check`: passed.
- Windows AMD64 cross-build completed; executable printed `Tencent Game Audit v0.9.0`.
- Synthetic end-to-end `-deep -root-only` CLI smoke test created five files under `packages`, `.git`, `node_modules`, and `Windows` directories. All five were scanned; one log was analyzed; report showed 15 filesystem entries, 10 directories, `traversal_complete=true`, `content_analysis_incomplete=0`, and `skipped_files=0`.
- No actual game directory or full disk volume was scanned. Synthetic fixtures, report, and temporary executable were removed. No server was started.
- Pre-existing untracked `a`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` remain untouched and excluded from staging.

**Publication pending:** feature PR/CI, merge, tag, and release verification.

**Publication completed:**
- Feature commit `42532fe` was pushed on `feat/unbounded-complete-scan-coverage`; [PR #16](https://github.com/fengnaiouo/Tencent-Game-Audit/pull/16) passed required CI run [42038528914](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/runs/42038528914) (tests, vet, Windows x64 build) and merged at `2026-11-05T13:46:01Z`.
- Merge commit: `05b1c74416d9aeeb718b79a88f492468ac96950f`; local `main` is synchronized with `origin/main`.
- Annotated tag `v0.9.0` was pushed. Release workflow [42038698787](https://github.com/fengnaiouo/Tencent-Game-Audit/actions/runs/42038698787) completed successfully and published [GitHub Release v0.9.0](https://github.com/fengnaiouo/Tencent-Game-Audit/releases/tag/v0.9.0).
- Release assets: `Tencent-Game-Audit-Windows-x64.zip` (1,712,219 bytes) and `SHA256SUMS.txt` (102 bytes). Downloaded the published ZIP, matched it against the published checksum file, extracted it, and ran the executable; it printed `Tencent Game Audit v0.9.0`. ZIP SHA-256: `527b687602f4c94514354e08225658424815bb37f69323b39e03b9bf5faffc0c`.
- Release workflow emitted the existing non-blocking Node.js 20 deprecation annotation for upload/download artifact v4; packaging and release publication both succeeded.
- Local `main` is clean relative to `origin/main`; only pre-existing unrelated untracked `a`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` remain. No real game or fixed-volume scan was run and no server was started.
- The repository build script was deliberately not used because it overwrites pre-existing root EXE and portable ZIP artifacts. The Windows build will be written to a unique OS temporary path instead.
- Pre-existing untracked `a`, `k2f-iocs-reference.csv`, and `riju-x-post.jpg` remain untouched and excluded from staging. No server or real game scan was started.
