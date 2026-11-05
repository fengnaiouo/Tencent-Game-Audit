# NIKKE / K2F incident: cross-game threat-hunting plan

## Purpose

Record the NIKKE / Level Infinite launcher incident indicators and define a defensible way to investigate whether related techniques or infrastructure affected other Tencent-operated, published, or affiliated games. This is a hunting plan, not a claim that other Tencent games were compromised.

## Incident information supplied in the project conversation

The following is retained as user-supplied incident intelligence. Individual claims must be checked against primary artifacts, trustworthy public research, or independently collected evidence before being promoted to a high-confidence detection or public attribution.

### Reported Stage 1: launcher/web-content execution

- Reported affected Level Infinite CDN JavaScript assets: `aegis-fix.min.js`, `vue-bucket.min.js`, `images.7fec4c32.js`, and `FeedList.feb647c9.js`.
- The reported attack path is launcher-rendered announcement/banner content loading modified JavaScript, which then references `insightjs.com` and retrieves an `insight.bundle` payload.
- Delivery was reportedly conditional/intermittent; opening the launcher does not establish that a host received or executed the payload.
- Reported launcher log markers include `k2f_chan`, `k2f_chan registered`, `agent started as`, and `lua downloaded to log\\tinyget`.
- The downloaded payload was reportedly disguised as a `.log` artifact below `Launcher/log/tinyget/`, executed, and self-deleted. Therefore, absence of the payload file is not evidence that it never ran; retained logs, caches, browser storage, file-system metadata, and correlated events may remain useful.

### Reported Stage 2: browser persistence

- A subset of affected hosts reportedly received an additional persistence stage associated with `chrome.exe`.
- Reported evidence classes include an unexpected DLL under a Chrome profile/application directory and a per-user `HKCU` COM registration. The known NIKKE/K2F CLSID is recorded in `iocs.csv`.
- Do not confuse the documented per-user key with a similarly named legitimate machine-wide registration. Verify the exact hive, CLSID, value, resolved DLL path, file hash, signature, timestamps, and loaded-module evidence.
- A browser process name alone is not evidence of compromise. Validate the actual executable path, command line, loaded modules, parent process, and persistence configuration.

### Reported impact

The incident reporting describes remote command execution, file access, screenshots, browser credential/session theft, Windows credential access, developer-secret discovery, and cryptocurrency-wallet data collection. Treat a well-corroborated execution indicator as a potential full-host compromise. Do not collect or print secrets during scanning; report only artifact paths, hashes, redacted context, and evidence metadata.

## Detection scope and evidence boundaries

### NIKKE-specific indicators

Keep the following scoped to the documented NIKKE / Level Infinite incident unless independent evidence demonstrates reuse elsewhere:

- The four launcher JavaScript asset names and their historical known-bad hashes/ETags.
- `insightjs.com`, `analytics.insightjs.com`, the reported bundle URL, and associated historical infrastructure.
- `k2f_chan`, `k2f.agent.state`, `K2F_*` markers, K2F command strings, and K2F LuaJIT structural signatures.
- `Launcher/log/tinyget/` payload/log artifacts and the known K2F browser-persistence CLSID/DLL path.

An exact NIKKE IOC found in another game's directory is a lead requiring validation, not automatic proof that the other publisher's CDN or game was compromised. Consider shared launcher components, copied assets, archived caches, test fixtures, and unrelated string occurrences.

### Cross-game hunting hypotheses

For other Tencent-operated, Tencent-published, Tencent-invested, and partner titles, investigate independently for:

1. **Launcher web surfaces:** announcement, news, banner, store, embedded browser, and update metadata assets; compare current content with trusted release baselines and historical known-good hashes where available.
2. **Unexpected remote script loading:** external script origins, dynamically loaded bundles, unexpected redirects, and changed asset contents. Do not block or label an entire legitimate CDN solely because one historical object was abused.
3. **Launcher/service logs:** discover `debug.log`, rotated logs, service logs, crash logs, and WebView/Chromium logs; search exact incident markers and title-specific variants while preserving timestamp and nearby context.
4. **Transient payload traces:** inspect launcher log/temp/cache directories, browser caches, download metadata, file-system timestamps, and residual fragments for payloads disguised with ordinary extensions. Never execute recovered files.
5. **Browser persistence:** inspect exact per-user registry registrations, unexpected DLLs, browser application/profile directories, loaded modules, and process command lines. Separate legitimate browser components from lookalike filenames and unexpected paths.
6. **Credential-theft aftermath:** identify suspicious collection artifacts and persistence evidence without reading, exporting, or revealing passwords, cookies, tokens, private keys, wallet files, or other secret contents.
7. **Timeline correlation:** correlate launcher startup, web asset/cache writes, log markers, payload creation/deletion, browser launches, DLL loads, registry writes, and network/DNS evidence.

## Evidence handling and severity

- `INFO`: log or asset discovered; no malicious conclusion.
- `REVIEW`: isolated string, unfamiliar script, unsigned file, or unusual module requiring context.
- `SUSPICIOUS`: multiple independent anomalies align in time or path, but attribution is not conclusive.
- `HIGH CONFIDENCE`: exact, well-sourced known-bad hash or highly specific persistence/structural evidence corroborated by independent artifacts.
- `CONFIRMED`: reserve for cases with sufficient independently verifiable evidence and documented provenance; never infer from a single generic string.

For every finding, retain source path, SHA-256 where safe and feasible, file metadata, timestamp/time-zone context, matched rule ID and source, bounded/redacted surrounding log lines, and the reason for the severity. Record unreadable, rotated, deleted, encrypted, compressed, and out-of-scope data as limitations. Do not claim a clean result when relevant evidence was unavailable.

## Planned implementation in Tencent Game Audit

1. Add a read-only log discovery/parser module for common text logs, rotated logs, and known launcher/service locations; include `Launcher/intl_service/debug.log` and `Launcher/log/tinyget/` as NIKKE profile paths, not universal paths.
2. Add a per-game profile/rule catalogue with publisher, operator, region, launcher family, known log paths, known-good baselines, and incident-specific IOC scope.
3. Add bounded log matching with context windows, timestamp normalization, secret redaction, file hashing, and duplicate suppression.
4. Add launcher web-asset integrity checks using independently sourced known-good baselines and historical known-bad hashes; avoid assuming hashed filenames imply integrity.
5. Add browser persistence checks that validate exact registry hive/key/value and resolved DLL path, plus signature/hash/module correlation.
6. Build a timeline/evidence-correlation layer that joins log, file, process, registry, browser, and network observations without elevating a single weak indicator.
7. Add synthetic tests for benign logs containing generic words, exact malicious markers, rotated/truncated logs, Unicode paths, timezone variations, redaction, and false-positive launcher/browser components.

## Global coverage

The investigation should cover regional editions and launcher variants rather than only games with a Tencent corporate relationship. Maintain separate records for ownership, operation, publishing, investment, and distribution. Prioritize titles sharing an actual launcher, CDN, embedded web runtime, service component, or code lineage with the affected product; verify each relationship before extending a detection rule. A Tencent portfolio relationship alone is not an IOC.

## Safety constraints

- Read-only inspection; no remediation, deletion, quarantine, or registry modification.
- Never execute samples, recovered bundles, scripts, or suspicious DLLs.
- Do not contact suspected command-and-control infrastructure from the scanner.
- Do not collect secret values or upload private logs/reports.
- Preserve original evidence; store reports locally and redact personal data before sharing.
- Report scan coverage, access limitations, and confidence explicitly.
