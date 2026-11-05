# Detection engineering notes and source provenance

This document records defensive techniques reviewed for Tencent Game Audit. The project implements its own Go checks; it does not copy third-party source code, YARA rules, malware samples, credentials, or private victim data.

## Primary K2F technical sources

- [WormW — nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis): loader-to-LuaJIT-bundle relationship, command surface, bytecode structure, IOC catalogue, YARA/Suricata detection concepts, and target-path research. The project uses public hashes and strings as attributed indicators and retains the documented limitations. No live samples are redistributed.
- [MotherSphere — NIKKE PC launcher compromise](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5): incident timeline, launcher log markers, cache paths, per-user CLSID persistence, browser DLL location, HSTS host-key hashes, and the warning that Tencent-wide compromise claims are unsubstantiated by known launcher evidence.
- [MotherSphere — NIKKE-Launcher-Check detection notes](https://github.com/MotherSphere/NIKKE-Launcher-Check/blob/main/docs/checks.md): checks across user profiles, browser persistence folders, loaded DLL modules, launcher webview profiles, and severity based on evidence rather than file presence alone.
- [WizerdBaChe — nikke-k2f-check](https://github.com/WizerdBaChe/nikke-k2f-check): byte-oriented artifact search and additional NIKKE / Delta Force Garena launcher layouts. Cross-game launcher reuse is treated as a hypothesis unless independently evidenced.
- [nikke-checker](https://github.com/nikke-checker/nikke-checker): additional Windows persistence and browser profile detection ideas. Its product-specific findings are not treated as proof of a broader Tencent incident.
- [NGA discussion](https://bbs.nga.cn/read.php?tid=47843502): supplied community context. Direct automated retrieval was unavailable during this review, so claims found only there are not promoted to high-confidence IOCs.

## Techniques implemented in this project

- Hash matching (SHA-256, SHA-1, MD5) and embedded CSV IOC data.
- K2F-specific strings and LuaJIT bytecode structure checks, including payloads under launcher download paths.
- Read-only inspection of game and launcher files, launcher logs, Chromium cache locations, and selected browser profile persistence paths.
- Exact `platform_experience_helper.dll` persistence filename detection in browser `PlatformExperienceHelper` paths; 64-hex child folders increase confidence. The parent folder by itself is not malicious.
- Per-user COM persistence checks for the documented CLSID, including the WOW6432Node view; the HKLM namesake is not treated as the same indicator.
- Chromium `TransportSecurity` hashed-host-key checks for the three documented InsightJS domains, plus literal IOC searches in `Network Persistent State`, `Reporting and NEL`, Local Storage and Code Cache files.
- Process module enumeration for the documented persistence DLL, where Windows permissions allow access.
- Cross-game API/string combinations as `REVIEW` only. APIs such as `CreateRemoteThread`, `VirtualAllocEx`, and `WriteProcessMemory` are common in legitimate game engines, anti-cheat, DRM, overlays and debugging tools.

## Evidence boundaries

- K2F-specific indicators are attributable to the documented NIKKE / Level Infinite incident. They are not proof that every Tencent game or launcher was compromised.
- Tencent-owned, operated, published, and invested-in studios are different relationships. The inventory labels candidates and asks analysts to verify edition, region, and publisher.
- A filename alone is weaker than a verified hash, exact persistence path, execution log marker, loaded module, or correlated network evidence.
- Chromium LevelDB `.ldb` blocks may be Snappy-compressed. This scanner currently performs bounded raw-byte searches and does not fully parse/decompress LevelDB records; absence of a text hit is not exculpatory.
- Browser HSTS records can be historical. They indicate that a browser profile recorded the host, not necessarily current execution or successful command-and-control.
- Current network connections are point-in-time observations. Historical DNS cache or hosts entries do not prove a live session.
- Public incident reporting indicates the agent had remote command execution and broad data collection capability. A confirmed agent execution should be handled as a serious host compromise, not merely a suspicious game file.

## Cross-game NIKKE incident hunting

- The project conversation records additional user-supplied incident details: four reportedly modified Level Infinite launcher JavaScript assets (`aegis-fix.min.js`, `vue-bucket.min.js`, `images.7fec4c32.js`, `FeedList.feb647c9.js`); conditional delivery through `insightjs.com`; a payload reportedly disguised below `Launcher/log/tinyget/`; `k2f_chan` and related launcher debug-log markers; and a second-stage browser persistence mechanism reportedly present on only a subset of hosts. These details are retained as leads and are not independently re-proven by this entry.
- NIKKE-specific names, hashes, domains, log markers, CLSID, and payload structures must remain scoped to the documented incident unless independent evidence supports reuse in another title.
- For other Tencent-operated/published/affiliated games, hunt for the same *techniques* independently: unexpected launcher web-asset changes or external script loads, suspicious service/launcher logs, transient payload artifacts, browser persistence, and correlated process/registry/network timelines.
- Prioritize games that demonstrably share a launcher, CDN, embedded browser runtime, service, or code lineage. Corporate ownership/investment alone is not evidence of a shared attack surface or compromise.
- See [NIKKE-K2F-CROSS-GAME-HUNTING.md](NIKKE-K2F-CROSS-GAME-HUNTING.md) for the recorded incident details, evidence boundaries, planned detection work, and handling constraints.

## Log Forensics implementation (v0.6.0)

- The scanner performs bounded, read-only discovery of `.log`, rotated `.log.*`, and selected debug/service/crash `.txt` files under selected game and launcher roots. It does not assume that NIKKE paths exist in every regional launcher build.
- NIKKE-specific rules are `NIKKE-K2F-LOG-001` through `NIKKE-K2F-LOG-012`. Exact `k2f_chan registered` and `lua downloaded to log\\tinyget` markers are treated as high-confidence incident-specific evidence; `k2f_chan` alone and launcher asset names are `REVIEW` only.
- `GENERIC-LOG-*` rules are low-confidence process/loader technique references. Their presence in logs is not proof of injection or compromise and must be correlated with process, file, registry, and network evidence.
- Each parsed finding retains rule ID, line number, bounded nearby context, timestamp text when present, and the source log SHA-256. Secret-like values are redacted from context. Original logs are not changed or transmitted.
- Log candidate discovery has no global or per-root file-count cap. Text analysis remains limited to 16 MiB per file; UTF-8 and UTF-16 BOMs are supported. Compressed/oversized/unreadable logs are explicit content-coverage limitations. Binary files with log-like names receive bounded hash and selected static signature checks but are not rendered as text or executed.

## Handling and legal notes

All checks are read-only. Do not execute samples, contact C2 infrastructure, upload private scan reports, or collect another user's private files. Keep secrets and personal data out of issues and pull requests. Follow the source projects' licenses before redistributing their code or rule content; this project currently references their public research and independently implements the detection logic.
