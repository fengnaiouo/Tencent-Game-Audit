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

## Handling and legal notes

All checks are read-only. Do not execute samples, contact C2 infrastructure, upload private scan reports, or collect another user's private files. Keep secrets and personal data out of issues and pull requests. Follow the source projects' licenses before redistributing their code or rule content; this project currently references their public research and independently implements the detection logic.
