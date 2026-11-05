Tencent Game Audit — Global Edition
Version 0.10.0

Portable Windows x64 scanner. No Go/Rust/Python installation or network access is required.

1. Copy Tencent-Game-Audit.exe to the target computer or USB drive.
2. For the broadest view, right-click and run as Administrator.
3. Run the EXE. A JSON report is written beside it by default.
4. To keep reports private on shared/USB media, write to the local temp folder:
   .\Tencent-Game-Audit.exe -json "$env:TEMP\Tencent-Game-Audit.json"
5. Select the console language explicitly when needed:
   -lang en | zh-Hant | zh-Hans | ja | ko | pt-BR
6. Add custom regional/library paths with repeatable -root arguments:
   .\Tencent-Game-Audit.exe -root "D:\Games" -root "F:\WeGame"
7. Use -full to scan every mounted fixed volume without file-count limits; this may take many hours. Use -system-only for system snapshot only.
8. Strictly scan only supplied paths (no registry discovery or global Windows snapshot):
   .\Tencent-Game-Audit.exe -root-only -root "D:\Games" -deep -format html -out "$env:TEMP\Game-Audit.html"

Read-only operation: the tool does not delete, quarantine, terminate processes, or modify Windows security settings. CRITICAL means a high-confidence documented indicator matched; REVIEW findings need human validation. No-hit does not prove a device is clean.

Reports may contain usernames, computer names, file paths and process command lines. Review and redact before sharing.
Log Forensics is enabled by default for selected game and launcher roots. It searches current and rotated text logs, redacts common secret values in evidence context, and records rule IDs, line numbers, timestamps when present, and SHA-256. Use `-no-logs` to disable this dedicated context-analysis pass; general file IOC scanning remains enabled. Binary files disguised with log-style names are not executed or rendered as text; only bounded static signatures and hashes are checked.

Strict `-root-only` mode scans only the explicitly supplied `-root` paths. It does not query uninstall registry entries or collect global Windows persistence, process, service, scheduled-task, network, DNS, hosts, or Defender data. Reports list the exact scan roots and state that the system snapshot was not collected. It includes all ordinary subdirectories such as `packages`; symbolic links/reparse points are not followed.

There are no global or per-root file-count cutoffs. Reports record filesystem traversal coverage and content-analysis limitations. Deep analysis is limited to 512 MiB per file and text-log parsing to 16 MiB per log; oversized or unreadable content is explicitly counted as incomplete. Reparse points are not followed for scope safety.
