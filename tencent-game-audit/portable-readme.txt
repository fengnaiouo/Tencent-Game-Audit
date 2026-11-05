Tencent Game Audit — Global Edition

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
7. Use -full for a larger scan budget; use -system-only for system snapshot only.

Read-only operation: the tool does not delete, quarantine, terminate processes, or modify Windows security settings. CRITICAL means a high-confidence documented indicator matched; REVIEW findings need human validation. No-hit does not prove a device is clean.

Reports may contain usernames, computer names, file paths and process command lines. Review and redact before sharing.
