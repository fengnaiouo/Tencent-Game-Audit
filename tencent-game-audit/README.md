# Tencent Game Audit — Global Edition

騰訊遊戲安全檢測工具，面向全球 Windows 使用者。此工具以唯讀方式盤點遊戲與啟動器，檢查已公開的 IOC、可疑持久化、程序、DLL 內容、數位簽章及網路線索。

## 全球／地區適配

- 適用中國大陸、台灣、香港、日本、韓國、東南亞、歐洲、美洲等地區的 Windows 遊戲環境。
- 不綁定國家、時區、小數格式或固定磁碟代號；使用系統環境變數、Windows 掛載磁碟資訊、登錄檔、啟動器清單、Steam/Epic 遊戲庫及使用者提供的路徑。
- 支援部分繁體中文、簡體中文及國際遊戲名稱別名。地區版本、代理商及安裝位置仍可能不同，請用 `-root` 補充自訂路徑。
- `-lang auto|en|zh-Hant|zh-Hans|ja|ko|pt-BR|fr|de|es|id|th|vi|ru|pl|tr|it` 可選擇主控台摘要語言；`auto` 會讀取系統語系。摘要標籤會翻譯，詳細 finding 與 JSON 欄位保留英文，方便跨國自動化與 SIEM 整合。
- IOC 比對不依賴使用者所在國家。騰訊投資關係只作為盤點線索，不代表遊戲必然由騰訊控制或已遭入侵。

## 快速使用

```powershell
.\Tencent-Game-Audit.exe
.\Tencent-Game-Audit.exe -lang zh-Hant
.\Tencent-Game-Audit.exe -root "D:\Games" -root "F:\WeGame"
.\Tencent-Game-Audit.exe -root-only -root "D:\Games"
.\Tencent-Game-Audit.exe -system-only
.\Tencent-Game-Audit.exe -full
.\Tencent-Game-Audit.exe -deep -root-only -root "D:\Games" -format html -out "$env:TEMP\Tencent-Game-Audit-deep.html"
.\Tencent-Game-Audit.exe -root-only -root "D:\Games" -format json -out "$env:TEMP\Tencent-Game-Audit-logs.json"
.\Tencent-Game-Audit.exe -no-logs -root-only -root "D:\Games"
.\Tencent-Game-Audit.exe -json "$env:TEMP\Tencent-Game-Audit.json"
.\Tencent-Game-Audit.exe -format html -out "$env:TEMP\Tencent-Game-Audit.html"
.\Tencent-Game-Audit.exe -format csv -out "$env:TEMP\Tencent-Game-Audit.csv"
.\Tencent-Game-Audit.exe -format md -out "$env:TEMP\Tencent-Game-Audit.md"
```

Supported report formats are `json` (default), `txt`, `html`, `csv`, and `md`. Use `-format` with `-out` to select a format and destination. The legacy `-json` option remains supported and always writes JSON. All formats use the same report model; HTML is offline and escapes untrusted content, while CSV neutralizes spreadsheet formula prefixes.

建議以系統管理員身分執行，以取得較完整的系統資訊；一般權限仍可執行，但部分資料可能無法讀取。工具不需要安裝 Go、Rust、Python，也不需要連線網路。

### 深度檔案檢測

- 一般掃描會完整遞迴每個已選定的掃描根目錄，不再設定全域或單一根目錄檔案數上限，也不會按 `Windows`、`packages`、`node_modules`、`.git` 等目錄名稱任意跳過子目錄。
- `-full` 會將所有已掛載的固定磁碟區根目錄納入掃描（例如 `C:\\`、`D:\\`），不只掃描自動發現的遊戲資料夾。這可能需要數小時甚至更久。`-root-only` 優先於 `-full`，仍只掃描明確提供的根目錄。
- `-root-only` 是嚴格範圍模式：只遞迴掃描明確提供的 `-root` 路徑（可重複指定），不查詢解除安裝登錄檔、不探索 Steam/Epic/WeGame/Launcher/其他使用者資料夾，也不收集全域 Windows 系統快照（程序、服務、排程、登錄持久化、網路連線、DNS、hosts、Defender 等）。報告會列出實際掃描根目錄，並標明系統快照未收集。
- 不跟隨符號連結／reparse point，以免掃描逃出指定根目錄；這些路徑會逐項記錄為範圍排除。無法讀取的目錄或檔案會記錄錯誤並繼續掃描其他項目。
- `-deep` 會對所選掃描根目錄中的所有檔案（不限副檔名）進行唯讀內容檢查與 SHA-256 計算；不會執行、載入、解壓或修改檔案。檔案數量沒有固定上限；一般靜態字串／IOC 內容檢查上限 64 MiB、深度分析上限 512 MiB、Log 文字分析上限 16 MiB，超限／讀取失敗會列入 `ContentAnalysisIncomplete`。
- 報告會列出檔案數、走訪項目數、目錄數、無法讀取項目、未跟隨 reparse point 數、`TraversalComplete` 及 `ContentAnalysisIncomplete`。只有 `TraversalComplete=true` 且 `ContentAnalysisIncomplete=0`、`SkippedFiles=0` 時，才能說本次所選範圍的走訪及受支援內容分析沒有已知缺口；這仍不代表已涵蓋所選根目錄之外的磁碟或已解密壓縮資料。
- 通用 LuaJIT `1B 4C 4A 01` 必須位於檔案開頭，且旗標與第一個 prototype 長度通過結構檢查，才會列為低信心 `REVIEW`；不再把 PE 指令位移中偶然出現的相同 bytes 當成 LuaJIT。只有額外命中 K2F 專屬結構或其他獨立 IOC，才會提高嚴重度。LuaJIT 標頭本身不是惡意程式證據。
- Authenticode 狀態分別呈現 `Valid`、`NotSigned`、`UntrustedRoot`、`InvalidSignature`、`NotSupported`、`UnknownError`；未簽署或憑證根不受信任本身不等於檔案惡意或遭竄改。
- 深度模式仍不會解密或解壓未知封裝、Chromium LevelDB 壓縮紀錄，也不是反編譯器或沙箱；必要時應以可信來源樣本比對 SHA-256，並使用隔離環境中的專業鑑識工具。

### Log Forensics（v0.6.0）

- 進階 Log 鑑識預設啟用，會在選定的遊戲／Launcher 根目錄尋找 `.log`、輪替 `.log.*`，以及特定 debug/service/crash `.txt` 紀錄。`-no-logs` 只停用這個上下文分析流程；一般檔案 IOC 掃描仍會檢查支援的 Log 內容。
- NIKKE 會特別涵蓋 `Launcher/intl_service/debug.log` 與 `Launcher/log/tinyget/`（透過遞迴發現，不假設每個地區版本都有這些路徑）。
- `k2f_chan registered`、`lua downloaded to log\\tinyget` 是事件專屬強指標；單獨 `k2f_chan`、資產檔名或通用程序 API 只列為 REVIEW，不直接判定感染。
- Log 候選檔案不再設全域或每根目錄數量上限；單一 Log 文字解析仍限制 16 MiB，超限會明確列入 `ContentAnalysisIncomplete`。支援 UTF-8 與含 BOM 的 UTF-16。壓縮 Log 不會解壓；二進制偽裝 Log 不會當文字解析，但會做有限的 SHA-256、MZ 與 LuaJIT/K2F 靜態檢查。
- 證據包含規則 ID、行號、有限前後文、可取得的時間戳記與 SHA-256。密碼、Token、Cookie、API Key、Bearer 值會在輸出上下文中遮蔽。原始 Log 不會被修改或上傳。

### 嚴格指定目錄模式（v0.7.0）

- `-root-only` 現在會跳過所有全域登錄檔／遊戲探索與 Windows 系統快照，僅處理 `-root` 明確指定的路徑。
- `-root-only` 的一般檔案掃描與 Log Forensics 都會涵蓋指定目錄下的 `packages` 等子目錄；不跟隨符號連結／reparse point。
- JSON/TXT/HTML/CSV/Markdown 報告都會記錄實際掃描根目錄及系統快照是否執行。
- 一般自動探索模式維持原有系統快照功能；如需全域持久化、程序及網路檢查，請另行執行一般模式或 `-system-only`。

## 安全與判讀

- 預設唯讀：不刪除、不隔離、不修復、不終止程序、不修改 Defender、防火牆、hosts 或登錄檔設定。涵蓋 Chrome、Edge、Brave、Vivaldi、Opera、Opera GX、Chromium 的已知持久化目錄及部分瀏覽器快取紀錄。
- `CRITICAL` 代表命中高信心的特定 IOC，不代表每個 `WARNING` 或 `REVIEW` 都是感染。
- NIKKE/K2F IOC 仍歸屬於目前有證據的事件範圍；不會因為遊戲與騰訊有投資或發行關係，就宣稱該遊戲已中毒。
- 所有報告格式都可能包含電腦名稱、使用者名稱、檔案路徑、程序命令列及遊戲清單。公開前請先檢查並遮蔽個資。
- 本工具是 IOC hunting，不是防毒軟體、EDR 或完整記憶體鑑識；沒有命中不等於保證安全。

## 建置與 Git

```powershell
cd tencent-game-audit
.\build-portable.ps1
```

建置會執行 Go 測試、`go vet`、Windows x64 編譯及可攜式 ZIP 打包，不會啟動伺服器。執行檔與掃描報告不應提交到原始碼 Git 歷史；請放在 GitHub Release 附件。

English documentation: see the English sections in the repository README and `tencent-game-audit/README.md`.

## Detection source provenance

See [DETECTION-SOURCES.md](../docs/DETECTION-SOURCES.md) for reviewed public research, implemented techniques, evidence boundaries, and limitations.
