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
.\Tencent-Game-Audit.exe -json "$env:TEMP\Tencent-Game-Audit.json"
.\Tencent-Game-Audit.exe -format html -out "$env:TEMP\Tencent-Game-Audit.html"
.\Tencent-Game-Audit.exe -format csv -out "$env:TEMP\Tencent-Game-Audit.csv"
.\Tencent-Game-Audit.exe -format md -out "$env:TEMP\Tencent-Game-Audit.md"
```

Supported report formats are `json` (default), `txt`, `html`, `csv`, and `md`. Use `-format` with `-out` to select a format and destination. The legacy `-json` option remains supported and always writes JSON. All formats use the same report model; HTML is offline and escapes untrusted content, while CSV neutralizes spreadsheet formula prefixes.

建議以系統管理員身分執行，以取得較完整的系統資訊；一般權限仍可執行，但部分資料可能無法讀取。工具不需要安裝 Go、Rust、Python，也不需要連線網路。

### 深度檔案檢測

- `-deep` 會對所選掃描根目錄中的所有檔案（不限副檔名）進行唯讀內容檢查與 SHA-256 計算；不會執行、載入、解壓或修改檔案。
- 建議先用 `-root-only -root "D:\\Delta Force" -deep` 限定單一遊戲目錄，再逐一掃描其他遊戲庫。深度模式上限為每個根目錄 250,000 個檔案、總計 1,000,000 個檔案；單檔分析上限 512 MiB，超限／讀取失敗會列入報告。
- 通用 LuaJIT `1B 4C 4A 01` 只會列為低信心 `REVIEW`；只有額外命中 K2F 專屬結構或其他獨立 IOC，才會提高嚴重度。LuaJIT 標頭本身不是惡意程式證據。
- 深度模式仍不會解密或解壓未知封裝、Chromium LevelDB 壓縮紀錄，也不是反編譯器或沙箱；必要時應以可信來源樣本比對 SHA-256，並使用隔離環境中的專業鑑識工具。

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
