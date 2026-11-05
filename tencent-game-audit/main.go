// Tencent Game Security Audit is a read-only Windows IOC hunter.
// It inventories game installations and hunts for the publicly documented
// NIKKE/K2F indicators without assuming that every Tencent game was affected.
package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed iocs.csv
var iocFS embed.FS

const clsid = `{E77CC89B-7401-4C04-8CED-149DB35ADD04}`
const version = "0.8.0"

var knownHashes = map[string]string{
	"f3e93d049851d5c19552c7d9b73c8be4580dc9d549e8f65f9f0c357c1df9d252": "K2F Sample-A.dll loader",
	"cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec": "K2F Sample-B.bundle payload",
	"60fd53ab7356384ba2161b9bc84420cd170905011a2f3ca09f3e38fe3122f3a1": "Earlier K2F LuaJIT payload (medium confidence)",
	"2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203": "Historical poisoned FeedList.feb647c9.js",
	"3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193": "Historical poisoned vue-bucket.min.js",
	"21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce": "Historical poisoned images.7fec4c32.js",
	"04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d": "Historical poisoned aegis-fix.min.js",
}

var knownSHA1 = map[string]string{
	"06447f4b6bc5858d8a21b9c86908f823616318f8": "K2F Sample-A.dll loader",
	"dbffaa25de8c57c21d03d53de17d0ec20b3b1c58": "K2F Sample-B.bundle payload",
}
var knownMD5 = map[string]string{
	"986267369c0d9cb6f0f9e7c937a1d627": "K2F Sample-A.dll loader",
	"f8baf640fbb940c4a65b64b70eb0b9e1": "K2F Sample-B.bundle payload",
}

var suspiciousStrings = []string{
	"k2f_chan registered", "k2f_chan", "k2f.agent.state", "K2F_LUA_BUILD", "K2F_CREDENTIALW",
	"the evaluated bundle is not on disk", "no thread for the evaluated bundle",
	"commands.chrome_install", "commands.browserscan", "commands.wallet_files",
	"agent started as", "lua downloaded to log\\tinyget", "analytics.insightjs.com",
	"insightjs.com/l.js", "insightjs.org/l.js", "k2f-bcreds-", "k2f_screen_",
}

// Generic cross-game loader indicators. These are triage leads only: game
// engines, anti-cheat and DRM can legitimately contain some of these APIs.
var crossGameStrings = []string{
	"CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx",
	"VirtualAllocEx", "WriteProcessMemory", "LoadLibraryW", "AppInit_DLLs",
	"powershell -enc", "FromBase64String(", "mshta.exe", "regsvr32.exe /s",
	"rundll32.exe javascript:",
}

type IOCRecord struct{ Type, Value, Description, Confidence string }

var embeddedIOCs = loadEmbeddedIOCs()

func loadEmbeddedIOCs() []IOCRecord {
	b, err := iocFS.ReadFile("iocs.csv")
	if err != nil {
		return nil
	}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil
	}
	out := []IOCRecord{}
	for i, row := range rows {
		if i == 0 || len(row) < 4 {
			continue
		}
		out = append(out, IOCRecord{strings.TrimSpace(row[0]), strings.TrimSpace(row[1]), strings.TrimSpace(row[2]), strings.TrimSpace(row[3])})
	}
	return out
}

type Finding struct {
	Severity        string `json:"severity"`
	Category        string `json:"category"`
	Path            string `json:"path,omitempty"`
	Evidence        string `json:"evidence"`
	Confidence      string `json:"confidence"`
	SignatureStatus string `json:"signature_status,omitempty"`
	Signer          string `json:"signer,omitempty"`
}
type Game struct {
	Title       string `json:"title"`
	Publisher   string `json:"publisher,omitempty"`
	InstallPath string `json:"install_path,omitempty"`
	Source      string `json:"source"`
	Relation    string `json:"relation"`
}
type Report struct {
	Version                 string         `json:"scanner_version"`
	Generated               string         `json:"generated"`
	Language                string         `json:"language"`
	Computer                string         `json:"computer"`
	User                    string         `json:"user"`
	Mode                    string         `json:"mode"`
	ScanRoots               []string       `json:"scan_roots"`
	SystemSnapshotCollected bool           `json:"system_snapshot_collected"`
	ScannedFiles            int            `json:"scanned_files"`
	SkippedFiles            int            `json:"skipped_files"`
	LogFilesScanned         int            `json:"log_files_scanned"`
	Games                   []Game         `json:"game_inventory"`
	Findings                []Finding      `json:"findings"`
	System                  SystemSnapshot `json:"system_snapshot"`
	Limitations             []string       `json:"limitations"`
}

type config struct {
	full         bool
	deep         bool
	logForensics bool
	maxFiles     int
	maxPerRoot   int
	maxBytes     int64
	roots        []string
	rootOnly     bool
}

// readFileBounded prevents a file that grows after its metadata check from
// causing an unbounded allocation. The extra byte distinguishes exact-limit
// files from files that exceed the configured limit.
func readFileBounded(path string, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 || maxBytes == int64(^uint64(0)>>1) {
		return nil, fmt.Errorf("invalid read limit %d", maxBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("file exceeds bounded read limit of %d bytes", maxBytes)
	}
	return b, nil
}

// deepInspectFile performs bounded, read-only content analysis on arbitrary
// file types. It never loads or executes the inspected content as code.
func deepInspectFile(path string, size, maxBytes int64, r *Report) {
	if size < 1 || size > maxBytes {
		if size > maxBytes {
			r.SkippedFiles++
			addFinding(r, "INFO", "Deep analysis size limit", path, fmt.Sprintf("File size %d exceeds deep-analysis limit %d bytes", size, maxBytes), "scan limitation")
		}
		return
	}
	b, err := readFileBounded(path, maxBytes)
	if err != nil {
		r.SkippedFiles++
		category := "Deep analysis read failure"
		if strings.Contains(err.Error(), "bounded read limit") {
			category = "Deep analysis size limit"
		}
		addFinding(r, "INFO", category, path, err.Error(), "scan limitation")
		return
	}
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	if desc, ok := knownHashes[sha]; ok {
		addFinding(r, "CRITICAL", "Known malicious SHA256 (deep scan)", path, desc+"; SHA256="+sha, "high")
	}
	// A bare LuaJIT magic header occurs in legitimate game resources. Treat it
	// only as a review lead unless the K2F-specific structure also matches.
	if hasLuaJITMagic(b) {
		if bytesK2FStructure(b) {
			addFinding(r, "CRITICAL", "K2F LuaJIT structural signature (deep scan)", path, "K2F-specific LuaJIT string-table structure; SHA256="+sha, "high")
		} else if hasLuaJITDumpHeader(b) {
			addFinding(r, "REVIEW", "LuaJIT bytecode header (deep scan)", path, "Generic LuaJIT 2.0 bytecode header only; not proof of K2F or malware; SHA256="+sha, "low; generic format marker")
		}
	}
	low := strings.ToLower(string(b))
	var hits []string
	for _, needle := range suspiciousStrings {
		if strings.Contains(low, strings.ToLower(needle)) {
			hits = append(hits, needle)
		}
	}
	if len(hits) > 0 {
		sev, confidence := k2fStringSeverity(hits)
		addFinding(r, sev, "K2F content indicators (deep scan)", path, strings.Join(hits, ", ")+"; SHA256="+sha, confidence)
	}
	for _, ioc := range embeddedIOCs {
		if ioc.Type == "bytes" && matchHexPattern(b, ioc.Value) {
			if isGenericLuaJITHeaderIOC(ioc) {
				continue // A raw byte sequence can occur inside unrelated machine code.
			}
			sev, confidence := "WARNING", ioc.Confidence
			if ioc.Confidence == "high" {
				sev = "CRITICAL"
			}
			addFinding(r, sev, "K2F byte signature (deep scan)", path, ioc.Description+" ("+ioc.Value+"); SHA256="+sha, confidence)
		}
	}
}

func addFinding(r *Report, sev, cat, path, ev, conf string) {
	for _, f := range r.Findings {
		if f.Category == cat && strings.EqualFold(f.Path, path) && f.Evidence == ev {
			return
		}
	}
	r.Findings = append(r.Findings, Finding{Severity: sev, Category: cat, Path: path, Evidence: ev, Confidence: conf})
}

func k2fStringSeverity(hits []string) (string, string) {
	if containsAny(hits, "k2f_chan registered", "lua downloaded to log\\tinyget") {
		return "CRITICAL", "high; exact incident-specific execution/download marker"
	}
	if containsAny(hits, "k2f.agent.state", "the evaluated bundle is not on disk", "analytics.insightjs.com", "insightjs.com/l.js", "insightjs.org/l.js") {
		return "WARNING", "high; incident-specific indicator requiring corroboration"
	}
	return "REVIEW", "low; isolated string or generic message is not proof of execution"
}

func runReg(args ...string) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	b, err := exec.Command("reg.exe", args...).CombinedOutput()
	if err != nil {
		return string(b)
	}
	return string(b)
}

func registryInventory(r *Report) []string {
	var roots []string
	if runtime.GOOS != "windows" {
		return roots
	}
	// PowerShell registry provider handles REG_SZ / REG_EXPAND_SZ and quoted
	// paths correctly; parsing localized `reg query` console output is brittle.
	ps := `$ErrorActionPreference='SilentlyContinue'; Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {$_.DisplayName} | Select-Object @{n='title';e={$_.DisplayName}},@{n='publisher';e={$_.Publisher}},@{n='path';e={$_.InstallLocation}} | ConvertTo-Json -Compress`
	psOut, psErr := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if psErr == nil {
		var entries []struct {
			Title     string `json:"title"`
			Publisher string `json:"publisher"`
			Path      string `json:"path"`
		}
		if json.Unmarshal(psOut, &entries) != nil {
			var one struct {
				Title     string `json:"title"`
				Publisher string `json:"publisher"`
				Path      string `json:"path"`
			}
			if json.Unmarshal(psOut, &one) == nil && one.Title != "" {
				entries = append(entries, one)
			}
		}
		for _, e := range entries {
			if e.Title == "" {
				continue
			}
			relation := classify(e.Title, e.Publisher)
			candidate := relation != "Unclassified game; scanned for known K2F indicators only" || regexp.MustCompile(`(?i)game|launcher|tencent|wegame|riot|garena|level infinite|steam|epic`).MatchString(e.Title)
			if candidate {
				r.Games = append(r.Games, Game{e.Title, e.Publisher, e.Path, "Uninstall registry", relation})
			}
			if candidate && e.Path != "" {
				roots = append(roots, strings.Trim(strings.TrimSpace(e.Path), `"`))
			}
		}
	}
	// The documented persistence is per-user. Check native and WOW6432Node
	// views; do not flag the legitimate HKLM class registration.
	for _, key := range []string{
		`HKCU\Software\Classes\CLSID\` + clsid + `\InprocServer32`,
		`HKCU\Software\Classes\WOW6432Node\CLSID\` + clsid + `\InprocServer32`,
	} {
		regOut := runReg("query", key, "/ve")
		if strings.Contains(strings.ToLower(regOut), "inprocserver32") {
			addFinding(r, "CRITICAL", "K2F per-user COM persistence key", key, strings.TrimSpace(regOut), "high")
		}
	}
	return roots
}

var titlePatterns = []struct {
	re       *regexp.Regexp
	relation string
}{
	{regexp.MustCompile(`(?i)NIKKE|Goddess of Victory|\x{52DD}\x{5229}\x{5973}\x{795E}|\x{80DC}\x{5229}\x{5973}\x{795E}`), "Level Infinite published; Shift Up developed (NIKKE-specific incident scope)"},
	{regexp.MustCompile(`(?i)Delta Force|\x{4E09}\x{89D2}\x{6D32}\x{884C}\x{52D5}|\x{4E09}\x{89D2}\x{6D32}\x{884C}\x{52A8}`), "Tencent/TiMi-related edition or regional publisher; verify edition"},
	{regexp.MustCompile(`(?i)Arena Breakout|\x{6697}\x{5340}\x{7A81}\x{570D}|\x{6697}\x{533A}\x{7A81}\x{56F4}|Honor of Kings|\x{738B}\x{8005}\x{69AE}\x{8000}|\x{738B}\x{8005}\x{8363}|Peacekeeper Elite|\x{548C}\x{5E73}\x{7CBE}\x{82F1}|PUBG Mobile|\x{7D55}\x{5730}\x{6C42}\x{751F} ?M|\x{7EDD}\x{5730}\x{6C42}\x{751F} ?M`), "Tencent-operated/published title candidate; verify region and package"},
	{regexp.MustCompile(`(?i)League of Legends|\x{82F1}\x{96C4}\x{806F}\x{76DF}|\x{82F1}\x{96C4}\x{8054}\x{76DF}|Teamfight Tactics|\x{806F}\x{76DF}\x{6230}\x{68CB}|\x{4E91}\x{9876}\x{4E4B}\x{5F08}|VALORANT|\x{7279}\x{6230}\x{82F1}\x{8C6A}|\x{7121}\x{754F}\x{5951}\x{7D04}|\x{65E0}\x{754F}\x{5951}\x{7EA6}|Legends of Runeterra|\x{7B26}\x{6587}\x{5927}\x{5730}\x{50B3}\x{8AAA}|\x{7B26}\x{6587}\x{4E4B}\x{5730}\x{4F20}\x{8BF4}|2XKO`), "Riot Games (Tencent-owned) title candidate"},
	{regexp.MustCompile(`(?i)CrossFire|\x{7A7F}\x{8D8A}\x{706B}\x{7DDA}|\x{7A7F}\x{8D8A}\x{706B}\x{7EBF}|Dungeon.?Fighter|\x{5730}\x{4E0B}\x{57CE}\x{8207}\x{52C7}\x{58EB}|\x{5730}\x{4E0B}\x{57CE}\x{4E0E}\x{52C7}\x{58EB}|QQ Speed|QQ\x{98DB}\x{8ECA}|QQ\x{98DE}\x{8F66}|\x{9006}\x{6230}|\x{9006}\x{6218}|\x{5929}\x{6DAF}\x{660E}\x{6708}\x{5200}|\x{528D}\x{9748}|\x{5251}\x{7075}|\x{706B}\x{5F71}\x{5FCD}\x{8005}|\x{91D1}\x{93DF}\x{93DF}\x{4E4B}\x{6230}|\x{91D1}\x{94F2}\x{94F2}\x{4E4B}\x{6218}`), "Tencent-operated/published title candidate; verify regional edition"},
	{regexp.MustCompile(`(?i)Warframe|Soulframe|Path of Exile|Dune Awakening|Conan Exiles|V Rising|Battlerite|Don't Starve|Oxygen Not Included|Clash of Clans|Clash Royale|Brawl Stars|Back 4 Blood|Dying Light`), "Tencent-controlled / invested portfolio candidate; ownership varies by studio"},
}

func classify(title, publisher string) string {
	for _, p := range titlePatterns {
		if p.re.MatchString(title) {
			return p.relation
		}
	}
	if regexp.MustCompile(`(?i)tencent|level infinite|proxima beta|timi|lightspeed|morefun|riot games|\x{9A30}\x{8A0A}|\x{817E}\x{8BAF}|\x{5929}\x{7F8E}|\x{5149}\x{5B50}|\x{9B54}\x{65B9}|\x{62F3}\x{9822}\x{904A}\x{6232}|\x{62F3}\x{5934}\x{6E38}\x{620F}`).MatchString(publisher) {
		return "Publisher metadata candidate; verify exact title and region"
	}
	return "Unclassified game; scanned for known K2F indicators only"
}

func steamRoots() []string {
	var roots []string
	base := os.Getenv("ProgramFiles(x86)")
	if base != "" {
		roots = append(roots, filepath.Join(base, "Steam"))
	}
	if home := os.Getenv("USERPROFILE"); home != "" {
		roots = append(roots, filepath.Join(home, "AppData", "Local", "Steam"), filepath.Join(home, ".steam", "steam"))
	}
	if runtime.GOOS == "windows" {
		ps := `$ErrorActionPreference='SilentlyContinue'; @((Get-ItemProperty 'HKCU:\Software\Valve\Steam').SteamPath,(Get-ItemProperty 'HKLM:\Software\WOW6432Node\Valve\Steam').InstallPath,(Get-ItemProperty 'HKLM:\Software\Valve\Steam').InstallPath) | Where-Object {$_} | ConvertTo-Json -Compress`
		if b, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps).Output(); err == nil {
			var paths []string
			if json.Unmarshal(b, &paths) != nil {
				var one string
				if json.Unmarshal(b, &one) == nil && one != "" {
					paths = append(paths, one)
				}
			}
			roots = append(roots, paths...)
		}
	}
	var libs []string
	for _, root := range roots {
		data, err := os.ReadFile(filepath.Join(root, "steamapps", "libraryfolders.vdf"))
		if err == nil {
			re := regexp.MustCompile(`"path"\s+"([^"]+)"`)
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				libs = append(libs, strings.ReplaceAll(m[1], `\\`, `\`))
			}
			libs = append(libs, root)
		}
	}
	var gameRoots []string
	for _, lib := range libs {
		common := filepath.Join(lib, "steamapps", "common")
		entries, _ := os.ReadDir(common)
		for _, e := range entries {
			if e.IsDir() {
				gameRoots = append(gameRoots, filepath.Join(common, e.Name()))
			}
		}
	}
	return unique(gameRoots)
}

func epicRoots() []string {
	var roots []string
	pf := os.Getenv("ProgramData")
	if pf == "" {
		return roots
	}
	man := filepath.Join(pf, "Epic", "EpicGamesLauncher", "Data", "Manifests")
	entries, _ := os.ReadDir(man)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".item") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(man, e.Name()))
		if err != nil {
			continue
		}
		var x map[string]any
		if json.Unmarshal(b, &x) != nil {
			continue
		}
		if p, ok := x["InstallLocation"].(string); ok && p != "" {
			roots = append(roots, p)
		}
	}
	return roots
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s == "" {
			continue
		}
		a, _ := filepath.Abs(os.ExpandEnv(s))
		k := strings.ToLower(filepath.Clean(a))
		if !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	return out
}

func fileHash(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", fmt.Errorf("over size limit")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileDigests(path string, limit int64) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h256, h1, hm := sha256.New(), sha1.New(), md5.New()
	n, err := io.Copy(io.MultiWriter(h256, h1, hm), io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, fmt.Errorf("over size limit")
	}
	return map[string]string{"sha256": hex.EncodeToString(h256.Sum(nil)), "sha1": hex.EncodeToString(h1.Sum(nil)), "md5": hex.EncodeToString(hm.Sum(nil))}, nil
}

func fileDigest(path string, limit int64, algorithm string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var h io.Writer
	var sum func() []byte
	switch algorithm {
	case "sha1":
		x := sha1.New()
		h = x
		sum = func() []byte { return x.Sum(nil) }
	case "md5":
		x := md5.New()
		h = x
		sum = func() []byte { return x.Sum(nil) }
	default:
		return "", fmt.Errorf("unsupported digest")
	}
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", fmt.Errorf("over size limit")
	}
	return hex.EncodeToString(sum()), nil
}

func matchHexPattern(data []byte, pattern string) bool {
	parts := strings.Fields(pattern)
	if len(parts) == 0 || len(data) < len(parts) {
		return false
	}
	for i := 0; i+len(parts) <= len(data); i++ {
		ok := true
		for j, p := range parts {
			if p == "??" {
				continue
			}
			v, err := strconv.ParseUint(p, 16, 8)
			if err != nil || data[i+j] != byte(v) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func inspectFile(path string, size int64, r *Report, maxBytes int64) {
	name := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(name))
	// Hash executable/library/script/payload candidates even when their filename
	// has been changed. This avoids depending on the original malware filename.
	if size <= maxBytes && (ext == ".dll" || ext == ".exe" || ext == ".js" || ext == ".lua" || ext == ".bundle" || name == "insight.bundle") {
		if d, e := fileDigests(path, maxBytes); e == nil {
			if desc, ok := knownHashes[d["sha256"]]; ok {
				addFinding(r, "CRITICAL", "Known malicious SHA256", path, desc+"; SHA256="+d["sha256"], "high")
			}
			if desc, ok := knownSHA1[d["sha1"]]; ok {
				addFinding(r, "CRITICAL", "Known malicious SHA1", path, desc+"; SHA1="+d["sha1"], "high")
			}
			if desc, ok := knownMD5[d["md5"]]; ok {
				addFinding(r, "CRITICAL", "Known malicious MD5", path, desc+"; MD5="+d["md5"], "high")
			}
		}
	}
	pathLower := strings.ToLower(path)
	cacheFile := strings.Contains(pathLower, "leveldb") || strings.Contains(pathLower, "code cache") || strings.Contains(pathLower, "tinyget") || strings.EqualFold(name, "transportsecurity") || strings.EqualFold(name, "network persistent state") || strings.Contains(pathLower, "reporting and nel")
	if size > 0 && size <= 64<<20 && (cacheFile || ext == ".log" || ext == ".ldb" || ext == ".js" || ext == ".lua" || ext == ".bundle" || ext == ".dat" || ext == ".bin" || ext == ".exe" || ext == ".dll" || ext == ".sys" || name == "data_3") {
		b, e := readFileBounded(path, 64<<20)
		if e == nil {
			low := strings.ToLower(string(b))
			hits := []string{}
			for _, needle := range suspiciousStrings {
				if strings.Contains(low, strings.ToLower(needle)) {
					hits = append(hits, needle)
				}
			}
			iocHits := []IOCRecord{}
			for _, ioc := range embeddedIOCs {
				if ioc.Type == "string" && len(ioc.Value) >= 8 && strings.Contains(low, strings.ToLower(ioc.Value)) {
					iocHits = append(iocHits, ioc)
				}
			}
			iocHits = independentIOCRecords(iocHits)
			if len(iocHits) >= 2 {
				labels := []string{}
				high := 0
				for _, x := range iocHits {
					labels = append(labels, x.Value)
					if x.Confidence == "high" {
						high++
					}
				}
				sev, conf := "WARNING", "medium"
				if high >= 2 {
					sev, conf = "CRITICAL", "high"
				}
				addFinding(r, sev, "Embedded K2F IOC string cluster", path, strings.Join(labels, ", "), conf)
			}
			if len(hits) > 0 {
				sev, conf := k2fStringSeverity(hits)
				addFinding(r, sev, "K2F string indicators", path, strings.Join(hits, ", "), conf)
			}
			if strings.EqualFold(name, "transportsecurity") {
				if strings.Contains(string(b), "wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw=") {
					addFinding(r, "CRITICAL", "Chromium HSTS record for K2F agent server", path, "TransportSecurity contains the hashed host key for analytics.insightjs.com", "high")
				} else if strings.Contains(string(b), "JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg=") || strings.Contains(string(b), "+EQMCXxbp1N4L3mxYGR66hSUD0cvdir6DDtJBLH3wPk=") {
					addFinding(r, "WARNING", "Chromium HSTS record for K2F loader domain", path, "TransportSecurity contains a hashed host key for insightjs.com or insightjs.org", "high")
				}
			}
			genericHits := []string{}
			for _, needle := range crossGameStrings {
				if strings.Contains(low, strings.ToLower(needle)) {
					genericHits = append(genericHits, needle)
				}
			}
			if len(genericHits) >= 2 && (ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".bin") {
				addFinding(r, "REVIEW", "Cross-game loader/remote-control heuristic", path, strings.Join(genericHits, ", "), "low; API strings alone are not proof of malicious behavior")
			}
			if hasLuaJITMagic(b) {
				if bytesK2FStructure(b) {
					addFinding(r, "CRITICAL", "K2F LuaJIT structural signature", path, "LuaJIT bcdump revision 1 plus K2F string-table structure", "high")
				} else if hasLuaJITDumpHeader(b) && strings.Contains(strings.ToLower(path), "tinyget") {
					addFinding(r, "WARNING", "LuaJIT payload in launcher download folder", path, "LuaJIT bytecode header 1B 4C 4A 01; preserve and investigate", "medium")
				} else if hasLuaJITDumpHeader(b) {
					addFinding(r, "REVIEW", "LuaJIT bytecode header", path, "Structurally plausible generic LuaJIT 2.0 dump; not proof of K2F or malware", "low; generic format marker")
				}
			}
			for _, ioc := range embeddedIOCs {
				if ioc.Type == "bytes" && matchHexPattern(b, ioc.Value) {
					sev := "WARNING"
					confidence := ioc.Confidence
					if isGenericLuaJITHeaderIOC(ioc) {
						continue // Generic LuaJIT magic is evaluated only at the file start with structure checks.
					} else if ioc.Confidence == "high" {
						sev = "CRITICAL"
					}
					addFinding(r, sev, "K2F byte signature", path, ioc.Description+" ("+ioc.Value+")", confidence)
				}
			}
		} else {
			r.SkippedFiles++
			addFinding(r, "INFO", "File content read limitation", path, e.Error(), "scan limitation")
		}
	}
	if strings.HasPrefix(name, "k2f-bcreds") || strings.HasPrefix(name, "k2f_screen") {
		addFinding(r, "CRITICAL", "K2F collection artifact", path, "Filename matches a documented credential-staging or screenshot artifact", "high")
	} else if strings.HasPrefix(name, "k2f") && strings.HasSuffix(name, ".lua") {
		addFinding(r, "WARNING", "K2F-named payload artifact", path, "Filename matches a documented K2F payload pattern; validate bytecode and provenance", "medium")
	}
	if name == "platform_experience_helper.dll" {
		parent := filepath.Base(filepath.Dir(path))
		if strings.Contains(pathLower, "platformexperiencehelper") {
			evidence := "Known persistence DLL filename found in a browser PlatformExperienceHelper path"
			if regexp.MustCompile(`(?i)^[0-9a-f]{64}$`).MatchString(parent) {
				evidence = "DLL is inside the documented 64-hex PlatformExperienceHelper subfolder; the parent folder alone is legitimate"
			}
			addFinding(r, "CRITICAL", "Browser K2F persistence DLL path", path, evidence, "high")
		}
	}
}

// independentIOCRecords removes a shorter IOC when it is wholly contained in
// a more specific matched IOC. Nested markers such as "k2f_chan" and
// "k2f_chan registered" are one piece of evidence, not an independent cluster.
func independentIOCRecords(records []IOCRecord) []IOCRecord {
	out := make([]IOCRecord, 0, len(records))
	for i, candidate := range records {
		value := strings.ToLower(candidate.Value)
		nested := false
		for j, other := range records {
			if i == j || len(other.Value) <= len(candidate.Value) {
				continue
			}
			if strings.Contains(strings.ToLower(other.Value), value) {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, candidate)
		}
	}
	return out
}

func isKnownNetworkIOCIP(ip string) bool {
	switch strings.TrimSpace(ip) {
	case "89.127.233.127", "89.126.250.172":
		return true
	default:
		return false
	}
}

func containsAny(h []string, wants ...string) bool {
	for _, a := range h {
		for _, w := range wants {
			if strings.EqualFold(a, w) {
				return true
			}
		}
	}
	return false
}

func enrichFindingSignatures(r *Report) {
	if runtime.GOOS != "windows" {
		return
	}
	paths := []string{}
	for _, f := range r.Findings {
		e := strings.ToLower(filepath.Ext(f.Path))
		if f.Path != "" && (e == ".exe" || e == ".dll" || e == ".sys") {
			paths = append(paths, f.Path)
		}
	}
	paths = unique(paths)
	if len(paths) == 0 {
		return
	}
	// Pass file paths as Base64-encoded JSON to avoid PowerShell quoting issues.
	b, _ := json.Marshal(paths)
	encoded := base64.StdEncoding.EncodeToString(b)
	ps := `$ErrorActionPreference='SilentlyContinue'; $j=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + encoded + `')); $paths=ConvertFrom-Json $j; $res=@(foreach($p in $paths){$s=Get-AuthenticodeSignature -LiteralPath $p; [pscustomobject]@{path=$p;status=[string]$s.Status;status_message=[string]$s.StatusMessage;signer=[string]$s.SignerCertificate.Subject}}); $res | ConvertTo-Json -Compress`
	out, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return
	}
	var results []struct {
		Path          string `json:"path"`
		Status        string `json:"status"`
		StatusMessage string `json:"status_message"`
		Signer        string `json:"signer"`
	}
	if json.Unmarshal(out, &results) != nil {
		var one struct {
			Path          string `json:"path"`
			Status        string `json:"status"`
			StatusMessage string `json:"status_message"`
			Signer        string `json:"signer"`
		}
		if json.Unmarshal(out, &one) == nil {
			results = append(results, one)
		}
	}
	byPath := map[string]struct{ status, signer string }{}
	for _, x := range results {
		byPath[strings.ToLower(x.Path)] = struct{ status, signer string }{normalizeAuthenticodeStatus(x.Status, x.StatusMessage), x.Signer}
	}
	for i := range r.Findings {
		if x, ok := byPath[strings.ToLower(r.Findings[i].Path)]; ok {
			r.Findings[i].SignatureStatus = x.status
			r.Findings[i].Signer = x.signer
		}
	}
}
func bytesK2FStructure(b []byte) bool {
	// K2F raw-bundle YARA structure: bcdump header and the 1791-entry string table.
	needle := []byte{0x01, 0xff, 0x0d, 0x00, 0x00, 0x1c, '1', 'p', 'd', '(', '-', 'H', '"', 'q', '_', 'L', 'T', '4', 'n', '`', '`', 'b', '_', 'h', '+', 'p', '<', '"', 'J'}
	return indexBytes(b, needle) >= 0
}

// hasLuaJITDumpHeader validates a LuaJIT 2.0 dump at the beginning of a file.
// The magic bytes alone are not sufficient: the flags and first prototype
// length must form a plausible bounded dump header. This intentionally does
// not search arbitrary offsets inside PE machine code.
func hasLuaJITDumpHeader(b []byte) bool {
	if len(b) < 6 || !hasLuaJITMagic(b) {
		return false
	}
	flags := b[4]
	if flags&0xf0 != 0 {
		return false
	}
	length, n := readULEB128(b[5:])
	return n > 0 && length > 0 && length <= uint64(len(b)-5-n)
}

func hasLuaJITMagic(b []byte) bool {
	return len(b) >= 4 && bytes.Equal(b[:4], []byte{0x1b, 'L', 'J', 1})
}

func readULEB128(b []byte) (uint64, int) {
	var value uint64
	for i, c := range b {
		if i == 10 || (i == 9 && c > 1) {
			return 0, 0
		}
		value |= uint64(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			return value, i + 1
		}
	}
	return 0, 0
}

func isGenericLuaJITHeaderIOC(ioc IOCRecord) bool {
	return ioc.Type == "bytes" && strings.Contains(strings.ToLower(ioc.Description), "luajit 2.0 bcdump revision 1 header")
}

// normalizeAuthenticodeStatus keeps trust-chain failures distinct from
// unsigned files and cryptographically invalid signatures.
func normalizeAuthenticodeStatus(status, statusMessage string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	m := strings.ToLower(strings.TrimSpace(statusMessage))
	if s == "valid" {
		return "Valid"
	}
	if s == "notsigned" {
		return "NotSigned"
	}
	if strings.Contains(m, "root certificate is not trusted") || strings.Contains(m, "terminated in a root certificate") || strings.Contains(m, "untrusted root") {
		return "UntrustedRoot"
	}
	switch s {
	case "hashmismatch", "nottrusted", "invalidsignature", "malformed":
		return "InvalidSignature"
	case "notsupportedfileformat", "incompatible":
		return "NotSupported"
	case "unknownerror", "":
		return "UnknownError"
	default:
		return "UnknownError"
	}
}
func indexBytes(b, n []byte) int {
	for i := 0; i+len(n) <= len(b); i++ {
		ok := true
		for j := range n {
			if b[i+j] != n[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func scanRoots(roots []string, cfg config, r *Report) {
	seen := map[string]bool{}
	globalLimitReached := false
	for _, root := range unique(roots) {
		if r.ScannedFiles >= cfg.maxFiles {
			globalLimitReached = true
			break
		}
		info, err := os.Stat(root)
		if err != nil {
			r.SkippedFiles++
			addFinding(r, "INFO", "Scan root unavailable", root, "Could not inspect scan root: "+err.Error(), "scan limitation")
			continue
		}
		if !info.IsDir() {
			r.ScannedFiles++
			inspectFile(root, info.Size(), r, cfg.maxBytes)
			if cfg.deep {
				deepInspectFile(root, info.Size(), cfg.maxBytes, r)
			}
			continue
		}
		rootFiles := 0
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				r.SkippedFiles++
				addFinding(r, "INFO", "Filesystem entry unavailable", path, "Could not inspect filesystem entry: "+err.Error(), "scan limitation")
				return nil
			}
			if d.IsDir() {
				if isSHA256DirName(d.Name()) && strings.EqualFold(filepath.Base(filepath.Dir(path)), "PlatformExperienceHelper") {
					addFinding(r, "WARNING", "Possible residual browser persistence directory", path, "A 64-hex folder exists under PlatformExperienceHelper; verify whether the documented DLL is present", "medium")
				}
				if path != root && (d.Type()&os.ModeSymlink != 0 || (!cfg.rootOnly && skipDir(d.Name()))) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 || seen[strings.ToLower(path)] {
				return nil
			}
			if r.ScannedFiles >= cfg.maxFiles {
				globalLimitReached = true
				return filepath.SkipAll
			}
			if rootFiles >= cfg.maxPerRoot {
				addFinding(r, "INFO", "Per-root scan limit", root, fmt.Sprintf("Stopped after %d files in this root", cfg.maxPerRoot), "scan limitation")
				return filepath.SkipDir
			}
			seen[strings.ToLower(path)] = true
			rootFiles++
			r.ScannedFiles++
			if r.ScannedFiles%5000 == 0 {
				fmt.Printf("Progress: %d files scanned; %d findings so far\n", r.ScannedFiles, len(r.Findings))
			}
			fi, e := d.Info()
			if e != nil {
				r.SkippedFiles++
				return nil
			}
			inspectFile(path, fi.Size(), r, cfg.maxBytes)
			if cfg.deep {
				deepInspectFile(path, fi.Size(), cfg.maxBytes, r)
			}
			return nil
		})
		if globalLimitReached {
			break
		}
	}
	if globalLimitReached {
		addFinding(r, "INFO", "Global scan limit", "", fmt.Sprintf("Stopped at the configured limit of %d files; use -full or -root for focused scanning", cfg.maxFiles), "n/a")
	}
}

func skipDir(n string) bool {
	switch strings.ToLower(n) {
	case "windows", "winsxs", "system volume information", "$recycle.bin", "node_modules", ".git", "packages", "windowsapps", "programdata", "users", "program files", "program files (x86)":
		return true
	}
	return false
}

func isSHA256DirName(name string) bool {
	if len(name) != 64 {
		return false
	}
	for _, c := range name {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func parseWindowsProfilePaths(data []byte) []string {
	var paths []string
	if err := json.Unmarshal(data, &paths); err != nil {
		var one string
		if json.Unmarshal(data, &one) == nil && strings.TrimSpace(one) != "" {
			paths = append(paths, one)
		}
	}
	var cleaned []string
	for _, path := range paths {
		path = strings.TrimSpace(os.ExpandEnv(path))
		if path != "" {
			cleaned = append(cleaned, filepath.Clean(path))
		}
	}
	return unique(cleaned)
}

// windowsUserProfilePaths asks Windows for registered local profiles instead
// of assuming that profiles live below %SystemDrive%\\Users. This also covers
// relocated profiles and installations whose system drive is not C:.
func windowsUserProfilePaths() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ps := `$ErrorActionPreference='Stop'; $paths=@(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath } | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_.LocalPath) }); ConvertTo-Json -InputObject $paths -Compress`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps)
	data, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseWindowsProfilePaths(data)
}

func existingUserLocalProfileRoots(localAppData, home string, profileHomes []string) []string {
	var candidates []string
	// LOCALAPPDATA is authoritative for the process user, including redirected
	// or relocated AppData locations.
	if localAppData != "" {
		candidates = append(candidates, localAppData)
	}
	if home != "" {
		candidates = append(candidates, filepath.Join(home, "AppData", "Local"))
	}
	for _, profile := range profileHomes {
		candidates = append(candidates, filepath.Join(profile, "AppData", "Local"))
	}
	var roots []string
	for _, candidate := range unique(candidates) {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			roots = append(roots, candidate)
		}
	}
	return unique(roots)
}

func userLocalProfileRoots() []string {
	home, _ := os.UserHomeDir()
	return existingUserLocalProfileRoots(os.Getenv("LOCALAPPDATA"), home, windowsUserProfilePaths())
}

func browserUserDataPaths(local string) []string {
	return []string{
		filepath.Join(local, "Google", "Chrome", "User Data"),
		filepath.Join(local, "Microsoft", "Edge", "User Data"),
		filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"),
		filepath.Join(local, "Vivaldi", "User Data"),
		filepath.Join(local, "Chromium", "User Data"),
		filepath.Join(filepath.Dir(local), "Roaming", "Opera Software", "Opera Stable"),
		filepath.Join(filepath.Dir(local), "Roaming", "Opera Software", "Opera GX Stable"),
	}
}

func collectLauncherRoots() []string {
	var roots []string
	for _, env := range []string{"APPDATA", "LOCALAPPDATA", "TEMP"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		for _, launcher := range []string{"nikke_launcher", "nikke_launcher_hmt", "nikke_launcher_google", "df_garena_launcher"} {
			roots = append(roots, filepath.Join(base, launcher))
		}
	}
	for _, local := range userLocalProfileRoots() {
		roots = append(roots, filepath.Join(local, "Google", "Chrome", "Application", "PlatformExperienceHelper"))
		for _, userData := range browserUserDataPaths(local) {
			roots = append(roots,
				filepath.Join(userData, "PlatformExperienceHelper"),
				filepath.Join(userData, "Application", "PlatformExperienceHelper"),
				filepath.Join(userData, "TransportSecurity"),
				filepath.Join(userData, "Network", "Network Persistent State"),
				filepath.Join(userData, "Reporting and NEL"),
				filepath.Join(userData, "Default", "Local Storage", "leveldb"),
				filepath.Join(userData, "Default", "Code Cache", "js"),
				filepath.Join(userData, "Default", "Cache"),
			)
			matches, _ := filepath.Glob(filepath.Join(userData, "Profile *"))
			for _, profile := range matches {
				roots = append(roots,
					filepath.Join(profile, "Local Storage", "leveldb"),
					filepath.Join(profile, "Code Cache", "js"),
					filepath.Join(profile, "Cache"),
				)
			}
		}
		for _, launcher := range []string{"nikke_launcher", "nikke_launcher_hmt", "nikke_launcher_google", "df_garena_launcher"} {
			roots = append(roots, filepath.Join(filepath.Dir(local), "Roaming", launcher))
		}
		roots = append(roots, filepath.Join(local, "CEF", "User Data"))
		for _, base := range []string{"Tencent", "WeGame", "TXGameAssistant", "TxGameDownload", "DawnLauncher", "LevelInfinite", "Riot Games", "Garena"} {
			roots = append(roots, filepath.Join(local, base))
		}
	}
	app := os.Getenv("APPDATA")
	if app != "" {
		for _, base := range []string{"Tencent", "WeGame", "TXGameAssistant", "LevelInfinite", "Riot Games", "Garena"} {
			roots = append(roots, filepath.Join(app, base))
		}
	}
	return unique(roots)
}

func discoverTencentRoots() []string {
	var roots []string
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		for _, pattern := range []string{"Tencent", "Tencent Games", "WeGame", "TXGameAssistant", "Level Infinite", "Riot Games"} {
			p := filepath.Join(base, pattern)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				roots = append(roots, p)
			}
		}
	}
	return roots
}

var gameLibraryDirPattern = regexp.MustCompile(`(?i)^(games?|steam ?library|steamapps|wegame|tencent( games)?|riot games|level infinite|epic games|garena|txgameassistant|txgamedownload|netease games|nikke|delta force|arena breakout|honor of kings|pubg mobile|peacekeeper elite|valorant|league of legends|\x{738B}\x{8005}\x{8363}\x{8000}|\x{738B}\x{8005}\x{69AE}\x{8000}|\x{4E09}\x{89D2}\x{6D32}\x{884C}\x{52A8}|\x{4E09}\x{89D2}\x{6D32}\x{884C}\x{52D5}|\x{548C}\x{5E73}\x{7CBE}\x{82F1}|\x{82F1}\x{96C4}\x{8054}\x{76DF}|\x{82F1}\x{96C4}\x{806F}\x{76DF}|\x{7A7F}\x{8D8A}\x{706B}\x{7EBF}|\x{7A7F}\x{8D8A}\x{706B}\x{7DDA}|\x{65E0}\x{754F}\x{5951}\x{7EA6}|\x{7279}\x{6218}\x{82F1}\x{8C6A}|\x{9006}\x{6218}|\x{9006}\x{6230}|\x{706B}\x{5F71}\x{5FCD}\x{8005})$`)

func discoverGameLibraryRoots(r *Report) []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	var roots []string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	volumes, err := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", `Get-CimInstance Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3 -and $_.DeviceID} | Select-Object -ExpandProperty DeviceID | ConvertTo-Json -Compress`).Output()
	if err != nil {
		addFinding(r, "INFO", "Volume discovery unavailable", "", "Could not enumerate mounted fixed volumes: "+err.Error(), "scan limitation")
		return roots
	}
	for _, d := range parseWindowsVolumeRoots(volumes) {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		_ = filepath.WalkDir(d, func(path string, ent os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !ent.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(d, path)
			depth := 0
			if rel != "." {
				depth = strings.Count(rel, string(os.PathSeparator)) + 1
			}
			if depth > 3 {
				return filepath.SkipDir
			}
			if depth > 0 && gameLibraryDirPattern.MatchString(ent.Name()) {
				roots = append(roots, path)
				return filepath.SkipDir
			}
			if depth >= 3 {
				return filepath.SkipDir
			}
			if depth > 0 && skipDir(ent.Name()) {
				return filepath.SkipDir
			}
			return nil
		})
	}
	return unique(roots)
}

func parseWindowsVolumeRoots(data []byte) []string {
	var volumes []string
	if json.Unmarshal(data, &volumes) != nil {
		var one string
		if json.Unmarshal(data, &one) == nil && one != "" {
			volumes = append(volumes, one)
		}
	}
	var roots []string
	for _, volume := range volumes {
		volume = strings.TrimSpace(volume)
		if volume == "" {
			continue
		}
		roots = append(roots, strings.TrimRight(volume, `\/`)+`\`)
	}
	return unique(roots)
}

func collectTempArtifacts() []string {
	var roots []string
	temps := []string{os.Getenv("TEMP")}
	for _, local := range userLocalProfileRoots() {
		temps = append(temps, filepath.Join(local, "Temp"))
	}
	for _, temp := range unique(temps) {
		if temp == "" {
			continue
		}
		for _, pattern := range []string{"k2f*", "K2F*"} {
			matches, _ := filepath.Glob(filepath.Join(temp, pattern))
			roots = append(roots, matches...)
		}
	}
	return unique(roots)
}

type scanScope struct {
	gameRoots             []string
	scanRoots             []string
	collectSystemSnapshot bool
}

// buildScanScope centralizes the boundary between strict explicit-root scans
// and the normal host-wide discovery mode. The strict branch must return
// before any registry, launcher, profile, volume, Steam, or Epic discovery.
func buildScanScope(rootOnly bool, explicitRoots []string, r *Report) scanScope {
	if rootOnly {
		roots := unique(explicitRoots)
		return scanScope{gameRoots: roots, scanRoots: roots, collectSystemSnapshot: false}
	}
	gameRoots := append([]string{}, registryInventory(r)...)
	gameRoots = append(gameRoots, steamRoots()...)
	gameRoots = append(gameRoots, epicRoots()...)
	gameRoots = append(gameRoots, discoverTencentRoots()...)
	gameRoots = append(gameRoots, discoverGameLibraryRoots(r)...)
	gameRoots = append(gameRoots, explicitRoots...)
	scanRoots := append([]string{}, gameRoots...)
	scanRoots = append(scanRoots, collectLauncherRoots()...)
	// Inspect only K2F-named temporary artifacts, not the user's entire TEMP tree.
	scanRoots = append(scanRoots, collectTempArtifacts()...)
	return scanScope{gameRoots: unique(gameRoots), scanRoots: unique(scanRoots), collectSystemSnapshot: true}
}

func main() {
	showVersion := flag.Bool("version", false, "Print scanner version and exit")
	full := flag.Bool("full", false, "Raise scan budget; still skips Windows/system trees")
	deep := flag.Bool("deep", false, "Deep read-only content analysis of every file in selected roots; hashes files and inspects embedded indicators")
	noLogs := flag.Bool("no-logs", false, "Disable enhanced log discovery/context analysis; general file IOC scanning remains enabled")
	systemOnly := flag.Bool("system-only", false, "Collect Windows persistence/process/network snapshot without walking game files")
	rootOnly := flag.Bool("root-only", false, "Strictly scan only folders supplied with -root; skip registry discovery and the global Windows system snapshot")
	jsonPath := flag.String("json", "", "Write a JSON report to this path (default: timestamped report beside executable)")
	reportFormat := flag.String("format", "json", "Report format: json, txt, html, csv, or md")
	reportPath := flag.String("out", "", "Report output path (extension is not used to infer format)")
	language := flag.String("lang", "auto", "Summary language: auto, en, zh-Hant, zh-Hans, ja, ko, pt-BR, fr, de, es, id, th, vi, ru, pl, tr, it")
	var extra multiFlag
	flag.Var(&extra, "root", "Add a game or launcher folder to scan (repeatable)")
	flag.Parse()
	if *showVersion {
		fmt.Println("Tencent Game Audit v" + version)
		return
	}
	if *jsonPath != "" {
		*reportFormat = "json"
	} else {
		*reportFormat = strings.ToLower(strings.TrimSpace(*reportFormat))
		if *reportFormat == "markdown" {
			*reportFormat = "md"
		}
		if *reportFormat != "json" && *reportFormat != "txt" && *reportFormat != "html" && *reportFormat != "csv" && *reportFormat != "md" {
			fmt.Fprintf(os.Stderr, "unsupported report format %q (choose json, txt, html, csv, or md)\n", *reportFormat)
			os.Exit(2)
		}
	}
	lang := normalizeLanguage(*language)
	limit := 100000
	perRootLimit := 25000
	if *full {
		limit = 500000
	}
	if *deep {
		limit = 1000000
		perRootLimit = 250000
	}
	cfg := config{full: *full, deep: *deep, logForensics: !*noLogs, maxFiles: limit, maxPerRoot: perRootLimit, maxBytes: 512 << 20, roots: extra, rootOnly: *rootOnly}
	mode := "read-only"
	if *deep {
		mode = "read-only deep content analysis"
	}
	if !*noLogs {
		mode += " + log forensics"
	}
	if *systemOnly {
		mode = "read-only system snapshot"
	}
	if *rootOnly {
		mode += " (strict explicit-root scope)"
	}
	r := &Report{Version: version, Generated: time.Now().Format(time.RFC3339), Language: lang, Computer: os.Getenv("COMPUTERNAME"), User: os.Getenv("USERNAME"), Mode: mode, ScanRoots: unique(extra), Games: []Game{}, Findings: []Finding{}, Limitations: []string{
		"This scanner treats Tencent game / launcher exposure as a broad hunting hypothesis, not a proven blanket compromise. K2F-specific indicators remain attributed to the NIKKE / Level Infinite incident unless independent samples establish wider reuse.",
		"Tencent portfolio inventory is best-effort: uninstall metadata, Steam libraries and Epic manifests do not cover every launcher, portable install, region or custom path.",
		"Raw LevelDB/Code Cache scans do not decompress Chromium records; a no-hit result does not exclude compressed or deleted evidence.",
		"Deep mode hashes and inspects file contents without executing them; encrypted, compressed, packed, sparse, inaccessible, and oversized files may still require specialist tooling.",
		"This is IOC hunting, not antivirus, EDR, memory forensics or proof that a device is clean. Historical IOC hits may indicate past contact, not current execution.",
		"No live C2, domain, IP, URL or third-party service is contacted. No files, registry keys, firewall, hosts or Defender settings are changed.",
	}}
	scope := buildScanScope(*rootOnly, extra, r)
	gameRoots := scope.gameRoots
	scan := scope.scanRoots
	r.ScanRoots = append([]string{}, scan...)
	for _, root := range unique(gameRoots) {
		title := filepath.Base(root)
		rel := classify(title, "")
		source := "Discovered install/library path"
		if *rootOnly {
			source = "Explicit -root argument"
		}
		r.Games = append(r.Games, Game{Title: title, InstallPath: root, Source: source, Relation: rel})
	}
	if !*systemOnly {
		scanRoots(scan, cfg, r)
		if cfg.logForensics {
			scanLogFiles(scan, r, *rootOnly)
		}
	}
	if scope.collectSystemSnapshot {
		r.Limitations = append(r.Limitations, "System persistence/process/network snapshot is point-in-time and best-effort; protected processes and other users' private profile data may be inaccessible without elevation.")
		r.System = collectWindowsSnapshot()
		r.SystemSnapshotCollected = true
		r.System.addFindings(r)
	} else {
		r.Limitations = append(r.Limitations, "Strict -root-only mode intentionally did not query uninstall registry inventory, global persistence, services, scheduled tasks, startup folders, processes, loaded modules, TCP connections, DNS cache, hosts, named pipes, or Defender status.")
	}
	enrichFindingSignatures(r)
	if r.ScannedFiles == 0 && !*systemOnly {
		addFinding(r, "INFO", "No scan roots accessible", "", "No game or launcher directories were discovered; supply -root paths.", "n/a")
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].Severity != r.Findings[j].Severity {
			return r.Findings[i].Severity < r.Findings[j].Severity
		}
		return r.Findings[i].Path < r.Findings[j].Path
	})
	if *jsonPath != "" {
		*reportFormat = "json"
		*reportPath = *jsonPath
	}
	if *reportPath == "" {
		exe, _ := os.Executable()
		ext := strings.ToLower(strings.TrimSpace(*reportFormat))
		*reportPath = filepath.Join(filepath.Dir(exe), "Tencent-Game-Audit-"+time.Now().Format("20060102-150405")+"."+ext)
	}
	if err := writeReport(*reportPath, *reportFormat, r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	labels := map[string][]string{
		"zh-Hant": {"騰訊遊戲安全檢測（唯讀）", "已掃描檔案", "略過", "遊戲／路徑候選", "發現項目", "報告"},
		"zh-Hans": {"腾讯游戏安全检测（只读）", "已扫描文件", "跳过", "游戏／路径候选", "发现项目", "报告"},
		"ja":      {"Tencent Game Audit（読み取り専用）", "スキャン済みファイル", "スキップ", "ゲーム／パス候補", "検出項目", "レポート"},
		"ko":      {"Tencent Game Audit (읽기 전용)", "검사한 파일", "건너뜀", "게임/경로 후보", "탐지 항목", "보고서"},
		"pt-BR":   {"Auditoria de segurança de jogos Tencent (somente leitura)", "Arquivos verificados", "Ignorados", "Candidatos de jogos/caminhos", "Detecções", "Relatório"},
		"fr":      {"Audit de sécurité des jeux Tencent (lecture seule)", "Fichiers analysés", "Ignorés", "Jeux/chemins candidats", "Détections", "Rapport"},
		"de":      {"Tencent-Spielsicherheitsaudit (nur lesend)", "Geprüfte Dateien", "Übersprungen", "Spiel-/Pfadkandidaten", "Befunde", "Bericht"},
		"es":      {"Auditoría de seguridad de juegos Tencent (solo lectura)", "Archivos analizados", "Omitidos", "Juegos/rutas candidatos", "Hallazgos", "Informe"},
		"id":      {"Audit keamanan game Tencent (hanya baca)", "File dipindai", "Dilewati", "Kandidat game/jalur", "Temuan", "Laporan"},
		"th":      {"การตรวจสอบความปลอดภัยเกม Tencent (อ่านอย่างเดียว)", "ไฟล์ที่สแกน", "ข้าม", "เกม/เส้นทางที่พบ", "สิ่งที่ตรวจพบ", "รายงาน"},
		"vi":      {"Kiểm tra bảo mật trò chơi Tencent (chỉ đọc)", "Tệp đã quét", "Đã bỏ qua", "Ứng viên trò chơi/đường dẫn", "Phát hiện", "Báo cáo"},
		"ru":      {"Аудит безопасности игр Tencent (только чтение)", "Проверено файлов", "Пропущено", "Кандидаты игр/путей", "Находки", "Отчёт"},
		"pl":      {"Audyt bezpieczeństwa gier Tencent (tylko odczyt)", "Przeskanowane pliki", "Pominięto", "Kandydaci gier/ścieżek", "Wyniki", "Raport"},
		"tr":      {"Tencent oyun güvenliği denetimi (salt okunur)", "Taranan dosyalar", "Atlanan", "Oyun/yol adayları", "Bulgular", "Rapor"},
		"it":      {"Audit di sicurezza dei giochi Tencent (sola lettura)", "File analizzati", "Ignorati", "Giochi/percorsi candidati", "Rilevamenti", "Rapporto"},
	}
	label, ok := labels[lang]
	if !ok {
		label = []string{"Tencent Game Security Audit (READ ONLY)", "Files scanned", "skipped", "Game/path candidates", "Findings", "Report"}
	}
	fmt.Printf("%s\n%s: %d | %s: %d\n%s: %d\n%s: %d\n", label[0], label[1], r.ScannedFiles, label[2], r.SkippedFiles, label[3], len(r.Games), label[4], len(r.Findings))
	fmt.Printf("Log files analyzed: %d\n", r.LogFilesScanned)
	for _, f := range r.Findings {
		fmt.Printf("[%s] %s | %s | %s\n", f.Severity, f.Category, f.Path, f.Evidence)
	}
	fmt.Println(label[5]+":", *reportPath)
}

func normalizeLanguage(requested string) string {
	requested = strings.TrimSpace(strings.ReplaceAll(requested, "_", "-"))
	if requested == "" || strings.EqualFold(requested, "auto") {
		requested = os.Getenv("LC_ALL")
		if requested == "" {
			requested = os.Getenv("LC_MESSAGES")
		}
		if requested == "" {
			requested = os.Getenv("LANG")
		}
		if requested == "" {
			requested = os.Getenv("LANGUAGE")
		}
		if requested == "" && runtime.GOOS == "windows" {
			// Windows does not normally define LANG/LC_*; query the user's UI culture.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if b, err := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "[Globalization.CultureInfo]::CurrentUICulture.Name").Output(); err == nil {
				requested = strings.TrimSpace(string(b))
			}
		}
		if requested == "" {
			return "en"
		}
	}
	v := strings.ToLower(requested)
	switch {
	case strings.HasPrefix(v, "zh-tw"), strings.HasPrefix(v, "zh-hk"), strings.HasPrefix(v, "zh-mo"), strings.HasPrefix(v, "zh-hant"):
		return "zh-Hant"
	case strings.HasPrefix(v, "zh"):
		return "zh-Hans"
	case strings.HasPrefix(v, "ja"):
		return "ja"
	case strings.HasPrefix(v, "ko"):
		return "ko"
	case strings.HasPrefix(v, "pt"):
		return "pt-BR"
	case strings.HasPrefix(v, "fr"):
		return "fr"
	case strings.HasPrefix(v, "de"):
		return "de"
	case strings.HasPrefix(v, "es"):
		return "es"
	case strings.HasPrefix(v, "id"):
		return "id"
	case strings.HasPrefix(v, "th"):
		return "th"
	case strings.HasPrefix(v, "vi"):
		return "vi"
	case strings.HasPrefix(v, "ru"):
		return "ru"
	case strings.HasPrefix(v, "pl"):
		return "pl"
	case strings.HasPrefix(v, "tr"):
		return "tr"
	case strings.HasPrefix(v, "it"):
		return "it"
	default:
		return "en"
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
