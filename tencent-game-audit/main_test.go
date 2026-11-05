package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifySeparatesNikkeFromOtherTitles(t *testing.T) {
	if got := classify("NIKKE", "Level Infinite"); got == "" || got == "Unclassified game; scanned for known K2F indicators only" {
		t.Fatalf("NIKKE not classified: %q", got)
	}
	if got := classify("Conan Exiles", ""); got == "" {
		t.Fatal("expected portfolio candidate relation")
	}
	if got := classify("Unrelated Indie Game", ""); got != "Unclassified game; scanned for known K2F indicators only" {
		t.Fatalf("unexpected relation: %q", got)
	}
}

func TestClassifyRegionalTitleAliases(t *testing.T) {
	for _, title := range []string{"\u738b\u8005\u8363\u8000", "\u738b\u8005\u69ae\u8000", "\u4e09\u89d2\u6d32\u884c\u52a8", "\u4e09\u89d2\u6d32\u884c\u52d5", "\u82f1\u96c4\u8054\u76df", "\u82f1\u96c4\u806f\u76df", "\u7a7f\u8d8a\u706b\u7ebf", "\u7a7f\u8d8a\u706b\u7dda", "\u80dc\u5229\u5973\u795e"} {
		if got := classify(title, ""); got == "Unclassified game; scanned for known K2F indicators only" {
			t.Errorf("regional title alias was not classified: %q", title)
		}
	}
	if got := classify("Unknown Game", "\u9a30\u8a0a\u4e92\u52d5\u5a1b\u6a02"); got == "Unclassified game; scanned for known K2F indicators only" {
		t.Fatal("localized Tencent publisher metadata was not recognized")
	}
	for _, directory := range []string{"\u738b\u8005\u8363\u8000", "\u4e09\u89d2\u6d32\u884c\u52a8", "\u7a7f\u8d8a\u706b\u7ebf"} {
		if !gameLibraryDirPattern.MatchString(directory) {
			t.Errorf("regional game directory was not discovered: %q", directory)
		}
	}
}

func TestParseWindowsVolumeRoots(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want int
	}{
		{name: "multiple fixed volumes", data: `["C:","D:","E:"]`, want: 3},
		{name: "single volume", data: `"Q:"`, want: 1},
		{name: "empty volume list", data: `[]`, want: 0},
		{name: "malformed response", data: `not-json`, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseWindowsVolumeRoots([]byte(tc.data))
			if len(got) != tc.want {
				t.Fatalf("parseWindowsVolumeRoots() returned %d roots, want %d: %#v", len(got), tc.want, got)
			}
			for _, root := range got {
				if !strings.HasSuffix(root, `\`) {
					t.Errorf("volume root lacks trailing separator: %q", root)
				}
			}
		})
	}
}

func TestNormalizeLanguage(t *testing.T) {
	cases := map[string]string{"zh_TW": "zh-Hant", "zh-HK": "zh-Hant", "zh-CN": "zh-Hans", "ja-JP": "ja", "ko-KR": "ko", "pt_BR": "pt-BR", "fr-FR": "fr", "de-DE": "de", "es-ES": "es", "id-ID": "id", "th-TH": "th", "vi-VN": "vi", "ru-RU": "ru", "pl-PL": "pl", "tr-TR": "tr", "it-IT": "it", "en-US": "en"}
	for input, want := range cases {
		if got := normalizeLanguage(input); got != want {
			t.Errorf("normalizeLanguage(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBrowserUserDataPathsCoverRegionalBrowserVariants(t *testing.T) {
	paths := browserUserDataPaths(filepath.Join("C:", "Users", "Example", "AppData", "Local"))
	if len(paths) < 7 {
		t.Fatalf("expected common Chromium browser profiles, got %d", len(paths))
	}
	for _, marker := range []string{"Chrome", "Edge", "Brave-Browser", "Vivaldi", "Chromium", "Opera Stable", "Opera GX Stable"} {
		found := false
		for _, path := range paths {
			if strings.Contains(path, marker) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("browser profile path missing %q", marker)
		}
	}
}

func TestK2FBundleStructure(t *testing.T) {
	needle := []byte{0x1b, 'L', 'J', 1, 0x01, 0xff, 0x0d, 0, 0, 0x1c, '1', 'p', 'd', '(', '-', 'H', '"', 'q', '_', 'L', 'T', '4', 'n', '`', '`', 'b', '_', 'h', '+', 'p', '<', '"', 'J'}
	if !bytesK2FStructure(needle) {
		t.Fatal("expected K2F bundle structural signature")
	}
	if bytesK2FStructure([]byte{0x1b, 'L', 'J', 1, 1, 2, 3}) {
		t.Fatal("ordinary LuaJIT header must not be enough")
	}
}

func TestUnique(t *testing.T) {
	x := unique([]string{".", ".", ""})
	if len(x) != 1 {
		t.Fatalf("expected one unique path, got %d", len(x))
	}
}

func TestIOCBundleLoaded(t *testing.T) {
	if len(embeddedIOCs) < 80 {
		t.Fatalf("expected embedded IOC bundle, got %d", len(embeddedIOCs))
	}
	found := false
	for _, ioc := range embeddedIOCs {
		if ioc.Type == "string" && ioc.Value == "commands.exec" {
			found = true
		}
	}
	if !found {
		t.Fatal("embedded IOC bundle missing commands.exec")
	}
}

func TestWildcardBytePattern(t *testing.T) {
	b := []byte{0xaa, 0x01, 0x00, 0x55, 0x06, 0x10, 0x03, 0x20, 0x06, 0x30, 0x03, 0xbb}
	if !matchHexPattern(b, "01 00 55 06 ?? 03 ?? 06 ?? 03") {
		t.Fatal("expected wildcard pattern to match")
	}
	if matchHexPattern(b, "01 00 54 06 ?? 03 ?? 06 ?? 03") {
		t.Fatal("unexpected wildcard pattern match")
	}
}

func TestDLLContentHeuristic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sample.dll")
	if err := os.WriteFile(p, []byte("CreateRemoteThread VirtualAllocEx"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	inspectFile(p, int64(len("CreateRemoteThread VirtualAllocEx")), r, 1024)
	found := false
	for _, f := range r.Findings {
		if f.Category == "Cross-game loader/remote-control heuristic" {
			found = true
		}
	}
	if !found {
		t.Fatal("DLL content scanner did not detect a multi-indicator review lead")
	}
}

func TestBrowserPersistenceDLLPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Google", "Chrome", "User Data", "PlatformExperienceHelper", strings.Repeat("a", 64))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "platform_experience_helper.dll")
	if err := os.WriteFile(p, []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	inspectFile(p, 6, r, 1024)
	if len(r.Findings) == 0 || r.Findings[0].Severity != "CRITICAL" {
		t.Fatalf("expected critical browser persistence DLL finding, got %+v", r.Findings)
	}
}

func TestSHA256DirectoryName(t *testing.T) {
	if !isSHA256DirName(strings.Repeat("a", 64)) || !isSHA256DirName(strings.Repeat("F", 64)) {
		t.Fatal("expected 64-character hexadecimal directory name")
	}
	for _, name := range []string{strings.Repeat("a", 63), strings.Repeat("g", 64), strings.Repeat("a", 65)} {
		if isSHA256DirName(name) {
			t.Errorf("unexpected SHA256 directory match: %q", name)
		}
	}
}

func TestK2FCollectionArtifactFilename(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k2f_screen_123_456.jpg")
	if err := os.WriteFile(p, []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	inspectFile(p, 5, r, 1024)
	if len(r.Findings) != 1 || r.Findings[0].Severity != "CRITICAL" {
		t.Fatalf("expected critical K2F screenshot artifact finding, got %+v", r.Findings)
	}
}

func TestChromiumTransportSecurityHashedIOC(t *testing.T) {
	p := filepath.Join(t.TempDir(), "TransportSecurity")
	content := "wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw="
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	inspectFile(p, int64(len(content)), r, 1024)
	found := false
	for _, finding := range r.Findings {
		if finding.Category == "Chromium HSTS record for K2F agent server" && finding.Severity == "CRITICAL" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected critical HSTS IOC finding, got %+v", r.Findings)
	}
}

func TestScanRootsHonorsGlobalAndPerRootLimits(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		name := filepath.Join(root, string(rune('a'+i))+".txt")
		if err := os.WriteFile(name, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{}
	scanRoots([]string{root}, config{maxFiles: 3, maxPerRoot: 2, maxBytes: 1024}, r)
	if r.ScannedFiles != 2 {
		t.Fatalf("per-root limit scanned %d files; want 2", r.ScannedFiles)
	}

	second := t.TempDir()
	for i := 0; i < 4; i++ {
		name := filepath.Join(second, string(rune('a'+i))+".txt")
		if err := os.WriteFile(name, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r = &Report{}
	scanRoots([]string{root, second}, config{maxFiles: 3, maxPerRoot: 10, maxBytes: 1024}, r)
	if r.ScannedFiles != 3 {
		t.Fatalf("global limit scanned %d files; want exactly 3", r.ScannedFiles)
	}
}

func TestScanRootsReportsUnavailableRoot(t *testing.T) {
	r := &Report{}
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	scanRoots([]string{missing}, config{maxFiles: 10, maxPerRoot: 10, maxBytes: 1024}, r)
	if r.SkippedFiles != 1 {
		t.Fatalf("unavailable root should increment skipped count, got %d", r.SkippedFiles)
	}
	if len(r.Findings) != 1 || r.Findings[0].Category != "Scan root unavailable" {
		t.Fatalf("unavailable root should be visible in findings, got %+v", r.Findings)
	}
}

func TestKnownNetworkIOCIP(t *testing.T) {
	for _, ip := range []string{"89.127.233.127", "89.126.250.172"} {
		if !isKnownNetworkIOCIP(ip) {
			t.Errorf("known IOC IP not detected: %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", " 89.127.233.127x"} {
		if isKnownNetworkIOCIP(ip) {
			t.Errorf("unexpected IOC IP match: %s", ip)
		}
	}
}

func TestSystemSnapshotAddsActiveTCPIOCAsCritical(t *testing.T) {
	r := &Report{}
	SystemSnapshot{NetworkIOCHits: []string{"active TCP: 89.127.233.127:443 [sample PID 42]"}}.addFindings(r)
	if len(r.Findings) != 1 {
		t.Fatalf("expected one network IOC finding, got %d", len(r.Findings))
	}
	if r.Findings[0].Severity != "CRITICAL" || r.Findings[0].Category != "Known K2F network IOC (DNS/hosts/TCP)" {
		t.Fatalf("unexpected TCP IOC finding: %+v", r.Findings[0])
	}
}

func TestSystemSnapshotCollectionErrorsBecomeFindings(t *testing.T) {
	r := &Report{}
	SystemSnapshot{CollectionErrors: []string{"PowerShell snapshot timed out"}}.addFindings(r)
	if len(r.Findings) != 1 || r.Findings[0].Severity != "INFO" || r.Findings[0].Category != "System snapshot collection limitation" {
		t.Fatalf("collection error should be visible as a limitation, got %+v", r.Findings)
	}
}

func TestLoadedK2FPersistenceModuleIsCritical(t *testing.T) {
	r := &Report{}
	SystemSnapshot{Processes: []ProcessItem{{PID: 12, Name: "chrome", Path: `C:\\Users\\Test\\AppData\\Local\\Google\\Chrome\\User Data\\PlatformExperienceHelper\\platform_experience_helper.dll`, Command: "Loaded module: platform_experience_helper.dll", Confidence: "high; documented K2F persistence module loaded"}}}.addFindings(r)
	if len(r.Findings) != 1 || r.Findings[0].Severity != "CRITICAL" {
		t.Fatalf("expected loaded K2F module to be critical, got %+v", r.Findings)
	}
}

func TestWriteReportFormatsAndEscaping(t *testing.T) {
	report := &Report{
		Version: "0.2.0", Generated: "2026-11-05T12:00:00+08:00", Language: "zh-Hant", Mode: "read-only",
		Computer: "測試主機", User: "測試使用者", ScannedFiles: 2, SkippedFiles: 1,
		Games:       []Game{{Title: "測試遊戲", InstallPath: "C:\\Games\\測試", Source: "fixture", Relation: "unclassified"}},
		Findings:    []Finding{{Severity: "REVIEW", Category: "HTML injection", Path: "=HYPERLINK(\"https://invalid\")", Evidence: "</td><script>alert(1)</script> | 證據", Confidence: "low", Signer: "Example & Co"}},
		Limitations: []string{"無法讀取的項目不代表安全"},
	}

	for _, format := range []string{"json", "txt", "html", "csv", "md"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report."+format)
			if err := writeReport(path, format, report); err != nil {
				t.Fatalf("writeReport(%s): %v", format, err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) == 0 {
				t.Fatal("report is empty")
			}
			if !strings.Contains(string(data), "network_ioc_hits") {
				t.Fatal("report omitted the system snapshot")
			}
			if format == "json" {
				var decoded Report
				if err := json.Unmarshal(data, &decoded); err != nil || len(decoded.Findings) != 1 {
					t.Fatalf("invalid JSON report: %v", err)
				}
			}
			if format == "html" {
				if strings.Contains(string(data), "<script>alert(1)</script>") || !strings.Contains(string(data), "&lt;script&gt;") {
					t.Fatal("HTML report did not escape untrusted evidence")
				}
			}
			if format == "csv" {
				rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) != 5 || rows[4][14] != "'=HYPERLINK(\"https://invalid\")" {
					t.Fatalf("CSV formula neutralization failed: %#v", rows)
				}
			}
			if format == "md" && (!strings.Contains(string(data), "測試遊戲") || !strings.Contains(string(data), "\\|")) {
				t.Fatal("Markdown report lost Unicode or failed to escape table delimiters")
			}
		})
	}
}

func TestWriteReportRejectsUnknownFormat(t *testing.T) {
	err := writeReport(filepath.Join(t.TempDir(), "report.bin"), "exe", &Report{})
	if err == nil || !strings.Contains(err.Error(), "unsupported report format") {
		t.Fatalf("expected unsupported-format error, got %v", err)
	}
}

func TestCSVReportKeepsFixedColumnCount(t *testing.T) {
	data, err := renderCSVReport(&Report{})
	if err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(strings.NewReader(string(data)))
	header, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	row, err := r.Read()
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if err == nil && len(row) != len(header) {
		t.Fatalf("CSV summary has %d columns; header has %d", len(row), len(header))
	}
}
