package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestBuildScanScopeRootOnlyUsesOnlyExplicitRoots(t *testing.T) {
	first := filepath.Join(t.TempDir(), "Delta Force")
	second := filepath.Join(t.TempDir(), "WeGame")
	r := &Report{}
	scope := buildScanScope(true, true, []string{first, second, first}, r)
	if scope.collectSystemSnapshot {
		t.Fatal("strict root-only scope must not collect a global system snapshot")
	}
	if len(scope.gameRoots) != 2 || len(scope.scanRoots) != 2 {
		t.Fatalf("strict root-only scope should contain exactly two unique explicit roots: %+v", scope)
	}
	for _, got := range scope.scanRoots {
		if !filepath.IsAbs(got) {
			t.Errorf("scan root is not normalized to an absolute path: %q", got)
		}
		if !strings.EqualFold(got, first) && !strings.EqualFold(got, second) {
			t.Errorf("unexpected auto-discovered path in strict scope: %q", got)
		}
	}
}

func TestReadFileBoundedEnforcesLimitEvenWhenMetadataIsStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "growing.bin")
	if err := os.WriteFile(path, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readFileBounded(path, 4)
	if err == nil || !strings.Contains(err.Error(), "bounded read limit") {
		t.Fatalf("expected hard read limit error, got data=%q err=%v", data, err)
	}
	data, err = readFileBounded(path, 10)
	if err != nil || string(data) != "0123456789" {
		t.Fatalf("exact-limit file should be readable, got %q err=%v", data, err)
	}
}

func TestDeepInspectEnforcesReadLimitAfterMetadataCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "growing.bin")
	if err := os.WriteFile(path, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	deepInspectFile(path, 4, 4, r)
	if r.SkippedFiles != 1 || len(r.Findings) != 1 || r.Findings[0].Category != "Deep analysis size limit" {
		t.Fatalf("deep inspection did not enforce the bounded read: %+v", r)
	}
}

func TestRootOnlyScanIncludesNormallySkippedPackagesDirectory(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "packages", "game")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "resource.bin"), []byte("ordinary game data"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	scanRoots([]string{root}, config{maxBytes: 1024}, r)
	if r.ScannedFiles != 1 {
		t.Fatalf("strict root-only scan should include packages subtree, scanned=%d findings=%+v", r.ScannedFiles, r.Findings)
	}
}

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

func TestFullVolumeScanRootsAvoidsNestedDuplicateRoots(t *testing.T) {
	volume := t.TempDir()
	nested := filepath.Join(volume, "Games", "Delta Force")
	outside := t.TempDir()
	got := fullVolumeScanRoots([]string{volume}, []string{nested, outside, nested})
	if len(got) != 2 || !strings.EqualFold(got[0], volume) || !strings.EqualFold(got[1], outside) {
		t.Fatalf("full-volume roots should cover nested explicit roots without duplicate walks: %#v", got)
	}
}

func TestParseWindowsProfilePaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want []string
	}{
		{name: "relocated profiles", data: `["D:\\Profiles\\alice","E:\\Accounts\\bob"]`, want: []string{`D:\Profiles\alice`, `E:\Accounts\bob`}},
		{name: "single profile", data: `"F:\\UserData\\carol"`, want: []string{`F:\UserData\carol`}},
		{name: "empty profile list", data: `[]`, want: nil},
		{name: "malformed response", data: `not-json`, want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseWindowsProfilePaths([]byte(tc.data))
			if len(got) != len(tc.want) {
				t.Fatalf("parseWindowsProfilePaths() returned %#v, want %#v", got, tc.want)
			}
			for i := range tc.want {
				if !strings.EqualFold(got[i], tc.want[i]) {
					t.Errorf("profile path %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestUserLocalProfileRootsAreDiscoveredAndExisting(t *testing.T) {
	roots := userLocalProfileRoots()
	t.Logf("detected %d existing user Local AppData roots: %q", len(roots), roots)
	if runtime.GOOS == "windows" {
		t.Logf("Windows registered profile homes: %q", windowsUserProfilePaths())
	}
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			t.Errorf("discovered profile root is not an accessible directory: %q (err=%v)", root, err)
		}
	}
	if runtime.GOOS == "windows" {
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			found := false
			for _, root := range roots {
				if strings.EqualFold(filepath.Clean(root), filepath.Clean(local)) {
					found = true
					break
				}
			}
			if _, err := os.Stat(local); err == nil && !found {
				t.Errorf("current user's LOCALAPPDATA was not included: %q", local)
			}
		}
	}
}

func TestExistingUserLocalProfileRootsSupportRelocatedProfiles(t *testing.T) {
	base := t.TempDir()
	redirectedLocal := filepath.Join(base, "Redirected", "CurrentUserLocal")
	otherProfile := filepath.Join(base, "E-drive", "Profiles", "other-user")
	otherLocal := filepath.Join(otherProfile, "AppData", "Local")
	for _, path := range []string{redirectedLocal, otherLocal} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}

	got := existingUserLocalProfileRoots(redirectedLocal, "", []string{otherProfile})
	if len(got) != 2 {
		t.Fatalf("expected redirected current-user and relocated other-user roots, got %#v", got)
	}
	for _, want := range []string{redirectedLocal, otherLocal} {
		found := false
		for _, root := range got {
			if strings.EqualFold(filepath.Clean(root), filepath.Clean(want)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("relocated profile root %q was not discovered in %#v", want, got)
		}
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

func TestDeepInspectTreatsGenericLuaJITHeaderAsReviewOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resource.bin")
	content := []byte{0x1b, 'L', 'J', 1, 0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(p, content, 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	deepInspectFile(p, int64(len(content)), 1024, r)
	for _, f := range r.Findings {
		if f.Severity == "CRITICAL" {
			t.Fatalf("generic LuaJIT header must not be critical: %+v", f)
		}
	}
	if len(r.Findings) == 0 || r.Findings[0].Severity != "REVIEW" {
		t.Fatalf("expected a low-confidence review lead, got %+v", r.Findings)
	}
	if !strings.Contains(r.Findings[0].Evidence, "SHA256=") {
		t.Fatalf("deep finding must include SHA256: %+v", r.Findings[0])
	}
}

func TestInspectFileDoesNotTreatPEInstructionDisplacementAsLuaJIT(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launcher.exe")
	// The LuaJIT-looking bytes are the RIP-relative displacement of an x64 LEA.
	content := []byte{0x4c, 0x8d, 0x0d, 0x1b, 0x4c, 0x4a, 0x01, 0xe9, 0x20, 0x01, 0x00, 0x00}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	inspectFile(path, int64(len(content)), r, 1024)
	for _, finding := range r.Findings {
		if strings.Contains(strings.ToLower(finding.Category), "luajit") || strings.Contains(strings.ToLower(finding.Category), "k2f byte signature") {
			t.Fatalf("instruction displacement must not be reported as LuaJIT: %+v", finding)
		}
	}
}

func TestLuaJITDumpHeaderRequiresPlausibleStructure(t *testing.T) {
	valid := []byte{0x1b, 'L', 'J', 1, 0x00, 0x03, 0xaa, 0xbb, 0xcc}
	if !hasLuaJITDumpHeader(valid) {
		t.Fatal("expected structurally plausible LuaJIT dump header")
	}
	for _, malformed := range [][]byte{
		{0x1b, 'L', 'J', 1, 0xf0, 0x01, 0xaa},      // reserved flags
		{0x1b, 'L', 'J', 1, 0x00, 0x00, 0xaa},      // zero prototype length
		{0x1b, 'L', 'J', 1, 0x00, 0x7f, 0xaa},      // declared length exceeds input
		{0x4c, 0x8d, 0x0d, 0x1b, 0x4c, 0x4a, 0x01}, // embedded magic-like bytes
	} {
		if hasLuaJITDumpHeader(malformed) {
			t.Errorf("malformed/non-leading header accepted: %x", malformed)
		}
	}
}

func TestNormalizeAuthenticodeStatusSeparatesTrustAndIntegrity(t *testing.T) {
	tests := []struct{ status, message, want string }{
		{"Valid", "Signature verified", "Valid"},
		{"NotSigned", "No signature found", "NotSigned"},
		{"UnknownError", "A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider", "UntrustedRoot"},
		{"NotTrusted", "The certificate chain includes an untrusted root", "UntrustedRoot"},
		{"HashMismatch", "The file hash does not match", "InvalidSignature"},
		{"UnknownError", "The revocation server was offline", "UnknownError"},
	}
	for _, tt := range tests {
		if got := normalizeAuthenticodeStatus(tt.status, tt.message); got != tt.want {
			t.Errorf("normalizeAuthenticodeStatus(%q, %q) = %q, want %q", tt.status, tt.message, got, tt.want)
		}
	}
}

func TestDeepInspectDetectsK2FStructureInArbitraryExtension(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opaque.resource")
	content := []byte{0x1b, 'L', 'J', 1, 0x01, 0xff, 0x0d, 0, 0, 0x1c, '1', 'p', 'd', '(', '-', 'H', '"', 'q', '_', 'L', 'T', '4', 'n', '`', '`', 'b', '_', 'h', '+', 'p', '<', '"', 'J'}
	if err := os.WriteFile(p, content, 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	deepInspectFile(p, int64(len(content)), 1024, r)
	found := false
	for _, f := range r.Findings {
		if f.Severity == "CRITICAL" && strings.Contains(f.Category, "structural signature") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected K2F-specific structure in arbitrary extension, got %+v", r.Findings)
	}
}

func TestLogForensicsFindsNIKKEMarkersAndRedactsSecrets(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "Launcher", "intl_service")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(logDir, "debug.log")
	content := "2026-11-05 10:11:12 launcher ready\n2026-11-05 10:11:13 token=do-not-leak user action\n2026-11-05 10:11:14 k2f_chan registered\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	scanLogFiles([]string{root}, r, false)
	if r.LogFilesScanned != 1 {
		t.Fatalf("analyzed %d log files, want 1", r.LogFilesScanned)
	}
	var hit *Finding
	for i := range r.Findings {
		if r.Findings[i].Category == "NIKKE/K2F launcher execution marker" {
			hit = &r.Findings[i]
		}
	}
	if hit == nil || hit.Severity != "CRITICAL" || hit.Confidence == "" {
		t.Fatalf("expected exact launcher execution marker finding, got %+v", r.Findings)
	}
	if !strings.Contains(hit.Evidence, "line=3") || !strings.Contains(hit.Evidence, "2026-11-05 10:11:14") || !strings.Contains(hit.Evidence, "SHA256=") {
		t.Fatalf("finding omitted line, timestamp, or hash evidence: %+v", hit)
	}
	if strings.Contains(hit.Evidence, "do-not-leak") || !strings.Contains(hit.Evidence, "[REDACTED]") {
		t.Fatalf("log context leaked a token or failed to redact it: %s", hit.Evidence)
	}
}

func TestLogForensicsBareK2FChannelIsReviewOnly(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "debug.log")
	if err := os.WriteFile(path, []byte("2026-11-05T10:00:00Z channel initialized: k2f_chan\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	scanLogFiles([]string{root}, r, false)
	if len(r.Findings) != 1 || r.Findings[0].Severity != "REVIEW" {
		t.Fatalf("an isolated channel string must remain REVIEW, got %+v", r.Findings)
	}
}

func TestLogForensicsBenignLogAndRotatedLog(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "debug.log"), []byte("launcher started normally\nnews panel ready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "debug.log.1"), []byte("agent started as worker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	scanLogFiles([]string{root}, r, false)
	if r.LogFilesScanned != 2 {
		t.Fatalf("expected current and rotated logs to be analyzed, got %d", r.LogFilesScanned)
	}
	if len(r.Findings) != 1 || r.Findings[0].Severity != "REVIEW" {
		t.Fatalf("benign log should be quiet and generic agent text low confidence, got %+v", r.Findings)
	}
}

func TestDecodeLogTextUTF16LE(t *testing.T) {
	text := "2026-11-05 10:11:12 k2f_chan registered"
	encoded := utf16.Encode([]rune(text))
	data := []byte{0xff, 0xfe}
	for _, word := range encoded {
		data = append(data, byte(word), byte(word>>8))
	}
	decoded, ok := decodeLogText(data)
	if !ok || decoded != text {
		t.Fatalf("UTF-16LE decode = %q, %v; want %q", decoded, ok, text)
	}
}

func TestRedactLogSecretsHandlesJSONAndQueryTokens(t *testing.T) {
	line := `{"access_token":"json-secret-value","OPENAI_API_KEY":"key-secret-value"} Authorization: Bearer bearer-secret-value https://example.invalid/?token=query-secret-value`
	got := redactLogSecrets(line)
	for _, secret := range []string{"json-secret-value", "key-secret-value", "bearer-secret-value", "query-secret-value"} {
		if strings.Contains(got, secret) {
			t.Errorf("redaction leaked %q in %q", secret, got)
		}
	}
	if strings.Count(got, "[REDACTED]") < 4 {
		t.Errorf("expected JSON and query secrets to be redacted, got %q", got)
	}
}

func TestLogContextRedactsPrivateKeyBlockLines(t *testing.T) {
	lines := []string{"before", "-----BEGIN PRIVATE KEY-----", "base64-private-key-material", "-----END PRIVATE KEY-----", "after"}
	evidence := formatLogEvidence(logRule{id: "TEST", marker: "before"}, 0, lines, "hash")
	if strings.Contains(evidence, "base64-private-key-material") || strings.Contains(evidence, "BEGIN PRIVATE KEY") {
		t.Fatalf("private key block leaked in context: %s", evidence)
	}
}

func TestLogForensicsBinaryCandidateIsNotRendered(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tinyget.log")
	if err := os.WriteFile(path, []byte{'M', 'Z', 0, 0, 'k', '2', 'f', '_', 'c', 'h', 'a', 'n'}, 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	scanLogFiles([]string{root}, r, false)
	if r.LogFilesScanned != 1 {
		t.Fatalf("expected one binary log candidate to be inspected, got %+v", r)
	}
	foundBinary, foundMZ := false, false
	for _, finding := range r.Findings {
		foundBinary = foundBinary || finding.Category == "Non-text log candidate"
		foundMZ = foundMZ || finding.Category == "Executable header in log-named file"
	}
	if !foundBinary || !foundMZ {
		t.Fatalf("binary payload disguised as log should be classified as non-text, got %+v", r)
	}
}

func TestLogForensicsDetectsForwardSlashTinygetMarker(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "debug.log")
	if err := os.WriteFile(path, []byte("lua downloaded to log/tinyget\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	scanLogFiles([]string{root}, r, false)
	if len(r.Findings) != 1 || r.Findings[0].Category != "NIKKE/K2F launcher payload-download marker" || r.Findings[0].Severity != "CRITICAL" {
		t.Fatalf("forward-slash tinyget marker was not recognized: %+v", r.Findings)
	}
}

func TestLogForensicsDetectsK2FPayloadDisguisedAsLog(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload.log")
	content := []byte{0x1b, 'L', 'J', 1, 0x01, 0xff, 0x0d, 0, 0, 0x1c, '1', 'p', 'd', '(', '-', 'H', '"', 'q', '_', 'L', 'T', '4', 'n', '`', '`', 'b', '_', 'h', '+', 'p', '<', '"', 'J'}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	inspectLogFile(path, int64(len(content)), r)
	found := false
	for _, finding := range r.Findings {
		if finding.Category == "K2F LuaJIT payload disguised as log" && finding.Severity == "CRITICAL" {
			found = true
		}
	}
	if !found {
		t.Fatalf("K2F payload in a log-named file was not identified: %+v", r.Findings)
	}
}

func TestLogForensicsReportsOversizedLogAsLimitation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "debug.log")
	if err := os.WriteFile(path, make([]byte, maxLogFileBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	scanLogFiles([]string{root}, r, false)
	if r.LogFilesScanned != 0 || r.SkippedFiles != 1 || len(r.Findings) != 1 || r.Findings[0].Category != "Log file size limit" {
		t.Fatalf("oversized log should be an explicit scan limitation, got %+v", r)
	}
}

func TestRootOnlyLogForensicsIncludesNormallySkippedDirectories(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "packages", "game", "logs")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "debug.log"), []byte("launcher ready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	scanLogFiles([]string{root}, r, true)
	if r.LogFilesScanned != 1 {
		t.Fatalf("strict root-only log scan should include packages subtree, got %+v", r)
	}
}

func TestK2FStringSeverityAvoidsBareMarkerEscalation(t *testing.T) {
	if severity, _ := k2fStringSeverity([]string{"k2f_chan"}); severity != "REVIEW" {
		t.Fatalf("bare k2f_chan severity = %s, want REVIEW", severity)
	}
	if severity, _ := k2fStringSeverity([]string{"k2f_chan registered"}); severity != "CRITICAL" {
		t.Fatalf("exact registration marker severity = %s, want CRITICAL", severity)
	}
}

func TestIndependentIOCRecordsDoNotCountNestedStringsTwice(t *testing.T) {
	got := independentIOCRecords([]IOCRecord{
		{Type: "string", Value: "k2f_chan", Confidence: "high"},
		{Type: "string", Value: "k2f_chan registered", Confidence: "high"},
		{Type: "string", Value: "analytics.insightjs.com", Confidence: "high"},
	})
	if len(got) != 2 || got[0].Value != "k2f_chan registered" || got[1].Value != "analytics.insightjs.com" {
		t.Fatalf("nested IOC strings should not count as independent evidence: %+v", got)
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

func TestScanRootsDoesNotTruncateAtFormerGlobalOrPerRootLimits(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		name := filepath.Join(root, string(rune('a'+i))+".txt")
		if err := os.WriteFile(name, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{TraversalComplete: true}
	scanRoots([]string{root}, config{maxBytes: 1024}, r)
	if r.ScannedFiles != 5 {
		t.Fatalf("scanner truncated a root: scanned %d files; want all 5", r.ScannedFiles)
	}

	second := t.TempDir()
	for i := 0; i < 4; i++ {
		name := filepath.Join(second, string(rune('a'+i))+".txt")
		if err := os.WriteFile(name, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r = &Report{TraversalComplete: true}
	scanRoots([]string{root, second}, config{maxBytes: 1024}, r)
	if r.ScannedFiles != 9 {
		t.Fatalf("scanner truncated combined roots: scanned %d files; want all 9", r.ScannedFiles)
	}
	if !r.TraversalComplete || r.EntriesVisited < r.ScannedFiles || r.DirectoriesVisited < 2 {
		t.Fatalf("expected complete traversal accounting, got %+v", r)
	}
	if r.SkippedFiles != 0 {
		t.Fatalf("unexpected skipped files: %+v", r.Findings)
	}
}

func TestScanRootsDoesNotPrunePreviouslyExcludedDirectoryNames(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"packages", "node_modules", ".git", "Windows", "WindowsApps", "ProgramData", "Users"} {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "payload.bin"), []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{TraversalComplete: true}
	scanRoots([]string{root}, config{maxBytes: 1024}, r)
	if r.ScannedFiles != 7 || !r.TraversalComplete {
		t.Fatalf("expected all files under formerly pruned directories to be scanned, got %+v", r)
	}
}

func TestScanRootsReportsUnavailableRoot(t *testing.T) {
	r := &Report{}
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	r.TraversalComplete = true
	scanRoots([]string{missing}, config{maxBytes: 1024}, r)
	if r.SkippedFiles != 1 {
		t.Fatalf("unavailable root should increment skipped count, got %d", r.SkippedFiles)
	}
	if len(r.Findings) != 1 || r.Findings[0].Category != "Scan root unavailable" {
		t.Fatalf("unavailable root should be visible in findings, got %+v", r.Findings)
	}
	if r.TraversalComplete || r.UnreadableEntries != 1 {
		t.Fatalf("unavailable root must mark traversal incomplete: %+v", r)
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
		Version: "0.7.0", Generated: "2026-11-05T12:00:00+08:00", Language: "zh-Hant", Mode: "read-only",
		Computer: "測試主機", User: "測試使用者", ScannedFiles: 2, SkippedFiles: 1, LogFilesScanned: 3,
		ScanRoots: []string{`D:\Games\Example`}, SystemSnapshotCollected: true,
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
				if decoded.LogFilesScanned != 3 {
					t.Fatalf("JSON report lost log count: %d", decoded.LogFilesScanned)
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
				if rows[0][19] != "log_files_scanned" || rows[1][19] != "3" {
					t.Fatalf("CSV report lost log count: %#v", rows[:2])
				}
			}
			if (format == "txt" || format == "md") && !strings.Contains(string(data), "Log files analyzed: 3") {
				t.Fatalf("%s report omitted analyzed log count", format)
			}
			if format == "html" && !strings.Contains(string(data), "Logs analyzed: 3") {
				t.Fatal("HTML report omitted analyzed log count")
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

func TestReportsClearlyMarkUncollectedSystemSnapshotAndScanRoots(t *testing.T) {
	report := &Report{Version: "0.9.0", Mode: "read-only deep content analysis (strict explicit-root scope)", ScanRoots: []string{`D:\Delta Force`}, SystemSnapshotCollected: false, TraversalComplete: true, EntriesVisited: 12, DirectoriesVisited: 3, ContentAnalysisIncomplete: 2}
	for _, format := range []string{"json", "txt", "html", "csv", "md"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "scope-report."+format)
			if err := writeReport(path, format, report); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			content := string(data)
			if !strings.Contains(content, "Delta Force") {
				t.Fatalf("%s report omitted explicit scan root: %s", format, content)
			}
			if !strings.Contains(content, "traversal_complete") && !strings.Contains(content, "Traversal complete") && !strings.Contains(content, "TraversalComplete") {
				t.Fatalf("%s report omitted traversal completeness", format)
			}
			if !strings.Contains(content, "content_analysis_incomplete") && !strings.Contains(content, "Content analyses incomplete") && !strings.Contains(content, "ContentAnalysisIncomplete") {
				t.Fatalf("%s report omitted incomplete content-analysis count", format)
			}
			if !strings.Contains(strings.ToLower(content), "system_snapshot_collected") && !strings.Contains(content, "Not collected") && !strings.Contains(content, "not collected") {
				t.Fatalf("%s report did not disclose that the system snapshot was skipped", format)
			}
		})
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
