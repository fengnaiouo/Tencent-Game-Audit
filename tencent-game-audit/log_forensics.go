package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxLogFileBytes = 16 << 20
)

type logRule struct {
	id         string
	marker     string
	category   string
	severity   string
	confidence string
}

// NIKKE/K2F rules are deliberately distinct from generic cross-game rules.
// A bare channel name is only a review lead; exact execution/download markers
// are high-confidence incident leads, strengthened further by cross-marker correlation.
var logRules = []logRule{
	{"NIKKE-K2F-LOG-001", "k2f_chan registered", "NIKKE/K2F launcher execution marker", "CRITICAL", "high; incident-specific exact marker"},
	{"NIKKE-K2F-LOG-002", "lua downloaded to log\\tinyget", "NIKKE/K2F launcher payload-download marker", "CRITICAL", "high; incident-specific exact marker"},
	{"NIKKE-K2F-LOG-003", "k2f.agent.state", "NIKKE/K2F agent state marker", "WARNING", "high; corroborate with execution evidence"},
	{"NIKKE-K2F-LOG-004", "analytics.insightjs.com", "NIKKE/K2F reported infrastructure reference", "WARNING", "high; historical infrastructure indicator"},
	{"NIKKE-K2F-LOG-005", "insightjs.com/l.js", "NIKKE/K2F reported script-loader reference", "WARNING", "high; historical infrastructure indicator"},
	{"NIKKE-K2F-LOG-006", "k2f_chan", "NIKKE/K2F channel-name reference", "REVIEW", "low; isolated string is not proof of execution"},
	{"NIKKE-K2F-LOG-007", "agent started as", "Generic agent-start message", "REVIEW", "low; generic message requires context"},
	{"NIKKE-K2F-LOG-008", "insight.bundle", "NIKKE/K2F reported bundle-name reference", "REVIEW", "medium; filename alone is not proof"},
	{"NIKKE-K2F-LOG-009", "aegis-fix.min.js", "NIKKE launcher asset reference", "REVIEW", "low; asset name alone is not proof"},
	{"NIKKE-K2F-LOG-010", "vue-bucket.min.js", "NIKKE launcher asset reference", "REVIEW", "low; asset name alone is not proof"},
	{"NIKKE-K2F-LOG-011", "images.7fec4c32.js", "NIKKE launcher asset reference", "REVIEW", "low; asset name alone is not proof"},
	{"NIKKE-K2F-LOG-012", "FeedList.feb647c9.js", "NIKKE launcher asset reference", "REVIEW", "low; asset name alone is not proof"},
	{"GENERIC-LOG-001", "powershell -enc", "Encoded PowerShell command reference", "REVIEW", "low; command-line context required"},
	{"GENERIC-LOG-002", "mshta.exe", "MSHTA execution reference", "REVIEW", "low; legitimate administration can use this binary"},
	{"GENERIC-LOG-003", "rundll32.exe javascript:", "Rundll32 script execution reference", "REVIEW", "low; validate exact command line and parent process"},
	{"GENERIC-LOG-004", "regsvr32.exe /s", "Regsvr32 execution reference", "REVIEW", "low; legitimate installers may use regsvr32"},
	{"GENERIC-LOG-005", "CreateRemoteThread", "Remote-thread API reference", "REVIEW", "low; API name in a log is not proof of injection"},
	{"GENERIC-LOG-006", "WriteProcessMemory", "Cross-process memory-write API reference", "REVIEW", "low; API name in a log is not proof of injection"},
	{"GENERIC-LOG-007", "VirtualAllocEx", "Remote memory-allocation API reference", "REVIEW", "low; API name in a log is not proof of injection"},
}

var logSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9._~+/-]+=*`),
	regexp.MustCompile(`(?i)(["']?[A-Z0-9_-]*(?:password|passwd|pwd|access[_-]?token|refresh[_-]?token|token|authorization|set-cookie|cookie|api[_-]?key|secret(?:[_-]?access[_-]?key)?|private[_-]?key|access[_-]?key)["']?\s*[=:]\s*["']?)([^"'\s,;}]+)`),
	regexp.MustCompile(`(?i)([?&](?:token|access_token|api_key|key|secret|password)=)[^&\s]+`),
}

var logTimestampPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b20\d{2}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?\b`),
	regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b`),
}

func isLogCandidate(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(name))
	if strings.HasSuffix(name, ".log") || strings.Contains(name, ".log.") || strings.Contains(name, ".log-") {
		return true
	}
	if ext == ".txt" {
		parent := strings.ToLower(filepath.Base(filepath.Dir(path)))
		return name == "debug.txt" || name == "launcher.txt" || name == "service.txt" || name == "crash.txt" || parent == "log" || parent == "logs"
	}
	return false
}

func scanLogFiles(roots []string, r *Report, _ bool) {
	seen := map[string]bool{}
	for _, root := range unique(roots) {
		info, err := os.Stat(root)
		if err != nil {
			continue // scanRoots already reports unavailable roots.
		}
		if !info.IsDir() {
			if isLogCandidate(root) {
				key := strings.ToLower(filepath.Clean(root))
				if !seen[key] {
					seen[key] = true
					inspectLogFile(root, info.Size(), r)
				}
			}
			continue
		}
		walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				r.TraversalComplete = false
				addFinding(r, "INFO", "Log directory entry unavailable", path, "Could not inspect log candidate entry: "+walkErr.Error(), "scan limitation")
				return nil
			}
			if entry.IsDir() {
				if entry.Type()&os.ModeSymlink != 0 {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 || !isLogCandidate(path) {
				return nil
			}
			key := strings.ToLower(filepath.Clean(path))
			if seen[key] {
				return nil
			}
			seen[key] = true
			fi, err := entry.Info()
			if err != nil {
				r.SkippedFiles++
				r.ContentAnalysisIncomplete++
				r.TraversalComplete = false
				addFinding(r, "INFO", "Log metadata unavailable", path, "Could not inspect log metadata: "+err.Error(), "scan limitation")
				return nil
			}
			inspectLogFile(path, fi.Size(), r)
			return nil
		})
		if walkErr != nil {
			r.TraversalComplete = false
			addFinding(r, "INFO", "Log directory traversal failure", root, "Log discovery traversal ended with an error: "+walkErr.Error(), "scan limitation")
		}
	}
}

func inspectLogFile(path string, size int64, r *Report) {
	if size <= 0 {
		r.LogFilesScanned++
		return
	}
	if size > maxLogFileBytes {
		r.SkippedFiles++
		r.ContentAnalysisIncomplete++
		addFinding(r, "INFO", "Log file size limit", path, fmt.Sprintf("Log is %d bytes; maximum text-log analysis size is %d bytes", size, maxLogFileBytes), "scan limitation")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		r.SkippedFiles++
		r.ContentAnalysisIncomplete++
		addFinding(r, "INFO", "Log file read failure", path, "Could not read candidate log: "+err.Error(), "scan limitation")
		return
	}
	b, readErr := io.ReadAll(io.LimitReader(f, maxLogFileBytes+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		r.SkippedFiles++
		r.ContentAnalysisIncomplete++
		addFinding(r, "INFO", "Log file read failure", path, "Could not read complete candidate log", "scan limitation")
		return
	}
	if int64(len(b)) > maxLogFileBytes {
		r.SkippedFiles++
		r.ContentAnalysisIncomplete++
		addFinding(r, "INFO", "Log file size limit", path, "Candidate log exceeded the bounded read limit", "scan limitation")
		return
	}
	r.LogFilesScanned++
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	if desc, ok := knownHashes[sha]; ok {
		addFinding(r, "CRITICAL", "Known malicious payload disguised as log", path, desc+"; SHA256="+sha, "high")
	}
	if len(b) >= 4 && b[0] == 0x1b && b[1] == 'L' && b[2] == 'J' && b[3] == 1 {
		if bytesK2FStructure(b) {
			addFinding(r, "CRITICAL", "K2F LuaJIT payload disguised as log", path, "K2F-specific LuaJIT structure found in a log-named file; SHA256="+sha, "high")
		} else {
			addFinding(r, "REVIEW", "LuaJIT bytecode disguised as log", path, "Generic LuaJIT header in a log-named file; this is not proof of K2F or malware; SHA256="+sha, "low")
		}
	}
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		addFinding(r, "REVIEW", "Executable header in log-named file", path, "MZ executable header found in a file with a log-style name; validate provenance without executing it; SHA256="+sha, "medium; disguised executable hypothesis")
	}
	text, ok := decodeLogText(b)
	if !ok {
		r.ContentAnalysisIncomplete++
		addFinding(r, "INFO", "Non-text log candidate", path, "File has a binary or unsupported encoding; content was not rendered as log text. SHA256="+sha+". Static signature checks were still applied.", "scan limitation")
		return
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	matched := map[string]bool{}
	strong := []string{}
	for i, line := range lines {
		lower := strings.ToLower(line)
		normalized := strings.ReplaceAll(lower, "/", `\`)
		for _, rule := range logRules {
			if rule.id == "NIKKE-K2F-LOG-006" && strings.Contains(lower, "k2f_chan registered") {
				continue // Do not duplicate an exact registration marker as a bare-name lead.
			}
			if matched[rule.id] || (!strings.Contains(lower, strings.ToLower(rule.marker)) && !strings.Contains(normalized, strings.ToLower(rule.marker))) {
				continue
			}
			matched[rule.id] = true
			if rule.severity == "CRITICAL" || rule.severity == "WARNING" {
				strong = append(strong, rule.id)
			}
			evidence := formatLogEvidence(rule, i, lines, sha)
			addFinding(r, rule.severity, rule.category, path, evidence, rule.confidence)
		}
	}
	if len(strong) >= 2 {
		addFinding(r, "CRITICAL", "Correlated NIKKE/K2F log marker cluster", path, fmt.Sprintf("Independent incident-specific marker rules matched: %s; SHA256=%s. Review the individual redacted line evidence.", strings.Join(strong, ", "), sha), "high; multiple distinct incident markers in one log")
	}
}

func decodeLogText(data []byte) (string, bool) {
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
		if len(data)%2 != 0 {
			data = data[:len(data)-1]
		}
		words := make([]uint16, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			words = append(words, binary.LittleEndian.Uint16(data[i:i+2]))
		}
		return string(utf16.Decode(words)), true
	}
	if len(data) >= 2 && data[0] == 0xfe && data[1] == 0xff {
		if len(data)%2 != 0 {
			data = data[:len(data)-1]
		}
		words := make([]uint16, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			words = append(words, binary.BigEndian.Uint16(data[i:i+2]))
		}
		return string(utf16.Decode(words)), true
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if bytes.IndexByte(data, 0) >= 0 {
		return "", false
	}
	if !utf8.Valid(data) {
		return strings.ToValidUTF8(string(data), "�"), true
	}
	return string(data), true
}

func formatLogEvidence(rule logRule, lineIndex int, lines []string, sha string) string {
	start := lineIndex - 2
	if start < 0 {
		start = 0
	}
	end := lineIndex + 2
	if end >= len(lines) {
		end = len(lines) - 1
	}
	contextLines := make([]string, 0, end-start+1)
	timestamp := "not present"
	inPrivateKeyBlock := false
	for i := start; i <= end; i++ {
		line := strings.TrimSpace(lines[i])
		upperLine := strings.ToUpper(line)
		if strings.Contains(upperLine, "-----BEGIN") && strings.Contains(upperLine, "PRIVATE KEY-----") {
			inPrivateKeyBlock = true
			line = "[REDACTED PRIVATE KEY BLOCK]"
		} else if inPrivateKeyBlock {
			line = "[REDACTED PRIVATE KEY BLOCK LINE]"
			if strings.Contains(upperLine, "-----END") && strings.Contains(upperLine, "PRIVATE KEY-----") {
				inPrivateKeyBlock = false
			}
		}
		if len(line) > 240 {
			line = line[:240] + "…"
		}
		line = redactLogSecrets(line)
		contextLines = append(contextLines, fmt.Sprintf("%d:%s", i+1, line))
		if i == lineIndex {
			if ts := extractLogTimestamp(lines[i]); ts != "" {
				timestamp = ts
			}
		}
	}
	return fmt.Sprintf("rule=%s; marker=%q; line=%d; timestamp=%s; SHA256=%s; redacted_context=%q", rule.id, rule.marker, lineIndex+1, timestamp, sha, strings.Join(contextLines, " | "))
}

func redactLogSecrets(line string) string {
	for i, pattern := range logSecretPatterns {
		switch i {
		case 0:
			line = pattern.ReplaceAllString(line, "${1}[REDACTED]")
		case 1:
			line = pattern.ReplaceAllString(line, "${1}[REDACTED]")
		case 2:
			line = pattern.ReplaceAllString(line, "${1}[REDACTED]")
		}
	}
	return line
}

func extractLogTimestamp(line string) string {
	for _, pattern := range logTimestampPatterns {
		if match := pattern.FindString(line); match != "" {
			return match
		}
	}
	return ""
}
