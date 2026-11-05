package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
)

// writeReport renders every supported output from the same canonical Report.
// Reports can contain private host details, so files are created owner-only
// where the operating system supports Unix-style permission bits.
func writeReport(path, format string, report *Report) error {
	var data []byte
	var err error
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		data, err = json.MarshalIndent(report, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	case "txt":
		data = []byte(renderTextReport(report))
	case "md", "markdown":
		data = []byte(renderMarkdownReport(report))
	case "html":
		data, err = renderHTMLReport(report)
	case "csv":
		data, err = renderCSVReport(report)
	default:
		return fmt.Errorf("unsupported report format %q (choose json, txt, html, csv, or md)", format)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func renderTextReport(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Tencent Game Audit v%s\nGenerated: %s\nLanguage: %s\nMode: %s\nComputer: %s\nUser: %s\nScanned files: %d\nLog files analyzed: %d\nSkipped files: %d\nGames/paths: %d\nFindings: %d\n\n",
		r.Version, r.Generated, r.Language, r.Mode, r.Computer, r.User, r.ScannedFiles, r.LogFilesScanned, r.SkippedFiles, len(r.Games), len(r.Findings))
	b.WriteString("GAME INVENTORY\n--------------\n")
	for _, g := range r.Games {
		fmt.Fprintf(&b, "- %s | %s | %s | %s | %s\n", g.Title, g.Publisher, g.InstallPath, g.Source, g.Relation)
	}
	b.WriteString("\nFINDINGS\n--------\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %s\n  Path: %s\n  Evidence: %s\n  Confidence: %s\n  Signature: %s\n  Signer: %s\n\n", f.Severity, f.Category, f.Path, f.Evidence, f.Confidence, f.SignatureStatus, f.Signer)
	}
	snapshot, _ := json.MarshalIndent(r.System, "", "  ")
	fmt.Fprintf(&b, "SYSTEM SNAPSHOT\n---------------\n%s\n\n", snapshot)
	b.WriteString("LIMITATIONS\n-----------\n")
	for _, limitation := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	b.WriteString("\nA no-hit result does not prove that a device is clean. Treat this report as sensitive host data.\n")
	return b.String()
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", "<br>")
}

func renderMarkdownReport(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Tencent Game Audit v%s\n\n- Generated: %s\n- Language: %s\n- Mode: %s\n- Computer: %s\n- User: %s\n- Scanned files: %d\n- Log files analyzed: %d\n- Skipped files: %d\n\n",
		r.Version, markdownCell(r.Generated), markdownCell(r.Language), markdownCell(r.Mode), markdownCell(r.Computer), markdownCell(r.User), r.ScannedFiles, r.LogFilesScanned, r.SkippedFiles)
	b.WriteString("## Game inventory\n\n| Title | Publisher | Install path | Source | Relationship |\n|---|---|---|---|---|\n")
	for _, g := range r.Games {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", markdownCell(g.Title), markdownCell(g.Publisher), markdownCell(g.InstallPath), markdownCell(g.Source), markdownCell(g.Relation))
	}
	b.WriteString("\n## Findings\n\n| Severity | Category | Path | Evidence | Confidence | Signature | Signer |\n|---|---|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", markdownCell(f.Severity), markdownCell(f.Category), markdownCell(f.Path), markdownCell(f.Evidence), markdownCell(f.Confidence), markdownCell(f.SignatureStatus), markdownCell(f.Signer))
	}
	snapshot, _ := json.MarshalIndent(r.System, "", "  ")
	b.WriteString("\n## System snapshot\n\n")
	for _, line := range strings.Split(string(snapshot), "\n") {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString("\n## Limitations\n\n")
	for _, limitation := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", markdownCell(limitation))
	}
	b.WriteString("\n> A no-hit result does not prove that a device is clean. Treat this report as sensitive host data.\n")
	return b.String()
}

func renderHTMLReport(r *Report) ([]byte, error) {
	const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tencent Game Audit</title><style>
body{font:15px/1.5 system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#202124;background:#fff}
h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%;margin:1rem 0;table-layout:fixed}th,td{border:1px solid #ccc;padding:.5rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#f2f3f5}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.5rem}.meta div{padding:.6rem;background:#f6f7f8}.warning{padding:.8rem;border-left:4px solid #b7791f;background:#fffaf0}
</style></head><body><h1>Tencent Game Audit v{{.Version}}</h1>
<section class="meta"><div>Generated: {{.Generated}}</div><div>Language: {{.Language}}</div><div>Mode: {{.Mode}}</div><div>Computer: {{.Computer}}</div><div>User: {{.User}}</div><div>Scanned: {{.ScannedFiles}}</div><div>Logs analyzed: {{.LogFilesScanned}}</div><div>Skipped: {{.SkippedFiles}}</div></section>
<h2>Game inventory ({{len .Games}})</h2><table><thead><tr><th>Title</th><th>Publisher</th><th>Install path</th><th>Source</th><th>Relationship</th></tr></thead><tbody>{{range .Games}}<tr><td>{{.Title}}</td><td>{{.Publisher}}</td><td>{{.InstallPath}}</td><td>{{.Source}}</td><td>{{.Relation}}</td></tr>{{else}}<tr><td colspan="5">No game paths recorded.</td></tr>{{end}}</tbody></table>
<h2>Findings ({{len .Findings}})</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Path</th><th>Evidence</th><th>Confidence</th><th>Signature</th><th>Signer</th></tr></thead><tbody>{{range .Findings}}<tr><td>{{.Severity}}</td><td>{{.Category}}</td><td>{{.Path}}</td><td>{{.Evidence}}</td><td>{{.Confidence}}</td><td>{{.SignatureStatus}}</td><td>{{.Signer}}</td></tr>{{else}}<tr><td colspan="7">No findings recorded.</td></tr>{{end}}</tbody></table>
<h2>System snapshot</h2><pre>{{.SystemJSON}}</pre>
<h2>Limitations</h2><ul>{{range .Limitations}}<li>{{.}}</li>{{else}}<li>None recorded.</li>{{end}}</ul>
<p class="warning">A no-hit result does not prove that a device is clean. This report may contain sensitive host data. Review and redact it before sharing.</p></body></html>`
	t, err := template.New("report").Parse(page)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	snapshot, err := json.MarshalIndent(r.System, "", "  ")
	if err != nil {
		return nil, err
	}
	data := struct {
		*Report
		SystemJSON string
	}{Report: r, SystemJSON: string(snapshot)}
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func csvSafeCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func renderCSVReport(r *Report) ([]byte, error) {
	var b strings.Builder
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"record_type", "scanner_version", "generated", "language", "mode", "scanned_files", "skipped_files", "severity", "category", "title", "publisher", "install_path", "source", "relationship", "path", "evidence", "confidence", "signature_status", "signer", "log_files_scanned"}); err != nil {
		return nil, err
	}
	write := func(row []string) error {
		for i := range row {
			row[i] = csvSafeCell(row[i])
		}
		return w.Write(row)
	}
	base := []string{"summary", r.Version, r.Generated, r.Language, r.Mode, fmt.Sprint(r.ScannedFiles), fmt.Sprint(r.SkippedFiles), "", "", "", "", "", "", "", "", "", "", "", "", fmt.Sprint(r.LogFilesScanned)}
	if err := write(base); err != nil {
		return nil, err
	}
	snapshot, err := json.Marshal(r.System)
	if err != nil {
		return nil, err
	}
	if err := write([]string{"system_snapshot", r.Version, r.Generated, r.Language, r.Mode, fmt.Sprint(r.ScannedFiles), fmt.Sprint(r.SkippedFiles), "", "", "", "", "", "", "", "", string(snapshot), "", "", "", fmt.Sprint(r.LogFilesScanned)}); err != nil {
		return nil, err
	}
	for _, g := range r.Games {
		row := []string{"game", r.Version, r.Generated, r.Language, r.Mode, fmt.Sprint(r.ScannedFiles), fmt.Sprint(r.SkippedFiles), "", "", g.Title, g.Publisher, g.InstallPath, g.Source, g.Relation, "", "", "", "", "", fmt.Sprint(r.LogFilesScanned)}
		if err := write(row); err != nil {
			return nil, err
		}
	}
	for _, f := range r.Findings {
		row := []string{"finding", r.Version, r.Generated, r.Language, r.Mode, fmt.Sprint(r.ScannedFiles), fmt.Sprint(r.SkippedFiles), f.Severity, f.Category, "", "", "", "", "", f.Path, f.Evidence, f.Confidence, f.SignatureStatus, f.Signer, fmt.Sprint(r.LogFilesScanned)}
		if err := write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
