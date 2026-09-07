// START_MODULE_CONTRACT
// PURPOSE: Render offline HTML and complete SARIF from sanitized canonical findings.
// SCOPE: Escape all HTML data; retain coverage and provenance; never load external resources.
// DEPENDS: internal/report/report.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-report-rendering, internal/report/render_test.go#TestSARIFRetainsEvidence
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// HTML - Render the visible report as a self-contained escaped document.
// SARIF - Encode full unfiltered findings and analysis limitations in SARIF 2.1.0.
// END_MODULE_MAP

package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"path"
	"slices"
	"strings"
)

// HTML renders the visible report without scripts, remote resources or source snippets.
func HTML(input Report) ([]byte, error) {
	view := canonicalReport(input)
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"join":   strings.Join,
		"places": findingPlaces,
		"json": func(value any) (string, error) {
			data, err := json.MarshalIndent(value, "", "  ")
			return string(data), err
		},
	}).Parse(htmlDocument)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, view); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// SARIF encodes an unfiltered scan, including failed and incomplete analysis evidence.
func SARIF(input Report) ([]byte, error) {
	if input.Baseline != nil {
		return nil, fmt.Errorf("SARIF requires the unfiltered scan")
	}
	view := canonicalReport(input)
	ruleIDs := make([]string, 0, len(view.Findings))
	for _, finding := range view.Findings {
		ruleIDs = append(ruleIDs, finding.Kind+"/"+finding.RuleID)
	}
	slices.Sort(ruleIDs)
	ruleIDs = slices.Compact(ruleIDs)
	rules := make([]any, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, map[string]any{"id": id})
	}
	results := make([]any, 0, len(view.Findings))
	for _, finding := range view.Findings {
		locations := make([]any, 0)
		for _, place := range findingPlaces(finding) {
			if path.IsAbs(place.Path) || path.Clean(place.Path) != place.Path || place.Path == "." || place.Path == ".." || strings.HasPrefix(place.Path, "../") || strings.ContainsAny(place.Path, "\\\x00\r\n") || place.Line < 0 || place.EndLine < 0 || place.EndLine > 0 && (place.Line == 0 || place.EndLine < place.Line) {
				return nil, fmt.Errorf("invalid canonical finding location for SARIF")
			}
			uri := (&url.URL{Path: place.Path}).String()
			physical := map[string]any{"artifactLocation": map[string]any{"uri": uri}}
			if place.Line > 0 {
				region := map[string]any{"startLine": place.Line}
				if place.EndLine > 0 {
					region["endLine"] = place.EndLine
				}
				physical["region"] = region
			}
			locations = append(locations, map[string]any{"physicalLocation": physical})
		}
		id := finding.Kind + "/" + finding.RuleID
		index, _ := slices.BinarySearch(ruleIDs, id)
		message := finding.Message
		if message == "" {
			message = "scanner finding"
		}
		result := map[string]any{"ruleId": id, "ruleIndex": index, "message": map[string]any{"text": message}, "level": sarifLevel(finding.Severity), "properties": map[string]any{"secscan": finding}}
		if len(locations) > 0 {
			result["locations"] = locations
		}
		if finding.Fingerprint != "" {
			result["partialFingerprints"] = map[string]string{"secscan/v1": finding.Fingerprint}
		}
		results = append(results, result)
	}
	success := true
	notifications := make([]any, 0)
	for _, scanner := range view.Scanners {
		c := scanner.Coverage
		failed := scanner.Status == "failed" || c.Failed > 0 || c.FailedFiles > 0 || c.FailedQueries > 0
		if failed {
			success = false
		}
		if failed || scanner.Status != "success" || c.Unread > 0 || c.Skipped > 0 || len(c.UnreadInputs) > 0 || len(c.FailedInputs) > 0 || len(scanner.Limitations) > 0 {
			level := "warning"
			if failed {
				level = "error"
			}
			notifications = append(notifications, map[string]any{"level": level, "message": map[string]any{"text": scanner.Name + ": " + scanner.Status + "; inspect scanner coverage and limitations"}, "properties": map[string]any{"scanner": scanner}})
		}
	}
	if len(view.UncheckedInputs) > 0 {
		notifications = append(notifications, map[string]any{"level": "warning", "message": map[string]any{"text": "Some discovered inputs have no confirmed analysis; inspect uncheckedInputs"}})
	}
	run := map[string]any{
		"tool":        map[string]any{"driver": map[string]any{"name": "secscan", "rules": rules}},
		"results":     results,
		"invocations": []any{map[string]any{"executionSuccessful": success, "toolExecutionNotifications": notifications}},
		"properties":  map[string]any{"scanners": view.Scanners, "inventory": view.Inventory, "uncheckedInputs": view.UncheckedInputs, "exclusions": view.Exclusions},
	}
	return json.Marshal(map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{run}})
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high", "error":
		return "error"
	case "medium", "warning":
		return "warning"
	default:
		return "note"
	}
}

func findingPlaces(finding Finding) []Location {
	locations := append([]Location(nil), finding.Locations...)
	if finding.Path != "" {
		locations = append(locations, Location{Path: finding.Path, Line: finding.Line, EndLine: finding.EndLine})
	}
	slices.SortFunc(locations, func(a, b Location) int {
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		return a.EndLine - b.EndLine
	})
	return slices.Compact(locations)
}

const htmlDocument = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Secscan report</title>
<style>
:root{color-scheme:light dark;--bg:#f4f6f3;--panel:#fff;--ink:#17241c;--muted:#536158;--line:#d5dfd6;--accent:#17613f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}main{max-width:1120px;margin:auto;padding:40px 24px 64px}header{border-bottom:2px solid var(--accent);padding-bottom:24px;margin-bottom:28px}.eyebrow{font:700 13px monospace;letter-spacing:.14em;color:var(--accent)}h1{font-size:36px;margin:8px 0}h2{font-size:23px;margin:32px 0 16px}h3{font-size:17px;margin:0 0 12px}p{margin:8px 0}.muted{color:var(--muted)}code,pre{font:13px/1.5 ui-monospace,monospace;overflow-wrap:anywhere}pre{white-space:pre-wrap;padding:16px;border:1px solid var(--line);border-radius:6px;max-height:440px;overflow:auto}.summary{display:flex;flex-wrap:wrap;gap:14px}.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px 22px;flex:1;min-width:150px}.metric strong{display:block;font-size:30px;line-height:1.2}.metric span{color:var(--muted);font-size:14px}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;background:var(--panel)}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:13px;color:var(--muted)}article{background:var(--panel);padding:20px;border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:6px;margin:14px 0;overflow-wrap:anywhere}.tag{display:inline-block;padding:2px 8px;border:1px solid var(--line);border-radius:4px;font-size:12px;margin-right:8px}.meta{font-size:13px;color:var(--muted)}details{margin:12px 0}summary{cursor:pointer;color:var(--accent)}ul{padding-left:22px}footer{margin-top:36px;border-top:1px solid var(--line);padding-top:16px;font-size:13px;color:var(--muted)}
@media(prefers-color-scheme:dark){:root{--bg:#101811;--panel:#18231b;--ink:#e0eae1;--muted:#a7b9ab;--line:#344638;--accent:#93dca8}}
@media(max-width:600px){main{padding:24px 14px}h1{font-size:28px}th,td{padding:8px}}
@media print{:root{color-scheme:light;--bg:#fff;--panel:#fff;--ink:#000;--muted:#444;--line:#ccc;--accent:#17492e}main{padding:0}article{break-inside:avoid}pre{max-height:none}}
</style></head><body><main>
<header><div class="eyebrow">SECSCAN / SECURITY REPORT</div><h1>Scan results</h1><p class="muted"><code>{{.Repository}}</code></p></header>
<section class="summary" aria-label="Summary"><div class="metric"><strong>{{len .Findings}}</strong><span>Visible findings</span></div><div class="metric"><strong>{{len .Scanners}}</strong><span>Scanner outcomes</span></div><div class="metric"><strong>{{len .UncheckedInputs}}</strong><span>Inputs without confirmed analysis</span></div></section>
<p class="muted">Finding counts do not measure coverage. Review scanner outcomes and unchecked inputs before drawing conclusions.</p>
{{if .Baseline}}<p>Baseline comparison: {{.Baseline.New}} new, {{.Baseline.Expanded}} expanded, {{.Baseline.Unchanged}} unchanged, {{.Baseline.Exempt}} exempt.</p>{{end}}
<section><h2>Scanner coverage</h2><div class="table-wrap"><table><thead><tr><th>Scanner</th><th>Status</th><th>Read</th><th>Failed</th><th>Evidence</th></tr></thead><tbody>
{{range .Scanners}}<tr><td>{{.Name}}</td><td>{{.Status}}</td><td>{{.Coverage.Read}} {{.Coverage.Unit}}</td><td>{{.Coverage.Failed}}</td><td>{{range .Limitations}}<p>{{.}}</p>{{end}}<details><summary>Inspect coverage</summary><pre>{{json .}}</pre></details></td></tr>{{else}}<tr><td colspan="5">No scanner evidence is available.</td></tr>{{end}}
</tbody></table></div></section>
{{if .UncheckedInputs}}<section><h2>Unchecked inputs</h2><ul>{{range .UncheckedInputs}}<li><code>{{.Path}}</code> — {{.Category}} / {{.Format}}: {{.Reason}}</li>{{end}}</ul></section>{{end}}
{{if .Inventory}}<section><h2>Input inventory</h2><p>{{.Inventory.Tracked.Files}} tracked, {{.Inventory.Untracked.Files}} untracked, {{.Inventory.Ignored.Files}} ignored files.</p><details><summary>Inspect directories and omissions</summary><pre>{{json .Inventory}}</pre></details></section>{{end}}
<section><h2>Findings</h2>{{range .Findings}}<article><h3><span class="tag">{{if .Severity}}{{.Severity}}{{else}}unknown{{end}}</span>{{.RuleID}}</h3><p>{{.Message}}</p><p class="meta">{{.Kind}} · {{join .Sources ", "}} · {{.Origin}}{{if .BaselineStatus}} · {{.BaselineStatus}}{{end}}</p>
{{if .Package}}<p><code>{{.Package.Ecosystem}} / {{.Package.Name}}@{{.Package.Version}}</code></p>{{end}}
{{if .Advisories}}<p>{{join .Advisories ", "}}</p>{{end}}<ul>{{range places .}}<li><code>{{.Path}}{{if gt .Line 0}}:{{.Line}}{{end}}</code></li>{{end}}</ul>
{{if .ImageDigest}}<p class="meta">Image: <code>{{.ImageDigest}}</code></p>{{end}}<p class="meta">Fingerprint: <code>{{.Fingerprint}}</code></p></article>{{else}}<p>No visible findings. This does not establish that every input was analysed.</p>{{end}}</section>
<details><summary>Canonical report data</summary><pre>{{json .}}</pre></details>
<footer>Generated by Secscan. Self-contained report; no remote resources or scripts.</footer>
</main></body></html>`
