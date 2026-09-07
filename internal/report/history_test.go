// START_MODULE_CONTRACT
// PURPOSE: Verify historical commit provenance is visible and portable in reports.
// SCOPE: Synthetic findings, offline HTML and full SARIF.
// DEPENDS: internal/report/render.go, internal/report/history.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestHistoryReportProvenance - Display commits in HTML and retain them in SARIF.
// END_MODULE_MAP

package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHistoryReportProvenance(t *testing.T) {
	commit := strings.Repeat("b", 40)
	input := Report{SchemaVersion: "1", Findings: []Finding{{Kind: "secret", RuleID: "synthetic", Message: "secret detected", Path: "deleted.txt", Line: 3, Origin: "git_history", Commit: commit, Fingerprint: strings.Repeat("a", 64), Sources: []string{"gitleaks"}}}, Scanners: []Scanner{{Name: "gitleaks-history", Status: "success", History: &GitHistory{Head: commit, Commits: 1}, Coverage: Coverage{Read: 1, Unit: "repository"}}}}
	html, err := HTML(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Commit: <code>"+commit+"</code>") {
		t.Fatal("HTML does not display finding commit")
	}
	data, err := SARIF(input)
	if err != nil {
		t.Fatal(err)
	}
	var sarif struct {
		Runs []struct {
			Results    []struct{ Properties struct{ Secscan Finding } }
			Properties struct{ Scanners []Scanner }
		}
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatal(err)
	}
	run := sarif.Runs[0]
	if run.Results[0].Properties.Secscan.Commit != commit || run.Properties.Scanners[0].History.Head != commit {
		t.Fatal("SARIF lost commit provenance")
	}
}
