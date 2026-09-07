// START_MODULE_CONTRACT
// PURPOSE: Verify history provenance survives baselines without hiding secrets.
// SCOPE: Synthetic findings and malformed commit identifiers.
// DEPENDS: internal/baseline/baseline.go, internal/report/history.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestHistoryBaselineProvenance - Preserve valid commits and reject inconsistent history.
// END_MODULE_MAP

package baseline

import (
	"github.com/sagolubev/secscan/internal/report"
	"strings"
	"testing"
)

func TestHistoryBaselineProvenance(t *testing.T) {
	f := report.Finding{Kind: "secret", RuleID: "gitlab-pat", Path: "old.txt", Line: 1, Origin: "git_history", Commit: strings.Repeat("b", 40), Fingerprint: strings.Repeat("a", 64), Sources: []string{"gitleaks"}, Severity: "high", Message: "secret detected"}
	encoded, err := Encode([]report.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, summary, err := Compare([]report.Finding{f}, snapshot)
	if err != nil || summary.Exempt != 1 || len(got) != 1 || got[0].Commit != f.Commit {
		t.Fatalf("history comparison=%+v %+v %v", got, summary, err)
	}
	for _, change := range []func(*report.Finding){func(f *report.Finding) { f.Commit = "not-a-commit" }, func(f *report.Finding) { f.Commit = "" }, func(f *report.Finding) { f.Origin = "working_tree" }, func(f *report.Finding) { f.Kind = "code" }} {
		invalid := f
		change(&invalid)
		if _, err := Encode([]report.Finding{invalid}); err == nil {
			t.Errorf("accepted inconsistent history origin=%q kind=%q commit=%q", invalid.Origin, invalid.Kind, invalid.Commit)
		}
	}
}
