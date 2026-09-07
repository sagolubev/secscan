// START_MODULE_CONTRACT
// PURPOSE: Verify complete, deterministic JSON budgets without losing protected evidence.
// SCOPE: Synthetic findings; exact UTF-8 byte boundaries, severity groups and immutable fragments.
// DEPENDS: internal/report/budget.go, internal/report/report.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-report-rendering
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestBudgetExactBoundary - Include UTF-8, escaping, metadata and final LF in the count.
// TestBudgetSeverityGroups - Remove complete severity groups independently of arrival order.
// TestBudgetProtectsEvidence - Retain errors, secrets, unknown severity and report metadata.
// TestBudgetPreservesFragments - Avoid merging or mutating existing filtered fragments.
// TestBudgetRejectsInvalidLimit - Reject nonpositive API limits.
// END_MODULE_MAP

package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestBudgetExactBoundary(t *testing.T) {
	input := Report{SchemaVersion: "1", Repository: "проект/🔐<&>\n"}
	_, summary, err := MarshalBudget(input, 1000)
	if err != nil {
		t.Fatal(err)
	}
	// The initial limit and actual length both have three or four digits. Settle
	// the limit width before testing the one-byte acceptance boundary.
	limit := summary.Measured
	_, summary, err = MarshalBudget(input, limit)
	if err != nil {
		t.Fatal(err)
	}
	limit = summary.Measured
	data, summary, err := MarshalBudget(input, limit)
	if err != nil || summary.Measured != len(data)+1 || summary.Measured != limit || summary.Exceeded || summary.Floor != "all" {
		t.Fatalf("MarshalBudget(boundary=%d) summary=%+v bytes=%d err=%v", limit, summary, len(data)+1, err)
	}
	if !bytes.Contains(data, []byte("проект/🔐")) || !bytes.Contains(data, []byte(`\u003c\u0026\u003e\n`)) || bytes.Contains(data, []byte("\n")) {
		t.Fatalf("MarshalBudget UTF-8/escaping = %q", data)
	}
	if summary.Counter != "utf8-bytes-v1" || summary.Limit != limit || bytes.Contains(data, []byte(`"exceeded"`)) {
		t.Fatalf("MarshalBudget boundary metadata=%s", data)
	}
	data, summary, err = MarshalBudget(input, limit-1)
	if err != nil || !summary.Exceeded || summary.Measured != len(data)+1 || summary.Measured <= limit-1 || summary.Floor != "protected-only" {
		t.Fatalf("MarshalBudget(below boundary=%d) summary=%+v bytes=%d err=%v", limit-1, summary, len(data)+1, err)
	}
}

func TestBudgetSeverityGroups(t *testing.T) {
	input := Report{SchemaVersion: "1"}
	for _, severity := range []string{"informational", "info", "low", "medium", "warning", "high", "error", "critical"} {
		input.Findings = append(input.Findings, Finding{Kind: "code", Severity: severity, Fingerprint: severity, Message: strings.Repeat("x", 1000)})
	}
	data, summary, err := MarshalBudget(input, 2900)
	if err != nil {
		t.Fatal(err)
	}
	var result Report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if summary.Floor != "critical" || summary.RemovedFragments != 7 || summary.RetainedFragments != 1 || summary.Exceeded || len(result.Findings) != 1 || result.Findings[0].Severity != "critical" {
		t.Fatalf("MarshalBudget(groups, 2900) summary=%+v findings=%+v", summary, result.Findings)
	}
	slices.Reverse(input.Findings)
	reversed, reversedSummary, err := MarshalBudget(input, 2900)
	if err != nil || !bytes.Equal(reversed, data) || reversedSummary != summary {
		t.Fatalf("MarshalBudget(reversed) differs: summary=%+v err=%v", reversedSummary, err)
	}
	for _, tc := range []struct {
		limit    int
		floor    string
		retained int
	}{{20000, "all", 8}, {8000, "low", 6}, {6500, "medium", 5}, {4000, "high", 3}, {100, "protected-only", 0}} {
		_, got, err := MarshalBudget(input, tc.limit)
		if err != nil || got.Floor != tc.floor || got.RetainedFragments != tc.retained {
			t.Errorf("MarshalBudget(groups, %d)=%+v err=%v, want floor %s retained %d", tc.limit, got, err, tc.floor, tc.retained)
		}
	}
}

func TestBudgetProtectsEvidence(t *testing.T) {
	input := Report{
		SchemaVersion: "1", Repository: "repo",
		Scope:           &Scope{Paths: []string{"app"}, SelectedFiles: 2},
		Inventory:       &Inventory{Omitted: []OmittedInput{{Path: "control", Reason: "control file"}}},
		UncheckedInputs: []UncheckedInput{{Path: "missing", Reason: "scanner unavailable"}},
		Filtering:       &FilterSummary{InputFindings: 9, OutputFragments: 7},
		Baseline:        &BaselineSummary{New: 6, Exempt: 1},
		Scanners:        []Scanner{{Name: "gitleaks", Status: "failed", Coverage: Coverage{Failed: 1, Unit: "files", FailedInputs: []string{"app.py"}}, Capabilities: []string{"network:none"}, Limitations: []string{"incomplete"}, History: &GitHistory{Head: strings.Repeat("a", 40), Commits: 2}}},
		Findings: []Finding{
			{Kind: "secret", Severity: "informational", Fingerprint: "secret"},
			{Kind: "error", Severity: "low", Fingerprint: "error"},
			{Kind: "code", Severity: "unknown", Fingerprint: "unknown"},
			{Kind: "code", Severity: "", Fingerprint: "empty"},
			{Kind: "code", Severity: "future", Fingerprint: "future"},
			{Kind: "code", Severity: "critical", Fingerprint: "ranked"},
		},
	}
	before, _ := json.Marshal(input)
	data, summary, err := MarshalBudget(input, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !summary.Exceeded || summary.RemovedFragments != 1 || summary.RetainedFragments != 5 || summary.Measured != len(data)+1 || len(got.Findings) != 5 {
		t.Fatalf("MarshalBudget(protected, 1)=%+v findings=%+v", summary, got.Findings)
	}
	for _, f := range got.Findings {
		if f.Fingerprint == "ranked" {
			t.Error("MarshalBudget retained an unprotected ranked finding")
		}
	}
	got.Findings, got.Budget = input.Findings, nil
	if !reflect.DeepEqual(got, input) {
		t.Errorf("MarshalBudget changed non-finding metadata: got %+v want %+v", got, input)
	}
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("MarshalBudget mutated input metadata or findings")
	}
}

func TestBudgetPreservesFragments(t *testing.T) {
	input := Report{Filtering: &FilterSummary{InputFindings: 1, OutputFragments: 2}, Findings: []Finding{
		{Kind: "dependency", Severity: "high", Fingerprint: "original", Package: &Package{Name: "example", Version: "1"}, Advisories: []string{"CVE-1"}, Locations: []Location{{Path: "a", Line: 1}}, Sources: []string{"trivy"}},
		{Kind: "dependency", Severity: "high", Fingerprint: "original", Package: &Package{Name: "example", Version: "1"}, Advisories: []string{"CVE-2"}, Locations: []Location{{Path: "b", Line: 1}}, Sources: []string{"grype"}},
	}}
	before, _ := json.Marshal(input)
	data, summary, err := MarshalBudget(input, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var result Report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if summary.RetainedFragments != 2 || !reflect.DeepEqual(result.Findings, input.Findings) {
		t.Fatalf("MarshalBudget merged or changed fragments: %+v", result.Findings)
	}
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("MarshalBudget mutated nested fragments")
	}
}

func TestBudgetRejectsInvalidLimit(t *testing.T) {
	for _, limit := range []int{0, -1} {
		if _, _, err := MarshalBudget(Report{}, limit); err == nil {
			t.Errorf("MarshalBudget(limit=%d) accepted invalid limit", limit)
		}
	}
}
