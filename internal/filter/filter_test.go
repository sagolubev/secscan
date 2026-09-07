// FILE: internal/filter/filter_test.go
// START_MODULE_CONTRACT
// PURPOSE: Verify strict project policy and lossless visible filtering.
// SCOPE: Synthetic findings; real parsing, baseline comparison and accounting.
// DEPENDS: internal/filter/config.go, internal/filter/filter.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-filtering-and-suppressions
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestParseBoundary - Reject malformed policy without exposing its contents.
// TestApplyPartialDependency - Preserve unsuppressed pairs and count overlaps once.
// TestApplyOrderAndExemptions - Apply ordered stages and preserve exempt kinds.
// TestApplySelectorsAndPaths - Intersect exact selectors and safe path patterns.
// TestApplyImmutable - Isolate every nested input collection.
// TestApplyBaselineAfterSplitting - Keep project subtraction through baseline growth.
// dependency - Build a normalized dependency rectangle.
// code - Build a synthetic source finding.
// snapshot - Build a validated baseline.
// END_MODULE_MAP

package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/report"
)

func TestParseBoundary(t *testing.T) {
	valid := "version = 1\nmin_severity = 'high'\ntest_paths = ['fixtures/', 'test/*.go']\n[[suppressions]]\nid = 'accepted-1'\nreason = 'SYNTHETIC_REASON_CANARY'\nkind = 'dependency'\nadvisory = 'CVE-A'\npath = 'a/lock.json'\n"
	got, err := Parse([]byte(valid))
	if err != nil || got.Version != 1 || len(got.Suppressions) != 1 || got.Suppressions[0].Advisory != "CVE-A" {
		t.Fatalf("Parse(valid policy) = %#v, %v, want version 1 and one advisory rule", got, err)
	}
	for name, data := range map[string][]byte{
		"empty":             nil,
		"missing version":   []byte("min_severity = 'high'"),
		"version":           []byte("version = 2"),
		"unknown key":       []byte(valid + "SYNTHETIC_CONFIG_CANARY = true"),
		"unknown root key":  []byte("SYNTHETIC_CONFIG_CANARY = true\n" + valid),
		"duplicate key":     []byte("version = 1\n" + valid),
		"root case alias":   []byte(strings.Replace(valid, "version =", "VERSION =", 1)),
		"rule case alias":   []byte(strings.Replace(valid, "advisory =", "ADVISORY =", 1)),
		"type":              []byte("version = 'SYNTHETIC_CONFIG_CANARY'"),
		"syntax":            []byte("version = [SYNTHETIC_CONFIG_CANARY"),
		"utf8":              append([]byte(valid), 0xff),
		"oversize":          bytes.Repeat([]byte(" "), (1<<20)+1),
		"severity":          []byte(strings.Replace(valid, "'high'", "'SYNTHETIC_CONFIG_CANARY'", 1)),
		"kind":              []byte(strings.Replace(valid, "'dependency'", "'SYNTHETIC_CONFIG_CANARY'", 1)),
		"missing selector":  []byte("version = 1\n[[suppressions]]\nid = 'rule'\nreason = 'required'"),
		"missing reason":    []byte(strings.Replace(valid, "reason = 'SYNTHETIC_REASON_CANARY'\n", "", 1)),
		"blank reason":      []byte(strings.Replace(valid, "SYNTHETIC_REASON_CANARY", "  ", 1)),
		"oversize reason":   []byte(strings.Replace(valid, "SYNTHETIC_REASON_CANARY", strings.Repeat("r", 1025), 1)),
		"id spaces":         []byte(strings.Replace(valid, "accepted-1", "bad id", 1)),
		"id unicode":        []byte(strings.Replace(valid, "accepted-1", "правило", 1)),
		"id long":           []byte(strings.Replace(valid, "accepted-1", strings.Repeat("a", 65), 1)),
		"fingerprint":       []byte(valid + "fingerprint = 'SYNTHETIC_CONFIG_CANARY'"),
		"selector controls": []byte(valid + "rule = \"bad\\u0001rule\""),
		"duplicate id":      []byte(valid + "[[suppressions]]\nid = 'accepted-1'\nreason = 'again'\nrule = 'r'"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Errorf("Parse(%s) accepted invalid policy", name)
			} else if strings.Contains(err.Error(), "CANARY") {
				t.Errorf("Parse(%s) exposed untrusted config: %v", name, err)
			}
		})
	}
	for _, pattern := range []string{"/absolute", "../parent", "a/../b", "a/./b", `a\b`, "a//b", "**/*.go", "bad[", "C:/drive", ".", "\x01bad"} {
		data := "version = 1\ntest_paths = [" + fmt.Sprintf("%q", pattern) + "]"
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("Parse(path %q) accepted invalid path pattern", pattern)
		}
	}
	var many strings.Builder
	many.WriteString("version = 1\n")
	for i := range 257 {
		fmt.Fprintf(&many, "[[suppressions]]\nid = 'r%d'\nreason = 'reviewed'\nrule = 'r'\n", i)
	}
	if _, err := Parse([]byte(many.String())); err == nil {
		t.Error("Parse(257 rules) accepted excessive rules")
	}
	last := strings.LastIndex(many.String(), "[[suppressions]]")
	if _, err := Parse([]byte(many.String()[:last])); err != nil {
		t.Errorf("Parse(256 rules) = %v, want accepted", err)
	}
}

func TestApplyPartialDependency(t *testing.T) {
	input := []report.Finding{dependency()}
	cfg := Config{Version: 1, Suppressions: []Rule{
		{ID: "one-pair", Reason: "reviewed", Advisory: "CVE-A", Path: "a/lock.json"},
		{ID: "overlap", Reason: "reviewed", Advisory: "CVE-A", Path: "a/lock.json"},
	}}
	got, err := Apply(input, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	pairs := make(map[string]bool)
	for _, f := range got.Findings {
		if f.Fingerprint != input[0].Fingerprint {
			t.Error("Apply(partial) changed the original fingerprint")
		}
		for _, id := range f.Advisories {
			for _, l := range f.Locations {
				pairs[id+"@"+l.Path] = true
			}
		}
	}
	want := map[string]bool{"CVE-A@b/lock.json": true, "CVE-B@a/lock.json": true, "CVE-B@b/lock.json": true}
	if !reflect.DeepEqual(pairs, want) {
		t.Errorf("Apply(partial) pairs = %#v, want %#v", pairs, want)
	}
	if got.Summary.InputFindings != 1 || got.Summary.OutputFragments != 2 || len(got.Summary.Stages) != 2 {
		t.Fatalf("Apply(partial) summary = %#v, want one input, two fragments and two stages", got.Summary)
	}
	if got.Summary.Stages[0] != (report.FilterStage{Name: "project", RuleID: "one-pair", Occurrences: 1}) || got.Summary.Stages[1] != (report.FilterStage{Name: "project", RuleID: "overlap"}) {
		t.Errorf("Apply(overlap) stages = %#v, want only one removed occurrence", got.Summary.Stages)
	}
	cfg.Suppressions = append(cfg.Suppressions, Rule{ID: "advisory", Reason: "reviewed", Advisory: "CVE-A"}, Rule{ID: "rest", Reason: "reviewed", Kind: "dependency"})
	got, err = Apply(input, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 0 || got.Summary.Stages[2] != (report.FilterStage{Name: "project", RuleID: "advisory", Advisories: 1, Occurrences: 1}) || got.Summary.Stages[3] != (report.FilterStage{Name: "project", RuleID: "rest", Findings: 1, Places: 2, Advisories: 1, Occurrences: 2}) {
		t.Errorf("Apply(successive removal) = %#v, want sets removed exactly once", got)
	}
}

func TestApplyOrderAndExemptions(t *testing.T) {
	project, known, low, testdata := code("project.go", "high"), code("known.go", "high"), code("low.go", "low"), code("tests/test.go", "high")
	secret, failure, unknown := code("tests/secret.go", "low"), code("tests/error.go", "low"), code("unknown.go", "unknown")
	secret.Kind, failure.Kind = "secret", "error"
	previous := snapshot(t, known, low, testdata, secret, failure)
	// Distinct rules keep baseline history from merging the purpose of each fixture.
	low.RuleID, testdata.RuleID = "new.low", "new.test"
	cfg := Config{Version: 1, MinSeverity: "high", TestPaths: []string{"tests/"}, Suppressions: []Rule{{ID: "project", Reason: "reviewed", Path: "project.go"}, {ID: "exempt", Reason: "reviewed", Path: "tests/", Kind: "secret"}}}
	got, err := Apply([]report.Finding{project, known, low, testdata, secret, failure, unknown}, cfg, &previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 3 || got.Baseline == nil || got.Baseline.InputFindings != 6 || got.Baseline.Unchanged != 1 || got.Baseline.Exempt != 2 {
		t.Fatalf("Apply(ordered stages) = %#v, want secret/error/unknown and six baseline inputs", got)
	}
	want := []report.FilterStage{
		{Name: "project", RuleID: "project", Findings: 1, Places: 1, Occurrences: 1},
		{Name: "project", RuleID: "exempt"},
		{Name: "baseline", Findings: 1, Places: 1, Occurrences: 1},
		{Name: "severity", Findings: 1, Places: 1, Occurrences: 1},
		{Name: "test-data", Findings: 1, Places: 1, Occurrences: 1},
	}
	if !reflect.DeepEqual(got.Summary.Stages, want) {
		t.Errorf("Apply(order) stages = %#v, want %#v", got.Summary.Stages, want)
	}
	for _, severity := range []string{"", "unknown", "future-level"} {
		got, err := Apply([]report.Finding{code("unknown.go", severity)}, Config{Version: 1, MinSeverity: "critical"}, nil)
		if err != nil || len(got.Findings) != 1 {
			t.Errorf("Apply(severity %q) = %#v, %v, want visible unknown severity", severity, got, err)
		}
	}
}

func TestApplySelectorsAndPaths(t *testing.T) {
	input := []report.Finding{code("src/app.go", "high")}
	for _, tc := range []struct {
		name    string
		rule    Rule
		removed bool
	}{
		{"all intersect", Rule{Kind: "code", RuleID: "rule", Fingerprint: input[0].Fingerprint, Path: "src/*.go"}, true},
		{"prefix", Rule{Path: "src/"}, true},
		{"prefix boundary", Rule{Path: "sr/"}, false},
		{"wrong kind", Rule{Kind: "configuration", Path: "src/"}, false},
		{"wrong rule", Rule{RuleID: "other", Path: "src/"}, false},
		{"exact rule", Rule{RuleID: "r*"}, false},
		{"wrong fingerprint", Rule{Fingerprint: strings.Repeat("f", 64)}, false},
		{"advisory requires dependency", Rule{Advisory: "CVE-A"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.rule.ID, tc.rule.Reason = "test", "reviewed"
			got, err := Apply(input, Config{Version: 1, Suppressions: []Rule{tc.rule}}, nil)
			if err != nil || (len(got.Findings) == 0) != tc.removed {
				t.Errorf("Apply(%s) = %#v, %v, want removed=%v", tc.name, got, err, tc.removed)
			}
		})
	}
	if _, err := Apply(input, Config{Version: 1, Suppressions: []Rule{{ID: "bad", Reason: "reviewed"}}}, nil); err == nil {
		t.Error("Apply(invalid in-memory config) accepted rule without selector")
	}
}

func TestApplyImmutable(t *testing.T) {
	input := []report.Finding{dependency()}
	before, _ := json.Marshal(input)
	got, err := Apply(input, Config{Version: 1, Suppressions: []Rule{{ID: "part", Reason: "SYNTHETIC_REASON_CANARY", Advisory: "CVE-A", Path: "a/lock.json"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(got)
	if bytes.Contains(data, []byte("SYNTHETIC_REASON_CANARY")) {
		t.Error("Apply() serialized suppression reason")
	}
	for i := range got.Findings {
		got.Findings[i].Package.Name = "mutated"
		got.Findings[i].Sources[0] = "mutated"
		got.Findings[i].Advisories[0] = "mutated"
		got.Findings[i].Locations[0].Path = "mutated"
	}
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Error("Apply() returned data aliases nested input")
	}
}

func TestApplyBaselineAfterSplitting(t *testing.T) {
	full := dependency()
	old := full
	old.Advisories = []string{"CVE-A"}
	old.Locations = []report.Location{{Path: "b/lock.json", Line: 1}}
	old.Path = "b/lock.json"
	previous := snapshot(t, old)
	got, err := Apply([]report.Finding{full}, Config{Version: 1, Suppressions: []Rule{{ID: "one-pair", Reason: "reviewed", Advisory: "CVE-A", Path: "a/lock.json"}}}, &previous)
	if err != nil || len(got.Findings) != 2 || got.Baseline == nil {
		t.Fatalf("Apply(project then baseline) = %#v, %v, want two CVE-B fragments", got, err)
	}
	for _, f := range got.Findings {
		if !reflect.DeepEqual(f.Advisories, []string{"CVE-B"}) || f.Fingerprint != full.Fingerprint {
			t.Errorf("Apply(project then baseline) = %#v, want only CVE-B with full fingerprint", f)
		}
	}
	want := report.BaselineSummary{InputFindings: 2, OutputFragments: 2, New: 1, Expanded: 1}
	if *got.Baseline != want || got.Summary.Stages[1] != (report.FilterStage{Name: "baseline", Advisories: 1, Occurrences: 1}) {
		t.Errorf("Apply(project then baseline) summaries = %#v, %#v, want %#v and one advisory/pair removed", got.Summary, got.Baseline, want)
	}
}

func dependency() report.Finding {
	return report.Normalize([]report.Finding{{Kind: "dependency", Package: &report.Package{Ecosystem: "npm", Name: "pkg", Version: "1"}, Advisories: []string{"CVE-A", "CVE-B"}, Locations: []report.Location{{Path: "a/lock.json", Line: 1}, {Path: "b/lock.json", Line: 1}}, Sources: []string{"trivy"}, Severity: "high"}})[0]
}

func code(path, severity string) report.Finding {
	return report.Finding{Kind: "code", RuleID: "rule", Path: path, Line: 1, Fingerprint: fmt.Sprintf("%064x", []byte(path)), Sources: []string{"scanner"}, Origin: "working_tree", Severity: severity}
}

func snapshot(t *testing.T, findings ...report.Finding) baseline.Snapshot {
	t.Helper()
	data, err := baseline.Encode(findings)
	if err != nil {
		t.Fatal(err)
	}
	got, err := baseline.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
