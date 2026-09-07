// FILE: internal/baseline/baseline_test.go
// START_MODULE_CONTRACT
// PURPOSE: Exercise portable snapshots and growth without trusting old output text.
// SCOPE: Pure codec/comparison tests with synthetic identities and canaries.
// DEPENDS: internal/baseline/baseline.go, internal/report/report.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-baselines
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestCompareGrowth - Check new, expanded, unchanged and exempt accounting.
// TestCompareDependencyGrowth - Preserve advisory/location growth combinations.
// TestCompareAliasBridge - Union old matches across a current alias bridge.
// TestCompareIdentityBoundaries - Keep package versions and source identities apart.
// TestCodecBoundary - Reject incompatible and corrupt data without echoing it.
// TestCodecDeterministicAndImmutable - Preserve inputs and normalized snapshots.
// TestCompareSeverityAtLocation - Keep severity growth at existing code locations.
// TestBaselineRejectsFilteredInput - Refuse partial snapshots and comparisons.
// TestCompareReturnedDataDoesNotAliasInputs - Isolate nested returned collections.
// TestCompareSharedCodeKeepsLineage - Preserve origins and images before comparing.
// TestCompareSharedCodeRetainsSeverityAliases - Retain higher scanner severity.
// TestCompareFragmentsPreservesSubtraction - Never reconstruct removed pairs.
// TestCompareFragmentsBoundary - Validate and isolate existing fragments.
// codeFinding - Build a synthetic source finding.
// dependencyFinding - Build a normalized synthetic dependency finding.
// snapshotFor - Encode and decode a real snapshot for comparison tests.
// END_MODULE_MAP

package baseline

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/report"
)

func codeFinding() report.Finding {
	return report.Finding{Kind: "code", RuleID: "test.rule", Message: "current message", Path: "app.go", Line: 3, Fingerprint: strings.Repeat("a", 64), Sources: []string{"scanner-a"}, Origin: "working_tree", Language: "go", Severity: "medium"}
}

func dependencyFinding(ids []string, locations ...string) report.Finding {
	f := report.Finding{Kind: "dependency", Package: &report.Package{Ecosystem: "npm", Name: "package", Version: "1.0"}, Advisories: ids, Sources: []string{"trivy"}, Severity: "medium"}
	for _, location := range locations {
		f.Locations = append(f.Locations, report.Location{Path: location, Line: 1})
	}
	return report.Normalize([]report.Finding{f})[0]
}

func snapshotFor(t *testing.T, findings ...report.Finding) Snapshot {
	t.Helper()
	data, err := Encode(findings)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	snapshot, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode(Encode()) error = %v", err)
	}
	return snapshot
}

func TestCompareGrowth(t *testing.T) {
	old := codeFinding()
	old.Message = "SYNTHETIC_OLD_TEXT_CANARY"
	for _, tc := range []struct {
		name   string
		change func(*report.Finding)
		status string
	}{
		{name: "unchanged", change: func(*report.Finding) {}},
		{name: "location", change: func(f *report.Finding) { f.Line++ }, status: "expanded"},
		{name: "severity", change: func(f *report.Finding) { f.Severity = "high" }, status: "expanded"},
		{name: "different rule", change: func(f *report.Finding) { f.RuleID = "other.rule" }, status: "new"},
		{name: "secret", change: func(f *report.Finding) { f.Kind = "secret" }, status: "exempt"},
		{name: "error", change: func(f *report.Finding) { f.Kind = "error" }, status: "exempt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := codeFinding()
			tc.change(&current)
			got, summary, err := Compare([]report.Finding{current}, snapshotFor(t, old))
			if err != nil {
				t.Fatal(err)
			}
			want := report.BaselineSummary{InputFindings: 1}
			switch tc.status {
			case "new":
				want.New = 1
			case "expanded":
				want.Expanded = 1
			case "exempt":
				want.Exempt = 1
			default:
				want.Unchanged = 1
			}
			if tc.status != "" {
				want.OutputFragments = 1
				if len(got) != 1 || got[0].BaselineStatus != tc.status || got[0].Fingerprint != current.Fingerprint || got[0].Message != current.Message {
					t.Fatalf("Compare(%s) = %#v, want one current %s finding", tc.name, got, tc.status)
				}
			} else if len(got) != 0 {
				t.Errorf("Compare(unchanged) = %#v, want no findings", got)
			}
			if summary != want {
				t.Errorf("Compare(%s) summary = %#v, want %#v", tc.name, summary, want)
			}
			encoded, err := json.Marshal(got)
			if err != nil || bytes.Contains(encoded, []byte(old.Message)) {
				t.Errorf("Compare(%s) emitted old text or failed serialization: %v", tc.name, err)
			}
		})
	}
}

func TestCompareDependencyGrowth(t *testing.T) {
	old := dependencyFinding([]string{"CVE-2026-1"}, "a/package-lock.json")
	current := dependencyFinding([]string{"CVE-2026-1", "GHSA-new"}, "a/package-lock.json", "b/package-lock.json")
	got, summary, err := Compare([]report.Finding{current}, snapshotFor(t, old))
	if err != nil {
		t.Fatal(err)
	}
	if summary != (report.BaselineSummary{InputFindings: 1, Expanded: 1, OutputFragments: 2}) || len(got) != 2 {
		t.Fatalf("Compare(simultaneous growth) = %#v, %#v, want one expanded input/two fragments", got, summary)
	}
	combinations := make(map[string]bool)
	for _, f := range got {
		if f.BaselineStatus != "expanded" || f.Fingerprint != current.Fingerprint {
			t.Errorf("Compare() fragment status/fingerprint = %#v, want current fingerprint and expanded", f)
		}
		for _, id := range f.Advisories {
			for _, location := range f.Locations {
				combinations[id+"@"+location.Path] = true
			}
		}
	}
	want := map[string]bool{"GHSA-new@a/package-lock.json": true, "GHSA-new@b/package-lock.json": true, "CVE-2026-1@b/package-lock.json": true}
	if !reflect.DeepEqual(combinations, want) {
		t.Errorf("Compare() advisory/location combinations = %#v, want %#v", combinations, want)
	}
	current = dependencyFinding([]string{"CVE-2026-99"}, "a/package-lock.json")
	got, summary, err = Compare([]report.Finding{current}, snapshotFor(t, old))
	if err != nil || len(got) != 1 || summary.New != 1 || got[0].BaselineStatus != "new" {
		t.Errorf("Compare(unrelated advisory) = %#v, %#v, %v, want new", got, summary, err)
	}
}

func TestCompareAliasBridge(t *testing.T) {
	oldA := dependencyFinding([]string{"CVE-2026-1", "ALIAS-a"}, "a/lock.json")
	oldB := dependencyFinding([]string{"GHSA-old", "ALIAS-b"}, "b/lock.json")
	current := dependencyFinding([]string{"CVE-2026-1", "GHSA-old", "ALIAS-a", "ALIAS-b"}, "a/lock.json", "b/lock.json")
	got, summary, err := Compare([]report.Finding{current}, snapshotFor(t, oldA, oldB))
	if err != nil || len(got) != 0 || summary.Unchanged != 1 {
		t.Errorf("Compare(alias bridge) = %#v, %#v, %v, want unchanged union", got, summary, err)
	}
}

func TestCompareIdentityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		old    report.Finding
		change func(*report.Finding)
	}{
		{name: "source", old: codeFinding(), change: func(f *report.Finding) { f.Sources = []string{"scanner-b"} }},
		{name: "language", old: codeFinding(), change: func(f *report.Finding) { f.Language = "python" }},
		{name: "origin", old: codeFinding(), change: func(f *report.Finding) { f.Origin = "history" }},
		{name: "package version", old: dependencyFinding([]string{"CVE-2026-1"}, "lock.json"), change: func(f *report.Finding) { p := *f.Package; p.Version = "2.0"; f.Package = &p }},
		{name: "package qualifiers", old: dependencyFinding([]string{"CVE-2026-1"}, "lock.json"), change: func(f *report.Finding) { p := *f.Package; p.Qualifiers = "arch=arm64"; f.Package = &p }},
		{name: "image", old: dependencyFinding([]string{"CVE-2026-1"}, "Dockerfile"), change: func(f *report.Finding) { f.ImageDigest = "sha256:" + strings.Repeat("b", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := tc.old
			tc.change(&current)
			got, summary, err := Compare([]report.Finding{current}, snapshotFor(t, tc.old))
			if err != nil || len(got) != 1 || summary.New != 1 {
				t.Errorf("Compare(%s collision) = %#v, %#v, %v, want new", tc.name, got, summary, err)
			}
		})
	}
}

func TestCodecBoundary(t *testing.T) {
	valid, err := Encode([]report.Finding{codeFinding()})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"empty":               nil,
		"truncated":           valid[:len(valid)-2],
		"trailing JSON":       append(slices.Clone(valid), []byte(`{}`)...),
		"schema":              bytes.Replace(valid, []byte(`"schemaVersion":"1"`), []byte(`"schemaVersion":"2"`), 1),
		"algorithm":           bytes.Replace(valid, []byte(`"fingerprintAlgorithm":"secscan-v1"`), []byte(`"fingerprintAlgorithm":"other"`), 1),
		"unknown field":       bytes.Replace(valid, []byte(`"findings":`), []byte(`"SYNTHETIC_UNTRUSTED_CANARY":true,"findings":`), 1),
		"duplicate field":     bytes.Replace(valid, []byte(`"schemaVersion":"1"`), []byte(`"schemaVersion":"1","schemaVersion":"1"`), 1),
		"null findings":       []byte(`{"schemaVersion":"1","fingerprintAlgorithm":"secscan-v1","findings":null}`),
		"missing findings":    []byte(`{"schemaVersion":"1","fingerprintAlgorithm":"secscan-v1"}`),
		"empty identity":      bytes.Replace(valid, []byte(`"ruleId":"test.rule"`), []byte(`"ruleId":""`), 1),
		"unsafe path":         bytes.Replace(valid, []byte(`"path":"app.go"`), []byte(`"path":"../SYNTHETIC_UNTRUSTED_CANARY"`), 1),
		"noncanonical path":   bytes.Replace(valid, []byte(`"path":"app.go"`), []byte(`"path":"a/../app.go"`), 1),
		"invalid fingerprint": bytes.Replace(valid, []byte(strings.Repeat("a", 64)), []byte("broken"), 1),
		"oversize":            bytes.Repeat([]byte(" "), MaxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(data)
			if err == nil {
				t.Errorf("Decode(%s) accepted invalid snapshot", name)
			} else if strings.Contains(err.Error(), "SYNTHETIC_UNTRUSTED_CANARY") {
				t.Errorf("Decode(%s) echoed untrusted data", name)
			}
		})
	}
	if _, _, err := Compare(nil, Snapshot{}); err == nil {
		t.Error("Compare(zero Snapshot) succeeded, want incompatible snapshot error")
	}
}

func TestCodecDeterministicAndImmutable(t *testing.T) {
	code := codeFinding()
	code.Sources = []string{"scanner-b", "scanner-a"}
	dep := dependencyFinding([]string{"GHSA-old", "CVE-2026-1"}, "b/lock.json", "a/lock.json")
	input := []report.Finding{code, dep}
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Decode(first)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, summary, err := Compare(input, snapshot)
		if err != nil || len(got) != 0 || summary.Unchanged != 2 {
			t.Fatalf("Compare(round trip) = %#v, %#v, %v, want unchanged", got, summary, err)
		}
	}
	after, err := json.Marshal(input)
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("Encode/Compare mutated inputs: before %s after %s error %v", before, after, err)
	}
	slices.Reverse(input)
	second, err := Encode(input)
	if err != nil || !bytes.Equal(first, second) {
		t.Errorf("Encode(reordered inputs) is not deterministic: %v", err)
	}
	var wire struct {
		Findings []report.Finding `json:"findings"`
	}
	if err := json.Unmarshal(first, &wire); err != nil || len(wire.Findings) != 2 {
		t.Fatalf("Encode() did not preserve full findings: %#v, %v", wire, err)
	}
	empty := snapshotFor(t)
	got, summary, err := Compare(nil, empty)
	if err != nil || len(got) != 0 || summary != (report.BaselineSummary{}) {
		t.Errorf("Compare(clean run) = %#v, %#v, %v, want clean", got, summary, err)
	}
}

func TestCompareSeverityAtLocation(t *testing.T) {
	low, high := codeFinding(), codeFinding()
	low.Severity = "low"
	high.Path = "other.go"
	high.Severity = "critical"
	got, summary, err := Compare([]report.Finding{codeFinding()}, snapshotFor(t, low, high))
	if err != nil || len(got) != 1 || summary.Expanded != 1 {
		t.Errorf("Compare(severity growth at existing location) = %#v, %#v, %v, want expanded despite another critical location", got, summary, err)
	}
}

func TestBaselineRejectsFilteredInput(t *testing.T) {
	input := codeFinding()
	input.BaselineStatus = "expanded"
	if _, err := Encode([]report.Finding{input}); err == nil {
		t.Error("Encode(filtered finding) succeeded, want refusal to persist partial snapshot")
	}
	if _, _, err := Compare([]report.Finding{input}, snapshotFor(t)); err == nil {
		t.Error("Compare(filtered finding) succeeded, want full input required")
	}
}

func TestCompareReturnedDataDoesNotAliasInputs(t *testing.T) {
	input := []report.Finding{dependencyFinding([]string{"CVE-2026-1"}, "a/lock.json")}
	snapshot := snapshotFor(t, input...)
	got, _, err := Compare(input, snapshotFor(t))
	if err != nil || len(got) != 1 {
		t.Fatalf("Compare(new finding) = %#v, %v, want one finding", got, err)
	}
	got[0].Package.Name = "changed"
	got[0].Advisories[0] = "changed"
	got[0].Locations[0].Path = "changed"
	got[0].Sources[0] = "changed"
	again, summary, err := Compare(input, snapshot)
	if err != nil || len(again) != 0 || summary.Unchanged != 1 {
		t.Errorf("Compare(after changing output) = %#v, %#v, %v, want unchanged input and snapshot", again, summary, err)
	}
}

func TestCompareSharedCodeKeepsLineage(t *testing.T) {
	for _, dimension := range []string{"origin", "image"} {
		t.Run(dimension, func(t *testing.T) {
			old := codeFinding()
			old.RuleID = "secscan.python.dynamic-code-execution"
			old.Language = "python"
			old.Sources = []string{"opengrep"}
			current := old
			if dimension == "origin" {
				old.Origin = "history"
			} else {
				old.Origin, current.Origin = "image", "image"
				old.ImageDigest = "sha256:" + strings.Repeat("a", 64)
				current.ImageDigest = "sha256:" + strings.Repeat("b", 64)
			}
			got, summary, err := Compare([]report.Finding{old, current}, snapshotFor(t, old))
			want := report.BaselineSummary{InputFindings: 2, OutputFragments: 1, New: 1, Unchanged: 1}
			if err != nil || summary != want || len(got) != 1 || got[0].Origin != current.Origin || got[0].ImageDigest != current.ImageDigest {
				t.Errorf("Compare(shared code with different %s) = %#v, %#v, %v, want current lineage new with %#v", dimension, got, summary, err, want)
			}
		})
	}
}

func TestCompareSharedCodeRetainsSeverityAliases(t *testing.T) {
	for _, severity := range []string{"info", "warning", "error"} {
		t.Run(severity, func(t *testing.T) {
			old := codeFinding()
			old.RuleID = "secscan.python.dynamic-code-execution"
			old.Language = "python"
			old.Sources = []string{"opengrep", "semgrep"}
			old.Severity = "unknown"
			left, right := old, old
			left.Sources = []string{"opengrep"}
			right.Sources = []string{"semgrep"}
			right.Severity = severity
			got, summary, err := Compare([]report.Finding{left, right}, snapshotFor(t, old))
			if err != nil || len(got) != 1 || summary.Expanded != 1 || got[0].Severity != severity {
				t.Errorf("Compare(shared code severity %s) = %#v, %#v, %v, want expanded with higher scanner severity", severity, got, summary, err)
			}
		})
	}
}

func TestCompareFragmentsPreservesSubtraction(t *testing.T) {
	full := dependencyFinding([]string{"CVE-A", "CVE-B"}, "a/lock.json", "b/lock.json")
	left, right := full, full
	left.Locations = []report.Location{{Path: "b/lock.json", Line: 1}}
	left.Path = "b/lock.json"
	right.Advisories = []string{"CVE-B"}
	right.Locations = []report.Location{{Path: "a/lock.json", Line: 1}}
	got, summary, err := CompareFragments([]report.Finding{left, right}, snapshotFor(t))
	if err != nil || len(got) != 2 || summary.InputFindings != 2 || summary.New != 2 {
		t.Fatalf("CompareFragments(subtracted rectangle) = %#v, %#v, %v, want two separate fragments", got, summary, err)
	}
	pairs := make(map[string]bool)
	for _, f := range got {
		if f.Fingerprint != full.Fingerprint {
			t.Error("CompareFragments() recomputed original fingerprint")
		}
		for _, id := range f.Advisories {
			for _, location := range f.Locations {
				pairs[id+"@"+location.Path] = true
			}
		}
	}
	want := map[string]bool{"CVE-A@b/lock.json": true, "CVE-B@b/lock.json": true, "CVE-B@a/lock.json": true}
	if !reflect.DeepEqual(pairs, want) {
		t.Errorf("CompareFragments() pairs = %#v, want %#v", pairs, want)
	}
}

func TestCompareFragmentsBoundary(t *testing.T) {
	input := []report.Finding{dependencyFinding([]string{"CVE-A"}, "a/lock.json")}
	before, _ := json.Marshal(input)
	got, _, err := CompareFragments(input, snapshotFor(t))
	if err != nil || len(got) != 1 {
		t.Fatalf("CompareFragments(valid) = %#v, %v, want one finding", got, err)
	}
	got[0].Package.Name, got[0].Sources[0], got[0].Advisories[0], got[0].Locations[0].Path = "mutated", "mutated", "mutated", "mutated"
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Error("CompareFragments() output aliases its input")
	}
	input[0].Fingerprint = "invalid"
	if _, _, err := CompareFragments(input, snapshotFor(t)); err == nil {
		t.Error("CompareFragments(invalid fingerprint) succeeded")
	}
	if _, _, err := CompareFragments(nil, Snapshot{}); err == nil {
		t.Error("CompareFragments(invalid snapshot) succeeded")
	}
}
