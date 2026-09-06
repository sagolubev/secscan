package report

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func TestMarshalSortsFindings(t *testing.T) {
	input := Report{
		SchemaVersion: "1",
		Repository:    "/repo",
		Findings: []Finding{
			{Fingerprint: "b", Path: "z.go", Line: 2},
			{Fingerprint: "a", Path: "a.go", Line: 1},
		},
	}

	first, err := Marshal(input)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	second, err := Marshal(input)
	if err != nil {
		t.Fatalf("Marshal() second error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Marshal() is not deterministic")
	}
	if bytes.Index(first, []byte(`"fingerprint":"a"`)) > bytes.Index(first, []byte(`"fingerprint":"b"`)) {
		t.Fatalf("Marshal() findings are not sorted: %s", first)
	}
}

func TestMarshalUsesEmptyArrays(t *testing.T) {
	got, err := Marshal(Report{SchemaVersion: "1", Repository: "/repo"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if bytes.Contains(got, []byte(`"scanners":null`)) || bytes.Contains(got, []byte(`"findings":null`)) {
		t.Fatalf("Marshal() emitted null collection: %s", got)
	}
}

func TestMarshalSortsScanners(t *testing.T) {
	input := Report{
		SchemaVersion: "1",
		Scanners: []Scanner{
			{Name: "typescript-sast"},
			{Name: "gitleaks"},
			{Name: "python-sast"},
		},
	}
	got, err := Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Index(got, []byte(`"name":"gitleaks"`)) >
		bytes.Index(got, []byte(`"name":"python-sast"`)) ||
		bytes.Index(got, []byte(`"name":"python-sast"`)) >
			bytes.Index(got, []byte(`"name":"typescript-sast"`)) {
		t.Fatalf("Marshal() scanners are not sorted: %s", got)
	}
}

func TestDependencyAliasMergeTransitiveAndStable(t *testing.T) {
	input := []Finding{
		{Kind: "dependency", Package: &Package{Ecosystem: "npm", Name: "lodash", Version: "1"}, Advisories: []string{"CVE-2026-1"}, Sources: []string{"trivy"}, Locations: []Location{{Path: "a/package-lock.json", Line: 1}}},
		{Kind: "dependency", Package: &Package{Ecosystem: "npm", Name: "lodash", Version: "1", PURL: "pkg:npm/lodash@1"}, Advisories: []string{"GHSA-aaaa-bbbb-cccc"}, Sources: []string{"grype"}, Locations: []Location{{Path: "b/package-lock.json", Line: 1}}},
		{Kind: "dependency", Package: &Package{Ecosystem: "npm", Name: "lodash", Version: "1"}, Advisories: []string{"CVE-2026-1", "GHSA-aaaa-bbbb-cccc"}, Sources: []string{"osv-scanner"}, Locations: []Location{{Path: "a/package-lock.json", Line: 1}}},
		{Kind: "dependency", Package: &Package{Ecosystem: "npm", Name: "lodash", Version: "2"}, Advisories: []string{"CVE-2026-1"}, Sources: []string{"trivy"}, Locations: []Location{{Path: "c/package-lock.json", Line: 1}}},
	}
	first, err := Marshal(Report{Findings: input})
	if err != nil {
		t.Fatal(err)
	}
	var result Report
	if err := json.Unmarshal(first, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("merged findings=%#v, want two package versions", result.Findings)
	}
	for _, f := range result.Findings {
		if f.Package.Version == "1" && (len(f.Sources) != 3 || len(f.Advisories) != 2 || len(f.Locations) != 2 || f.Package.PURL != "pkg:npm/lodash@1") {
			t.Errorf("merged finding=%#v", f)
		}
	}
	slices.Reverse(input)
	second, err := Marshal(Report{Findings: input})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("merge is order dependent: %s\n%s", first, second)
	}
	if len(input[1].Sources) != 1 {
		t.Fatal("Marshal mutated input")
	}
}
