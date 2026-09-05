package report

import (
	"bytes"
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
