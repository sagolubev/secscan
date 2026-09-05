package gitleaks

import (
	"bytes"
	"testing"
)

func TestParseRedactsSecretMaterial(t *testing.T) {
	const canary = "CANARY_SECRET_VALUE_123456"
	input := []byte(`[{
		"Description":"Generic API Key",
		"StartLine":7,
		"File":"config.txt",
		"Secret":"` + canary + `",
		"Match":"token=` + canary + `",
		"RuleID":"generic-api-key"
	}]`)

	findings, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Parse() returned %d findings, want 1", len(findings))
	}
	encoded := []byte(findings[0].Fingerprint + findings[0].Message)
	if bytes.Contains(encoded, []byte(canary)) {
		t.Fatal("Parse() retained secret material")
	}
	if findings[0].Origin != "working_tree" {
		t.Errorf("Parse() origin = %q, want working_tree", findings[0].Origin)
	}
}

func TestParseRejectsPathOutsideRepository(t *testing.T) {
	input := []byte(`[{
		"StartLine":1,
		"File":"../../outside",
		"RuleID":"generic-api-key"
	}]`)

	if _, err := Parse(input); err == nil {
		t.Fatal("Parse() error = nil, want path traversal error")
	}
}

func TestParseNormalizesContainerRepositoryPath(t *testing.T) {
	input := []byte(`[{
		"StartLine":1,
		"File":"/repo/config/app.env",
		"RuleID":"generic-api-key"
	}]`)

	got, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got[0].Path != "config/app.env" {
		t.Errorf("Parse() path = %q, want repository-relative path", got[0].Path)
	}
}
