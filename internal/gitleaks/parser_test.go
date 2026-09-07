// START_MODULE_CONTRACT
// PURPOSE: Verify redacted working-tree and history finding identities.
// SCOPE: Synthetic metadata only; reject unsafe paths, rules, lines and commits.
// DEPENDS: internal/gitleaks/parser.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestParseRedactsSecretMaterial - Keep synthetic secret text outside canonical findings.
// TestParseHistorySeparatesProvenanceAndRedacts - Preserve old fingerprints and distinguish commit provenance.
// TestParseHistoryRejectsInvalidMetadata - Reject malformed and unknown history identities.
// TestParseRejectsPathOutsideRepository - Reject working-tree traversal.
// TestParseNormalizesContainerRepositoryPath - Normalize known repository mount paths.
// END_MODULE_MAP

package gitleaks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
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

func TestParseHistorySeparatesProvenanceAndRedacts(t *testing.T) {
	commit := strings.Repeat("a", 40)
	data := []byte(`[{"File":"config.txt","StartLine":7,"RuleID":"generic-api-key","Commit":"` + commit + `","Secret":"SYNTHETIC_SECRET","Match":"SYNTHETIC_SNIPPET","Message":"SYNTHETIC_MESSAGE","Author":"SYNTHETIC_AUTHOR"}]`)
	history, err := parseHistory(data, map[string]struct{}{commit: {}})
	if err != nil || len(history) != 1 {
		t.Fatalf("parseHistory() = %v, %v; want one finding", history, err)
	}
	working, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	old := sha256.Sum256([]byte("generic-api-key\x00config.txt\x007"))
	if working[0].Fingerprint != hex.EncodeToString(old[:]) || working[0].Commit != "" {
		t.Fatalf("Parse() changed working-tree identity: %+v", working[0])
	}
	if history[0].Fingerprint == working[0].Fingerprint || history[0].Origin != "git_history" || history[0].Commit != commit {
		t.Errorf("parseHistory() provenance = %+v", history[0])
	}
	encoded, err := json.Marshal(history)
	if err != nil || bytes.Contains(encoded, []byte("SYNTHETIC_")) {
		t.Errorf("parseHistory() retained raw content or failed marshal: %v", err)
	}
}

func TestParseHistoryRejectsInvalidMetadata(t *testing.T) {
	commit := strings.Repeat("a", 40)
	for _, test := range []struct {
		name, key string
		value     any
	}{
		{"short commit", "Commit", "a123"}, {"uppercase commit", "Commit", strings.Repeat("A", 40)},
		{"unknown commit", "Commit", strings.Repeat("b", 40)}, {"missing commit", "Commit", ""},
		{"traversal", "File", "../secret"}, {"unclean path", "File", "a/../secret"},
		{"absolute", "File", "/etc/passwd"}, {"windows absolute", "File", "C:/secret"},
		{"control path", "File", "a\x00b"}, {"negative line", "StartLine", -1}, {"zero line", "StartLine", 0},
		{"empty rule", "RuleID", ""}, {"control rule", "RuleID", "a\nb"}, {"long rule", "RuleID", strings.Repeat("a", 257)},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := map[string]any{"File": "config.txt", "StartLine": 1, "RuleID": "generic-api-key", "Commit": commit}
			item[test.key] = test.value
			data, err := json.Marshal([]any{item})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseHistory(data, map[string]struct{}{commit: {}}); err == nil {
				t.Errorf("parseHistory(%s) succeeded, want invalid metadata error", test.name)
			}
		})
	}
	for _, data := range []string{"null", "{}", "", "[null]"} {
		if _, err := parseHistory([]byte(data), nil); err == nil {
			t.Errorf("parseHistory(%q) succeeded, want array/metadata error", data)
		}
	}
	commit = strings.Repeat("c", 64)
	data := []byte(`[{"File":"config.txt","StartLine":1,"RuleID":"gitlab-pat","Commit":"` + commit + `"}]`)
	if _, err := parseHistory(data, map[string]struct{}{commit: {}}); err != nil {
		t.Errorf("parseHistory(SHA256) = %v", err)
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
