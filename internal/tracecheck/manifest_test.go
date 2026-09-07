// START_MODULE_CONTRACT
// PURPOSE: Verify strict documents and executable test references.
// SCOPE: Synthetic local files; no external services.
// DEPENDS: internal/tracecheck/tracecheck.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestLoadManifestRejectsAmbiguousJSON - Reject duplicate keys, case aliases and trailing JSON.
// TestTraceRejectsReadmeAsTest - Documentation cannot stand in for a test.
// TestRepositoryReadsRejectEscapesAndSpecialFiles - Keep input reads inside the repository.
// TestTraceValidatesGoTestAnchor - Reject absent Go test anchors.
// TestTraceRejectsIgnoredGoHelpers - Require Go test discovery names and signatures.
// END_MODULE_MAP

package tracecheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifestRejectsAmbiguousJSON(t *testing.T) {
	for _, data := range []string{`{"schemaVersion":"1"} {}`, `{"schemaVersion":"1","schemaVersion":"1"}`, `{"SchemaVersion":"1"}`, `{"schemaVERSION":"1"}`} {
		path := filepath.Join(t.TempDir(), "trace.json")
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadManifest(path); err == nil {
			t.Errorf("LoadManifest(%s) accepted ambiguous document", data)
		}
	}
}

func TestRepositoryReadsRejectEscapesAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.json")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../outside.json", outside, "link.json", "."} {
		if _, err := ReadRepositoryFile(root, path); err == nil {
			t.Errorf("ReadRepositoryFile(%q) accepted unsafe input", path)
		}
	}
}

func TestTraceValidatesGoTestAnchor(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "example_test.go"), []byte("package example\nimport \"testing\"\nfunc TestExample(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateReference(root, "example_test.go#TestExample", true); err != nil {
		t.Fatal(err)
	}
	if err := validateReference(root, "example_test.go#TestMissing", true); err == nil {
		t.Error("validateReference(missing anchor) accepted")
	}
}

func TestTraceRejectsIgnoredGoHelpers(t *testing.T) {
	for _, declaration := range []string{"func Testhelper() {}", "func TestHelper() {}", "func TestHelper(t *testing.B) {}", "func TestHelper(t *testing.T) bool { return true }", "func Example() {}"} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "helper_test.go"), []byte("package example\nimport \"testing\"\n"+declaration), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validateReference(root, "helper_test.go", true); err == nil {
			t.Errorf("validateReference(%q) accepted ignored or invalid test", declaration)
		}
	}
}

func TestTraceRejectsReadmeAsTest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("documentation"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := ScenarioRef{Requirement: "r", Scenario: "s"}
	m := Manifest{SchemaVersion: "1", TargetOutcome: "test.1", Traces: []Trace{{ScenarioRef: ref, Disposition: "target", Components: []string{"README.md"}, Tests: []string{"README.md"}}}}
	if err := ValidateTrace(root, m, []ScenarioRef{ref}, true); err == nil {
		t.Error("ValidateTrace(README.md as test) accepted documentation")
	}
}
