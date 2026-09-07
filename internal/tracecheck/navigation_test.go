// START_MODULE_CONTRACT
// PURPOSE: Exercise source navigation validation against real Git fixtures.
// SCOPE: Reject stale metadata and unsafe references without decorating untouched legacy files.
// DEPENDS: internal/tracecheck/navigation.go, internal/tracecheck/git_test.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-source-navigation-comments
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestNavigationRejectsInvalidMetadata - Check malformed contracts, maps and references.
// TestNavigationSelectiveRollout - Require metadata only for changed or already marked files.
// TestNavigationRenameAndDeletion - Check renamed sources and reject links to deleted files.
// TestNavigationRejectsUnsafeFiles - Keep source and reference reads inside the repository.
// END_MODULE_MAP

package tracecheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func navigationSource() string {
	return `// START_MODULE_CONTRACT
// PURPOSE: Provide fixture declarations for source navigation.
// SCOPE: Expose symbols without executing repository code.
// DEPENDS: none
// LINKS: spec.md#requirement-navigation, internal/example/source_test.go#TestExample
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Example - Hold fixture state.
// Example.Seal - Seal fixture state.
// Run - Execute the fixture operation.
// Limit - Bound fixture state.
// Current - Hold the current fixture value.
// END_MODULE_MAP

package example

type Example[T any] struct{}
func (*Example[T]) Seal() {}
func Run() {}
const Limit = 1
var Current = 1
func hidden() {}
`
}

func navigationFixture(t *testing.T, source string) (string, string) {
	t.Helper()
	return gitFixture(t, map[string]string{
		"internal/example/source.go":      source,
		"internal/example/source_test.go": "package example\nfunc TestExample() {}\n",
		"spec.md":                         "### Requirement: Navigation\n```\n### Fake heading\n```\n",
	})
}

func TestNavigationRejectsInvalidMetadata(t *testing.T) {
	for _, test := range []struct{ name, old, replacement string }{
		{"missing map", "// START_MODULE_MAP", "// Removed map"},
		{"missing contract", "// START_MODULE_CONTRACT", "// Removed contract"},
		{"duplicate marker", "// START_MODULE_MAP", "// START_MODULE_MAP\n// START_MODULE_MAP"},
		{"marker suffix", "// END_MODULE_MAP", "// END_MODULE_MAP extra"},
		{"unknown symbol", "// Run -", "// Missing -"},
		{"missing function export", "// Run - Execute the fixture operation.\n", ""},
		{"missing method export", "// Example.Seal - Seal fixture state.\n", ""},
		{"missing type export", "// Example - Hold fixture state.\n", ""},
		{"missing constant export", "// Limit - Bound fixture state.\n", ""},
		{"missing variable export", "// Current - Hold the current fixture value.\n", ""},
		{"duplicate symbol", "// Run -", "// Run - Repeated entry.\n// Run -"},
		{"missing meaning", "// Run - Execute the fixture operation.", "// Run - "},
		{"empty purpose", "PURPOSE: Provide fixture declarations for source navigation.", "PURPOSE:"},
		{"placeholder scope", "SCOPE: Expose symbols without executing repository code.", "SCOPE: TODO"},
		{"missing role", "// ROLE: RUNTIME\n", ""},
		{"bad pair", "MAP_MODE: EXPORTS", "MAP_MODE: LOCALS"},
		{"wrong test role", "ROLE: RUNTIME", "ROLE: TEST"},
		{"duplicate field", "// ROLE: RUNTIME", "// ROLE: RUNTIME\n// ROLE: RUNTIME"},
		{"duplicate empty field", "// ROLE: RUNTIME", "// ROLE:\n// ROLE: RUNTIME"},
		{"missing dependency", "DEPENDS: none", "DEPENDS: missing.go"},
		{"mixed none dependency", "DEPENDS: none", "DEPENDS: none, spec.md"},
		{"missing link", "spec.md#requirement-navigation", "missing.md"},
		{"missing Go anchor", "source_test.go#TestExample", "source_test.go#TestMissing"},
		{"missing heading", "spec.md#requirement-navigation", "spec.md#missing"},
		{"code fence heading", "spec.md#requirement-navigation", "spec.md#fake-heading"},
		{"escaping link", "spec.md#requirement-navigation", "../outside.md"},
		{"empty links", "LINKS: spec.md#requirement-navigation, internal/example/source_test.go#TestExample", "LINKS:"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, _ := navigationFixture(t, strings.Replace(navigationSource(), test.old, test.replacement, 1))
			if err := ValidateNavigation(root, nil); err == nil {
				t.Errorf("ValidateNavigation(%q) accepted invalid metadata", test.name)
			}
		})
	}
}

func TestNavigationSelectiveRollout(t *testing.T) {
	root, baseline := navigationFixture(t, navigationSource()+"\nvar marker = `// START_MODULE_MAP\n// END_CONTRACT: Fake`\n")
	if err := ValidateNavigation(root, nil); err != nil {
		t.Fatalf("ValidateNavigation(valid marked source and untouched legacy test) = %v", err)
	}
	writeGitFile(t, root, "internal/example/source_test.go", "package example\nfunc TestExample() {}\nfunc TestNew() {}\n")
	changes, err := Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNavigation(root, changes); err == nil {
		t.Fatal("ValidateNavigation(changed legacy test) accepted missing metadata")
	}
	testSource := strings.NewReplacer("RUNTIME", "TEST", "EXPORTS", "LOCALS", "// Example - Hold fixture state.", "// TestExample - Exercise fixture behavior.").Replace(navigationSource())
	testSource = strings.Replace(testSource, "func hidden() {}", "func hidden() {}\nfunc TestExample() {}", 1)
	writeGitFile(t, root, "internal/example/source_test.go", testSource)
	if err := ValidateNavigation(root, changes); err != nil {
		t.Fatalf("ValidateNavigation(selective TEST map) = %v", err)
	}
	writeGitFile(t, root, "cmd/new/main.go", "package main\nfunc main() {}\n")
	changes, err = Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNavigation(root, changes); err == nil {
		t.Fatal("ValidateNavigation(new source) accepted missing metadata")
	}
}

func TestNavigationContractsAndBlocks(t *testing.T) {
	contract := "// START_CONTRACT: Run\n// LINKS: internal/example/source.go#Example.Seal\n// END_CONTRACT: Run\n"
	block := "// START_BLOCK_OUTER\n// START_BLOCK_INNER\n// END_BLOCK_INNER\n// END_BLOCK_OUTER\n"
	for _, test := range []struct {
		name, comments string
		wantErr        bool
	}{
		{"valid", contract + block, false},
		{"contract mismatch", strings.Replace(contract, "END_CONTRACT: Run", "END_CONTRACT: Other", 1), true},
		{"unknown contract", strings.ReplaceAll(contract, ": Run", ": Missing"), true},
		{"contract link", strings.Replace(contract, "#Example.Seal", "#Example.Missing", 1), true},
		{"crossed blocks", strings.ReplaceAll(block, "END_BLOCK_INNER\n// END_BLOCK_OUTER", "END_BLOCK_OUTER\n// END_BLOCK_INNER"), true},
		{"open block", "// START_BLOCK_OUTER\n", true},
		{"unopened block", "// END_BLOCK_OUTER\n", true},
		{"duplicate block", block + block, true},
		{"malformed block", "// START_BLOCK_OUTER extra\n// END_BLOCK_OUTER extra\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, _ := navigationFixture(t, navigationSource()+"\n"+test.comments)
			if err := ValidateNavigation(root, nil); (err != nil) != test.wantErr {
				t.Errorf("ValidateNavigation(%s) = %v, want error %t", test.name, err, test.wantErr)
			}
		})
	}
}

func TestNavigationRenameAndDeletion(t *testing.T) {
	root, baseline := navigationFixture(t, navigationSource())
	fixtureGit(t, root, "mv", "internal/example/source.go", "internal/example/renamed.go")
	changes, err := Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNavigation(root, changes); err != nil {
		t.Fatalf("ValidateNavigation(rename) = %v", err)
	}
	if err := os.Remove(filepath.Join(root, "internal/example/source_test.go")); err != nil {
		t.Fatal(err)
	}
	changes, err = Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNavigation(root, changes); err == nil {
		t.Fatal("ValidateNavigation(link to deleted source) accepted a dangling link")
	}
	if err := os.Remove(filepath.Join(root, "internal/example/renamed.go")); err != nil {
		t.Fatal(err)
	}
	changes, err = Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNavigation(root, changes); err != nil {
		t.Fatalf("ValidateNavigation(deleted files) = %v", err)
	}
}

func TestNavigationRejectsUnsafeFiles(t *testing.T) {
	for _, test := range []string{"source symlink", "link symlink", "oversized source"} {
		t.Run(test, func(t *testing.T) {
			root, _ := navigationFixture(t, navigationSource())
			path := filepath.Join(root, "internal/example/source.go")
			if test == "oversized source" {
				writeGitFile(t, root, "internal/example/source.go", strings.Repeat(" ", (4<<20)+1))
			} else {
				if test == "link symlink" {
					path = filepath.Join(root, "spec.md")
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte(navigationSource()), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			}
			if err := ValidateNavigation(root, nil); err == nil {
				t.Errorf("ValidateNavigation(%s) accepted unsafe input", test)
			}
		})
	}
}

func TestNavigationReportsEachInvalidFile(t *testing.T) {
	root, _ := gitFixture(t, map[string]string{
		"cmd/first/main.go":  "// START_MODULE_MAP\npackage main\n",
		"cmd/second/main.go": "// START_MODULE_MAP\npackage main\n",
	})
	err := ValidateNavigation(root, nil)
	if err == nil || !strings.Contains(err.Error(), "cmd/first/main.go") || !strings.Contains(err.Error(), "cmd/second/main.go") {
		t.Errorf("ValidateNavigation(two invalid files) = %v, want both file paths", err)
	}
}
