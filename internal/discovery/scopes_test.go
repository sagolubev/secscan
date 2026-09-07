// START_MODULE_CONTRACT
// PURPOSE: Verify exact, safe scope selection without losing traversal evidence.
// SCOPE: Real filesystem and Git fixtures; candidate counts are not scanner reads.
// DEPENDS: internal/discovery/scopes.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-scoped-scans
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestSelectScopesFiltersEveryCandidate - All scanner candidates follow the selected files.
// TestSelectScopesUnionsAndNormalizes - File, directory and root scopes form a unique union.
// TestSelectScopesRejectsUnsafeOrIneligible - Invalid inputs never produce a clean empty result.
// TestSelectScopesLimit - Argument limits apply before deduplication.
// TestSelectScopesNoScopes - The existing unscoped inventory is returned unchanged.
// END_MODULE_MAP

package discovery

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"testing"

	"github.com/sagolubev/secscan/internal/report"
)

func TestSelectScopesFiltersEveryCandidate(t *testing.T) {
	root := newGitRepository(t)
	for _, directory := range []string{"selected", "other"} {
		for _, name := range []string{"Dockerfile", "action.yaml", "app.py", "app.ts", "azure-pipelines.yml", "build.gradle", "code.cpp", "main.tf", "package-lock.json", "versions.properties"} {
			writeFile(t, root, directory+"/"+name, "synthetic")
		}
	}
	writeFile(t, root, ".gitignore", "cache/\n")
	writeFile(t, root, "cache/ignored.py", "ignored")
	writeFile(t, root, "control.json", "control")
	runGit(t, root, "add", "selected/app.py")
	full, err := Discover(root, "control.json")
	if err != nil {
		t.Fatal(err)
	}
	want := Inventory{
		Files:        []string{"selected/Dockerfile", "selected/action.yaml", "selected/app.py", "selected/app.ts", "selected/azure-pipelines.yml", "selected/build.gradle", "selected/code.cpp", "selected/main.tf", "selected/package-lock.json", "selected/versions.properties"},
		Sources:      []SourceInput{{Path: "selected/app.py", Language: "python"}, {Path: "selected/app.ts", Language: "typescript"}, {Path: "selected/build.gradle", Language: "groovy"}, {Path: "selected/code.cpp", Language: "c-cpp"}},
		Native:       []string{"selected/build.gradle", "selected/versions.properties"},
		OCI:          []string{"selected/Dockerfile", "selected/action.yaml", "selected/azure-pipelines.yml"},
		Dependencies: []string{"selected/build.gradle", "selected/package-lock.json"},
		Terraform:    []string{"selected/main.tf"},
		Checkov:      []string{"selected/Dockerfile", "selected/action.yaml", "selected/azure-pipelines.yml", "selected/package-lock.json"},
		KICS:         []string{"selected/Dockerfile", "selected/action.yaml", "selected/azure-pipelines.yml", "selected/main.tf", "selected/package-lock.json"},
		Python:       []string{"selected/app.py"},
		TypeScript:   []string{"selected/app.ts"},
		Bearer:       []string{"selected/app.py", "selected/app.ts"},
		Cppcheck:     []string{"selected/code.cpp"},
		CI:           []string{"selected/action.yaml", "selected/azure-pipelines.yml"},
		Zizmor:       []string{"selected/action.yaml"},
		Poutine:      []string{"selected/action.yaml", "selected/azure-pipelines.yml"},
		Traversal:    full.Traversal,
		Ignored:      full.Ignored,
	}
	scopes := []string{"selected"}
	got, paths, err := SelectScopes(root, full, scopes)
	if err != nil {
		t.Fatalf("SelectScopes(%q) error = %v", scopes, err)
	}
	if !reflect.DeepEqual(got, want) || !slices.Equal(paths, []string{"selected"}) {
		t.Fatalf("SelectScopes(%q) = %+v, %q; want %+v, [selected]", scopes, got, paths, want)
	}
	// Mutating any returned candidate or traversal slice must not corrupt full.
	fields := reflect.ValueOf(&got).Elem()
	for i := 0; i < fields.NumField(); i++ {
		field := fields.Field(i)
		if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String && field.Len() > 0 {
			field.Index(0).SetString("changed")
		}
	}
	got.Sources[0].Path = "changed"
	got.Traversal.Tracked.Directories[0].Path = "changed"
	got.Traversal.Untracked.Directories[0].Path = "changed"
	got.Traversal.Ignored.Directories[0].Path = "changed"
	got.Traversal.Omitted[0].Path = "changed"
	got.Traversal.Unclassified[0] = "changed"
	paths[0] = "changed"
	again, err := Discover(root, "control.json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(full, again) || !slices.Equal(scopes, []string{"selected"}) {
		t.Fatalf("SelectScopes mutated inputs: full=%+v, scopes=%q", full, scopes)
	}
}

func TestSelectScopesUnionsAndNormalizes(t *testing.T) {
	root := newGitRepository(t)
	for _, name := range []string{"left/app.py", "left/nested/view.ts", "leftover/other.py", "right/app.py"} {
		writeFile(t, root, name, "synthetic")
	}
	runGit(t, root, "add", "left/app.py")
	full, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		scopes []string
		paths  []string
		files  []string
	}{
		{"file", []string{"left/app.py"}, []string{"left/app.py"}, []string{"left/app.py"}},
		{"directory", []string{"left"}, []string{"left"}, []string{"left/app.py", "left/nested/view.ts"}},
		{"overlap", []string{"right/app.py", "./left/", "left/app.py", "left", "././left"}, []string{"left", "left/app.py", "right/app.py"}, []string{"left/app.py", "left/nested/view.ts", "right/app.py"}},
		{"root", []string{".", "left"}, []string{".", "left"}, []string{"left/app.py", "left/nested/view.ts", "leftover/other.py", "right/app.py"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, paths, err := SelectScopes(root, full, test.scopes)
			if err != nil || !slices.Equal(paths, test.paths) || !slices.Equal(got.Files, test.files) {
				t.Fatalf("SelectScopes(%q) files=%q paths=%q err=%v; want files=%q paths=%q", test.scopes, got.Files, paths, err, test.files, test.paths)
			}
		})
	}
}

func TestSelectScopesRejectsUnsafeOrIneligible(t *testing.T) {
	root := newGitRepository(t)
	writeFile(t, root, "left/app.py", "synthetic")
	writeFile(t, root, "left\\app.py", "synthetic")
	writeFile(t, root, "ignored/app.py", "ignored")
	writeFile(t, root, "controls/config.json", "control")
	writeFile(t, root, "deleted.py", "deleted")
	writeFile(t, root, ".gitignore", "ignored/\n")
	runGit(t, root, "add", "deleted.py")
	if err := os.Remove(filepath.Join(root, "deleted.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "left"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "left/app.py"), filepath.Join(root, "link.py")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	full, err := Discover(root, "controls/config.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", filepath.Join(root, "left/app.py"), "..", "left/../left/app.py", "left\\app.py", "missing", "deleted.py", "empty", "ignored", "ignored/app.py", "controls", "controls/config.json", "link", "link.py", "link/app.py", "pipe", "LEFT", "left/APP.py"} {
		t.Run(scope, func(t *testing.T) {
			if got, paths, err := SelectScopes(root, full, []string{scope}); err == nil {
				t.Fatalf("SelectScopes(%q) = %+v, %q, nil; want rejection", scope, got, paths)
			}
		})
	}
	if _, _, err := SelectScopes(root, full, []string{"left", "empty"}); err == nil {
		t.Fatal("SelectScopes([left empty]) error = nil, want every scope validated")
	}
	if _, _, err := SelectScopes(root, Inventory{}, []string{"."}); err == nil {
		t.Fatal("SelectScopes([.]) with no eligible files error = nil, want rejection")
	}
	if _, _, err := SelectScopes(root, Inventory{Python: []string{"left/app.py"}}, []string{"left/app.py"}); err == nil {
		t.Fatal("SelectScopes([left/app.py]) with only a scanner candidate error = nil, want full.Files authority")
	}
}

func TestSelectScopesLimit(t *testing.T) {
	root := newGitRepository(t)
	writeFile(t, root, "app.py", "synthetic")
	full, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	scopes := make([]string, 16)
	for i := range scopes {
		scopes[i] = "app.py"
	}
	got, paths, err := SelectScopes(root, full, scopes)
	if err != nil || !slices.Equal(got.Files, []string{"app.py"}) || !slices.Equal(paths, []string{"app.py"}) {
		t.Fatalf("SelectScopes(16 duplicate scopes) files=%q paths=%q err=%v; want one file and path", got.Files, paths, err)
	}
	if _, _, err := SelectScopes(root, full, append(scopes, "app.py")); err == nil {
		t.Fatal("SelectScopes(17 duplicate scopes) error = nil, want rejection")
	}
}

func TestSelectScopesNoScopes(t *testing.T) {
	full := Inventory{Files: []string{"app.py"}, Python: []string{"app.py"}, Traversal: report.Inventory{Tracked: report.FileInventory{Files: 1}}}
	got, paths, err := SelectScopes("nonexistent root", full, nil)
	if err != nil || paths != nil || !reflect.DeepEqual(got, full) {
		t.Fatalf("SelectScopes(nil) = %+v, %q, %v; want unchanged inventory and nil paths", got, paths, err)
	}
}
