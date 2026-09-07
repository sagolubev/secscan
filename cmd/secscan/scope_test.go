// START_MODULE_CONTRACT
// PURPOSE: Verify scoped CLI execution and honest whole-repository fallbacks.
// SCOPE: Synthetic Git fixtures; selected source and complete metadata remain distinct.
// DEPENDS: cmd/secscan/scope.go, internal/discovery/scopes.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-scoped-scans
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestScopeKeepsWholeScannerResults - Preserve outside findings from context-dependent scanners.
// TestScopeArgumentConflicts - Reject unsupported combinations before scanning.
// TestScopeAvoidsUnneededRuntime - Skip a narrowed scanner with no selected matching input.
// TestScopedWholeScannerCoverageRoutes - Preserve positive outside-scope read evidence.
// TestAcceptanceScopedScan - Prove real selected Python analysis and a whole-repository fallback.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func TestScopeKeepsWholeScannerResults(t *testing.T) {
	root := exportTestRepository(t)
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src/notes.txt"), []byte("source note"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "versions.properties"), []byte("version.synthetic=1.0\n## # available=2.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--scope", "src", "--scanners", "refresh-versions", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("scoped native scan exit=%d stderr=%s", code, &stderr)
	}
	var result struct {
		Findings []report.Finding
		Scope    struct {
			Paths         []string
			SelectedFiles int
		}
		Scanners []struct {
			Name  string
			Scope struct {
				Mode           string
				CandidateFiles int
			}
		}
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 || result.Findings[0].Path != "versions.properties" || result.Scope.SelectedFiles != 1 || len(result.Scope.Paths) != 1 || result.Scope.Paths[0] != "src" {
		t.Fatalf("whole fallback=%s", &stdout)
	}
	if len(result.Scanners) != 1 || result.Scanners[0].Scope.Mode != "repository" || result.Scanners[0].Scope.CandidateFiles != 1 {
		t.Fatalf("scope evidence=%s", &stdout)
	}
}

func TestScopeArgumentConflicts(t *testing.T) {
	root := exportTestRepository(t)
	cases := [][]string{{"--scope", "", root}, {"--scope", "src", "--baseline", "missing.json", root}, {"--scope", "src", "--write-baseline", "new.json", root}, {"update", "--scope", "src", root}}
	var excessive []string
	for i := 0; i < 17; i++ {
		excessive = append(excessive, "--scope", "src")
	}
	cases = append(cases, append(excessive, root))
	for _, args := range cases {
		fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
			t.Fatal("invalid scoped request started scan")
			return report.Report{}, nil
		}
		if code := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}, fake); code != 2 {
			t.Errorf("scope args=%v exit=%d, want2", args, code)
		}
	}
}

func TestScopeAvoidsUnneededRuntime(t *testing.T) {
	root := exportTestRepository(t)
	for path, data := range map[string]string{"notes.txt": "note", "other.py": "print('outside')\n"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(git, filepath.Join(bin, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--scope", "notes.txt", "--scanners", "python-sast", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("empty scoped scanner required runtime: exit=%d stderr=%s", code, &stderr)
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || len(result.Scanners) != 1 || result.Scanners[0].Status != "skipped" || len(result.UncheckedInputs) != 0 {
		t.Fatalf("scoped skipped=%s error=%v", &stdout, err)
	}
}

func TestScopedWholeScannerCoverageRoutes(t *testing.T) {
	for _, tc := range []struct{ name, path string }{{"bearer", "outside/app.py"}, {"cppcheck", "outside/app.cpp"}, {"gradle-catalog", "outside/libs.versions.toml"}} {
		t.Run(tc.name, func(t *testing.T) {
			root := exportTestRepository(t)
			for _, dir := range []string{"src", "outside"} {
				if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range []string{"src/app.py", tc.path} {
				if err := os.WriteFile(filepath.Join(root, path), []byte("synthetic fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			full, err := discovery.Discover(root)
			if err != nil {
				t.Fatal(err)
			}
			selected, _, err := discovery.SelectScopes(root, full, []string{"src"})
			if err != nil {
				t.Fatal(err)
			}
			selection := []string{"python-sast", tc.name}
			results := []report.Scanner{{Name: "python-sast", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "files", ReadInputs: []string{"src/app.py"}}}, {Name: tc.name, Status: "success", Coverage: report.Coverage{Read: 1, Unit: "files", ReadInputs: []string{tc.path}}}}
			gaps := coverageGaps(scopedCoverageInventory(full, selected, selection), selection, results)
			if len(gaps) != 0 {
				t.Fatalf("confirmed whole-scanner reads marked unchecked: %+v", gaps)
			}
		})
	}
}

func TestAcceptanceScopedScan(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for real scoped analysis")
	}
	root := exportTestRepository(t)
	for _, dir := range []string{"src", "other"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "app.py"), []byte("eval(user_input)\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "versions.properties"), []byte("version.synthetic=1.0\n## # available=2.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	selection := "python-sast,refresh-versions"
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", selection, root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("prepare exit=%d stderr=%s", code, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--scope", "src", "--scanners", selection, root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("scoped scan exit=%d stderr=%s", code, &stderr)
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, finding := range result.Findings {
		paths[finding.Path] = true
	}
	if !paths["src/app.py"] || !paths["versions.properties"] || paths["other/app.py"] || len(result.UncheckedInputs) != 0 {
		t.Fatalf("scoped native findings=%s", &stdout)
	}
	for _, scanner := range result.Scanners {
		if scanner.Name == "python-sast" && (scanner.Coverage.Read != 1 || len(scanner.Coverage.ReadInputs) != 1 || scanner.Coverage.ReadInputs[0] != "src/app.py") {
			t.Fatalf("wrong scoped read evidence=%+v", scanner)
		}
	}
}
