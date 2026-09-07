// START_MODULE_CONTRACT
// PURPOSE: Verify positive read evidence and disclosed input gaps.
// SCOPE: Repository inventory is distinct from successful code or dependency analysis.
// DEPENDS: cmd/secscan/coverage.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-honest-coverage
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestCoverageGapsSeparateAnalysisKinds - Prevent secret scans from claiming SAST or SCA coverage.
// TestCoverageRequiresPerInputEvidence - Retain unread inputs after a partial scan.
// TestSkippedScanIncludesInventory - Keep inventory when every selected scanner skips.
// TestAcceptanceGitleaksUsesSelectedInventory - Keep ignored files outside real scanner input.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func TestCoverageGapsSeparateAnalysisKinds(t *testing.T) {
	inventory := discovery.Inventory{Python: []string{"app.py"}, Sources: []discovery.SourceInput{{Path: "app.py", Language: "python"}, {Path: "app.rs", Language: "rust"}}, Dependencies: []string{"package-lock.json", "project.csproj"}}
	results := []report.Scanner{{Name: "gitleaks", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "repository"}}, {Name: "python-sast", Status: "failed"}, {Name: "trivy", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "packages", ReadInputs: []string{"package-lock.json"}}}}
	gaps := coverageGaps(inventory, []string{"gitleaks", "python-sast", "trivy"}, results)
	got := map[string]string{}
	for _, gap := range gaps {
		got[gap.Category+":"+gap.Path] = gap.Reason
	}
	if len(gaps) != 3 || got["code:app.py"] != "no_successful_analysis" || got["code:app.rs"] != "no_matching_scanner" || got["dependency:project.csproj"] != "no_matching_scanner" {
		t.Fatalf("analysis gaps=%+v", gaps)
	}
	results[1] = report.Scanner{Name: "python-sast", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "files", ReadInputs: []string{"app.py"}}}
	if got := coverageGaps(inventory, []string{"python-sast", "trivy"}, results); len(got) != 2 {
		t.Fatalf("positive read evidence ignored: %+v", got)
	}
	if got := coverageGaps(discovery.Inventory{Python: []string{"app.py"}, Sources: inventory.Sources[:1]}, []string{"gitleaks"}, results); len(got) != 1 || got[0].Reason != "scanner_not_selected" {
		t.Fatalf("secret scanner claimed code analysis: %+v", got)
	}
}

func TestCoverageRequiresPerInputEvidence(t *testing.T) {
	inventory := discovery.Inventory{Python: []string{"a.py", "b.py"}, Sources: []discovery.SourceInput{{Path: "a.py", Language: "python"}, {Path: "b.py", Language: "python"}}}
	result := report.Scanner{Name: "python-sast", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "files", ReadInputs: []string{"a.py"}, UnreadInputs: []string{"b.py"}}}
	got := coverageGaps(inventory, []string{"python-sast"}, []report.Scanner{result})
	if len(got) != 1 || got[0].Path != "b.py" {
		t.Fatalf("partial input coverage=%+v", got)
	}
}

func TestSkippedScanIncludesInventory(t *testing.T) {
	root := exportTestRepository(t)
	for name, content := range map[string]string{"app.rs": "fn main() {}", "README.md": "docs"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := scan(context.Background(), root, scanOptions{Scanners: []string{"python-sast"}}, func(progress.Event) {})
	if err != nil || result.Inventory == nil || result.Inventory.Untracked.Files != 2 || len(result.UncheckedInputs) != 1 {
		t.Fatalf("skipped inventory=%+v err=%v", result, err)
	}
}

func TestAcceptanceGitleaksUsesSelectedInventory(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for real Gitleaks boundary")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(filepath.Join(cache, "secscan"), "inventory-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err := exec.Command("git", "-C", root, "init", "--quiet").Run(); err != nil {
		t.Fatal(err)
	}
	canary := strings.Join([]string{"gl", "pat-", "0123456789", "AbCdEfGhIj"}, "")
	for _, dir := range []string{"visible", "ignored"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "canary.txt"), []byte("token="+canary+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("ignored/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("git", "-C", root, "add", ".gitignore").Run(); err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", "gitleaks", root}, &bytes.Buffer{}, &diagnostics, scan); code != 0 {
		t.Fatalf("prepare=%d %s", code, &diagnostics)
	}
	result, err := scan(context.Background(), root, scanOptions{Scanners: []string{"gitleaks"}}, func(progress.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if result.Inventory == nil || result.Inventory.Ignored.Files != 1 || result.Inventory.Tracked.Files != 1 || result.Inventory.Untracked.Files != 1 {
		t.Fatalf("inventory=%+v", result.Inventory)
	}
	if len(result.Findings) != 1 || result.Findings[0].Path != "visible/canary.txt" {
		t.Fatalf("ignored secret was scanned or selected secret missing: %+v", result.Findings)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(canary)) {
		t.Fatal("raw secret escaped into report")
	}
}
