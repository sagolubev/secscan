// START_MODULE_CONTRACT
// PURPOSE: Verify explicit history selection and commit-aware scan reports.
// SCOPE: Synthetic Git repositories; real containers are opt-in.
// DEPENDS: cmd/secscan/main.go, internal/gitleaks/history.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestHistorySelectionIsExplicit - Preserve defaults while allowing both secret sources.
// TestHistoryRejectsFileScope - Reject unsupported narrowing of historical data.
// TestHistoryRuntimeFailurePreservesNativeSibling - Keep independent native analysis when containers are unavailable.
// TestAcceptanceHistoryCLI - Preserve removed findings, commit provenance and successful siblings.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/report"
)

func TestHistorySelectionIsExplicit(t *testing.T) {
	all, err := parseScannerSelection("all")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(all, "gitleaks-history") {
		t.Fatal("history enabled by default")
	}
	selected, err := parseScannerSelection("gitleaks,gitleaks-history")
	if err != nil || !slices.Equal(selected, []string{"gitleaks", "gitleaks-history"}) {
		t.Fatalf("explicit history=%v error=%v", selected, err)
	}
}

func TestHistoryRejectsFileScope(t *testing.T) {
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"--scanners", "gitleaks-history", "--scope", "src"}, &out, &errout, nil); code != 2 || out.Len() != 0 {
		t.Fatalf("scoped history=%d output=%s", code, &out)
	}
}

func TestHistoryRuntimeFailurePreservesNativeSibling(t *testing.T) {
	root := exportTestRepository(t)
	if err := os.WriteFile(filepath.Join(root, "versions.properties"), []byte("version.synthetic=1\n"), 0o600); err != nil {
		t.Fatal(err)
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
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"--scanners", "gitleaks-history,refresh-versions", root}, &out, &errout, scan); code != 0 {
		t.Fatalf("native sibling lost on runtime failure: exit=%d stderr=%s", code, &errout)
	}
	var result report.Report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Scanners) != 2 {
		t.Fatalf("scanner outcomes=%+v", result.Scanners)
	}
	for _, s := range result.Scanners {
		if s.Name == "gitleaks-history" && (s.Status != "failed" || s.Coverage.Read != 0) || s.Name == "refresh-versions" && s.Status != "success" {
			t.Fatalf("runtime failure outcomes=%+v", result.Scanners)
		}
	}
	out.Reset()
	errout.Reset()
	if code := run(context.Background(), []string{"--scanners", "gitleaks-history", root}, &out, &errout, scan); code != 1 || out.Len() != 0 {
		t.Fatalf("runtime-only failure exit=%d output=%s", code, &out)
	}
}

func TestAcceptanceHistoryCLI(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for real Git-history scan")
	}
	root := exportTestRepository(t)
	canary := strings.Join([]string{"gl", "pat-", "0123456789", "AbCdEfGhIj"}, "")
	if err := os.WriteFile(filepath.Join(root, "old.txt"), []byte("token="+canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	historyGit(t, root, "add", ".")
	historyGit(t, root, "commit", "-qm", "synthetic fixture")
	old := historyGit(t, root, "rev-parse", "HEAD")
	if err := os.Remove(filepath.Join(root, "old.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("clean fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	historyGit(t, root, "add", "-A")
	historyGit(t, root, "commit", "-qm", "remove fixture")
	head := historyGit(t, root, "rev-parse", "HEAD")
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", "gitleaks-history", root}, &out, &errout, scan); code != 0 {
		t.Fatalf("prepare=%d %s", code, &errout)
	}
	file := filepath.Join(t.TempDir(), "baseline.json")
	out.Reset()
	errout.Reset()
	if code := run(context.Background(), []string{"--scanners", "gitleaks,gitleaks-history", "--write-baseline", file, root}, &out, &errout, scan); code != 0 {
		t.Fatalf("history scan=%d %s", code, &errout)
	}
	var result report.Report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Scanners) != 2 || len(result.Findings) != 1 || result.Findings[0].Origin != "git_history" || result.Findings[0].Commit != old || result.Findings[0].Path != "old.txt" {
		t.Fatalf("history result=%+v", result)
	}
	for _, s := range result.Scanners {
		if s.Name == "gitleaks-history" && (s.Status != "success" || s.History == nil || s.History.Head != head || s.History.Commits != 2 || s.Coverage.Unit != "repository") {
			t.Fatalf("history coverage=%+v", s)
		}
	}
	if strings.Contains(out.String()+errout.String(), canary) {
		t.Fatal("history secret leaked")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := baseline.Decode(data); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	if code := run(context.Background(), []string{"--scanners", "gitleaks-history", "--baseline", file, root}, &out, &errout, scan); code != 0 {
		t.Fatalf("compare history=%d %s", code, &errout)
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || len(result.Findings) != 1 || result.Findings[0].BaselineStatus != "exempt" || result.Findings[0].Commit != old {
		t.Fatalf("history baseline=%+v error=%v", result, err)
	}
	if historyGit(t, root, "rev-parse", "HEAD") != head || historyGit(t, root, "status", "--porcelain") != "" {
		t.Fatal("history scan changed source Git state")
	}
	unborn := exportTestRepository(t)
	if err := os.WriteFile(filepath.Join(unborn, "versions.properties"), []byte("version.synthetic=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	if code := run(context.Background(), []string{"--scanners", "gitleaks-history,refresh-versions", unborn}, &out, &errout, scan); code != 0 {
		t.Fatalf("history failure lost successful sibling=%d %s", code, &errout)
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, s := range result.Scanners {
		if s.Name == "gitleaks-history" && s.Status != "failed" || s.Name == "refresh-versions" && s.Status != "success" {
			t.Fatalf("partial result=%+v", result)
		}
	}
}

func historyGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	argv := []string{"-C", root, "-c", "user.name=History Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}
	data, err := exec.Command("git", append(argv, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("fixture Git %q: %v %s", args, err, data)
	}
	return strings.TrimSpace(string(data))
}
