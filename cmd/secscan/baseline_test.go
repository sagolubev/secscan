// START_MODULE_CONTRACT
// PURPOSE: Verify baseline comparison, output ownership and old-text isolation.
// SCOPE: Synthetic reports plus opt-in container acceptance.
// DEPENDS: cmd/secscan/baseline.go, cmd/secscan/output.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-baselines
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestRunWritesAndComparesBaseline - Keep only current growth after loading a snapshot.
// TestBaselineArgumentAndDataFailures - Reject invalid controls before starting scanners.
// TestBaselinePublicationFailuresPreserveData - Preserve existing files and remove incomplete outputs.
// TestBaselineKeepsTrivyExportsUnfiltered - Keep integration exports independent of baseline filtering.
// TestBaselinePinsOutputParent - Prevent publication through a replaced parent directory.
// TestAcceptanceBaselineCompare - Check real scanning and isolation from old snapshot text.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func baselineCode(path string, line int) report.Finding {
	return report.Finding{Kind: "code", RuleID: "secscan.python.dynamic-code-execution", Message: "dynamic code execution", Path: path, Line: line, EndLine: line, Fingerprint: strings.Repeat("a", 64), Sources: []string{"opengrep"}, Origin: "working_tree", Language: "python", Severity: "error"}
}

func TestRunWritesAndComparesBaseline(t *testing.T) {
	root := exportTestRepository(t)
	path := filepath.Join(root, "baseline.json")
	current := []report.Finding{baselineCode("app.py", 1)}
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1", Repository: root, Scanners: []report.Scanner{{Name: "python-sast", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "files", ReadInputs: []string{"app.py"}}}}, Findings: current}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--write-baseline", path, "--scanners", "python-sast", root}, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("write baseline exit=%d stderr=%s", code, &stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := baseline.Decode(data); err != nil {
		t.Fatalf("saved snapshot invalid: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	current = append(current, baselineCode("app.py", 2))
	if code := run(context.Background(), []string{"--baseline", path, "--scanners", "python-sast", root}, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("compare exit=%d stderr=%s", code, &stderr)
	}
	var result struct {
		Findings []report.Finding
		Baseline *report.BaselineSummary
	}
	if json.Unmarshal(stdout.Bytes(), &result) != nil || len(result.Findings) != 1 || result.Findings[0].Line != 2 || result.Findings[0].BaselineStatus != "expanded" || result.Baseline == nil || result.Baseline.Unchanged != 1 {
		t.Fatalf("baseline result=%s", &stdout)
	}
}

func TestBaselineArgumentAndDataFailures(t *testing.T) {
	root := exportTestRepository(t)
	file := filepath.Join(root, "baseline.json")
	if err := os.WriteFile(file, []byte(`{"schemaVersion":"1","fingerprintAlgorithm":"UNTRUSTED_OLD_CANARY","findings":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"update", "--baseline", file, root}, 2},
		{[]string{"--baseline", file, "--write-baseline", file, root}, 2},
		{[]string{"--baseline", "", root}, 2},
		{[]string{"--baseline", file, root}, 1},
		{[]string{"--write-baseline", file, root}, 1},
	} {
		var stdout, stderr bytes.Buffer
		fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
			t.Fatal("invalid baseline request started scanners")
			return report.Report{}, nil
		}
		if code := run(context.Background(), tc.args, &stdout, &stderr, fake); code != tc.code || stdout.Len() != 0 {
			t.Errorf("args=%v exit=%d stdout=%s stderr=%s", tc.args, code, &stdout, &stderr)
		}
		if strings.Contains(stderr.String(), "UNTRUSTED_OLD_CANARY") {
			t.Fatal("old baseline text leaked")
		}
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBaseline(link); err == nil {
		t.Fatal("baseline leaf symlink accepted")
	}
}

func TestBaselinePublicationFailuresPreserveData(t *testing.T) {
	root := exportTestRepository(t)
	for _, mode := range []string{"late file", "canceled", "failed scanner"} {
		t.Run(mode, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "baseline.json")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
				switch mode {
				case "late file":
					if err := os.WriteFile(output, []byte("preserve"), 0600); err != nil {
						t.Fatal(err)
					}
				case "canceled":
					cancel()
				}
				status := "success"
				if mode == "failed scanner" {
					status = "failed"
				}
				return report.Report{SchemaVersion: "1", Repository: root, Scanners: []report.Scanner{{Name: "python-sast", Status: status}}, Findings: []report.Finding{baselineCode("app.py", 1)}}, nil
			}
			var stdout, stderr bytes.Buffer
			if code := run(ctx, []string{"--write-baseline", output, root}, &stdout, &stderr, fake); code != 1 || !json.Valid(stdout.Bytes()) {
				t.Fatalf("%s exit=%d stdout=%s stderr=%s", mode, code, &stdout, &stderr)
			}
			if mode == "late file" {
				data, err := os.ReadFile(output)
				if err != nil || string(data) != "preserve" {
					t.Fatalf("existing target changed: %s %v", data, err)
				}
			} else if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("failed baseline published: %v", err)
			}
			files, err := filepath.Glob(filepath.Join(filepath.Dir(output), ".secscan-baseline-*"))
			if err != nil || len(files) != 0 {
				t.Fatalf("staging files remain: %v %v", files, err)
			}
		})
	}
}

func TestBaselineKeepsTrivyExportsUnfiltered(t *testing.T) {
	root := exportTestRepository(t)
	input := filepath.Join(root, "baseline.json")
	findings := report.Normalize([]report.Finding{{Kind: "dependency", Package: &report.Package{Ecosystem: "npm", Name: "library", Version: "1"}, Advisories: []string{"CVE-2026-1000"}, Locations: []report.Location{{Path: "package-lock.json", Line: 1}}, Sources: []string{"trivy"}, Severity: "high"}})
	encoded, err := baseline.Encode(findings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	payload := &report.TrivyReports{CycloneDX: []byte(`{"bomFormat":"CycloneDX","components":[{"name":"library"}]}`), SonarQube: []byte(`{"rules":[{"id":"CVE-2026-1000"}],"issues":[]}`)}
	fake := func(_ context.Context, _ string, options scanOptions, _ func(progress.Event)) (report.Report, error) {
		if !options.TrivyReports || len(options.Excluded) != 1 || options.Excluded[0] != "baseline.json" {
			t.Fatalf("baseline controls not routed: %+v", options)
		}
		return report.Report{SchemaVersion: "1", Repository: root, Findings: findings, Scanners: []report.Scanner{{Name: "trivy", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "packages", ReadInputs: []string{"package-lock.json"}}, TrivyReports: payload}}}, nil
	}
	output := filepath.Join(t.TempDir(), "reports")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--baseline", input, "--trivy-reports", output, "--scanners", "trivy", root}, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("baseline+export exit=%d %s", code, &stderr)
	}
	var result report.Report
	if json.Unmarshal(stdout.Bytes(), &result) != nil || len(result.Findings) != 0 || result.Baseline == nil || result.Baseline.Unchanged != 1 {
		t.Fatalf("filtered stdout=%s", &stdout)
	}
	for name, want := range map[string][]byte{"trivy.cdx.json": payload.CycloneDX, "trivy.sonarqube.json": payload.SonarQube} {
		data, err := os.ReadFile(filepath.Join(output, name))
		if err != nil || !bytes.Equal(data, want) {
			t.Fatalf("%s was filtered: %s %v", name, data, err)
		}
	}
}

func TestBaselinePinsOutputParent(t *testing.T) {
	root := exportTestRepository(t)
	parent := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	redirect := t.TempDir()
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		if err := os.Rename(parent, parent+"-original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(redirect, parent); err != nil {
			t.Fatal(err)
		}
		return report.Report{SchemaVersion: "1", Repository: root, Findings: []report.Finding{baselineCode("app.py", 1)}}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--write-baseline", filepath.Join(parent, "baseline.json"), root}, &stdout, &stderr, fake)
	files, err := os.ReadDir(redirect)
	if err != nil || len(files) != 0 {
		t.Fatalf("publication redirected: files=%v err=%v", files, err)
	}
	if code == 0 {
		data, err := os.ReadFile(filepath.Join(parent+"-original", "baseline.json"))
		if err != nil || !json.Valid(data) {
			t.Fatalf("pinned publication missing: %v", err)
		}
	}
}

func TestControlPathsThroughRepositoryCaseAlias(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "REPO")
	if _, err := os.Stat(alias); os.IsNotExist(err) {
		t.Skip("case-sensitive filesystem")
	}
	request, err := prepareBaseline(root, "", filepath.Join(alias, "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer request.output.close()
	if len(request.excluded) != 1 || request.excluded[0] != "baseline.json" {
		t.Errorf("case alias lost control path: %v", request.excluded)
	}
	if destination, err := prepareExportDestination(root, filepath.Join(alias, "trivy")); err == nil {
		destination.parent.Close()
		t.Error("Trivy destination inside worktree accepted through case alias")
	}
}

func TestAcceptanceBaselineCompare(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for real baseline scanning")
	}
	root := exportTestRepository(t)
	app := filepath.Join(root, "app.py")
	if err := os.WriteFile(app, []byte("eval(user_input)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	canary := strings.Join([]string{"gl", "pat-", "0123456789", "AbCdEfGhIj"}, "")
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("token="+canary+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	selection := "gitleaks,python-sast"
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", selection, root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("prepare=%d %s", code, &stderr)
	}
	snapshot := filepath.Join(root, "baseline.json")
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--write-baseline", snapshot, "--scanners", selection, root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("write=%d %s", code, &stderr)
	}
	if err := os.WriteFile(app, []byte("eval(user_input)\neval(other_input)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--baseline", snapshot, "--scanners", selection, root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("compare=%d %s", code, &stderr)
	}
	var result report.Report
	if json.Unmarshal(stdout.Bytes(), &result) != nil || result.Baseline == nil || result.Baseline.Expanded != 1 || result.Baseline.Unchanged != 1 || result.Baseline.Exempt != 1 || len(result.Findings) != 2 {
		t.Fatalf("native baseline output=%s", &stdout)
	}
	if result.Inventory == nil || len(result.Inventory.Omitted) != 1 || result.Inventory.Omitted[0].Path != "baseline.json" || result.Inventory.Omitted[0].Reason != "control_file" {
		t.Fatalf("baseline file was not excluded: %+v", result.Inventory)
	}
	if bytes.Contains(stdout.Bytes(), []byte(canary)) {
		t.Fatal("secret value leaked")
	}
	old := baselineCode("old.py", 1)
	old.Message = "token=" + canary
	data, err := baseline.Encode([]report.Finding{old})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--baseline", snapshot, "--scanners", "gitleaks", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("old-text isolation=%d %s", code, &stderr)
	}
	if json.Unmarshal(stdout.Bytes(), &result) != nil || len(result.Findings) != 0 || bytes.Contains(stdout.Bytes(), []byte(canary)) {
		t.Fatalf("old snapshot text was scanned or echoed: %s", &stdout)
	}
}
