// START_MODULE_CONTRACT
// PURPOSE: Verify JSON-only budgets through CLI validation and publication.
// SCOPE: Synthetic scanner results; preserve existing exits and independent full exports.
// DEPENDS: cmd/secscan/main.go, internal/report/budget.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-report-rendering
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestRunBudgetValidation - Reject invalid scan-only limits before starting scanners.
// TestRunBudgetAbsent - Keep existing JSON bytes when the flag is absent.
// TestRunBudgetPreservesExports - Budget JSON after filtering while keeping HTML and full exports.
// TestRunBudgetPreservesFailure - Emit complete failure evidence and preserve exit one.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func TestRunBudgetValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--max-tokens", "0"}, {"--max-tokens", "-1"}, {"--max-tokens", ""},
		{"--max-tokens", "1.5"}, {"--max-tokens", "99999999999999999999999999999"},
		{"update", "--max-tokens", "1000"}, {"rules", "show", "--max-tokens", "1000"},
	} {
		var stdout, stderr bytes.Buffer
		fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
			t.Fatal("invalid budget started a scanner")
			return report.Report{}, nil
		}
		if code := run(context.Background(), args, &stdout, &stderr, fake); code != 2 || stdout.Len() != 0 {
			t.Errorf("run(%v) exit=%d stdout=%q stderr=%q, want exit 2 without stdout", args, code, &stdout, &stderr)
		}
	}
}

func TestRunBudgetAbsent(t *testing.T) {
	root := exportTestRepository(t)
	input := report.Report{SchemaVersion: "1", Repository: root, Findings: []report.Finding{baselineCode("app.py", 2)}}
	want, err := report.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	var stdout, stderr bytes.Buffer
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return input, nil
	}
	if code := run(context.Background(), []string{"--no-config", "--progress", "off", root}, &stdout, &stderr, fake); code != 0 || !bytes.Equal(stdout.Bytes(), want) || bytes.Contains(stdout.Bytes(), []byte(`"budget"`)) {
		t.Fatalf("run(no budget) exit=%d stdout=%q want=%q stderr=%q", code, &stdout, want, &stderr)
	}
}

func TestRunBudgetPreservesExports(t *testing.T) {
	root, output := exportTestRepository(t), t.TempDir()
	findings := []report.Finding{baselineCode("info.py", 1), baselineCode("low.py", 2), baselineCode("secret.py", 3)}
	findings[0].Severity, findings[1].Severity = "informational", "low"
	findings[2].Kind = "secret"
	for i := range findings {
		findings[i].Fingerprint = strings.Repeat(string(rune('a'+i)), 64)
	}
	payload := &report.TrivyReports{CycloneDX: []byte(`{"bomFormat":"CycloneDX","components":[]}`), SonarQube: []byte(`{"rules":[],"issues":[]}`)}
	input := report.Report{SchemaVersion: "1", Repository: root, Findings: findings, Scanners: []report.Scanner{
		{Name: "trivy", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "packages", ReadInputs: []string{"package-lock.json"}}, TrivyReports: payload},
	}}
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return input, nil
	}
	htmlPath, sarifPath := filepath.Join(output, "report.html"), filepath.Join(output, "report.sarif")
	snapshotPath, trivyPath := filepath.Join(output, "baseline.json"), filepath.Join(output, "trivy")
	var stdout, stderr bytes.Buffer
	args := []string{"--max-tokens", "1", "--min-severity", "low", "--write-baseline", snapshotPath, "--html", htmlPath, "--sarif", sarifPath, "--trivy-reports", trivyPath, "--progress", "off", root}
	if code := run(context.Background(), args, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("run(budget exports) exit=%d stderr=%s", code, &stderr)
	}
	var got report.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Budget == nil || !got.Budget.Exceeded || got.Budget.Measured != stdout.Len() || got.Budget.RemovedFragments != 1 || got.Budget.RetainedFragments != 1 || got.Filtering == nil || got.Filtering.OutputFragments != 2 || len(got.Findings) != 1 || got.Findings[0].Kind != "secret" || !strings.Contains(stderr.String(), "JSON budget exceeded") {
		t.Fatalf("run(budget exports) stdout=%s stderr=%s", &stdout, &stderr)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil || bytes.Contains(html, []byte("info.py")) || !bytes.Contains(html, []byte("low.py")) || !bytes.Contains(html, []byte("secret.py")) || bytes.Contains(html, []byte("utf8-bytes-v1")) {
		t.Fatalf("budget changed visible HTML: err=%v html=%s", err, html)
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatal(err)
	}
	var sarif struct {
		Runs []struct{ Results []json.RawMessage }
	}
	if err := json.Unmarshal(data, &sarif); err != nil || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 3 || bytes.Contains(data, []byte("utf8-bytes-v1")) {
		t.Fatalf("budget changed full SARIF: err=%v data=%s", err, data)
	}
	data, err = os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := baseline.Encode(findings)
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("budget changed full baseline: err=%v data=%s want=%s", err, data, want)
	}
	for name, want := range map[string][]byte{"trivy.cdx.json": payload.CycloneDX, "trivy.sonarqube.json": payload.SonarQube} {
		got, err := os.ReadFile(filepath.Join(trivyPath, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("budget changed %s: err=%v got=%s want=%s", name, err, got, want)
		}
	}
	if input.Budget != nil || input.Filtering != nil || len(input.Findings) != 3 {
		t.Fatalf("run(budget exports) mutated input: %+v", input)
	}
}

func TestRunBudgetPreservesFailure(t *testing.T) {
	root := exportTestRepository(t)
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1", Scanners: []report.Scanner{{Name: "gitleaks", Status: "failed", Coverage: report.Coverage{Failed: 1, Unit: "repository"}}}, Findings: []report.Finding{{Kind: "error", Message: "synthetic scanner error"}}}, errors.New("synthetic scan failure")
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--max-tokens", "1", "--progress", "off", root}, &stdout, &stderr, fake); code != 1 {
		t.Fatalf("run(budget failure) exit=%d stderr=%s, want 1", code, &stderr)
	}
	var got report.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil || got.Budget == nil || !got.Budget.Exceeded || len(got.Findings) != 1 || len(got.Scanners) != 1 || got.Scanners[0].Status != "failed" || got.Scanners[0].Coverage.Failed != 1 || !strings.Contains(stderr.String(), "synthetic scan failure") {
		t.Fatalf("run(budget failure) hid failure evidence: stdout=%s stderr=%s err=%v", &stdout, &stderr, err)
	}
}
