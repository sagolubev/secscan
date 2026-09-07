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

func TestRunExportsVisibleHTMLAndFullSARIF(t *testing.T) {
	root := exportTestRepository(t)
	old := baselineCode("app.py", 1)
	data, err := baseline.Encode([]report.Finding{old})
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "baseline.json")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	current := baselineCode("app.py", 2)
	current.Message = "<script>alert('untrusted')</script>"
	htmlPath, sarifPath := filepath.Join(root, "report.html"), filepath.Join(root, "report.sarif")
	fake := func(_ context.Context, _ string, options scanOptions, _ func(progress.Event)) (report.Report, error) {
		if len(options.Excluded) != 3 {
			t.Fatalf("control paths=%v, want 3", options.Excluded)
		}
		return report.Report{SchemaVersion: "1", Repository: root, Findings: []report.Finding{old, current}, Scanners: []report.Scanner{{Name: "python-sast", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "files"}}}}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--baseline", input, "--html", htmlPath, "--sarif", sarifPath, root}, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("export exit=%d stderr=%s", code, &stderr)
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || len(result.Findings) != 1 || result.Findings[0].Line != 2 {
		t.Fatalf("stdout=%s error=%v", &stdout, err)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil || !bytes.Contains(html, []byte("&lt;script&gt;")) || bytes.Contains(html, []byte("<script>")) || bytes.Contains(html, []byte("app.py:1")) {
		t.Fatalf("unsafe or unfiltered HTML: %v %s", err, html)
	}
	data, err = os.ReadFile(sarifPath)
	if err != nil {
		t.Fatal(err)
	}
	var sarif struct {
		Version string
		Runs    []struct{ Results []json.RawMessage }
	}
	if err := json.Unmarshal(data, &sarif); err != nil || sarif.Version != "2.1.0" || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 2 {
		t.Fatalf("SARIF=%s error=%v", data, err)
	}
	for _, path := range []string{htmlPath, sarifPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("output permissions: %s %v", path, err)
		}
	}
}

func TestRunExportsFailedScanEvidence(t *testing.T) {
	root := exportTestRepository(t)
	output := filepath.Join(t.TempDir(), "failure.sarif")
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1", Repository: root, Scanners: []report.Scanner{{Name: "python-sast", Status: "failed", Coverage: report.Coverage{Failed: 1, Unit: "files"}}}}, errors.New("scanner failed")
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--sarif", output, root}, &stdout, &stderr, fake)
	data, err := os.ReadFile(output)
	if code != 1 || !json.Valid(stdout.Bytes()) || err != nil || !bytes.Contains(data, []byte(`"executionSuccessful":false`)) || !bytes.Contains(data, []byte("toolExecutionNotifications")) {
		t.Fatalf("failure export exit=%d error=%v stdout=%s output=%s stderr=%s", code, err, &stdout, data, &stderr)
	}
}

func TestReportOutputValidation(t *testing.T) {
	root := exportTestRepository(t)
	existing := filepath.Join(root, "existing.html")
	if err := os.WriteFile(existing, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--html", "", root}, 2},
		{[]string{"update", "--sarif", filepath.Join(root, "new.sarif"), root}, 2},
		{[]string{"--html", existing, root}, 1},
	} {
		var stdout, stderr bytes.Buffer
		fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
			t.Fatal("invalid destination started scan")
			return report.Report{}, nil
		}
		if code := run(context.Background(), tc.args, &stdout, &stderr, fake); code != tc.code || stdout.Len() != 0 {
			t.Errorf("args=%v exit=%d stdout=%s stderr=%s", tc.args, code, &stdout, &stderr)
		}
	}
	data, err := os.ReadFile(existing)
	if err != nil || strings.TrimSpace(string(data)) != "preserve" {
		t.Fatalf("existing file replaced: %q %v", data, err)
	}
}

func TestOutputCollisionsFailBeforeScan(t *testing.T) {
	for _, mode := range []string{"same", "baseline", "trivy", "parent alias", "case alias", "unicode alias"} {
		t.Run(mode, func(t *testing.T) {
			root, parent := exportTestRepository(t), t.TempDir()
			first, second := filepath.Join(parent, "report"), filepath.Join(parent, "report")
			left, right := "--html", "--sarif"
			switch mode {
			case "baseline":
				left, right = "--write-baseline", "--html"
			case "trivy":
				left, right = "--trivy-reports", "--html"
			case "parent alias":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(parent, alias); err != nil {
					t.Fatal(err)
				}
				second = filepath.Join(alias, "report")
			case "case alias":
				second = filepath.Join(parent, "REPORT")
			case "unicode alias":
				first, second = filepath.Join(parent, "r\u00e9port"), filepath.Join(parent, "re\u0301port")
			}
			if mode == "case alias" || mode == "unicode alias" {
				if err := os.WriteFile(first, []byte("probe"), 0600); err != nil {
					t.Fatal(err)
				}
				_, aliasErr := os.Stat(second)
				if err := os.Remove(first); err != nil {
					t.Fatal(err)
				}
				if os.IsNotExist(aliasErr) {
					t.Skip("filesystem distinguishes these names")
				}
				if aliasErr != nil {
					t.Fatal(aliasErr)
				}
			}
			var stdout, stderr bytes.Buffer
			fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
				t.Fatal("colliding output started scan")
				return report.Report{}, nil
			}
			if code := run(context.Background(), []string{left, first, right, second, root}, &stdout, &stderr, fake); code != 1 || stdout.Len() != 0 {
				t.Fatalf("collision exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("preflight left files: %v %v", entries, err)
			}
		})
	}
}

func TestAcceptanceRenderedReports(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for real report generation")
	}
	root := exportTestRepository(t)
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("eval(user_input)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", "python-sast", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("update exit=%d stderr=%s", code, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	html, sarif := filepath.Join(root, "report.html"), filepath.Join(root, "report.sarif")
	if code := run(context.Background(), []string{"--scanners", "python-sast", "--html", html, "--sarif", sarif, root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("scan exit=%d stderr=%s", code, &stderr)
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || len(result.Findings) != 1 || len(result.Inventory.Omitted) != 2 {
		t.Fatalf("scan output=%s error=%v", &stdout, err)
	}
	for _, file := range []string{html, sarif} {
		data, err := os.ReadFile(file)
		if err != nil || !bytes.Contains(data, []byte("secscan.python.dynamic-code-execution")) {
			t.Fatalf("missing native finding in %s: %v", file, err)
		}
	}
}
