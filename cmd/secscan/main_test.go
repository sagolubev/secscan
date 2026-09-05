package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigiuscom/secscan/internal/report"
)

func TestRunWritesOneJSONDocument(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	scan := func(context.Context, string) (report.Report, error) {
		return report.Report{SchemaVersion: "1", Repository: "/repo"}, nil
	}

	code := run(context.Background(), []string{"--scanners", "gitleaks", "."}, &stdout, &stderr, scan)
	if code != 0 {
		t.Fatalf("run() exit = %d, want 0; stderr=%s", code, stderr.String())
	}
	if got := bytes.Count(stdout.Bytes(), []byte("\n")); got != 1 {
		t.Errorf("run() stdout newlines = %d, want 1; stdout=%q", got, stdout.String())
	}
	if stderr.String() != "scanner=gitleaks status=starting\n" {
		t.Errorf("run() stderr = %q, want one progress line", stderr.String())
	}
}

func TestRunExitCodesAndScannerSelection(t *testing.T) {
	failed := func(context.Context, string) (report.Report, error) {
		return report.Report{}, errors.New("scan failed")
	}
	for _, test := range []struct {
		name string
		args []string
		scan scanFunc
		want int
	}{
		{name: "scan failure", args: []string{"."}, scan: failed, want: 1},
		{name: "invalid scanner", args: []string{"--scanners", "unknown"}, scan: failed, want: 2},
		{
			name: "all selects gitleaks",
			args: []string{"--scanners", "all"},
			scan: func(context.Context, string) (report.Report, error) {
				return report.Report{SchemaVersion: "1"}, nil
			},
			want: 0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := run(context.Background(), test.args, &bytes.Buffer{}, &bytes.Buffer{}, test.scan)
			if code != test.want {
				t.Errorf("run() exit = %d, want %d", code, test.want)
			}
		})
	}
}

func TestAcceptanceCLIContainerScan(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 to run container acceptance")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(cache, "secscan")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	repository, err := os.MkdirTemp(base, "cli-fixture-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(repository) })

	canary := strings.Join([]string{"gl", "pat-", "0123456789", "AbCdEfGhIj"}, "")
	if err := os.WriteFile(filepath.Join(repository, "canary.txt"), []byte("token="+canary+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", repository, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"--scanners", "gitleaks", repository}, &stdout, &stderr, scan)
	if code != 0 {
		t.Fatalf("run() exit = %d, want 0; stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), canary) {
		t.Fatal("run() stdout contains synthetic secret")
	}
	var got report.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("run() stdout is not one JSON document: %v", err)
	}
	if len(got.Findings) == 0 {
		t.Fatal("run() report has no findings")
	}
}
