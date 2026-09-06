package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sigiuscom/secscan/internal/orchestrator"
	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
)

func TestRunWritesOneJSONDocument(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	scan := func(_ context.Context, _ string, _ []string, emit func(progress.Event)) (report.Report, error) {
		emit(progress.Event{Scanner: "gitleaks", Stage: progress.StageQueued, Status: progress.StatusQueued})
		return report.Report{SchemaVersion: "1", Repository: "/repo"}, nil
	}

	code := run(context.Background(), []string{"--scanners", "gitleaks", "."}, &stdout, &stderr, scan)
	if code != 0 {
		t.Fatalf("run() exit = %d, want 0; stderr=%s", code, stderr.String())
	}
	if got := bytes.Count(stdout.Bytes(), []byte("\n")); got != 1 {
		t.Errorf("run() stdout newlines = %d, want 1; stdout=%q", got, stdout.String())
	}
	if !strings.Contains(stderr.String(), "scanner=gitleaks stage=queued") {
		t.Errorf("run() stderr = %q, want queued progress", stderr.String())
	}
}

func TestRunExitCodesAndScannerSelection(t *testing.T) {
	failed := func(context.Context, string, []string, func(progress.Event)) (report.Report, error) {
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
			scan: func(context.Context, string, []string, func(progress.Event)) (report.Report, error) {
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

func TestRunProgressModes(t *testing.T) {
	success := func(context.Context, string, []string, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1"}, nil
	}

	var off bytes.Buffer
	if code := run(context.Background(), []string{"--progress", "off"}, &bytes.Buffer{}, &off, success); code != 0 {
		t.Fatalf("run(--progress off) exit = %d, want 0", code)
	}
	if off.Len() != 0 {
		t.Errorf("run(--progress off) stderr = %q, want empty", off.String())
	}

	if code := run(context.Background(), []string{"--progress", "spinner"}, &bytes.Buffer{}, &bytes.Buffer{}, success); code != 2 {
		t.Errorf("run(invalid progress) exit = %d, want 2", code)
	}
}

func TestParseScannerSelection(t *testing.T) {
	got, err := parseScannerSelection("typescript-sast,gitleaks,typescript-sast")
	if err != nil {
		t.Fatalf("parseScannerSelection() error = %v", err)
	}
	want := []string{"typescript-sast", "gitleaks"}
	if !slices.Equal(got, want) {
		t.Errorf("parseScannerSelection() = %q, want %q", got, want)
	}
	if _, err := parseScannerSelection(""); err == nil {
		t.Fatal("parseScannerSelection(empty) error = nil")
	}
}

func TestBuildReportAllowsAllSkipped(t *testing.T) {
	skipped := []report.Scanner{{
		Name:   "python-sast",
		Status: "skipped",
		Coverage: report.Coverage{
			Unit: "files",
		},
	}}

	got, err := buildReport(
		"/repo",
		report.Exclusions{},
		skipped,
		orchestrator.Result{},
		nil,
	)
	if err != nil {
		t.Fatalf("buildReport() error = %v", err)
	}
	if len(got.Scanners) != 1 || got.Scanners[0].Status != "skipped" {
		t.Errorf("buildReport() = %#v", got)
	}
}

func TestRunTTYFallsBackToPlainWhenStderrIsNotTerminal(t *testing.T) {
	failed := func(context.Context, string, []string, func(progress.Event)) (report.Report, error) {
		return report.Report{}, errors.New("scan failed")
	}
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"--progress", "tty"}, &bytes.Buffer{}, &stderr, failed)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1", code)
	}
	got := stderr.String()
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("non-terminal stderr contains ANSI: %q", got)
	}
	if !strings.HasSuffix(got, "scan failed\n") {
		t.Fatalf("plain stderr is incomplete: %q", got)
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
	if err := os.WriteFile(filepath.Join(repository, "app.py"), []byte("eval(user_input)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "app.ts"), []byte("eval(userInput);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", repository, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", "all", repository}, &bytes.Buffer{}, &stderr, scan); code != 0 {
		t.Fatalf("update exit = %d: %s", code, stderr.String())
	}
	code := run(context.Background(), []string{"--scanners", "all", repository}, &stdout, &stderr, scan)
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
	if len(got.Findings) < 3 || len(got.Scanners) != 3 {
		t.Fatalf("run() findings/scanners = %d/%d, want at least 3/3", len(got.Findings), len(got.Scanners))
	}
}

func TestScanMissingPreparationIsActionableAndDoesNotPull(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
	bin := t.TempDir()
	log := filepath.Join(bin, "calls")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SECSCAN_TEST_CALLS\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSCAN_TEST_CALLS", log)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := scan(context.Background(), root, []string{"gitleaks"}, func(progress.Event) {})
	if err == nil || !strings.Contains(err.Error(), "secscan update") {
		t.Fatalf("scan missing cache error=%v", err)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "info" {
		t.Fatalf("missing-cache scan ran commands beyond local runtime probe: %s", data)
	}
}
