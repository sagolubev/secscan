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

	"github.com/sagolubev/secscan/internal/orchestrator"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func TestInformationFlagsWithoutRepositoryOrRuntime(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PATH", "")
	for _, test := range []struct {
		flag string
		want string
	}{
		{flag: "--version", want: "secscan dev\n"},
		{flag: "--licenses", want: "MIT License"},
	} {
		t.Run(test.flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{test.flag}, &stdout, &stderr, nil)
			if code != 0 || !strings.Contains(stdout.String(), test.want) || stderr.Len() != 0 {
				t.Fatalf("run(%s) exit=%d stdout=%q stderr=%q", test.flag, code, &stdout, &stderr)
			}
		})
	}
}

func TestInformationFlagsRejectScanAndUpdateArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--version", "--licenses"},
		{"--version", "."},
		{"--licenses", "--scanners", "all"},
		{"--version", "--progress", "auto"},
		{"--licenses", "--scan-images=false"},
		{"update", "--version"},
		{"update", "--licenses"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr, nil); code != 2 || stdout.Len() != 0 {
			t.Errorf("run(%q) exit=%d stdout=%q, want exit 2 and no output", args, code, &stdout)
		}
	}
}

func TestRunWritesOneJSONDocument(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	scan := func(_ context.Context, _ string, _ []string, _ bool, emit func(progress.Event)) (report.Report, error) {
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
	failed := func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
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
			scan: func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
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
	success := func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
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
	failed := func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
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
	if len(got.Findings) < 3 || len(got.Scanners) != 17 {
		t.Fatalf("run() findings/scanners = %d/%d, want at least 3/17", len(got.Findings), len(got.Scanners))
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
	_, err := scan(context.Background(), root, []string{"gitleaks"}, false, func(progress.Event) {})
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

func TestCISkippedWithoutRuntime(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	selected, err := parseScannerSelection("zizmor,poutine")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scan(context.Background(), root, selected, false, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 2 {
		t.Fatalf("%#v %v", result, err)
	}
	for _, scanner := range result.Scanners {
		if scanner.Status != "skipped" {
			t.Fatalf("%#v", scanner)
		}
	}
}

func TestIaCSkippedWithoutRuntime(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	selected, err := parseScannerSelection("checkov,checkov-terraform,kics")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scan(context.Background(), root, selected, false, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 3 {
		t.Fatalf("%#v %v", result, err)
	}
	for _, scanner := range result.Scanners {
		if scanner.Status != "skipped" {
			t.Fatalf("%#v", scanner)
		}
	}
}

func TestIaCMissingPreparation(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
	bin := t.TempDir()
	log := filepath.Join(bin, "calls")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SECSCAN_TEST_CALLS\"\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSCAN_TEST_CALLS", log)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, name := range []string{"checkov", "checkov-terraform", "kics"} {
		_, err := scan(context.Background(), root, []string{name}, false, func(progress.Event) {})
		if err == nil || !strings.Contains(err.Error(), "secscan update") {
			t.Errorf("%s error=%v", name, err)
		}
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "info\ninfo\ninfo\n" {
		t.Fatalf("unexpected runtime commands: %s", data)
	}
}

func TestCLIRejectsIaCWithoutEvaluatedInputs(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("broken = ["), 0600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
	bin := t.TempDir()
	t.Setenv("SECSCAN_TEST_IMAGE_ID", "sha256:"+strings.Repeat("a", 64))
	script := `#!/bin/sh
case "$1" in info|pull) exit 0;; image) printf '%s\n' "$SECSCAN_TEST_IMAGE_ID"; exit 0;; esac
for arg in "$@"; do
 case "$arg" in type=bind,src=*,dst=/out) output="${arg#type=bind,src=}"; output="${output%,dst=/out}"; printf '%s\n' "$SECSCAN_TEST_RESULT" > "$output/result.json";; esac
done
printf '%s\n' "$SECSCAN_TEST_RESULT"
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var updateError bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", "checkov-terraform,kics", root}, &bytes.Buffer{}, &updateError, scan); code != 0 {
		t.Fatalf("prepare exit=%d: %s", code, &updateError)
	}
	for name, data := range map[string]string{
		"checkov-terraform": `{"check_type":"terraform","results":{"failed_checks":[]},"summary":{"passed":0,"failed":0,"skipped":0,"parsing_errors":1}}`,
		"kics":              `{"files_scanned":1,"files_parsed":0,"files_failed_to_scan":0,"queries_failed_to_execute":0,"queries_failed_to_compute_similarity_id":0,"queries":[]}`,
	} {
		t.Setenv("SECSCAN_TEST_RESULT", data)
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{"--scanners", name, root}, &stdout, &stderr, scan)
		if code != 1 || !strings.Contains(stderr.String(), "all selected scanners failed") {
			t.Errorf("%s zero analysis: exit=%d stdout=%s stderr=%s", name, code, &stdout, &stderr)
		}
		assertFailedReport(t, stdout.Bytes(), name)
	}
}

func TestDependenciesSkippedWithoutRuntime(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	selected, err := parseScannerSelection("trivy,grype,osv-scanner")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scan(context.Background(), root, selected, false, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 3 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	for _, scanner := range result.Scanners {
		if scanner.Status != "skipped" {
			t.Fatalf("unexpected scanner=%#v", scanner)
		}
	}
}

func TestDependencyUnreadOnlyDoesNotSucceed(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte(`dependencies { implementation(variable) }`), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := scan(context.Background(), root, []string{"osv-scanner"}, false, func(progress.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Scanners) != 1 || result.Scanners[0].Status != "skipped" || result.Scanners[0].Coverage.Read != 0 || len(result.Scanners[0].Coverage.UnreadInputs) != 1 {
		t.Fatalf("unread-only result=%#v", result)
	}
}

func TestCodeSkippedWithoutRuntime(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	selected, err := parseScannerSelection("semgrep,bearer,cppcheck")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scan(context.Background(), root, selected, false, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 3 {
		t.Fatalf("code scan empty = %#v, %v", result, err)
	}
	for _, s := range result.Scanners {
		if s.Status != "skipped" {
			t.Fatalf("empty code scanner=%#v", s)
		}
	}
}

func TestCLIBearerSkippedOnServerArm64(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("print('hello')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	script := `#!/bin/sh
case "$1" in info) exit 0;; version) printf '{"Arch":"arm64"}'; exit 0;; esac
exit 99
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--scanners", "bearer", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("Bearer skip exit=%d stderr=%s", code, &stderr)
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Scanners) != 1 || result.Scanners[0].Status != "skipped" || result.Scanners[0].Coverage.Unread != 1 || !strings.Contains(strings.Join(result.Scanners[0].Limitations, " "), "unsupported_runtime_arch") {
		t.Fatalf("Bearer result=%#v", result)
	}
}

// This verifies the adapter/CLI contract with synthetic process output. It never
// launches Bearer; the network gate is needed only to prepare its pinned rules.
func TestAcceptanceBearerCoverageContractWithFakeRuntime(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 to prepare pinned private rules")
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git: %v %s", err, out)
	}
	for name, data := range map[string]string{"app.py": "eval(user_input)\n", "bundle.min.js": "eval(userInput);\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
	bin := t.TempDir()
	script := `#!/bin/sh
case "$1" in
 info|pull) exit 0;;
 version) printf '{"Arch":"amd64"}'; exit 0;;
 image) printf '%s\n' "$SECSCAN_TEST_IMAGE_ID"; exit 0;;
esac
case "$*" in
 *"semgrep scan"*) printf '{"version":"1.176.0","results":[],"errors":[],"paths":{"scanned":["/target/app.py"]}}'; exit 0;;
esac
for arg in "$@"; do
 case "$arg" in type=bind,src=*,dst=/out) output="${arg#type=bind,src=}"; output="${output%,dst=/out}"; printf '%s' "$SECSCAN_TEST_BEARER_REPORT" > "$output/result.sarif"; exit 0;; esac
done
exit 99
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SECSCAN_TEST_IMAGE_ID", "sha256:"+strings.Repeat("a", 64))
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", "bearer,semgrep", root}, &bytes.Buffer{}, &stderr, scan); code != 0 {
		t.Fatalf("prepare fake runtime exit=%d stderr=%s", code, &stderr)
	}
	clean := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Bearer","rules":[{"id":"python_lang_pickle"}]}},"results":null}]}`
	t.Setenv("SECSCAN_TEST_BEARER_REPORT", clean)
	var stdout bytes.Buffer
	stderr.Reset()
	if code := run(context.Background(), []string{"--scanners", "bearer", root}, &stdout, &stderr, scan); code != 1 || !strings.Contains(stderr.String(), "coverage_unconfirmed") {
		t.Fatalf("empty Bearer exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	assertFailedReport(t, stdout.Bytes(), "bearer")
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--scanners", "bearer,semgrep", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("mixed scan exit=%d stderr=%s", code, &stderr)
	}
	var mixed report.Report
	if err := json.Unmarshal(stdout.Bytes(), &mixed); err != nil {
		t.Fatal(err)
	}
	for _, engine := range mixed.Scanners {
		if engine.Name == "bearer" && (engine.Status != "failed" || engine.Coverage.Read != 0 || engine.Coverage.Unread != 2 || !slices.Equal(engine.Coverage.UnreadInputs, []string{"app.py", "bundle.min.js"}) || !strings.Contains(strings.Join(engine.Limitations, " "), "coverage_unconfirmed")) {
			t.Fatalf("empty Bearer metadata=%#v", engine)
		}
	}
	positive := strings.Replace(clean, `"results":null`, `"results":[{"ruleId":"python_lang_pickle","locations":[{"physicalLocation":{"artifactLocation":{"uri":"/target/app.py"},"region":{"startLine":1}}}]}]`, 1)
	t.Setenv("SECSCAN_TEST_BEARER_REPORT", positive)
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--scanners", "bearer", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("positive Bearer exit=%d stderr=%s", code, &stderr)
	}
	var partial report.Report
	if err := json.Unmarshal(stdout.Bytes(), &partial); err != nil {
		t.Fatal(err)
	}
	if len(partial.Scanners) != 1 || len(partial.Findings) != 1 {
		t.Fatalf("partial Bearer=%#v", partial)
	}
	engine := partial.Scanners[0]
	if engine.Status != "success" || engine.Coverage.Read != 1 || !slices.Equal(engine.Coverage.ReadInputs, []string{"app.py"}) || engine.Coverage.Unread != 1 || !slices.Equal(engine.Coverage.UnreadInputs, []string{"bundle.min.js"}) {
		t.Fatalf("positive Bearer metadata=%#v", engine)
	}
}

func TestNativeSelectionAndOCIConsent(t *testing.T) {
	if _, err := parseScannerSelection("oci-images"); err != nil {
		t.Errorf("canonical OCI persona rejected: %v", err)
	}
	if _, err := parseScannerSelection("oci"); err == nil {
		t.Error("unrequested OCI alias accepted")
	}
	all, err := parseScannerSelection("all")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gradle-catalog", "gradle-scripts", "refresh-versions"} {
		if !slices.Contains(all, name) {
			t.Errorf("all lacks %s", name)
		}
	}
	if slices.Contains(all, "oci-images") {
		t.Fatal("default enables OCI")
	}
	fake := func(_ context.Context, _ string, names []string, _ bool, _ func(progress.Event)) (report.Report, error) {
		if !slices.Contains(names, "oci-images") {
			t.Error("explicit flag did not add OCI")
		}
		return report.Report{}, nil
	}
	if code := run(context.Background(), []string{"--scan-images", "--scanners", "refresh-versions"}, &bytes.Buffer{}, &bytes.Buffer{}, fake); code != 0 {
		t.Errorf("flag exit=%d", code)
	}
	if code := run(context.Background(), []string{"--scanners", "oci-images"}, &bytes.Buffer{}, &bytes.Buffer{}, fake); code != 2 {
		t.Errorf("missing consent exit=%d", code)
	}
}

func TestNativeAndOCIWithoutRuntime(t *testing.T) {
	root := t.TempDir()
	if err := exec.Command("git", "-C", root, "init", "--quiet").Run(); err != nil {
		t.Fatal(err)
	}
	for file, data := range map[string]string{"versions.properties": "version.synthetic=1\n", "Dockerfile": "FROM example.invalid/synthetic:1\n"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := scan(context.Background(), root, []string{"refresh-versions"}, false, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 2 {
		t.Fatalf("metadata+unchecked images=%#v err=%v", result, err)
	}
	for _, s := range result.Scanners {
		if s.Name == "oci-images" && (s.Status != "skipped" || s.Coverage.Unread != 1) {
			t.Errorf("disabled OCI=%#v", s)
		}
	}
}

func TestRunEmitsFailureEvidenceWithoutClaimingSuccess(t *testing.T) {
	for _, failure := range []error{errors.New("SYNTHETIC_RAW_DIAGNOSTIC"), context.Canceled} {
		attempted := func(ctx context.Context, _ string, _ []string, _ bool, emit func(progress.Event)) (report.Report, error) {
			outcome, err := orchestrator.Run(ctx, []orchestrator.Job{{Name: "oci-images", Run: func(context.Context) (report.Scanner, []report.Finding, error) {
				return report.Scanner{Name: "oci-images", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "images"}, Capabilities: []string{"host-runtime-registry-access"}, Images: []report.Image{{Reference: "synthetic:first", Digest: "sha256:complete", Status: "success"}, {Reference: "synthetic:second", Digest: "sha256:second", Status: "cleanup_failed"}}}, []report.Finding{{Kind: "code", RuleID: "completed-safe-finding", Fingerprint: "completed"}}, failure
			}}}, 1, emit)
			return buildReport("/synthetic", report.Exclusions{}, nil, outcome, err)
		}
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{"--scan-images", "--scanners", "oci-images", "--progress", "off"}, &stdout, &stderr, attempted)
		var result report.Report
		if code != 1 || json.Unmarshal(stdout.Bytes(), &result) != nil || bytes.Count(stdout.Bytes(), []byte("\n")) != 1 {
			t.Fatalf("failure output exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
		}
		if len(result.Scanners) != 1 || result.Scanners[0].Status != "failed" || result.Scanners[0].Coverage.Read != 1 || len(result.Scanners[0].Images) != 2 || len(result.Findings) != 2 {
			t.Errorf("failure report lost evidence: %#v", result)
		}
		if strings.Contains(stdout.String()+stderr.String(), "SYNTHETIC_RAW_DIAGNOSTIC") {
			t.Error("raw error leaked")
		}
	}
}

func TestRunFailureWithoutReportEmitsNoJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--progress", "off"}, &stdout, &stderr, func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
		return report.Report{}, errors.New("runtime unavailable")
	})
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("no-evidence failure exit=%d stdout=%s", code, &stdout)
	}
}

func assertFailedReport(t *testing.T, data []byte, name string) {
	t.Helper()
	var result report.Report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed %s report JSON: %v", name, err)
	}
	if result.SchemaVersion != "1" || len(result.Scanners) != 1 || len(result.Findings) != 1 || bytes.Count(data, []byte("\n")) != 1 {
		t.Fatalf("failed %s report=%#v", name, result)
	}
	scanner := result.Scanners[0]
	if scanner.Name != name || scanner.Status != "failed" || scanner.Coverage.Read != 0 || scanner.Coverage.Failed == 0 {
		t.Errorf("failed scanner claims coverage: %#v", scanner)
	}
	if result.Findings[0].Kind != "error" || result.Findings[0].Message != "scanner failed" {
		t.Errorf("failure leaked noncanonical result: %#v", result.Findings)
	}
}
