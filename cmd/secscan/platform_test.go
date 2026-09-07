// START_MODULE_CONTRACT
// PURPOSE: Verify platform skips preserve native work, selected paths and coverage.
// SCOPE: Synthetic daemon platforms; no unsupported engine may inspect, pull, build or run.
// DEPENDS: cmd/secscan/main.go, internal/scanner/platform.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-supported-environments
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestPlatformSkipsPreserveScopesAndNativeSibling - Keep original coverage routes after platform filtering.
// TestPlatformHistoryAndMalformedMetadata - Preserve history units and independent native work.
// TestPlatformAliasesAndOCI - Gate all selected aliases and keep OCI consent disclosure accurate.
// TestPlatformRulePackRoute - Preserve custom-language scoped unread inputs.
// TestPlatformMixedCompatibleScan - Reuse one query and retain a successful compatible engine.
// TestPlatformNativeUpdateWithoutRuntime - Keep native preparation container-free.
// TestAcceptancePlatform - Execute a small real supported engine on the detected native server.
// platformCLI - Install a fake daemon with static metadata and a command ledger.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/rules"
	"github.com/sagolubev/secscan/internal/scanner"
)

func platformCLI(t *testing.T, data string) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(git, filepath.Join(dir, "git")); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls")
	t.Setenv("SECSCAN_PLATFORM_CALLS", log)
	t.Setenv("SECSCAN_TEST_PLATFORM", data)
	t.Setenv("PATH", dir)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$SECSCAN_PLATFORM_CALLS"
case "$1" in
info) printf '[]'; exit 0;;
version) printf '%s' "$SECSCAN_TEST_PLATFORM"; exit 0;;
pull) exit 0;;
image) printf 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; exit 0;;
run) case "$*" in *"semgrep scan"*) printf '{"version":"1.176.0","results":[],"errors":[],"paths":{"scanned":["/target/app.py"]}}'; exit 0;; esac;;
esac
exit 99
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return log
}

func TestPlatformAliasesAndOCI(t *testing.T) {
	root := exportTestRepository(t)
	for name, data := range map[string]string{"app.py": "print('fixture')", "app.ts": "const n=1", "app.cpp": "int main(){}", "libs.versions.toml": "[versions]\n", "build.gradle.kts": "dependencies {}", "Dockerfile": "FROM example.invalid/synthetic:1\n", "main.tf": "resource \"synthetic\" \"fixture\" {}", "package-lock.json": "{}", ".github/workflows/ci.yml": "on: push\njobs: {}"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	log := platformCLI(t, `{"Os":"windows","Arch":"amd64"}`)
	selection, err := parseScannerSelection("all")
	if err != nil {
		t.Fatal(err)
	}
	selection = append(selection, "gitleaks-history", "oci-images")
	result, err := scan(context.Background(), root, scanOptions{Scanners: selection}, func(progress.Event) {})
	if err != nil || len(result.Scanners) != len(selection) {
		t.Fatalf("all aliases on Windows = %+v, %v", result, err)
	}
	for _, s := range result.Scanners {
		if s.Status != "skipped" || s.Coverage.Read != 0 {
			t.Errorf("unsupported alias ran: %+v", s)
		}
		if s.Name != "refresh-versions" && !strings.Contains(strings.Join(s.Limitations, " "), "unsupported_runtime_os") {
			t.Errorf("alias lacks platform skip: %+v", s)
		}
		if s.Name == "oci-images" && (len(s.Images) != 1 || s.Coverage.Unit != "images" || s.Coverage.Unread != 1 || !slices.Contains(s.Coverage.UnreadInputs, "Dockerfile") || strings.Contains(strings.Join(s.Limitations, " "), "image scanning disabled")) {
			t.Errorf("authorized OCI platform skip = %+v", s)
		}
	}
	calls, err := os.ReadFile(log)
	if err != nil || string(calls) != "info --format {{json .SecurityOptions}}\nversion --format {{json .Server}}\n" {
		t.Errorf("alias gate runtime calls = %q, %v; want no engine operations", calls, err)
	}
}

func TestPlatformRulePackRoute(t *testing.T) {
	root := exportTestRepository(t)
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := rulePackFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "custom.yml"), []byte("rules:\n- id: forbidden-go\n  languages: [go]\n  message: unsafe\n  severity: ERROR\n  pattern: forbidden($X)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pack, err := rules.Import(context.Background(), t.TempDir(), dir)
	if err != nil {
		t.Fatal(err)
	}
	platformCLI(t, `{"Os":"linux","Arch":"s390x"}`)
	result, err := scan(context.Background(), root, scanOptions{Scanners: []string{"semgrep"}, Scopes: []string{"app.go"}, RulePack: &pack}, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 1 || result.Scanners[0].Status != "skipped" || !slices.Equal(result.Scanners[0].Coverage.UnreadInputs, []string{"app.go"}) || len(result.UncheckedInputs) != 1 || result.UncheckedInputs[0].Reason != "no_successful_analysis" {
		t.Fatalf("custom-language platform route = %+v, %v", result, err)
	}
}

func TestPlatformMixedCompatibleScan(t *testing.T) {
	root := exportTestRepository(t)
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("print('fixture')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	log := platformCLI(t, `{"Os":"linux","Arch":"arm64"}`)
	if code := run(context.Background(), []string{"update", "--scanners", "semgrep,bearer", root}, &bytes.Buffer{}, &bytes.Buffer{}, scan); code != 0 {
		t.Fatalf("mixed compatible update exit = %d; want 0", code)
	}
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := scan(context.Background(), root, scanOptions{Scanners: []string{"semgrep", "bearer"}}, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 2 || len(result.UncheckedInputs) != 0 {
		t.Fatalf("compatible sibling scan = %+v, %v", result, err)
	}
	for _, s := range result.Scanners {
		if s.Name == "semgrep" && (s.Status != "success" || s.Coverage.Read != 1) || s.Name == "bearer" && (s.Status != "skipped" || s.Coverage.Unread != 1 || s.EngineVersion != scanner.Catalog()["bearer"].Version) {
			t.Errorf("compatible sibling outcome = %+v", s)
		}
	}
	calls, err := os.ReadFile(log)
	if err != nil || strings.Count(string(calls), "version --format") != 1 || strings.Count(string(calls), "run --name") != 1 || strings.Contains(string(calls), "bearer") || strings.Contains(string(calls), "--platform") || strings.Contains(string(calls), "pull ghcr") {
		t.Errorf("mixed scan calls = %q, %v; want one query and one compatible engine", calls, err)
	}
}

func TestPlatformNativeUpdateWithoutRuntime(t *testing.T) {
	root := exportTestRepository(t)
	log := platformCLI(t, "invalid")
	var diagnostics bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", "refresh-versions", root}, &bytes.Buffer{}, &diagnostics, scan); code != 0 {
		t.Fatalf("native preparation exit=%d diagnostics=%s; want no runtime dependency", code, &diagnostics)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Errorf("native preparation queried runtime; stat=%v", err)
	}
}

func TestAcceptancePlatform(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for a native server platform check")
	}
	ctx := context.Background()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	platform, err := scanner.RuntimePlatform(ctx, runtime)
	if err != nil || platform.UnsupportedReason("gitleaks") != "" {
		t.Fatalf("native acceptance platform = %s, %v; want supported Linux server", platform, err)
	}
	t.Logf("native platform: %s", platform)
	root := exportTestRepository(t)
	if err := os.WriteFile(filepath.Join(root, "fixture.txt"), []byte("synthetic platform fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	if code := run(ctx, []string{"update", "--scanners", "gitleaks", root}, &bytes.Buffer{}, &diagnostics, scan); code != 0 {
		t.Fatalf("native platform preparation exit=%d diagnostics=%s", code, &diagnostics)
	}
	result, err := scan(ctx, root, scanOptions{Scanners: []string{"gitleaks"}}, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 1 || result.Scanners[0].Status != "success" || result.Scanners[0].Coverage.Read != 1 {
		t.Fatalf("native platform scan = %+v, %v", result, err)
	}
}

func TestPlatformSkipsPreserveScopesAndNativeSibling(t *testing.T) {
	root := exportTestRepository(t)
	for name, data := range map[string]string{"app.py": "eval(input())\n", "outside.py": "print('outside')\n", "build.gradle.kts": "dependencies { implementation(\"org.example:lib:1\") }\n", "versions.properties": "version.synthetic=1\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	log := platformCLI(t, `{"Os":"linux","Arch":"s390x"}`)
	selection := []string{"python-sast", "bearer", "gradle-scripts", "refresh-versions"}
	result, err := scan(context.Background(), root, scanOptions{Scanners: selection, Scopes: []string{"app.py"}}, func(progress.Event) {})
	if err != nil || len(result.Scanners) != 4 || result.Scope == nil || result.Scope.SelectedFiles != 1 {
		t.Fatalf("unsupported platform with scope = %+v, %v", result, err)
	}
	for _, s := range result.Scanners {
		if s.Name == "refresh-versions" {
			if s.Status != "success" || s.Coverage.Read != 1 {
				t.Errorf("native sibling = %+v; want success", s)
			}
			continue
		}
		want := []string{"app.py"}
		if s.Name == "bearer" {
			want = append(want, "outside.py")
		}
		if s.Name == "gradle-scripts" {
			want = []string{"build.gradle.kts"}
		}
		if s.Status != "skipped" || s.Coverage.Read != 0 || !slices.Equal(s.Coverage.UnreadInputs, want) || s.Scope == nil || s.Scope.CandidateFiles != len(want) || !strings.Contains(strings.Join(s.Limitations, " "), "linux/s390x") {
			t.Errorf("platform skip = %+v; want unread %v", s, want)
		}
	}
	for _, gap := range result.UncheckedInputs {
		if gap.Reason == "scanner_not_selected" {
			t.Errorf("original selection lost: %+v", gap)
		}
	}
	calls, err := os.ReadFile(log)
	if err != nil || string(calls) != "info --format {{json .SecurityOptions}}\nversion --format {{json .Server}}\n" {
		t.Errorf("unsupported runtime calls = %q, %v; want only detection and one server query", calls, err)
	}
}

func TestPlatformHistoryAndMalformedMetadata(t *testing.T) {
	for _, data := range []string{`{"Os":"windows","Arch":"amd64"}`, `{"Arch":"amd64"}`, `{"Os":"linux","Arch":"CANARY"}`} {
		t.Run(data, func(t *testing.T) {
			root := exportTestRepository(t)
			if err := os.WriteFile(filepath.Join(root, "versions.properties"), []byte("version.synthetic=1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			log := platformCLI(t, data)
			result, err := scan(context.Background(), root, scanOptions{Scanners: []string{"gitleaks-history", "refresh-versions"}}, func(progress.Event) {})
			if err != nil || len(result.Scanners) != 2 {
				t.Fatalf("platform history with native = %+v, %v", result, err)
			}
			for _, s := range result.Scanners {
				if s.Name == "refresh-versions" && s.Status != "success" {
					t.Errorf("native sibling lost = %+v", s)
				}
				if s.Name == "gitleaks-history" {
					want := "failed"
					if strings.Contains(data, "windows") {
						want = "skipped"
					}
					if s.Status != want || s.Coverage.Unit != "repository" || s.Coverage.Read != 0 || s.History != nil || strings.Contains(strings.Join(s.Limitations, " "), "CANARY") {
						t.Errorf("history outcome = %+v; want %s with no invented commit evidence", s, want)
					}
				}
			}
			calls, err := os.ReadFile(log)
			if err != nil || string(calls) != "info --format {{json .SecurityOptions}}\nversion --format {{json .Server}}\n" {
				t.Errorf("history unsupported calls = %q, %v", calls, err)
			}
			if !strings.Contains(data, "windows") {
				result, err = scan(context.Background(), root, scanOptions{Scanners: []string{"gitleaks-history"}}, func(progress.Event) {})
				if err == nil || result.SchemaVersion != "" {
					t.Errorf("malformed required platform = %+v, %v; want preflight failure without report", result, err)
				}
			}
		})
	}
}
