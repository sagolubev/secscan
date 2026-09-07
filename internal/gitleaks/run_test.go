// START_MODULE_CONTRACT
// PURPOSE: Verify Gitleaks process, output and cleanup boundaries.
// SCOPE: Real container acceptance and synthetic unsafe reports or runtime diagnostics.
// DEPENDS: internal/gitleaks/run.go, internal/gitleaks/history.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestContainerArgsEnforceSecurityBoundary - Keep the working-tree container isolated.
// TestAcceptanceContainerScanRedactsSecret - Verify real scanner redaction.
// TestCreateReportDirUsesUserCache - Use Docker-shareable private output paths.
// TestReadReportRejectsSymlinksAndOversize - Reject unsafe report files.
// TestHistoryScanRejectsZeroExitGitDiagnostics - Reject false clean results without raw error text.
// TestHistoryScanCleanResultAndCancellationCleanup - Accept clean arrays and remove owned files on cancellation.
// END_MODULE_MAP

package gitleaks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func TestContainerArgsEnforceSecurityBoundary(t *testing.T) {
	args := ContainerArgs("/repo", "/tmp/report")

	for _, required := range []string{
		"--rm",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"type=bind,src=/repo,dst=/repo,readonly",
		"dir", "/repo",
		"--redact=100",
		"--exit-code", "0",
	} {
		if !slices.Contains(args, required) {
			t.Errorf("ContainerArgs() missing %q: %q", required, args)
		}
	}
	for _, forbidden := range []string{"/var/run/docker.sock", "sh", "-c"} {
		if slices.Contains(args, forbidden) {
			t.Errorf("ContainerArgs() contains forbidden argument %q", forbidden)
		}
	}
}

func TestAcceptanceContainerScanRedactsSecret(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 to run container acceptance")
	}
	runtime, err := container.DetectDefault(context.Background())
	if err != nil {
		t.Fatalf("DetectDefault() error = %v", err)
	}

	repository, err := createReportDir(os.UserCacheDir)
	if err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(repository) })
	canary := strings.Join([]string{"gl", "pat-", "0123456789", "AbCdEfGhIj"}, "")
	if err := os.WriteFile(filepath.Join(repository, "canary.txt"), []byte("token="+canary+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Scan(context.Background(), runtime, repository, func(progress.Event) {})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got.Findings) == 0 {
		t.Fatal("Scan() returned no findings for synthetic canary")
	}
	if len(got.Scanners) != 1 || got.Scanners[0].Coverage.Read != 1 || got.Scanners[0].Coverage.Unit != "repository" {
		t.Errorf("Scan() coverage = %#v, want one repository read", got.Scanners)
	}
	data, err := report.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), canary) {
		t.Fatal("Scan() report contains synthetic secret")
	}
}

func TestCreateReportDirUsesUserCache(t *testing.T) {
	cache := t.TempDir()
	path, err := createReportDir(func() (string, error) { return cache, nil })
	if err != nil {
		t.Fatalf("createReportDir() error = %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(path) })

	wantParent := filepath.Join(cache, "secscan")
	if filepath.Dir(path) != wantParent {
		t.Errorf("createReportDir() parent = %q, want %q", filepath.Dir(path), wantParent)
	}
}

func TestReadReportRejectsSymlinksAndOversize(t *testing.T) {
	for _, mode := range []string{"symlink", "directory", "oversize", "regular"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			name := filepath.Join(dir, "gitleaks.json")
			switch mode {
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("[]"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, name); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(name, 0o700); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				f, err := os.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate((64 << 20) + 1); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			case "regular":
				if err := os.WriteFile(name, []byte("[]"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			data, err := readReport(name)
			if mode == "regular" {
				if err != nil || string(data) != "[]" {
					t.Errorf("readReport(regular) = %q, %v", data, err)
				}
			} else if err == nil {
				t.Errorf("readReport(%s) accepted unsafe report", mode)
			}
		})
	}
}

func TestHistoryScanRejectsZeroExitGitDiagnostics(t *testing.T) {
	dir, _, _ := historyFixture(t)
	for _, marker := range []string{"fatal", "ERR", "[git]", "error="} {
		t.Run(marker, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "runtime")
			script := "#!/bin/sh\nprintf '%s\\n' '" + marker + " SYNTHETIC_DIAGNOSTIC' >&2\nexit 0\n"
			if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			_, err := ScanHistory(context.Background(), container.Runtime{Binary: binary}, dir, func(progress.Event) {}, Image)
			if err == nil || strings.Contains(err.Error(), "SYNTHETIC_DIAGNOSTIC") {
				t.Errorf("ScanHistory(%q) = %v; want sanitized failure", marker, err)
			}
		})
	}
}

func TestHistoryScanCleanResultAndCancellationCleanup(t *testing.T) {
	dir, _, _ := historyFixture(t)
	for _, cancelled := range []bool{false, true} {
		name := "clean"
		if cancelled {
			name = "cancelled"
		}
		t.Run(name, func(t *testing.T) {
			bin := t.TempDir()
			marker := filepath.Join(bin, "output-directory")
			t.Setenv("SECSCAN_TEST_OUTPUT_DIR", marker)
			script := `#!/bin/sh
for arg do
  case "$arg" in
    type=bind,src=*,dst=/out) output="${arg#type=bind,src=}"; output="${output%,dst=/out}" ;;
  esac
done
printf '%s' "$output" > "$SECSCAN_TEST_OUTPUT_DIR"
printf '[]' > "$output/gitleaks.json"
`
			binary := filepath.Join(bin, "runtime")
			if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			got, err := ScanHistory(ctx, container.Runtime{Binary: binary}, dir, func(event progress.Event) {
				if cancelled && event.Stage == progress.StageReading {
					cancel()
				}
			}, Image)
			if cancelled {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("ScanHistory(cancel) = %v, want context.Canceled", err)
				}
			} else if err != nil || len(got.Scanners) != 1 || got.Scanners[0].Coverage.Read != 1 || len(got.Findings) != 0 {
				t.Errorf("ScanHistory(clean) = %+v, %v; want clean repository completion", got, err)
			}
			output, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Dir(string(output))); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("ScanHistory(%s) left owned workspace: %v", name, err)
			}
		})
	}
}
