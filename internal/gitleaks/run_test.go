package gitleaks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/report"
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

	got, err := Scan(context.Background(), runtime, repository)
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
