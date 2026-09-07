// START_MODULE_CONTRACT
// PURPOSE: Verify actual server platform validation and preparation isolation.
// SCOPE: Fake daemon replies must never cause unsupported asset preparation or leak metadata.
// DEPENDS: internal/scanner/platform.go, internal/scanner/prepare.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-supported-environments
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestPlatformMetadataRejectsMissingAndHostileFields - Fail closed on invalid server metadata.
// TestPlatformPreparationPreservesPriorCache - Reject wholly unsupported preparation without publication.
// TestPlatformDirectCodeGuard - Stop direct code adapters before cache lookup or staging.
// TestRuntimePlatformServerJSON - Normalize Docker and Podman server metadata.
// TestPlatformCapabilities - Apply identical limits to engines and scanner aliases.
// TestPlatformPreparationMixed - Prepare only compatible engines and retain native no-op behavior.
// platformRuntime - Supply bounded synthetic daemon replies and record all commands.
// END_MODULE_MAP

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
)

func platformRuntime(t *testing.T, binary, data string) (container.Runtime, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	t.Setenv("SECSCAN_TEST_PLATFORM", data)
	t.Setenv("SECSCAN_PLATFORM_CALLS", log)
	path := filepath.Join(dir, binary)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$SECSCAN_PLATFORM_CALLS"
case "$1" in
version|info) printf '%s' "$SECSCAN_TEST_PLATFORM"; exit 0;;
pull) exit 0;;
image) printf 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; exit 0;;
esac
exit 99
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return container.Runtime{Binary: path}, log
}

func TestPlatformMetadataRejectsMissingAndHostileFields(t *testing.T) {
	for _, data := range []string{`{"Arch":"amd64"}`, `{"Os":"linux"}`, `{"Os":"CANARY","Arch":"amd64"}`, `{"Os":"linux","Arch":"CANARY"}`, `{"Os":"linux","Arch":"amd64\nCANARY"}`, `null`, `{"Server":{"Os":"linux","Arch":"amd64"}}`, strings.Repeat(" ", 64<<10) + `{"Os":"linux","Arch":"amd64"}`} {
		runtime, _ := platformRuntime(t, "docker", data)
		arch, err := RuntimeArchitecture(context.Background(), runtime)
		if err == nil || arch != "" || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("RuntimeArchitecture rejected metadata = %q, %v; want static validation error", arch, err)
		}
	}
}

func TestPlatformPreparationPreservesPriorCache(t *testing.T) {
	root := t.TempDir()
	if err := exec.Command("git", "-C", root, "init", "--quiet").Run(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ data, name, marker string }{
		{`{"Os":"linux","Arch":"arm64"}`, "bearer", "unsupported_runtime_arch"},
		{`{"Os":"windows","Arch":"amd64"}`, "gitleaks-history", "unsupported_runtime_os"},
		{`{"Os":"linux","Arch":"s390x"}`, "python-sast", "unsupported_runtime_arch"},
		{`{"Arch":"amd64"}`, "gitleaks", "invalid or missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime, log := platformRuntime(t, "docker", tc.data)
			cache := Cache{Root: t.TempDir()}
			prior := []byte("{\n}\n")
			path := filepath.Join(cache.Root, "manifest.json")
			if err := os.WriteFile(path, prior, 0600); err != nil {
				t.Fatal(err)
			}
			err := Update(context.Background(), runtime, cache, []string{tc.name, "refresh-versions"}, root)
			if err == nil || !strings.Contains(err.Error(), tc.marker) {
				t.Errorf("Update(%s) = %v; want %s", tc.name, err, tc.marker)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != string(prior) {
				t.Errorf("prior manifest changed: %q, %v", got, err)
			}
			calls, err := os.ReadFile(log)
			if err != nil || strings.TrimSpace(string(calls)) != "version --format {{json .Server}}" {
				t.Errorf("unsupported preparation commands = %q, %v; want only server query", calls, err)
			}
		})
	}
}

func TestRuntimePlatformServerJSON(t *testing.T) {
	for _, tc := range []struct{ binary, data, want, command string }{
		{"docker", `{"Os":"linux","Arch":"x86_64","Components":[{"Details":{"Os":"windows","Arch":"s390x"}}]}`, "linux/amd64", "version --format {{json .Server}}"},
		{"podman", `{"host":{"os":"linux","arch":"aarch64"},"version":{"Os":"darwin","Arch":"amd64"}}`, "linux/arm64", "info --format json"},
		{"docker", `{"Os":"windows","Arch":"amd64"}`, "windows/amd64", "version --format {{json .Server}}"},
	} {
		runtime, log := platformRuntime(t, tc.binary, tc.data)
		got, err := RuntimePlatform(context.Background(), runtime)
		if err != nil || got.String() != tc.want {
			t.Errorf("RuntimePlatform(%s) = %s, %v; want %s", tc.binary, got, err, tc.want)
		}
		calls, err := os.ReadFile(log)
		if err != nil || strings.TrimSpace(string(calls)) != tc.command {
			t.Errorf("RuntimePlatform(%s) commands = %q, %v; want %s", tc.binary, calls, err, tc.command)
		}
	}
}

func TestPlatformCapabilities(t *testing.T) {
	names := []string{"gitleaks", "opengrep", "gitleaks-history", "python-sast", "typescript-sast", "gradle-catalog", "gradle-scripts", "oci-images"}
	for name := range Catalog() {
		names = append(names, name)
	}
	for _, platform := range []Platform{{os: "linux", arch: "amd64"}, {os: "linux", arch: "arm64"}, {os: "linux", arch: "riscv64"}, {os: "windows", arch: "amd64"}} {
		for _, name := range names {
			reason := platform.UnsupportedReason(name)
			unsupported := platform.os != "linux" || platform.arch != "amd64" && (platform.arch != "arm64" || name == "bearer")
			if (reason != "") != unsupported || unsupported && (!strings.Contains(reason, platform.String()) || !strings.Contains(reason, "requires native linux/amd64")) {
				t.Errorf("UnsupportedReason(%s, %s) = %q; want unsupported=%t", platform, name, reason, unsupported)
			}
		}
		if got := platform.UnsupportedReason("refresh-versions"); got != "" {
			t.Errorf("native refresh-versions on %s = %q; want no runtime limitation", platform, got)
		}
	}
}

func TestPlatformPreparationMixed(t *testing.T) {
	root := t.TempDir()
	if err := exec.Command("git", "-C", root, "init", "--quiet").Run(); err != nil {
		t.Fatal(err)
	}
	runtime, log := platformRuntime(t, "docker", `{"Os":"linux","Arch":"arm64"}`)
	cache := Cache{Root: t.TempDir()}
	if err := Update(context.Background(), runtime, cache, []string{"bearer", "gitleaks", "gitleaks-history", "semgrep", "refresh-versions"}, root); err != nil {
		t.Fatal(err)
	}
	assets, err := cache.Load()
	if err != nil || len(assets) != 2 || assets["gitleaks"].ImageID == "" || assets["semgrep"].ImageID == "" {
		t.Fatalf("mixed preparation = %+v, %v; want only Gitleaks and Semgrep", assets, err)
	}
	calls, err := os.ReadFile(log)
	if err != nil || strings.Count(string(calls), "version --format") != 1 || strings.Count(string(calls), "pull ") != 2 || strings.Contains(string(calls), "bearer") || strings.Contains(string(calls), "build") || strings.Contains(string(calls), "--platform") {
		t.Errorf("mixed preparation commands = %q, %v", calls, err)
	}
	if err := Update(context.Background(), container.Runtime{}, Cache{Root: "missing"}, []string{"refresh-versions"}, root); err != nil {
		t.Errorf("container-free preparation = %v; want no runtime or cache required", err)
	}
}

func TestPlatformDirectCodeGuard(t *testing.T) {
	for _, name := range []string{"semgrep", "cppcheck", "bearer"} {
		runtime, log := platformRuntime(t, "docker", `{"Os":"windows","Arch":"amd64"}`)
		files := []string{"unread.py"}
		got, findings, err := ScanCode(context.Background(), runtime, Cache{}, name, "missing", files, func(progress.Event) {})
		if err != nil || got.Status != "skipped" || len(findings) != 0 || got.Coverage.Read != 0 || !slices.Equal(got.Coverage.UnreadInputs, files) || !strings.Contains(strings.Join(got.Limitations, " "), "unsupported_runtime_os") {
			t.Errorf("ScanCode(%s, windows) = %+v, %v; want unread skip", name, got, err)
		}
		calls, err := os.ReadFile(log)
		if err != nil || strings.TrimSpace(string(calls)) != "version --format {{json .Server}}" {
			t.Errorf("direct unsupported calls = %q, %v; want only server query", calls, err)
		}
	}
}
