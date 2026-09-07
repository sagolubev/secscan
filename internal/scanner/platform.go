// START_MODULE_CONTRACT
// PURPOSE: Match pinned engines to the actual container server platform.
// SCOPE: Validate bounded daemon metadata; never infer host support or enable emulation.
// DEPENDS: internal/container/runtime.go, internal/scanner/catalog.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-supported-environments, internal/scanner/platform_test.go#TestPlatformMetadataRejectsMissingAndHostileFields
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Platform - Retain validated daemon OS and architecture.
// Platform.String - Describe the actual normalized server platform.
// Platform.UnsupportedReason - Apply the shared finite engine capability policy.
// RuntimePlatform - Read and validate Docker or Podman server metadata.
// RuntimeArchitecture - Preserve the architecture-only caller API with strict platform validation.
// EngineNames - Resolve scanner personas to their prepared engine keys.
// END_MODULE_MAP

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sagolubev/secscan/internal/container"
)

// Platform contains validated server metadata, independent of the CLI host.
type Platform struct {
	os   string
	arch string
}

// String returns the normalized OS/architecture pair.
func (p Platform) String() string { return p.os + "/" + p.arch }

// UnsupportedReason is empty only for compatible engines or container-free work.
func (p Platform) UnsupportedReason(name string) string {
	if len(EngineNames(name)) == 0 {
		return ""
	}
	if p.os == "" || p.arch == "" {
		return "invalid_runtime_platform: server OS and architecture are required"
	}
	required := "linux/amd64 or linux/arm64"
	if name == "bearer" {
		required = "linux/amd64"
	}
	marker := ""
	if p.os != "linux" {
		marker = "unsupported_runtime_os"
	} else if p.arch != "amd64" && p.arch != "arm64" || name == "bearer" && p.arch != "amd64" {
		marker = "unsupported_runtime_arch"
	}
	if marker == "" {
		return ""
	}
	return marker + ": requires native " + required + "; actual " + p.String() + "; emulation disabled"
}

// RuntimePlatform reads the actual server, including remote Docker and Podman.
// Arbitrary daemon fields and diagnostics never become report text.
func RuntimePlatform(ctx context.Context, runtime container.Runtime) (Platform, error) {
	args := []string{"version", "--format", "{{json .Server}}"}
	podman := strings.Contains(filepath.Base(runtime.Binary), "podman")
	if podman {
		args = []string{"info", "--format", "json"}
	}
	data, err := runtime.Output(ctx, args...)
	if err != nil {
		return Platform{}, fmt.Errorf("container server platform unavailable: %w", err)
	}
	var server struct {
		OS   string `json:"Os"`
		Arch string `json:"Arch"`
		Host struct {
			OS   string `json:"os"`
			Arch string `json:"arch"`
		} `json:"host"`
	}
	if len(data) > 64<<10 || json.Unmarshal(data, &server) != nil {
		return Platform{}, fmt.Errorf("invalid container server platform metadata")
	}
	p := Platform{os: server.OS, arch: server.Arch}
	if podman {
		p = Platform{os: server.Host.OS, arch: server.Host.Arch}
	}
	switch p.arch {
	case "x86_64":
		p.arch = "amd64"
	case "aarch64":
		p.arch = "arm64"
	}
	// Known platform tokens allow precise unsupported-platform disclosure without
	// reflecting arbitrary server strings, credentials or terminal control bytes.
	if !slices.Contains([]string{"linux", "windows", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly", "solaris", "illumos", "aix", "android", "ios", "plan9", "js", "wasip1"}, p.os) ||
		!slices.Contains([]string{"amd64", "arm64", "386", "arm", "ppc64", "ppc64le", "s390x", "riscv64", "mips", "mipsle", "mips64", "mips64le", "loong64", "wasm"}, p.arch) {
		return Platform{}, fmt.Errorf("invalid or missing container server OS or architecture")
	}
	return p, nil
}

// RuntimeArchitecture reads validated server metadata for legacy callers.
func RuntimeArchitecture(ctx context.Context, runtime container.Runtime) (string, error) {
	p, err := RuntimePlatform(ctx, runtime)
	return p.arch, err
}

// EngineNames maps scanner personas to their prepared engines; native-only work
// has no engines. CLI selection validation owns the finite set of persona names.
func EngineNames(name string) []string {
	switch name {
	case "refresh-versions":
		return nil
	case "gitleaks-history":
		return []string{"gitleaks"}
	case "python-sast", "typescript-sast":
		return []string{"opengrep"}
	case "gradle-catalog", "gradle-scripts":
		return []string{"osv-scanner"}
	case "oci-images":
		return []string{"trivy", "grype"}
	default:
		return []string{name}
	}
}
