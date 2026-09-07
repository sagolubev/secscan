// START_MODULE_CONTRACT
// PURPOSE: Verify pinned image inputs, portable context arguments and immutable private staging.
// SCOPE: Synthetic assets; native CLI acceptance verifies the actual Docker and Podman builds.
// DEPENDS: internal/opengrep/image.go, scanner/opengrep/assets/Dockerfile
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-container-runtime, cmd/secscan/render_test.go#TestAcceptanceRenderedReports
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestBuildArgsUsePinnedDefinition - Use one local context with pinned build metadata.
// TestEmbeddedRulePackMatchesConstants - Check embedded rule identity.
// TestRulePackMetadataIsDeterministic - Keep rule hashing stable.
// TestParseImageMetadata - Reject mutable image tags.
// TestEnsureImageAlwaysBuildsBeforeTrustingTag - Verify every preparation rebuilds.
// TestBuildContextsArePrivateAndStable - Keep concurrent contexts independent.
// END_MODULE_MAP

package opengrep

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	scannerassets "github.com/sagolubev/secscan/scanner/opengrep/assets"
)

type fakeImageRuntime struct {
	builds int
	output []byte
}

func (runtime *fakeImageRuntime) RunDiagnostic(context.Context, []string) error {
	runtime.builds++
	return nil
}

func (runtime *fakeImageRuntime) Output(context.Context, ...string) ([]byte, error) {
	return runtime.output, nil
}

func TestBuildArgsUsePinnedDefinition(t *testing.T) {
	assets := "/cache/opengrep"
	args := BuildArgs(assets)

	for _, required := range []string{
		"build",
		"--pull=false",
		"--provenance=false",
		"--tag", ImageTag,
		"--file", filepath.Join(assets, "Dockerfile"),
		assets,
	} {
		if !slices.Contains(args, required) {
			t.Errorf("BuildArgs() missing %q: %q", required, args)
		}
	}
	if slices.Contains(args, "--build-context") {
		t.Fatal("image build requires a named context unsupported by Podman FROM")
	}
}

func TestEmbeddedRulePackMatchesConstants(t *testing.T) {
	root := t.TempDir()
	if err := fs.WalkDir(scannerassets.Files, "rules", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := scannerassets.Files.ReadFile(path)
		if err != nil {
			return err
		}
		target := filepath.Join(root, filepath.Base(path))
		return os.WriteFile(target, content, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	got, err := RulePackMetadata(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != RulePackDigest || got.RuleCount != RuleCount {
		t.Errorf("embedded rule metadata = %#v, want digest %s and count %d", got, RulePackDigest, RuleCount)
	}
}

func TestRulePackMetadataIsDeterministic(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "b.yml"), []byte("rules:\n  - id: b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.yaml"), []byte("rules:\n  - id: a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := RulePackMetadata(root)
	if err != nil {
		t.Fatalf("RulePackMetadata() error = %v", err)
	}
	second, err := RulePackMetadata(root)
	if err != nil {
		t.Fatalf("RulePackMetadata() second error = %v", err)
	}
	if first != second {
		t.Errorf("RulePackMetadata() = %#v, then %#v", first, second)
	}
	if first.RuleCount != 2 || len(first.Digest) != 64 {
		t.Errorf("RulePackMetadata() = %#v, want 2 rules and SHA-256", first)
	}
}

func TestParseImageMetadata(t *testing.T) {
	got, err := ParseImageMetadata([]byte(
		"sha256:0123456789abcdef 1.29.0 6389f1f651ceaa52527e17a7ed0675f2c0b2c1933ede4f3e80ac167b886851e8\n",
	))
	if err != nil {
		t.Fatalf("ParseImageMetadata() error = %v", err)
	}
	if got.ID != "sha256:0123456789abcdef" || got.EngineVersion != "1.29.0" ||
		got.RuleDigest != RulePackDigest {
		t.Errorf("ParseImageMetadata() = %#v", got)
	}

	if _, err := ParseImageMetadata([]byte("secscan-opengrep:latest")); err == nil {
		t.Fatal("ParseImageMetadata() accepted mutable tag")
	}
}

func TestEnsureImageAlwaysBuildsBeforeTrustingTag(t *testing.T) {
	runtime := &fakeImageRuntime{
		output: []byte(
			"sha256:0123456789abcdef 1.29.0 6389f1f651ceaa52527e17a7ed0675f2c0b2c1933ede4f3e80ac167b886851e8\n",
		),
	}

	id, err := ensureImage(context.Background(), runtime, t.TempDir())
	if err != nil {
		t.Fatalf("ensureImage() error = %v", err)
	}
	if runtime.builds != 1 {
		t.Errorf("ensureImage() builds = %d, want 1", runtime.builds)
	}
	if id != "sha256:0123456789abcdef" {
		t.Errorf("ensureImage() ID = %q", id)
	}
}

func TestBuildContextsArePrivateAndStable(t *testing.T) {
	assets := t.TempDir()
	for _, name := range []string{"opengrep-amd64", "opengrep-arm64", "OPENGREP-LICENSE"} {
		if err := os.WriteFile(filepath.Join(assets, name), []byte("synthetic "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		path string
		err  error
	}
	const builds = 8
	results := make(chan result, builds) // One bounded result per concurrent preparation.
	for i := 0; i < builds; i++ {
		go func() { path, err := stageBuildContext(assets); results <- result{path, err} }()
	}
	seen := make(map[string]bool)
	for i := 0; i < builds; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("prepare concurrent build: %v", r.err)
			continue
		}
		if r.path == assets || seen[r.path] {
			t.Errorf("shared build context %q", r.path)
		}
		seen[r.path] = true
	}
	for path := range seen {
		for _, arch := range []string{"amd64", "arm64"} {
			license := filepath.Join(path, "rootfs-"+arch, "etc", "OPENGREP-LGPL-2.1.txt")
			data, err := os.ReadFile(license)
			if err != nil || string(data) != "synthetic OPENGREP-LICENSE" {
				t.Errorf("build context mutated by another preparation: %q, %v", data, err)
			}
			info, err := os.Stat(license)
			if err != nil || info.Mode().Perm() != 0444 {
				t.Errorf("license permissions changed: %v", err)
			}
		}
		if !strings.HasPrefix(path, assets+string(filepath.Separator)) {
			t.Errorf("context outside cache: %q", path)
		}
	}
}
