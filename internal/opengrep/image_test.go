package opengrep

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBuildArgsUsePinnedDefinition(t *testing.T) {
	root := "/repo"
	assets := "/cache/opengrep"
	args := BuildArgs(root, assets)

	for _, required := range []string{
		"build",
		"--pull=false",
		"--provenance=false",
		"--build-context", "opengrep-assets=" + assets,
		"--tag", ImageTag,
		"--file", filepath.Join(root, "scanner", "opengrep", "Dockerfile"),
		root,
	} {
		if !slices.Contains(args, required) {
			t.Errorf("BuildArgs() missing %q: %q", required, args)
		}
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
