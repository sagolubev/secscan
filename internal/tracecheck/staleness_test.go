package tracecheck

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateStaleness(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, map[string]any)
	}{
		{name: "missing record", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			delete(artifacts, "design.md")
		}},
		{name: "extra record", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			artifacts["removed.md"] = artifacts["design.md"]
		}},
		{name: "missing artifact", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			if err := os.Remove(filepath.Join(root, "design.md")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hash mismatch", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			writeStaleFixture(t, root, "proposal.md", []byte("changed"))
		}},
		{name: "new spec", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			writeStaleFixture(t, root, "specs/new/spec.md", []byte("new"))
		}},
		{name: "missing dependency", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			artifacts["design.md"].(map[string]any)["depends_on"] = []string{}
		}},
		{name: "extra dependency", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			artifacts["design.md"].(map[string]any)["depends_on"] = []string{"proposal.md", "missing.md"}
		}},
		{name: "missing dependency metadata", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			delete(artifacts["proposal.md"].(map[string]any), "depends_on")
		}},
		{name: "unknown field", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			artifacts["design.md"].(map[string]any)["unknown"] = true
		}},
		{name: "upstream synced after dependent", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			artifacts["design.md"].(map[string]any)["synced_at"] = "2026-09-01T00:00:00Z"
		}},
		{name: "symlink artifact", mutate: func(t *testing.T, root string, artifacts map[string]any) {
			path := filepath.Join(root, "proposal.md")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, state := staleFixture(t)
			if err := ValidateStaleness(root); err != nil {
				t.Fatalf("ValidateStaleness(valid fixture) = %v", err)
			}
			test.mutate(t, root, state["artifacts"].(map[string]any))
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			writeStaleFixture(t, root, ".stale.json", data)
			if err := ValidateStaleness(root); err == nil {
				t.Errorf("ValidateStaleness(%s) = nil, want rejection", test.name)
			}
		})
	}
}

func TestValidateStalenessRejectsMissingAndMalformedState(t *testing.T) {
	for _, data := range []string{"", "{}", `{"version":2}`, `{"version":1} {}`} {
		root, _ := staleFixture(t)
		writeStaleFixture(t, root, ".stale.json", []byte(data))
		if err := ValidateStaleness(root); err == nil {
			t.Errorf("ValidateStaleness(%q) = nil, want rejection", data)
		}
	}
	if err := ValidateStaleness(t.TempDir()); err == nil {
		t.Error("ValidateStaleness(missing state) = nil, want rejection")
	}
}

func staleFixture(t *testing.T) (string, map[string]any) {
	t.Helper()
	root := t.TempDir()
	artifacts := make(map[string]any)
	for path, deps := range map[string][]string{
		"proposal.md": {}, "design.md": {"proposal.md"}, "specs/secscan/spec.md": {"design.md"},
	} {
		data := []byte(path + "\n")
		writeStaleFixture(t, root, path, data)
		artifacts[path] = map[string]any{
			"sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "synced_at": "2026-09-06T00:00:00Z", "depends_on": deps,
		}
	}
	state := map[string]any{"version": 1, "updated_at": "2026-09-06T00:00:00Z", "artifacts": artifacts}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	writeStaleFixture(t, root, ".stale.json", data)
	return root, state
}

func writeStaleFixture(t *testing.T, root, path string, data []byte) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
