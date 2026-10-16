// START_MODULE_CONTRACT
// PURPOSE: Verify strict legacy and br-flow staleness graph validation.
// SCOPE: Synthetic metadata only; no external opsx-stale invocation.
// DEPENDS: internal/tracecheck/staleness.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability, internal/tracecheck/staleness_test.go#TestValidateStalenessV2
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestValidateStaleness - Reject legacy drift and malformed artifacts.
// TestValidateStalenessV2 - Reject br-flow graph and upstream digest drift.
// TestValidateStalenessV2AdditionalMarkdown - Include every Markdown artifact.
// TestValidateStalenessV1RejectsV2Fields - Keep legacy metadata strict.
// TestValidateStalenessRejectsMissingAndMalformedState - Reject absent state.
// staleFixture - Build a synchronized legacy fixture.
// writeStaleFixture - Store synthetic artifact bytes.
// END_MODULE_MAP

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

func TestValidateStalenessV2(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "valid"},
		{name: "unknown graph", mutate: func(state map[string]any) { state["graph"] = "legacy" }},
		{name: "wrong dependency", mutate: func(state map[string]any) {
			state["artifacts"].(map[string]any)["design.md"].(map[string]any)["depends_on"] = []string{"proposal.md"}
		}},
		{name: "missing upstream metadata", mutate: func(state map[string]any) {
			delete(state["artifacts"].(map[string]any)["design.md"].(map[string]any), "upstream_sha256")
		}},
		{name: "stale upstream hash", mutate: func(state map[string]any) {
			state["artifacts"].(map[string]any)["specs/secscan/spec.md"].(map[string]any)["upstream_sha256"] = map[string]string{"proposal.md": "stale"}
		}},
		{name: "extra upstream hash", mutate: func(state map[string]any) {
			state["artifacts"].(map[string]any)["specs/secscan/spec.md"].(map[string]any)["upstream_sha256"] = map[string]string{"proposal.md": state["artifacts"].(map[string]any)["proposal.md"].(map[string]any)["sha256"].(string), "extra.md": "stale"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, state := staleFixture(t)
			artifacts := state["artifacts"].(map[string]any)
			state["version"] = 2
			state["graph"] = "br-flow"
			artifacts["proposal.md"].(map[string]any)["upstream_sha256"] = map[string]string{}
			artifacts["specs/secscan/spec.md"].(map[string]any)["depends_on"] = []string{"proposal.md"}
			artifacts["specs/secscan/spec.md"].(map[string]any)["upstream_sha256"] = map[string]string{"proposal.md": artifacts["proposal.md"].(map[string]any)["sha256"].(string)}
			artifacts["design.md"].(map[string]any)["depends_on"] = []string{"specs/**"}
			artifacts["design.md"].(map[string]any)["upstream_sha256"] = map[string]string{"specs/secscan/spec.md": artifacts["specs/secscan/spec.md"].(map[string]any)["sha256"].(string)}
			if test.mutate != nil {
				test.mutate(state)
			}
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			writeStaleFixture(t, root, ".stale.json", data)
			err = ValidateStaleness(root)
			if test.mutate == nil && err != nil {
				t.Errorf("ValidateStaleness(v2 valid) = %v, want nil", err)
			}
			if test.mutate != nil && err == nil {
				t.Errorf("ValidateStaleness(v2 %s) = nil, want rejection", test.name)
			}
		})
	}
}

func TestValidateStalenessV2AdditionalMarkdown(t *testing.T) {
	root, state := staleFixture(t)
	artifacts := state["artifacts"].(map[string]any)
	state["version"] = 2
	state["graph"] = "br-flow"
	artifacts["proposal.md"].(map[string]any)["upstream_sha256"] = map[string]string{}
	proposalHash := artifacts["proposal.md"].(map[string]any)["sha256"].(string)
	artifacts["specs/secscan/spec.md"].(map[string]any)["depends_on"] = []string{"proposal.md"}
	artifacts["specs/secscan/spec.md"].(map[string]any)["upstream_sha256"] = map[string]string{"proposal.md": proposalHash}
	extra := "specs/secscan/overview.md"
	content := []byte("extra artifact\n")
	writeStaleFixture(t, root, extra, content)
	extraHash := fmt.Sprintf("%x", sha256.Sum256(content))
	artifacts[extra] = map[string]any{"sha256": extraHash, "synced_at": "2026-09-06T00:00:00Z", "depends_on": []string{"proposal.md"}, "upstream_sha256": map[string]string{"proposal.md": proposalHash}}
	artifacts["design.md"].(map[string]any)["depends_on"] = []string{"specs/**"}
	artifacts["design.md"].(map[string]any)["upstream_sha256"] = map[string]string{"specs/secscan/spec.md": artifacts["specs/secscan/spec.md"].(map[string]any)["sha256"].(string), extra: extraHash}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	writeStaleFixture(t, root, ".stale.json", data)
	if err := ValidateStaleness(root); err != nil {
		t.Errorf("ValidateStaleness(v2 multiple specs) = %v, want nil", err)
	}
}

func TestValidateStalenessV1RejectsV2Fields(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "empty graph", mutate: func(state map[string]any) { state["graph"] = "" }},
		{name: "null upstream", mutate: func(state map[string]any) {
			state["artifacts"].(map[string]any)["design.md"].(map[string]any)["upstream_sha256"] = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, state := staleFixture(t)
			test.mutate(state)
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			writeStaleFixture(t, root, ".stale.json", data)
			if err := ValidateStaleness(root); err == nil {
				t.Errorf("ValidateStaleness(v1 %s) = nil, want rejection", test.name)
			}
		})
	}
}
