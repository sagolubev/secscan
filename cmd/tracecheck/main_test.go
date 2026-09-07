// START_MODULE_CONTRACT
// PURPOSE: Verify provenance and command preflights through the CLI boundary.
// SCOPE: Temporary Git repositories and synthetic Beads responses.
// DEPENDS: cmd/tracecheck/main.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestValidationBindsLoadedManifest - Different loaded check sets cannot share identity.
// TestValidationRejectsUnresolvedDeferredIssue - Unknown deferred work fails validation.
// TestPhaseRejectsMutationDuringChecks - Code, authority and manifest edits invalidate runs.
// TestPhaseRejectsLateBaselineAndUnstagedTarget - Invalid phase state blocks commands.
// END_MODULE_MAP

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/tracecheck"
)

func TestValidateOnlyDoesNotRunPhaseChecks(t *testing.T) {
	root, manifest := traceFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--manifest", manifest, "--validate-only"}, &stdout, &stderr); code != 0 {
		t.Fatalf("validation exit=%d stderr=%s", code, &stderr)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["mode"] != "validation-only" || result["stateIdentity"] == "" || result["authorityHash"] == "" {
		t.Errorf("validation identity=%#v", result)
	}
	for _, key := range []string{"phase", "checks"} {
		if _, exists := result[key]; exists {
			t.Errorf("validation unexpectedly contains %q: %s", key, &stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "ran-check")); !os.IsNotExist(err) {
		t.Errorf("validation ran a check: %v", err)
	}
}

func TestValidationBindsLoadedManifest(t *testing.T) {
	_, path := traceFixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	alternate := filepath.Join(filepath.Dir(path), "alternate.json")
	writeFixture(t, alternate, bytes.ReplaceAll(data, []byte("synthetic"), []byte("different-check")))
	var identities []string
	for _, name := range []string{path, alternate} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"--manifest", name, "--validate-only"}, &stdout, &stderr); code != 0 {
			t.Fatalf("validate %s: %s", name, &stderr)
		}
		var result validation
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		identities = append(identities, result.StateIdentity)
	}
	if identities[0] == identities[1] {
		t.Error("validation ignored loaded manifest path/check set")
	}
	outside := filepath.Join(t.TempDir(), "trace.json")
	writeFixture(t, outside, data)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--manifest", outside, "--validate-only"}, &stdout, &stderr); code != 1 {
		t.Errorf("outside manifest exit=%d; want 1", code)
	}
}

func TestValidationRejectsUnresolvedDeferredIssue(t *testing.T) {
	_, path := traceFixture(t)
	m, err := tracecheck.LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	m.Traces[0].Disposition, m.Traces[0].Issue = "deferred", "missing.1"
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, path, data)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--manifest", path, "--validate-only"}, &stdout, &stderr); code != 1 {
		t.Errorf("unresolved deferred issue exit=%d; want 1", code)
	}
}

func TestTracecheckRejectsConflictingModes(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--validate-only", "--run"}, {"--validate-only", "--phase", "target"},
		{"--validate-only", "--run=false"}, {"--validate-only", "--phase="},
		{"--phase", "target"}, {"--run"}, {"--validate-only", "unexpected"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Errorf("run(%q) exit=%d stdout=%q; want exit 2 without output", args, code, &stdout)
		}
	}
}

func TestValidateOnlyRequiresTargetPathsScopeAndAuthority(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(t *testing.T, root string)
	}{
		{name: "missing target", edit: func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "source.go")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "outside scope", edit: func(t *testing.T, root string) {
			writeFixture(t, filepath.Join(root, "outside"), []byte("untracked"))
		}},
		{name: "wrong authority", edit: func(t *testing.T, root string) {
			writeFixture(t, os.Getenv("TRACECHECK_TEST_ISSUE"), []byte(`[{"id":"test.1","parent":"different"}]`))
		}},
		{name: "stale spec", edit: func(t *testing.T, root string) {
			writeFixture(t, filepath.Join(root, "openspec/changes/test/design.md"), []byte("changed"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, manifest := traceFixture(t)
			test.edit(t, root)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"--manifest", manifest, "--validate-only"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
				t.Errorf("validation(%s) exit=%d stdout=%s stderr=%s", test.name, code, &stdout, &stderr)
			}
		})
	}
}

func TestPhaseRequiresChecksAndPreservesSuccessfulEvidence(t *testing.T) {
	for _, phase := range []string{"baseline", "target", "final"} {
		t.Run(phase, func(t *testing.T) {
			_, path := traceFixture(t)
			manifest, err := tracecheck.LoadManifest(path)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Checks = map[string][]tracecheck.Check{phase: nil}
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, path, data)
			var stdout, stderr bytes.Buffer
			args := []string{"--manifest", path, "--phase", phase, "--run"}
			if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
				t.Fatalf("empty %s phase exit=%d stdout=%s stderr=%s", phase, code, &stdout, &stderr)
			}
			manifest.Checks[phase] = []tracecheck.Check{{Name: "pass", Argv: []string{os.Args[0], "-test.run=^TestPhaseCheckProcess$"}}}
			data, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, path, data)
			stdout.Reset()
			stderr.Reset()
			stageFixture(t)
			code := run(args, &stdout, &stderr)
			var evidence tracecheck.Evidence
			if code != 0 || json.Unmarshal(stdout.Bytes(), &evidence) != nil || !evidence.OK || evidence.Phase != phase || len(evidence.Checks) != 1 {
				t.Errorf("passing %s phase exit=%d stdout=%s stderr=%s", phase, code, &stdout, &stderr)
			}
			if evidence.SchemaVersion != "2" || evidence.ID == "" || evidence.ManifestDigest == "" || evidence.StartedAt.IsZero() || evidence.FinishedAt.Before(evidence.StartedAt) {
				t.Errorf("incomplete v2 provenance: %+v", evidence)
			}
		})
	}
}

func TestPhaseRejectsMutationDuringChecks(t *testing.T) {
	for _, action := range []string{"source", "authority", "manifest"} {
		t.Run(action, func(t *testing.T) {
			_, manifest := traceFixture(t)
			data, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, manifest, bytes.ReplaceAll(data, []byte("TRACECHECK_TEST_ACTION=marker"), []byte("TRACECHECK_TEST_ACTION="+action)))
			stageFixture(t)
			var stdout, stderr bytes.Buffer
			code := run([]string{"--manifest", manifest, "--phase", "target", "--run"}, &stdout, &stderr)
			var evidence tracecheck.Evidence
			if code != 1 || json.Unmarshal(stdout.Bytes(), &evidence) != nil || evidence.OK || !strings.Contains(stderr.String(), "changed during checks") {
				t.Errorf("phase(%s) exit=%d stdout=%s stderr=%s; want rejected evidence", action, code, &stdout, &stderr)
			}
		})
	}
}

func stageFixture(t *testing.T) {
	t.Helper()
	if output, err := exec.Command("git", "add", ".").CombinedOutput(); err != nil {
		t.Fatalf("stage fixture: %v: %s", err, output)
	}
}

func TestPhaseCheckProcess(t *testing.T) {
	var path, text string
	switch os.Getenv("TRACECHECK_TEST_ACTION") {
	case "marker":
		path, text = "ran-check", "ran"
	case "source":
		path, text = "source.go", "changed"
	case "authority":
		path, text = os.Getenv("TRACECHECK_TEST_ISSUE"), `[{"id":"test.1","parent":"test","title":"changed"}]`
	case "manifest":
		path = "openspec/changes/test/trace.json"
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text = string(bytes.ReplaceAll(data, []byte("synthetic"), []byte("changed-check")))
	default:
		return
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPhaseRejectsLateBaselineAndUnstagedTarget(t *testing.T) {
	for _, phase := range []string{"baseline", "target", "final"} {
		t.Run(phase, func(t *testing.T) {
			root, path := traceFixture(t)
			m, err := tracecheck.LoadManifest(path)
			if err != nil {
				t.Fatal(err)
			}
			m.Checks[phase] = m.Checks["target"]
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, path, data)
			stageFixture(t)
			writeFixture(t, filepath.Join(root, "source.go"), []byte("package changed\n"))
			var stdout, stderr bytes.Buffer
			if code := run([]string{"--manifest", path, "--phase", phase, "--run"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
				t.Errorf("invalid %s state exit=%d stdout=%s stderr=%s", phase, code, &stdout, &stderr)
			}
			if _, err := os.Stat(filepath.Join(root, "ran-check")); !os.IsNotExist(err) {
				t.Error("phase ran checks despite invalid state")
			}
		})
	}
}

func traceFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)
	change := "openspec/changes/test/"
	artifacts := make(map[string]any)
	for path, deps := range map[string][]string{
		"proposal.md": {}, "design.md": {"proposal.md"}, "specs/test/spec.md": {"design.md"},
	} {
		data := []byte("### Requirement: Example\n#### Scenario: Example\n")
		writeFixture(t, filepath.Join(root, change, path), data)
		artifacts[path] = map[string]any{
			"sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "synced_at": "2026-09-06T00:00:00Z", "depends_on": deps,
		}
	}
	state, err := json.Marshal(map[string]any{"version": 1, "updated_at": "2026-09-06T00:00:00Z", "artifacts": artifacts})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(root, change, ".stale.json"), state)
	writeFixture(t, filepath.Join(root, change, ".br-link"), []byte("test\n"))
	for _, path := range []string{"source.go", "source_test.go"} {
		writeFixture(t, filepath.Join(root, path), []byte("package example\n"))
	}
	writeFixture(t, filepath.Join(root, "source_test.go"), []byte("package example\nimport \"testing\"\nfunc TestExample(t *testing.T) {}\n"))
	for _, args := range [][]string{
		{"init", "--quiet"}, {"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "fixture"},
	} {
		if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %q: %v: %s", args, err, output)
		}
	}
	baseline, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	manifest := tracecheck.Manifest{
		SchemaVersion: "1", Change: "test", Spec: change + "specs/test/spec.md", Epic: "test", TargetOutcome: "test.1", BaselineCommit: strings.TrimSpace(string(baseline)),
		Scope:  tracecheck.Scope{Implementation: []string{"source.go", "source_test.go"}, Governance: []string{change}},
		Traces: []tracecheck.Trace{{ScenarioRef: tracecheck.ScenarioRef{Requirement: "Example", Scenario: "Example"}, Disposition: "target", Components: []string{"source.go"}, Tests: []string{"source_test.go"}}},
		Checks: map[string][]tracecheck.Check{"target": {{Name: "synthetic", Argv: []string{os.Args[0], "-test.run=^TestPhaseCheckProcess$"}, Env: []string{"TRACECHECK_TEST_ACTION=marker"}}}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := change + "trace.json"
	writeFixture(t, filepath.Join(root, manifestPath), encoded)
	bin := t.TempDir()
	issue := filepath.Join(bin, "issue.json")
	writeFixture(t, issue, []byte(`[{"id":"test.1","parent":"test","title":"fixture"}]`))
	writeFixture(t, filepath.Join(bin, "br"), []byte("#!/bin/sh\ncat \"$TRACECHECK_TEST_ISSUE\"\n"))
	if err := os.Chmod(filepath.Join(bin, "br"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRACECHECK_TEST_ISSUE", issue)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return root, manifestPath
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
