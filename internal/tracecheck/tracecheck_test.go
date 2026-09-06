package tracecheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseScenarios(t *testing.T) {
	spec := strings.NewReader(`## ADDED Requirements

### Requirement: CLI contract

Description.

#### Scenario: Machine-readable stdout
- **WHEN** scan runs
- **THEN** stdout is JSON

#### Scenario: Exit status
- **WHEN** arguments are invalid
- **THEN** exit code is 2
`)

	got, err := ParseScenarios(spec)
	if err != nil {
		t.Fatalf("ParseScenarios() error = %v", err)
	}

	want := []ScenarioRef{
		{Requirement: "CLI contract", Scenario: "Machine-readable stdout"},
		{Requirement: "CLI contract", Scenario: "Exit status"},
	}
	if len(got) != len(want) {
		t.Fatalf("ParseScenarios() returned %d scenarios, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ParseScenarios()[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestValidateTraceRequiresEveryScenario(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"cmd/secscan/main.go", "cmd/secscan/main_test.go"} {
		fullPath := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	refs := []ScenarioRef{
		{Requirement: "CLI contract", Scenario: "Machine-readable stdout"},
		{Requirement: "CLI contract", Scenario: "Exit status"},
	}
	manifest := Manifest{
		SchemaVersion: "1",
		Change:        "build-secscan",
		TargetOutcome: "secscan-ij8.1",
		Traces: []Trace{
			{
				ScenarioRef: refs[0],
				Disposition: "target",
				Components:  []string{"cmd/secscan/main.go"},
				Tests:       []string{"cmd/secscan/main_test.go"},
			},
			{
				ScenarioRef: refs[1],
				Disposition: "deferred",
				Issue:       "secscan-ij8",
			},
		},
	}

	if err := ValidateTrace(root, manifest, refs, true); err != nil {
		t.Fatalf("ValidateTrace() error = %v", err)
	}

	manifest.Traces = manifest.Traces[:1]
	if err := ValidateTrace(root, manifest, refs, true); err == nil {
		t.Fatal("ValidateTrace() error = nil, want missing scenario error")
	}
}

func TestValidateScopeChecksBothRenamePaths(t *testing.T) {
	scope := Scope{
		Implementation: []string{"internal/"},
		Governance:     []string{"openspec/changes/build-secscan/"},
		EvidenceSinks:  []string{".beads/issues.jsonl"},
	}
	changes := []Change{{
		Status:  "R100",
		OldPath: "outside/secret.go",
		Path:    "internal/secret.go",
	}}

	err := ValidateScope(scope, changes)
	if err == nil {
		t.Fatal("ValidateScope() error = nil, want old rename path outside scope")
	}
}

func TestValidateScopeAcceptsDirectoryPrefix(t *testing.T) {
	scope := Scope{Implementation: []string{"cmd/secscan/"}}
	changes := []Change{{Status: "A", Path: "cmd/secscan/main.go"}}

	if err := ValidateScope(scope, changes); err != nil {
		t.Fatalf("ValidateScope() error = %v, want nil", err)
	}
}

func TestParseChangesPreservesBothRenamePaths(t *testing.T) {
	got, err := parseChanges([]byte("R100\x00old/name.go\x00internal/name.go\x00M\x00go.mod\x00"))
	if err != nil {
		t.Fatalf("parseChanges() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parseChanges() returned %d changes, want 2", len(got))
	}
	if got[0].OldPath != "old/name.go" || got[0].Path != "internal/name.go" {
		t.Errorf("parseChanges() rename = %#v, want old and new paths", got[0])
	}
}

func TestStateIdentityIgnoresEvidenceSinkContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".beads", "issues.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	scope := Scope{EvidenceSinks: []string{".beads/issues.jsonl"}}
	changes := []Change{{Status: "M", Path: ".beads/issues.jsonl"}}

	first, err := StateIdentity(root, "abc123", scope, changes)
	if err != nil {
		t.Fatalf("StateIdentity() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := StateIdentity(root, "abc123", scope, changes)
	if err != nil {
		t.Fatalf("StateIdentity() error = %v", err)
	}
	if first != second {
		t.Errorf("StateIdentity() changed for evidence sink: %q != %q", first, second)
	}
}

func TestStateIdentityIncludesFileMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cmd", "tool")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	scope := Scope{Implementation: []string{"cmd/"}}
	changes := []Change{{Status: "M", Path: "cmd/tool"}}
	first, err := StateIdentity(root, "abc123", scope, changes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	second, err := StateIdentity(root, "abc123", scope, changes)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("StateIdentity() ignored file mode change")
	}
}

func TestStateIdentityRejectsSensitiveRenameSource(t *testing.T) {
	scope := Scope{
		Governance:    []string{".env", "safe.txt"},
		EvidenceSinks: []string{".beads/issues.jsonl"},
	}
	changes := []Change{{
		Status:  "R100",
		OldPath: ".env",
		Path:    ".beads/issues.jsonl",
	}}

	if _, err := StateIdentity(t.TempDir(), "abc123", scope, changes); err == nil {
		t.Fatal("StateIdentity() error = nil, want sensitive old path error")
	}
}

func TestAuthorityHashRejectsManifestEpicMismatch(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "openspec", "changes", "build-secscan", ".br-link")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("secscan-real\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := AuthorityHash(root, "secscan-real.1", "secscan-fake", "build-secscan"); err == nil {
		t.Fatal("AuthorityHash() error = nil, want manifest epic mismatch")
	}
}

func TestRunChecksStopsAfterFailure(t *testing.T) {
	checks := []Check{
		{Name: "pass", Argv: []string{os.Args[0], "-test.run=TestHelperProcess", "--", "0"}},
		{Name: "fail", Argv: []string{os.Args[0], "-test.run=TestHelperProcess", "--", "7"}},
		{Name: "not-run", Argv: []string{os.Args[0], "-test.run=TestHelperProcess", "--", "0"}},
	}

	results, ok := RunChecks(context.Background(), ".", checks)
	if ok {
		t.Fatal("RunChecks() ok = true, want false")
	}
	if len(results) != 2 {
		t.Fatalf("RunChecks() returned %d results, want 2", len(results))
	}
	if results[1].ExitCode != 7 {
		t.Errorf("RunChecks() failure exit code = %d, want 7", results[1].ExitCode)
	}
}

func TestRunChecksRejectsEmptyPhase(t *testing.T) {
	if results, ok := RunChecks(context.Background(), ".", nil); ok || len(results) != 0 {
		t.Errorf("RunChecks(empty) = %#v, %t; want no results and failure", results, ok)
	}
}

func TestRunChecksRejectsUnexpectedStdout(t *testing.T) {
	checks := []Check{{
		Name:               "format",
		Argv:               []string{os.Args[0], "-test.run=TestHelperProcess", "--", "print"},
		RequireEmptyStdout: true,
	}}

	results, ok := RunChecks(context.Background(), ".", checks)
	if ok {
		t.Fatal("RunChecks() ok = true, want false for unexpected stdout")
	}
	if len(results) != 1 || results[0].ExitCode == 0 {
		t.Fatalf("RunChecks() result = %#v, want failed check", results)
	}
}

func TestRunChecksPassesDeclaredEnvironment(t *testing.T) {
	checks := []Check{{
		Name: "environment",
		Argv: []string{os.Args[0], "-test.run=TestHelperProcess", "--", "env"},
		Env:  []string{"TRACECHECK_TEST_ENV=present"},
	}}

	results, ok := RunChecks(context.Background(), ".", checks)
	if !ok || len(results) != 1 || results[0].ExitCode != 0 {
		t.Fatalf("RunChecks() = %#v, %t; want one passing result", results, ok)
	}
}

func TestHelperProcess(t *testing.T) {
	if len(os.Args) < 2 {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			if os.Args[i+1] == "env" {
				if os.Getenv("TRACECHECK_TEST_ENV") == "present" {
					os.Exit(0)
				}
				os.Exit(9)
			}
			if os.Args[i+1] == "print" {
				os.Stdout.WriteString("unexpected\n")
				os.Exit(0)
			}
			if os.Args[i+1] == "7" {
				os.Exit(7)
			}
			os.Exit(0)
		}
	}
}
