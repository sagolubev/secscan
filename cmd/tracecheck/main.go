// START_MODULE_CONTRACT
// PURPOSE: Validate scope and run declared verification phases.
// SCOPE: Check state before and after commands; validation-only never claims test success.
// DEPENDS: cmd/tracecheck/main_test.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability
// ROLE: RUNTIME
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// run - Validate arguments and coordinate phase checks.
// phaseState - Reject late baselines and split index/worktree states.
// validate - Bind manifest, references, Git state and Beads authority.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sagolubev/secscan/internal/tracecheck"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("tracecheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String(
		"manifest",
		"openspec/changes/build-secscan/trace.json",
		"trace manifest path",
	)
	phase := flags.String("phase", "", "verification phase: baseline, target, or final")
	runChecks := flags.Bool("run", false, "run the phase checks")
	validateOnly := flags.Bool("validate-only", false, "validate trace, scope, authority and staleness without running checks")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	conflict := false
	if *validateOnly {
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "phase" || f.Name == "run" {
				conflict = true
			}
		})
	}
	if flags.NArg() != 0 || conflict || !*validateOnly && (!*runChecks || (*phase != "baseline" && *phase != "target" && *phase != "final")) {
		fmt.Fprintln(stderr, "use --validate-only alone, or --phase baseline|target|final --run")
		return 2
	}

	root, err := repositoryRoot()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	manifest, err := tracecheck.LoadRepositoryManifest(root, *manifestPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !*validateOnly && len(manifest.Checks[*phase]) == 0 {
		fmt.Fprintf(stderr, "phase %q requires at least one check\n", *phase)
		return 1
	}
	before, err := validate(root, manifest, *validateOnly || *phase != "baseline")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *validateOnly {
		if err := json.NewEncoder(stdout).Encode(before); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if err := phaseState(root, manifest, *phase, before.Changes); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	results, ok := tracecheck.RunChecks(ctx, root, manifest.Checks[*phase])
	reloaded, err := tracecheck.LoadRepositoryManifest(root, manifest.SourcePath)
	var after validation
	if err == nil {
		after, err = validate(root, reloaded, *phase != "baseline")
	}
	if err == nil {
		err = phaseState(root, reloaded, *phase, after.Changes)
	}
	if err != nil {
		fmt.Fprintf(stderr, "verification state changed during checks: %v\n", err)
		ok = false
	} else if before.StateIdentity != after.StateIdentity || before.AuthorityHash != after.AuthorityHash {
		fmt.Fprintln(stderr, "verification state or Beads authority changed during checks")
		ok = false
	}
	evidence := tracecheck.Evidence{
		SchemaVersion:  "2",
		StateAlgorithm: tracecheck.StateAlgorithm,
		ManifestPath:   manifest.SourcePath,
		ManifestDigest: manifest.Digest,
		StartedAt:      started,
		FinishedAt:     time.Now().UTC(),
		Phase:          *phase,
		Baseline:       manifest.BaselineCommit,
		Outcome:        manifest.TargetOutcome,
		StateIdentity:  before.StateIdentity,
		AuthorityHash:  before.AuthorityHash,
		Changes:        before.Changes,
		Checks:         results,
		OK:             ok,
	}
	if err := evidence.Seal(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(evidence); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !ok {
		return 1
	}
	return 0
}

func phaseState(root string, manifest tracecheck.Manifest, phase string, changes []tracecheck.Change) error {
	if phase == "baseline" {
		return tracecheck.ValidateBaseline(manifest.Scope, changes)
	}
	return tracecheck.ValidateIndexAgreement(root, manifest.Scope, changes)
}

type validation struct {
	StateAlgorithm string              `json:"stateAlgorithm"`
	ManifestPath   string              `json:"manifestPath"`
	ManifestDigest string              `json:"manifestDigest"`
	SchemaVersion  string              `json:"schemaVersion"`
	Mode           string              `json:"mode"`
	Baseline       string              `json:"baselineCommit"`
	Outcome        string              `json:"targetOutcome"`
	StateIdentity  string              `json:"stateIdentity"`
	AuthorityHash  string              `json:"authorityHash"`
	Changes        []tracecheck.Change `json:"changes"`
}

func validate(root string, manifest tracecheck.Manifest, requirePaths bool) (validation, error) {
	result := validation{SchemaVersion: "2", Mode: "validation-only", Baseline: manifest.BaselineCommit, Outcome: manifest.TargetOutcome, StateAlgorithm: tracecheck.StateAlgorithm, ManifestPath: manifest.SourcePath, ManifestDigest: manifest.Digest}
	spec, err := tracecheck.ReadRepositoryFile(root, manifest.Spec)
	if err != nil {
		return result, err
	}
	refs, err := tracecheck.ParseScenarios(bytes.NewReader(spec))
	if err != nil {
		return result, err
	}
	if err := tracecheck.ValidateTrace(root, manifest, refs, requirePaths); err != nil {
		return result, err
	}
	if err := tracecheck.ValidateDeferred(root, manifest); err != nil {
		return result, err
	}
	if err := tracecheck.ValidateStaleness(filepath.Join(root, "openspec", "changes", manifest.Change)); err != nil {
		return result, err
	}
	result.Changes, err = tracecheck.Changes(root, manifest.BaselineCommit)
	if err != nil {
		return result, err
	}
	if err := tracecheck.ValidateScope(manifest.Scope, result.Changes); err != nil {
		return result, err
	}
	result.StateIdentity, err = tracecheck.StateIdentity(root, manifest.BaselineCommit, manifest.Scope, result.Changes)
	if err != nil {
		return result, err
	}
	result.StateIdentity = fmt.Sprintf("%x", sha256.Sum256([]byte(result.StateIdentity+"\x00"+manifest.SourcePath+"\x00"+manifest.Digest)))
	result.AuthorityHash, err = tracecheck.AuthorityHash(root, manifest.TargetOutcome, manifest.Epic, manifest.Change)
	return result, err
}

func repositoryRoot() (string, error) {
	command := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("find repository root: %w", err)
	}
	return filepath.Clean(string(bytes.TrimSpace(output))), nil
}
