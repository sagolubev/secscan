package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sigiuscom/secscan/internal/tracecheck"
)

func main() {
	os.Exit(run())
}

func run() int {
	manifestPath := flag.String(
		"manifest",
		"openspec/changes/build-secscan/trace.json",
		"trace manifest path",
	)
	phase := flag.String("phase", "", "verification phase: baseline, target, or final")
	runChecks := flag.Bool("run", false, "run the phase checks")
	flag.Parse()

	if *phase != "baseline" && *phase != "target" && *phase != "final" {
		fmt.Fprintln(os.Stderr, "phase must be baseline, target, or final")
		return 2
	}
	if !*runChecks {
		fmt.Fprintln(os.Stderr, "--run is required to produce evidence")
		return 2
	}

	root, err := repositoryRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	manifest, err := tracecheck.LoadManifest(filepath.Join(root, *manifestPath))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	spec, err := os.Open(filepath.Join(root, manifest.Spec))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	refs, err := tracecheck.ParseScenarios(spec)
	spec.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := tracecheck.ValidateTrace(root, manifest, refs, *phase != "baseline"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	changes, err := tracecheck.Changes(root, manifest.BaselineCommit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := tracecheck.ValidateScope(manifest.Scope, changes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	identity, err := tracecheck.StateIdentity(root, manifest.BaselineCommit, manifest.Scope, changes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	authority, err := tracecheck.AuthorityHash(root, manifest.TargetOutcome, manifest.Epic, manifest.Change)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	results, ok := tracecheck.RunChecks(ctx, root, manifest.Checks[*phase])
	evidence := tracecheck.Evidence{
		SchemaVersion: "1",
		Phase:         *phase,
		Baseline:      manifest.BaselineCommit,
		Outcome:       manifest.TargetOutcome,
		StateIdentity: identity,
		AuthorityHash: authority,
		Changes:       changes,
		Checks:        results,
		OK:            ok,
	}
	if err := json.NewEncoder(os.Stdout).Encode(evidence); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !ok {
		return 1
	}
	return 0
}

func repositoryRoot() (string, error) {
	command := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("find repository root: %w", err)
	}
	return filepath.Clean(string(bytes.TrimSpace(output))), nil
}
