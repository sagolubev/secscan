package tracecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"
)

type Evidence struct {
	SchemaVersion string        `json:"schemaVersion"`
	Phase         string        `json:"phase"`
	Baseline      string        `json:"baselineCommit"`
	Outcome       string        `json:"targetOutcome"`
	StateIdentity string        `json:"stateIdentity"`
	AuthorityHash string        `json:"authorityHash"`
	Changes       []Change      `json:"changes"`
	Checks        []CheckResult `json:"checks"`
	OK            bool          `json:"ok"`
}

type CheckResult struct {
	Name        string   `json:"name"`
	Argv        []string `json:"argv"`
	Env         []string `json:"env,omitempty"`
	Cwd         string   `json:"cwd"`
	ExitCode    int      `json:"exitCode"`
	DurationMS  int64    `json:"durationMs"`
	StdoutEmpty bool     `json:"stdoutEmpty"`
}

type issue struct {
	ID                 string       `json:"id"`
	Parent             string       `json:"parent"`
	Title              string       `json:"title"`
	Description        string       `json:"description"`
	AcceptanceCriteria string       `json:"acceptance_criteria"`
	Dependencies       []dependency `json:"dependencies"`
}

type dependency struct {
	ID   string `json:"id"`
	Type string `json:"dependency_type"`
}

func AuthorityHash(root, outcome, epic string) (string, error) {
	command := exec.Command(
		"br", "show", outcome, "--json", "--no-auto-import", "--no-auto-flush",
	)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("read Beads outcome %q: %w", outcome, err)
	}

	var issues []issue
	if err := json.Unmarshal(output, &issues); err != nil || len(issues) != 1 {
		return "", fmt.Errorf("decode Beads outcome %q", outcome)
	}
	selected := issues[0]
	if selected.Parent != epic {
		return "", fmt.Errorf("outcome %q parent = %q, want %q", outcome, selected.Parent, epic)
	}
	sort.Slice(selected.Dependencies, func(i, j int) bool {
		if selected.Dependencies[i].ID == selected.Dependencies[j].ID {
			return selected.Dependencies[i].Type < selected.Dependencies[j].Type
		}
		return selected.Dependencies[i].ID < selected.Dependencies[j].ID
	})
	canonical, err := json.Marshal(selected)
	if err != nil {
		return "", fmt.Errorf("encode Beads authority: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func RunChecks(ctx context.Context, root string, checks []Check) ([]CheckResult, bool) {
	results := make([]CheckResult, 0, len(checks))
	for _, check := range checks {
		started := time.Now()
		result := CheckResult{
			Name: check.Name,
			Argv: append([]string(nil), check.Argv...),
			Env:  append([]string(nil), check.Env...),
			Cwd:  root,
		}
		if len(check.Argv) == 0 {
			result.ExitCode = 2
		} else {
			command := exec.CommandContext(ctx, check.Argv[0], check.Argv[1:]...)
			command.Dir = root
			command.Env = append(os.Environ(), check.Env...)
			var stdout bytes.Buffer
			command.Stdout = &stdout
			if err := command.Run(); err != nil {
				result.ExitCode = exitCode(err)
			}
			result.StdoutEmpty = stdout.Len() == 0
			if check.RequireEmptyStdout && !result.StdoutEmpty {
				result.ExitCode = 1
			}
		}
		result.DurationMS = time.Since(started).Milliseconds()
		results = append(results, result)
		if result.ExitCode != 0 {
			return results, false
		}
	}
	return results, true
}

func exitCode(err error) int {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return 1
}
