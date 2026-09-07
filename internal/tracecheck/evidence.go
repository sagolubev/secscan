// START_MODULE_CONTRACT
// PURPOSE: Record check results and stable Beads authority.
// SCOPE: No raw command output in evidence; digests detect edits, not authorship.
// DEPENDS: internal/tracecheck/tracecheck_test.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability
// ROLE: RUNTIME
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Evidence.Seal - Bind the recorded provenance and check results.
// AuthorityHash - Hash task meaning without lifecycle or evidence comments.
// ValidateDeferred - Require deferred work to exist in the selected epic.
// RunChecks - Run explicit argument vectors and record success or failure.
// END_MODULE_MAP

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
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Evidence struct {
	ID             string        `json:"id,omitempty"`
	Previous       string        `json:"previous,omitempty"`
	StateAlgorithm string        `json:"stateAlgorithm"`
	ManifestPath   string        `json:"manifestPath"`
	ManifestDigest string        `json:"manifestDigest"`
	StartedAt      time.Time     `json:"startedAt"`
	FinishedAt     time.Time     `json:"finishedAt"`
	SchemaVersion  string        `json:"schemaVersion"`
	Phase          string        `json:"phase"`
	Baseline       string        `json:"baselineCommit"`
	Outcome        string        `json:"targetOutcome"`
	StateIdentity  string        `json:"stateIdentity"`
	AuthorityHash  string        `json:"authorityHash"`
	Changes        []Change      `json:"changes"`
	Checks         []CheckResult `json:"checks"`
	OK             bool          `json:"ok"`
}

type CheckResult struct {
	Status      string   `json:"status"`
	Name        string   `json:"name"`
	Argv        []string `json:"argv"`
	Env         []string `json:"env,omitempty"`
	Cwd         string   `json:"cwd"`
	ExitCode    int      `json:"exitCode"`
	DurationMS  int64    `json:"durationMs"`
	StdoutEmpty bool     `json:"stdoutEmpty"`
}

// Seal binds all recorded fields. It detects edits; it is not a signature.
func (e *Evidence) Seal() error {
	e.ID = ""
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	e.ID = fmt.Sprintf("%x", sha256.Sum256(data))
	return nil
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

func AuthorityHash(root, outcome, epic, change string) (string, error) {
	link, err := ReadRepositoryFile(root, filepath.ToSlash(filepath.Join("openspec", "changes", change, ".br-link")))
	if err != nil {
		return "", fmt.Errorf("read OpenSpec Beads link: %w", err)
	}
	linkedEpic := strings.TrimSpace(string(link))
	if linkedEpic != epic {
		return "", fmt.Errorf("manifest epic %q does not match .br-link %q", epic, linkedEpic)
	}

	selected, _, err := readIssue(root, outcome)
	if err != nil {
		return "", err
	}
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

func readIssue(root, id string) (issue, string, error) {
	if id == "" || strings.HasPrefix(id, "-") || strings.ContainsAny(id, " \t\r\n") {
		return issue{}, "", fmt.Errorf("invalid Beads id %q", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "br", "show", id, "--json", "--no-auto-import", "--no-auto-flush")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return issue{}, "", fmt.Errorf("read Beads issue %q: %w", id, err)
	}
	var records []struct {
		issue
		Status string `json:"status"`
	}
	if err := json.Unmarshal(output, &records); err != nil || len(records) != 1 || records[0].ID != id {
		return issue{}, "", fmt.Errorf("invalid Beads response for %q", id)
	}
	return records[0].issue, records[0].Status, nil
}

// ValidateDeferred requires every deferred reference to resolve to open work.
func ValidateDeferred(root string, m Manifest) error {
	seen := map[string]bool{}
	for _, trace := range m.Traces {
		if trace.Disposition != "deferred" || seen[trace.Issue] {
			continue
		}
		selected, status, err := readIssue(root, trace.Issue)
		if err != nil {
			return err
		}
		if selected.ID != m.Epic && selected.Parent != m.Epic {
			return fmt.Errorf("deferred issue %q is outside epic %q", trace.Issue, m.Epic)
		}
		if status != "open" && status != "in_progress" && status != "blocked" {
			return fmt.Errorf("deferred issue %q is not open work", trace.Issue)
		}
		seen[trace.Issue] = true
	}
	return nil
}

func RunChecks(ctx context.Context, root string, checks []Check) ([]CheckResult, bool) {
	results := make([]CheckResult, 0, len(checks))
	if len(checks) == 0 {
		return results, false
	}
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
		result.Status = "passed"
		if result.ExitCode != 0 {
			result.Status = "failed"
		}
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
