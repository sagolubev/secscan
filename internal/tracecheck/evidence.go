// START_MODULE_CONTRACT
// PURPOSE: Record check results and stable Beads authority.
// SCOPE: No raw command output in evidence; digests detect edits, not authorship.
// DEPENDS: internal/tracecheck/tracecheck.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Evidence - A digest-linked record of one verification phase.
// CheckResult - A declared command result without raw output.
// OutputSummary - Bounded output byte counts and SHA-256 hashes.
// TestCounts - Terminal Go test pass/fail/skip counters.
// LoadEvidence - Decode tagged portable records without running saved commands.
// AppendEvidence - Append a complete record through the Beads CLI.
// ValidateEvidenceChain - Check exact phase plans, digest links and current state.
// Evidence.Seal - Bind the recorded provenance and check results.
// AuthorityHash - Hash task meaning without lifecycle or evidence comments.
// ValidateDeferred - Require deferred work to exist in the selected epic.
// RunChecks - Run explicit argument vectors and record success or failure.
// checkOutput.Write - Bound and hash check output while counting Go test events.
// limitedBuffer.Write - Bound Beads output before decoding its records.
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
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	Status      string         `json:"status"`
	Name        string         `json:"name"`
	Argv        []string       `json:"argv"`
	Env         []string       `json:"env,omitempty"`
	Cwd         string         `json:"cwd"`
	ExitCode    int            `json:"exitCode"`
	DurationMS  int64          `json:"durationMs"`
	StdoutEmpty bool           `json:"stdoutEmpty"`
	Stdout      *OutputSummary `json:"stdout,omitempty"`
	Stderr      *OutputSummary `json:"stderr,omitempty"`
	Tests       *TestCounts    `json:"tests,omitempty"`
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

// OutputSummary retains only bounded byte counts and a content digest.
type OutputSummary struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// TestCounts counts terminal Go test events, never package summaries.
type TestCounts struct {
	Passed  int  `json:"passed"`
	Failed  int  `json:"failed"`
	Skipped int  `json:"skipped"`
	Invalid bool `json:"invalid,omitempty"`
}

const maxOutputBytes = 64 << 20
const maxEventBytes = 1 << 20

type checkOutput struct {
	hash  hash.Hash
	bytes int64
	line  []byte
	tests *TestCounts
}

func (w *checkOutput) Write(p []byte) (int, error) {
	if int64(len(p)) > maxOutputBytes-w.bytes {
		return 0, fmt.Errorf("check output exceeds byte limit")
	}
	w.hash.Write(p)
	w.bytes += int64(len(p))
	if w.tests != nil && !w.tests.Invalid {
		for _, b := range p {
			if b == '\n' {
				w.event()
				continue
			}
			if len(w.line) >= maxEventBytes {
				w.tests.Invalid = true
				w.line = nil
				break
			}
			w.line = append(w.line, b)
		}
	}
	return len(p), nil
}

func (w *checkOutput) event() {
	var event struct {
		Action string
		Test   string
	}
	if json.Unmarshal(w.line, &event) != nil {
		w.tests.Invalid = true
	} else {
		switch event.Action {
		case "pass":
			if event.Test != "" {
				w.tests.Passed++
			}
		case "fail":
			if event.Test != "" {
				w.tests.Failed++
			}
		case "skip":
			if event.Test != "" {
				w.tests.Skipped++
			}
		case "start", "run", "pause", "cont", "bench", "output", "build-output":
		case "build-fail":
			w.tests.Invalid = true
		default:
			w.tests.Invalid = true
		}
	}
	w.line = w.line[:0]
}

func (w *checkOutput) summary() *OutputSummary {
	return &OutputSummary{Bytes: w.bytes, SHA256: hex.EncodeToString(w.hash.Sum(nil))}
}

func goTestJSON(argv []string) bool {
	if len(argv) < 3 || filepath.Base(argv[0]) != "go" || argv[1] != "test" {
		return false
	}
	enabled := false
	for _, arg := range argv[2:] {
		if arg == "-args" || arg == "--" {
			break
		}
		if arg == "-json" || arg == "-json=true" {
			enabled = true
		}
		if arg == "-json=false" {
			enabled = false
		}
	}
	return enabled
}

func RunChecks(ctx context.Context, root string, checks []Check) ([]CheckResult, bool) {
	results := make([]CheckResult, 0, len(checks))
	if len(checks) == 0 {
		return results, false
	}
	for _, check := range checks {
		started := time.Now()
		result := CheckResult{Name: check.Name, Argv: append([]string(nil), check.Argv...), Env: append([]string(nil), check.Env...), Cwd: root}
		stdout, stderr := checkOutput{hash: sha256.New()}, checkOutput{hash: sha256.New()}
		if goTestJSON(check.Argv) {
			result.Tests = &TestCounts{}
			stdout.tests = result.Tests
		}
		if len(check.Argv) == 0 {
			result.ExitCode = 2
		} else {
			command := exec.CommandContext(ctx, check.Argv[0], check.Argv[1:]...)
			command.Dir = root
			command.Env = append(os.Environ(), check.Env...)
			command.Stdout, command.Stderr = &stdout, &stderr
			command.WaitDelay = time.Second
			if err := command.Run(); err != nil {
				result.ExitCode = exitCode(err)
			}
		}
		if len(stdout.line) > 0 {
			stdout.event()
		}
		result.Stdout, result.Stderr = stdout.summary(), stderr.summary()
		result.StdoutEmpty = stdout.bytes == 0
		if check.RequireEmptyStdout && !result.StdoutEmpty || result.Tests != nil && (result.Tests.Invalid || result.Tests.Passed == 0 || result.Tests.Failed != 0) {
			if result.ExitCode == 0 {
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

const evidenceMarker = "<!-- secscan:tracecheck:v2 -->"
const maxEvidenceBytes = 1 << 20
const maxCommentsBytes = 16 << 20

// LoadEvidence reads only tagged v2 records. Legacy comments cannot satisfy gates.
func LoadEvidence(root, outcome string) ([]Evidence, error) {
	if !validIssueID(outcome) {
		return nil, fmt.Errorf("invalid Beads outcome")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "br", "comments", "list", outcome, "--json", "--no-auto-import", "--no-auto-flush")
	command.Dir = root
	var output limitedBuffer
	output.limit = maxCommentsBytes
	command.Stdout = &output
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("read Beads evidence: %w", err)
	}
	var comments []struct {
		ID        int64     `json:"id"`
		IssueID   string    `json:"issue_id"`
		Text      string    `json:"text"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(output.buffer.Bytes(), &comments); err != nil {
		return nil, fmt.Errorf("invalid Beads comments response")
	}
	sort.Slice(comments, func(i, j int) bool {
		if comments[i].CreatedAt.Equal(comments[j].CreatedAt) {
			return comments[i].ID < comments[j].ID
		}
		return comments[i].CreatedAt.Before(comments[j].CreatedAt)
	})
	var records []Evidence
	for _, comment := range comments {
		if !strings.HasPrefix(comment.Text, evidenceMarker) {
			continue
		}
		if comment.IssueID != outcome || comment.CreatedAt.IsZero() {
			return nil, fmt.Errorf("invalid tagged comment metadata")
		}
		data := []byte(strings.TrimPrefix(comment.Text, evidenceMarker))
		record, err := decodeEvidence(data)
		if err != nil {
			return nil, fmt.Errorf("invalid tagged evidence comment %d: %w", comment.ID, err)
		}
		if record.Outcome != outcome {
			return nil, fmt.Errorf("evidence outcome differs from comment issue")
		}
		records = append(records, record)
	}
	return records, nil
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, fmt.Errorf("Beads response exceeds byte limit")
	}
	return b.buffer.Write(p)
}

// AppendEvidence publishes a sealed record before any caller reports success.
func AppendEvidence(root string, evidence Evidence) error {
	if !validIssueID(evidence.Outcome) {
		return fmt.Errorf("invalid Beads outcome")
	}
	if err := validateRecord(evidence, time.Now().UTC()); err != nil {
		return err
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	if len(data) > maxEvidenceBytes {
		return fmt.Errorf("evidence exceeds byte limit")
	}
	// Refuse TMPDIR inside the repository; staging a comment must not alter checked state.
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	actualDir, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return err
	}
	actualRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(actualRoot, actualDir)
	if err != nil || filepath.IsLocal(rel) {
		return fmt.Errorf("evidence temporary directory must be outside repository")
	}
	dir, err := os.MkdirTemp(actualDir, "secscan-evidence-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "record.json")
	if err := os.WriteFile(path, append([]byte(evidenceMarker+"\n"), data...), 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "br", "comments", "add", evidence.Outcome, "--file", path, "--no-auto-import")
	command.Dir = root
	if err := command.Run(); err != nil {
		return fmt.Errorf("append Beads evidence: %w", err)
	}
	return nil
}

func validIssueID(id string) bool {
	return id != "" && !strings.HasPrefix(id, "-") && !strings.ContainsAny(id, " \t\r\n\x00")
}

func decodeEvidence(data []byte) (Evidence, error) {
	var e Evidence
	if len(data) > maxEvidenceBytes {
		return e, fmt.Errorf("evidence exceeds byte limit")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(data)), evidenceKey); err != nil {
		return e, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return e, fmt.Errorf("evidence must contain one JSON document")
	}
	if err := evidenceFields(data); err != nil {
		return e, err
	}
	return e, validateRecord(e, time.Now().UTC())
}

// Require explicit zero values; decoding null or an absent integer as zero would
// otherwise leave a record digest unchanged after removal of a result field.
func evidenceFields(data []byte) error {
	fields, err := requiredFields(data, "id", "stateAlgorithm", "manifestPath", "manifestDigest", "startedAt", "finishedAt", "schemaVersion", "phase", "baselineCommit", "targetOutcome", "stateIdentity", "authorityHash", "checks", "ok")
	if err != nil {
		return err
	}
	if _, ok := fields["changes"]; !ok {
		return fmt.Errorf("missing evidence changes")
	}
	var checks []json.RawMessage
	if err := json.Unmarshal(fields["checks"], &checks); err != nil {
		return err
	}
	for _, check := range checks {
		result, err := requiredFields(check, "status", "name", "argv", "cwd", "exitCode", "durationMs", "stdoutEmpty")
		if err != nil {
			return err
		}
		for _, key := range []string{"stdout", "stderr"} {
			if value, ok := result[key]; ok {
				if _, err := requiredFields(value, "bytes", "sha256"); err != nil {
					return err
				}
			}
		}
		if value, ok := result["tests"]; ok {
			if _, err := requiredFields(value, "passed", "failed", "skipped"); err != nil {
				return err
			}
		}
	}
	return nil
}

func requiredFields(data []byte, keys ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("missing or null evidence field %q", key)
		}
	}
	return fields, nil
}

func evidenceKey(key string) bool {
	switch key {
	case "id", "previous", "stateAlgorithm", "manifestPath", "manifestDigest", "startedAt", "finishedAt", "schemaVersion", "phase", "baselineCommit", "targetOutcome", "stateIdentity", "authorityHash", "changes", "checks", "ok", "status", "oldPath", "path", "name", "argv", "env", "cwd", "exitCode", "durationMs", "stdoutEmpty", "stdout", "stderr", "bytes", "sha256", "tests", "passed", "failed", "skipped", "invalid":
		return true
	default:
		return false
	}
}

func validDigest(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == sha256.Size && strings.ToLower(value) == value
}

func validateRecord(e Evidence, now time.Time) error {
	original := e.ID
	if !validDigest(original) || e.Seal() != nil || e.ID != original {
		return fmt.Errorf("evidence digest mismatch")
	}
	if e.SchemaVersion != "2" || e.StateAlgorithm != StateAlgorithm || !validRelative(e.ManifestPath) || !validDigest(e.ManifestDigest) || !validDigest(e.StateIdentity) || !validDigest(e.AuthorityHash) || !validIssueID(e.Outcome) {
		return fmt.Errorf("invalid evidence provenance")
	}
	anchor, err := hex.DecodeString(e.Baseline)
	if err != nil || len(anchor) != 20 && len(anchor) != 32 || strings.ToLower(e.Baseline) != e.Baseline {
		return fmt.Errorf("invalid evidence anchor")
	}
	if e.StartedAt.IsZero() || e.StartedAt.Location() != time.UTC || e.FinishedAt.Location() != time.UTC || e.FinishedAt.Before(e.StartedAt) || e.FinishedAt.After(now) {
		return fmt.Errorf("invalid evidence timestamps")
	}
	switch e.Phase {
	case "baseline":
		if e.Previous != "" {
			return fmt.Errorf("baseline cannot have a parent")
		}
	case "target", "final":
		if !validDigest(e.Previous) {
			return fmt.Errorf("phase requires a parent digest")
		}
	default:
		return fmt.Errorf("invalid evidence phase")
	}
	return nil
}

// ValidateEvidenceChain returns the required predecessor, or the current final for verify.
// Saved argv are compared with the manifest and are never executed.
func ValidateEvidenceChain(m Manifest, records []Evidence, nextPhase, authority, currentState string, now time.Time) (Evidence, error) {
	latest := map[string]Evidence{}
	seen := map[string]bool{}
	var finished time.Time
	for _, e := range records {
		if err := validateRecord(e, now); err != nil {
			return Evidence{}, err
		}
		if seen[e.ID] || e.StartedAt.Before(finished) {
			return Evidence{}, fmt.Errorf("duplicate or unordered evidence")
		}
		seen[e.ID] = true
		finished = e.FinishedAt
		if e.Outcome != m.TargetOutcome || e.Baseline != m.BaselineCommit || e.ManifestPath != m.SourcePath || e.ManifestDigest != m.Digest || e.AuthorityHash != authority {
			return Evidence{}, fmt.Errorf("evidence does not match current manifest or authority")
		}
		if err := ValidateScope(m.Scope, e.Changes); err != nil {
			return Evidence{}, err
		}
		if e.Phase == "baseline" {
			if err := ValidateBaseline(m.Scope, e.Changes); err != nil {
				return Evidence{}, err
			}
		} else {
			parentPhase := "baseline"
			if e.Phase == "final" {
				parentPhase = "target"
			}
			parent, ok := latest[parentPhase]
			if !ok || !parent.OK || parent.ID != e.Previous || e.StartedAt.Before(parent.FinishedAt) {
				return Evidence{}, fmt.Errorf("missing successful %s parent", parentPhase)
			}
			if e.Phase == "final" && e.StateIdentity != parent.StateIdentity {
				return Evidence{}, fmt.Errorf("final does not match target state")
			}
		}
		if err := validateResults(e, m.Checks[e.Phase]); err != nil {
			return Evidence{}, err
		}
		latest[e.Phase] = e
		if e.Phase == "baseline" {
			delete(latest, "target")
			delete(latest, "final")
		}
		if e.Phase == "target" {
			delete(latest, "final")
		}
	}
	required := ""
	switch nextPhase {
	case "baseline":
		return Evidence{}, nil
	case "target":
		required = "baseline"
	case "final":
		required = "target"
	case "verify":
		required = "final"
	default:
		return Evidence{}, fmt.Errorf("invalid evidence mode")
	}
	last, ok := latest[required]
	if !ok || !last.OK {
		return Evidence{}, fmt.Errorf("missing successful saved %s evidence", required)
	}
	if nextPhase != "target" && last.StateIdentity != currentState {
		return Evidence{}, fmt.Errorf("saved %s evidence is stale", required)
	}
	return last, nil
}

func validateResults(e Evidence, plan []Check) error {
	if len(plan) == 0 || len(e.Checks) == 0 || len(e.Checks) > len(plan) || e.OK && len(e.Checks) != len(plan) {
		return fmt.Errorf("evidence has incomplete declared checks")
	}
	for i, result := range e.Checks {
		check := plan[i]
		if result.Name != check.Name || !slices.Equal(result.Argv, check.Argv) || !slices.Equal(result.Env, check.Env) || result.Cwd == "" || !filepath.IsAbs(result.Cwd) || result.DurationMS < 0 {
			return fmt.Errorf("recorded check differs from manifest")
		}
		if result.Status != "passed" && result.Status != "failed" || (result.Status == "passed") != (result.ExitCode == 0) || result.ExitCode < -1 || result.ExitCode > 255 {
			return fmt.Errorf("invalid check status")
		}
		if result.Status == "failed" && (e.OK || i != len(e.Checks)-1) || check.RequireEmptyStdout && !result.StdoutEmpty && result.Status == "passed" {
			return fmt.Errorf("unsuccessful check claimed success")
		}
		bootstrap := e.Phase == "baseline" && !goTestJSON(check.Argv) && result.Stdout == nil && result.Stderr == nil && result.Tests == nil
		if bootstrap {
			continue
		}
		for _, output := range []*OutputSummary{result.Stdout, result.Stderr} {
			if output == nil || output.Bytes < 0 || output.Bytes > maxOutputBytes || !validDigest(output.SHA256) || output.Bytes == 0 && output.SHA256 != fmt.Sprintf("%x", sha256.Sum256(nil)) {
				return fmt.Errorf("invalid output summary")
			}
		}
		if result.StdoutEmpty != (result.Stdout.Bytes == 0) {
			return fmt.Errorf("inconsistent stdout count")
		}
		if goTestJSON(check.Argv) {
			counts := result.Tests
			if counts == nil || counts.Passed < 0 || counts.Failed < 0 || counts.Skipped < 0 || result.Status == "passed" && (counts.Invalid || counts.Passed == 0 || counts.Failed != 0) {
				return fmt.Errorf("invalid Go test counts")
			}
		} else if result.Tests != nil {
			return fmt.Errorf("test counts on non-JSON command")
		}
	}
	return nil
}
