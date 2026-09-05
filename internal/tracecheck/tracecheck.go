package tracecheck

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ScenarioRef struct {
	Requirement string `json:"requirement"`
	Scenario    string `json:"scenario"`
}

type Trace struct {
	ScenarioRef
	Disposition string   `json:"disposition"`
	Components  []string `json:"components,omitempty"`
	Tests       []string `json:"tests,omitempty"`
	Issue       string   `json:"issue,omitempty"`
}

type Scope struct {
	Implementation []string `json:"implementation"`
	Governance     []string `json:"governance"`
	EvidenceSinks  []string `json:"evidenceSinks"`
}

type Check struct {
	Name               string   `json:"name"`
	Argv               []string `json:"argv"`
	RequireEmptyStdout bool     `json:"requireEmptyStdout,omitempty"`
}

type Manifest struct {
	SchemaVersion  string             `json:"schemaVersion"`
	Change         string             `json:"change"`
	Spec           string             `json:"spec"`
	Epic           string             `json:"epic"`
	TargetOutcome  string             `json:"targetOutcome"`
	BaselineCommit string             `json:"baselineCommit"`
	Scope          Scope              `json:"scope"`
	Traces         []Trace            `json:"traces"`
	Checks         map[string][]Check `json:"checks"`
}

type Change struct {
	Status  string `json:"status"`
	OldPath string `json:"oldPath,omitempty"`
	Path    string `json:"path"`
}

func LoadManifest(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open manifest: %w", err)
	}
	defer file.Close()

	var manifest Manifest
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	return manifest, nil
}

func ParseScenarios(reader io.Reader) ([]ScenarioRef, error) {
	scanner := bufio.NewScanner(reader)
	var requirement string
	var scenarios []ScenarioRef

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "### Requirement: "):
			requirement = strings.TrimSpace(strings.TrimPrefix(line, "### Requirement: "))
		case strings.HasPrefix(line, "#### Scenario: "):
			if requirement == "" {
				return nil, fmt.Errorf("scenario declared before requirement")
			}
			scenario := strings.TrimSpace(strings.TrimPrefix(line, "#### Scenario: "))
			scenarios = append(scenarios, ScenarioRef{
				Requirement: requirement,
				Scenario:    scenario,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}

	return scenarios, nil
}

func ValidateTrace(root string, manifest Manifest, refs []ScenarioRef, requirePaths bool) error {
	if manifest.SchemaVersion != "1" {
		return fmt.Errorf("unsupported schema version %q", manifest.SchemaVersion)
	}
	if manifest.TargetOutcome == "" {
		return fmt.Errorf("target outcome is required")
	}

	expected := make(map[ScenarioRef]bool, len(refs))
	for _, ref := range refs {
		expected[ref] = false
	}
	for _, trace := range manifest.Traces {
		covered, ok := expected[trace.ScenarioRef]
		if !ok {
			return fmt.Errorf("unknown scenario %q / %q", trace.Requirement, trace.Scenario)
		}
		if covered {
			return fmt.Errorf("duplicate scenario %q / %q", trace.Requirement, trace.Scenario)
		}
		expected[trace.ScenarioRef] = true

		switch trace.Disposition {
		case "target":
			if len(trace.Components) == 0 || len(trace.Tests) == 0 {
				return fmt.Errorf("target scenario %q / %q requires components and tests", trace.Requirement, trace.Scenario)
			}
			if requirePaths {
				for _, path := range append(append([]string{}, trace.Components...), trace.Tests...) {
					if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); err != nil {
						return fmt.Errorf("trace path %q: %w", path, err)
					}
				}
			}
		case "deferred":
			if trace.Issue == "" {
				return fmt.Errorf("deferred scenario %q / %q requires issue", trace.Requirement, trace.Scenario)
			}
		default:
			return fmt.Errorf("scenario %q / %q has invalid disposition %q", trace.Requirement, trace.Scenario, trace.Disposition)
		}
	}

	for ref, covered := range expected {
		if !covered {
			return fmt.Errorf("missing scenario %q / %q", ref.Requirement, ref.Scenario)
		}
	}
	return nil
}

func ValidateScope(scope Scope, changes []Change) error {
	for _, change := range changes {
		if change.OldPath != "" && !inScope(scope, change.OldPath) {
			return fmt.Errorf("path outside scope: %s", change.OldPath)
		}
		if !inScope(scope, change.Path) {
			return fmt.Errorf("path outside scope: %s", change.Path)
		}
	}
	return nil
}

func inScope(scope Scope, path string) bool {
	for _, allowed := range append(append(append([]string{}, scope.Implementation...), scope.Governance...), scope.EvidenceSinks...) {
		allowed = filepath.ToSlash(filepath.Clean(allowed))
		path = filepath.ToSlash(filepath.Clean(path))
		if path == allowed || strings.HasSuffix(allowed, "/") && strings.HasPrefix(path, allowed) {
			return true
		}
	}
	return false
}

func inList(paths []string, path string) bool {
	for _, candidate := range paths {
		if filepath.ToSlash(filepath.Clean(candidate)) == filepath.ToSlash(filepath.Clean(path)) {
			return true
		}
	}
	return false
}
