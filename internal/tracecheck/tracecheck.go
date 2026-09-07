// START_MODULE_CONTRACT
// PURPOSE: Bind trace manifests to exact bytes and validate requirement references.
// SCOPE: Bounded repository reads; structural references do not prove test sufficiency.
// DEPENDS: internal/tracecheck/manifest_test.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability
// ROLE: RUNTIME
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// LoadRepositoryManifest - Bind exact manifest bytes and validate repository paths.
// ReadRepositoryFile - Read bounded regular files within the repository.
// ValidateTrace - Match all scenarios to components, tests or deferred work.
// ValidateScope - Check both rename endpoints against the declared scope.
// END_MODULE_MAP

package tracecheck

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
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
	Env                []string `json:"env,omitempty"`
	RequireEmptyStdout bool     `json:"requireEmptyStdout,omitempty"`
}

type Manifest struct {
	SourcePath     string             `json:"-"`
	Digest         string             `json:"-"`
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
	data, err := ReadRepositoryFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return Manifest{}, err
	}
	return decodeManifest(data)
}

func decodeManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return manifest, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return manifest, fmt.Errorf("manifest must contain one JSON document")
	}
	manifest.Digest = fmt.Sprintf("%x", sha256.Sum256(data))
	return manifest, nil
}

// LoadRepositoryManifest binds the exact document bytes and its repository path.
func LoadRepositoryManifest(root, path string) (Manifest, error) {
	if filepath.IsAbs(path) {
		var err error
		path, err = filepath.Rel(root, path)
		if err != nil {
			return Manifest{}, err
		}
	}
	path = filepath.ToSlash(path)
	data, err := ReadRepositoryFile(root, path)
	if err != nil {
		return Manifest{}, err
	}
	m, err := decodeManifest(data)
	if err != nil {
		return m, err
	}
	m.SourcePath = path
	if !validRelative(m.Change) || strings.Contains(m.Change, "/") {
		return m, fmt.Errorf("invalid change name")
	}
	if !strings.HasPrefix(m.Spec, "openspec/changes/"+m.Change+"/specs/") || filepath.Base(m.Spec) != "spec.md" || !validRelative(m.Spec) {
		return m, fmt.Errorf("spec must belong to the selected change")
	}
	for _, paths := range [][]string{m.Scope.Implementation, m.Scope.Governance, m.Scope.EvidenceSinks} {
		for _, p := range paths {
			if !validRelative(strings.TrimSuffix(p, "/")) {
				return m, fmt.Errorf("invalid scope path %q", p)
			}
		}
	}
	for _, sink := range m.Scope.EvidenceSinks {
		if sink != ".beads/issues.jsonl" {
			return m, fmt.Errorf("unsupported evidence sink %q", sink)
		}
	}
	return m, nil
}

func validRelative(path string) bool {
	return path != "." && filepath.IsLocal(path) && filepath.ToSlash(filepath.Clean(path)) == path && !strings.ContainsAny(path, "\\\x00")
}

// ReadRepositoryFile reads bounded regular input without escaping the repository.
func ReadRepositoryFile(root, path string) ([]byte, error) {
	if !validRelative(path) || forbiddenContentPath(path) {
		return nil, fmt.Errorf("invalid repository path %q", path)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	info, err := r.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q must be a regular file", path)
	}
	f, err := r.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q must be a regular file", path)
	}
	const limit = 4 << 20
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && len(data) > limit {
		err = fmt.Errorf("%q exceeds %d bytes", path, limit)
	}
	return data, err
}

// Reject duplicate keys and case aliases that encoding/json otherwise accepts.
func uniqueJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			k := key.(string)
			if !manifestKey(k) || seen[k] {
				return fmt.Errorf("ambiguous JSON key %q", k)
			}
			seen[k] = true
			if err := uniqueJSON(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err := uniqueJSON(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}

func manifestKey(key string) bool {
	switch key {
	case "schemaVersion", "change", "spec", "epic", "targetOutcome", "baselineCommit", "scope", "traces", "checks", "implementation", "governance", "evidenceSinks", "requirement", "scenario", "disposition", "components", "tests", "issue", "baseline", "target", "final", "name", "argv", "env", "requireEmptyStdout":
		return true
	default:
		return false
	}
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
			for _, ref := range append(append([]string{}, trace.Components...), trace.Tests...) {
				path, _, _ := strings.Cut(ref, "#")
				if !validRelative(strings.TrimSuffix(path, "/")) || forbiddenContentPath(path) {
					return fmt.Errorf("invalid trace reference %q", ref)
				}
			}
			if requirePaths {
				for _, path := range trace.Components {
					if err := validateReference(root, path, false); err != nil {
						return err
					}
				}
				for _, path := range trace.Tests {
					if err := validateReference(root, path, true); err != nil {
						return err
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

func validateReference(root, ref string, test bool) error {
	path, anchor, _ := strings.Cut(ref, "#")
	if !test && anchor == "" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
		if !validRelative(path) {
			return fmt.Errorf("invalid component path %q", ref)
		}
		r, err := os.OpenRoot(root)
		if err != nil {
			return err
		}
		defer r.Close()
		info, err := r.Stat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("component %q is not a directory", ref)
		}
		return nil
	}
	data, err := ReadRepositoryFile(root, path)
	if err != nil {
		return fmt.Errorf("trace reference %q: %w", ref, err)
	}
	if strings.HasSuffix(path, ".go") {
		file, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ParseComments)
		if err != nil {
			return err
		}
		found := false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && (anchor == "" || anchor == fn.Name.Name) && (!test || strings.HasSuffix(path, "_test.go") && runnableGoTest(file, fn)) {
				found = true
			}
		}
		if (test || anchor != "") && !found {
			return fmt.Errorf("trace reference %q has no matching Go test or symbol", ref)
		}
	} else if anchor != "" || test && !strings.HasSuffix(path, ".sh") && !strings.HasSuffix(path, ".py") {
		return fmt.Errorf("trace reference %q is not a test source", ref)
	}
	return nil
}

func runnableGoTest(file *ast.File, fn *ast.FuncDecl) bool {
	if fn.Name.Name == "TestMain" || fn.Type.TypeParams != nil || fn.Type.Results.NumFields() != 0 {
		return false
	}
	for _, example := range doc.Examples(file) {
		if fn.Name.Name == "Example"+example.Name && (example.Output != "" || example.EmptyOutput) {
			return true
		}
	}
	for prefix, parameter := range map[string]string{"Test": "T", "Benchmark": "B", "Fuzz": "F"} {
		name := fn.Name.Name
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix, _ := utf8.DecodeRuneInString(strings.TrimPrefix(name, prefix))
		if unicode.IsLower(suffix) || fn.Type.Params.NumFields() != 1 {
			continue
		}
		pointer, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		for _, imp := range file.Imports {
			if imp.Path.Value != `"testing"` {
				continue
			}
			alias := "testing"
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			if id, ok := pointer.X.(*ast.Ident); ok && alias == "." && id.Name == parameter {
				return true
			}
			selector, ok := pointer.X.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			pkg, ok := selector.X.(*ast.Ident)
			if ok && pkg.Name == alias && selector.Sel.Name == parameter {
				return true
			}
		}
	}
	return false
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
		prefix := strings.HasSuffix(filepath.ToSlash(allowed), "/")
		allowed = filepath.ToSlash(filepath.Clean(allowed))
		path = filepath.ToSlash(filepath.Clean(path))
		if path == allowed || prefix && strings.HasPrefix(path, allowed+"/") {
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
