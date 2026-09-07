// START_MODULE_CONTRACT
// PURPOSE: Run prepared code scanners and preserve positive analysis evidence.
// SCOPE: Gate the actual server platform before staging selected inputs; never build repository code or fetch rules.
// DEPENDS: internal/opengrep/parser.go, internal/opengrep/rules.go, internal/rules/pack.go, internal/scanner/platform.go
// LINKS: cmd/secscan/rules_test.go#TestAcceptanceRulePacks, internal/scanner/platform_test.go#TestPlatformDirectCodeGuard
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// CodeArgs - Build isolated engine arguments with local rules.
// ScanCode - Run a prepared built-in scanner.
// ScanCodeWithRules - Add a verified pack to Semgrep and validate its full input evidence.
// END_MODULE_MAP

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/opengrep"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
	"github.com/sagolubev/secscan/internal/rules"
	ruleassets "github.com/sagolubev/secscan/scanner/opengrep/assets"
)

// CodeArgs uses local rules and disables upstream updating and target configuration.
func CodeArgs(name, imageID, target, output, rules string, files ...string) []string {
	args := append(container.IsolatedArgs(target, "/target"), "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m", "--workdir", "/target")
	if name != "cppcheck" {
		args = append(args, "--mount", "type=bind,src="+rules+",dst=/rules,readonly")
	}
	if name != "semgrep" {
		args = append(args, "--mount", "type=bind,src="+output+",dst=/out")
	}
	args = append(args, imageID)
	switch name {
	case "semgrep":
		return append(args, "semgrep", "scan", "--json", "--quiet", "--config", "/rules", "--metrics", "off", "--disable-version-check", "--no-git-ignore", "--no-rewrite-rule-ids", "/target")
	case "bearer":
		return append(args, "scan", "/target", "--scanner", "sast", "--report", "security", "--format", "sarif", "--output", "/out/result.sarif", "--exit-code", "0", "--config-file", "/dev/null", "--ignore-file=", "--disable-default-rules", "--external-rule-dir", "/rules", "--disable-version-check", "--disable-domain-resolution", "--quiet", "--hide-progress-bar", "--no-color", "--no-extract")
	case "cppcheck":
		args = append(args, "--output-format=sarif", "--output-file=/out/result.sarif", "--quiet")
		for _, file := range files {
			args = append(args, "/target/"+filepath.ToSlash(file))
		}
		return args
	default:
		return nil
	}
}

// ScanCode stages only source candidates and never executes project build files.
func ScanCode(ctx context.Context, runtime container.Runtime, cache Cache, name, root string, files []string, emit func(progress.Event)) (report.Scanner, []report.Finding, error) {
	return ScanCodeWithRules(ctx, runtime, cache, name, root, files, emit, nil)
}

// ScanCodeWithRules adds a verified custom pack only to the Semgrep persona.
// A supplied platform must come from RuntimePlatform for this same runtime;
// omitted metadata is queried before resolving assets or staging repository files.
func ScanCodeWithRules(ctx context.Context, runtime container.Runtime, cache Cache, name, root string, files []string, emit func(progress.Event), pack *rules.Pack, knownPlatform ...Platform) (report.Scanner, []report.Finding, error) {
	var platform Platform
	if len(knownPlatform) == 1 {
		platform = knownPlatform[0]
	} else {
		var err error
		platform, err = RuntimePlatform(ctx, runtime)
		if err != nil {
			return report.Scanner{}, nil, err
		}
	}
	if reason := platform.UnsupportedReason(name); reason != "" {
		emit(progress.Event{Scanner: name, Stage: progress.StageSkipped, Status: progress.StatusSkipped})
		return report.Scanner{Name: name, Status: "skipped", EngineVersion: Catalog()[name].Version, Coverage: report.Coverage{Unit: "files", Unread: len(files), UnreadInputs: append([]string(nil), files...)}, Limitations: []string{reason}}, nil, nil
	}
	emit(progress.Event{Scanner: name, Stage: progress.StagePreparing, Status: progress.StatusRunning, Files: len(files)})
	asset, err := cache.Resolve(ctx, runtime, name)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	target, err := discovery.Stage(root, files)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	defer os.RemoveAll(target)
	work, err := os.MkdirTemp(filepath.Dir(target), "code-output-")
	if err != nil {
		return report.Scanner{}, nil, err
	}
	defer os.RemoveAll(work)
	rules := filepath.Join(work, "rules")
	if name == "semgrep" {
		if err := writeCodeRules(rules); err != nil {
			return report.Scanner{}, nil, err
		}
		if pack != nil {
			if err := pack.WriteForPaths(rules, "", files); err != nil {
				return report.Scanner{}, nil, err
			}
		}
	} else if name == "bearer" {
		if err := extractBearerRules(filepath.Join(cache.Root, asset.Static["rules"].Path), rules); err != nil {
			return report.Scanner{}, nil, err
		}
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageScanning, Status: progress.StatusRunning, Files: len(files)})
	data, err := runtime.Output(ctx, CodeArgs(name, asset.ImageID, target, work, rules, files...)...)
	if err != nil {
		return report.Scanner{}, nil, fmt.Errorf("code scanner execution failed: %w", err)
	}
	if name != "semgrep" {
		data, err = readCodeReport(filepath.Join(work, "result.sarif"))
		if err != nil {
			return report.Scanner{}, nil, err
		}
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageReading, Status: progress.StatusRunning, Files: len(files)})
	var findings []report.Finding
	if name == "semgrep" {
		parsed, parseErr := opengrep.ParseWithRules(data, "", pack)
		var input struct {
			Results []json.RawMessage `json:"results"`
			Errors  []json.RawMessage `json:"errors"`
			Paths   struct {
				Scanned []string `json:"scanned"`
			} `json:"paths"`
		}
		if parseErr != nil || json.Unmarshal(data, &input) != nil || input.Results == nil || input.Errors == nil || parsed.Version != Catalog()[name].Version {
			return report.Scanner{}, nil, fmt.Errorf("invalid Semgrep report or scanner errors")
		}
		read := make(map[string]bool)
		for _, path := range input.Paths.Scanned {
			path, err := TargetPath(path)
			if err != nil || !slices.Contains(files, path) {
				return report.Scanner{}, nil, fmt.Errorf("invalid Semgrep scanned path")
			}
			read[path] = true
		}
		if len(read) != len(files) {
			return report.Scanner{}, nil, fmt.Errorf("Semgrep did not analyze every selected source")
		}
		findings = parsed.Findings
		for i := range findings {
			findings[i].Sources = []string{"semgrep"}
		}

	} else {
		findings, err = parseCodeSARIF(data, name)
		if err != nil {
			return report.Scanner{}, nil, err
		}
	}
	coverage, err := codeCoverage(name, files, findings)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	result := report.Scanner{Name: name, Status: "success", Image: asset.ImageID, EngineVersion: Catalog()[name].Version, Coverage: coverage, Limitations: []string{"only Git-selected source candidates staged; repository configuration and project builds excluded"}}
	if name == "semgrep" {
		result.RulePackDigest, result.RuleCount, result.CustomRulePack = opengrep.RuleEvidence("", pack)
	}
	if name == "cppcheck" {
		result.Limitations = append(result.Limitations, "default Cppcheck language/platform settings; external headers, project compiler flags and addons excluded")
	}
	if name == "bearer" {
		result.RulePackDigest = bearerRulesDigest
		result.RuleCount = 552
		result.Limitations = append(result.Limitations, "static Bearer rules v0.48.4; native inline suppressions remain enabled", "Bearer SARIF omits native severity; findings have unknown severity",
			"partial coverage: only unique validated finding paths prove file analysis; all other selected inputs remain unread",
			"native minified JavaScript, size, language and test-file exclusions may apply; empty findings do not prove a clean scan")
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageNormalizing, Status: progress.StatusRunning, Files: len(files)})
	emit(progress.Event{Scanner: name, Stage: progress.StageDone, Status: progress.StatusSuccess, Files: len(files), Findings: len(findings)})
	return result, findings, nil
}

func writeCodeRules(root string) error {
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	return fs.WalkDir(ruleassets.Files, "rules", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := ruleassets.Files.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, filepath.Base(path)), data, 0600)
	})
}

func readCodeReport(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, fmt.Errorf("missing or oversized code report")
	}
	input, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, (64<<20)+1))
	if err != nil || len(data) > 64<<20 {
		return nil, fmt.Errorf("read code report failed")
	}
	return data, nil
}

func parseCodeSARIF(data []byte, name string) ([]report.Finding, error) {
	if name == "bearer" {
		var err error
		data, err = normalizeBearerSARIF(data)
		if err != nil {
			return nil, err
		}
	}
	findings, err := ParseSARIF(data, name, "code")
	if err != nil {
		return nil, err
	}
	var input struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"semanticVersion"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if json.Unmarshal(data, &input) != nil {
		return nil, fmt.Errorf("invalid code SARIF")
	}
	for _, run := range input.Runs {
		if !strings.EqualFold(run.Tool.Driver.Name, name) {
			return nil, fmt.Errorf("unexpected code SARIF engine")
		}
		if name == "cppcheck" && run.Tool.Driver.Version != Catalog()[name].Version {
			return nil, fmt.Errorf("unexpected Cppcheck version")
		}
	}
	result := make([]report.Finding, 0, len(findings))
	seen := make(map[string]bool)
	for _, finding := range findings {
		if name == "bearer" {
			finding.Severity = "unknown"
		}
		if name == "cppcheck" && (finding.RuleID == "syntaxError" || finding.RuleID == "internalError" || finding.RuleID == "cppcheckError") {
			return nil, fmt.Errorf("Cppcheck could not analyze input")
		}
		if !seen[finding.Fingerprint] {
			result = append(result, finding)
			seen[finding.Fingerprint] = true
		}
	}
	return result, nil
}

// Bearer 2.1.1 initializes its clean result slice to nil; keep the shared SARIF
// reader strict for other engines and for missing results or missing loaded rules.
func normalizeBearerSARIF(data []byte) ([]byte, error) {
	var document map[string]json.RawMessage
	if json.Unmarshal(data, &document) != nil {
		return nil, fmt.Errorf("invalid Bearer SARIF")
	}
	var runs []map[string]json.RawMessage
	if json.Unmarshal(document["runs"], &runs) != nil {
		return nil, fmt.Errorf("invalid Bearer SARIF runs")
	}
	for _, run := range runs {
		var tool struct {
			Driver struct {
				Name  string            `json:"name"`
				Rules []json.RawMessage `json:"rules"`
			} `json:"driver"`
		}
		if json.Unmarshal(run["tool"], &tool) != nil || tool.Driver.Name != "Bearer" || len(tool.Driver.Rules) == 0 {
			return nil, fmt.Errorf("Bearer SARIF missing loaded rules")
		}
		if bytes.Equal(bytes.TrimSpace(run["results"]), []byte("null")) {
			run["results"] = json.RawMessage("[]")
		}
	}
	normalized, err := json.Marshal(runs)
	if err != nil {
		return nil, err
	}
	document["runs"] = normalized
	return json.Marshal(document)
}

// codeCoverage counts only validated finding paths as positive Bearer evidence.
// Its SARIF has no completion ledger, so an empty report cannot prove analysis.
func codeCoverage(name string, files []string, findings []report.Finding) (report.Coverage, error) {
	evidence := make(map[string]bool)
	for _, finding := range findings {
		if !slices.Contains(files, finding.Path) {
			return report.Coverage{}, fmt.Errorf("code finding outside staged inventory")
		}
		evidence[finding.Path] = true
	}
	if name != "bearer" {
		return report.Coverage{Unit: "files", Read: len(files), ReadInputs: append([]string(nil), files...)}, nil
	}
	coverage := report.Coverage{Unit: "files"}
	seen := make(map[string]bool)
	for _, file := range files {
		if seen[file] {
			continue
		}
		seen[file] = true
		if evidence[file] {
			coverage.ReadInputs = append(coverage.ReadInputs, file)
		} else {
			coverage.UnreadInputs = append(coverage.UnreadInputs, file)
		}
	}
	coverage.Read = len(coverage.ReadInputs)
	coverage.Unread = len(coverage.UnreadInputs)
	if coverage.Read == 0 {
		return coverage, fmt.Errorf("Bearer coverage_unconfirmed: no positive file analysis evidence; empty findings do not prove a clean scan")
	}
	return coverage, nil
}
