package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/discovery"
	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
)

var ciRule = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

// ParseCI discards free-form scanner text and retains only validated structured fields.
// The count records native ignored findings, which are excluded from active findings.
func ParseCI(data []byte, name string) ([]report.Finding, int, error) {
	var findings []report.Finding
	ignored := 0
	add := func(rule, severity, file string, line int) error {
		if !ciRule.MatchString(rule) || line < 1 || line > 1<<30 {
			return fmt.Errorf("invalid CI finding")
		}
		switch severity {
		case "informational", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid CI severity")
		}
		file, err := TargetPath(file)
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", name, rule, file, line)))
		findings = append(findings, report.Finding{Kind: "configuration", RuleID: rule, Severity: severity, Path: file, Line: line, Message: "scanner detected a potential CI security issue", Sources: []string{name}, Origin: "working_tree", Fingerprint: hex.EncodeToString(sum[:])})
		return nil
	}
	switch name {
	case "zizmor":
		var input []struct {
			Ident          string `json:"ident"`
			Ignored        *bool  `json:"ignored"`
			Determinations struct {
				Severity string `json:"severity"`
			} `json:"determinations"`
			Locations []struct {
				Symbolic struct {
					Kind string `json:"kind"`
					Key  struct {
						Local struct {
							Path string `json:"verbatim_path"`
						} `json:"Local"`
					} `json:"key"`
				} `json:"symbolic"`
				Concrete struct {
					Location struct {
						Start struct {
							Row *int `json:"row"`
						} `json:"start_point"`
					} `json:"location"`
				} `json:"concrete"`
			} `json:"locations"`
		}
		if json.Unmarshal(data, &input) != nil || input == nil {
			return nil, 0, fmt.Errorf("invalid Zizmor JSON")
		}
		for _, item := range input {
			if item.Ignored == nil {
				return nil, 0, fmt.Errorf("missing Zizmor disposition")
			}
			primary := 0
			start := len(findings)
			for _, loc := range item.Locations {
				if loc.Symbolic.Kind != "Primary" {
					continue
				}
				primary++
				row := loc.Concrete.Location.Start.Row
				if row == nil || *row < 0 || *row >= 1<<30 {
					return nil, 0, fmt.Errorf("invalid Zizmor line")
				}
				if err := add(item.Ident, strings.ToLower(item.Determinations.Severity), loc.Symbolic.Key.Local.Path, *row+1); err != nil {
					return nil, 0, err
				}
			}
			if primary == 0 {
				return nil, 0, fmt.Errorf("missing Zizmor primary location")
			}
			if *item.Ignored {
				ignored++
				findings = findings[:start]
			}
		}
	case "poutine":
		var input struct {
			Packages map[string]struct{} `json:"packages"`
			Findings []struct {
				Rule string `json:"rule_id"`
				Meta struct {
					Path string `json:"path"`
					Line *int   `json:"line"`
				} `json:"meta"`
			} `json:"findings"`
			Rules map[string]struct {
				ID    string `json:"id"`
				Level string `json:"level"`
			} `json:"rules"`
		}
		if json.Unmarshal(data, &input) != nil || input.Findings == nil || len(input.Rules) == 0 || len(input.Packages) == 0 {
			return nil, 0, fmt.Errorf("invalid Poutine JSON")
		}
		for _, item := range input.Findings {
			rule, ok := input.Rules[item.Rule]
			if !ok || rule.ID != item.Rule {
				return nil, 0, fmt.Errorf("missing Poutine rule")
			}
			severity := ""
			switch rule.Level {
			case "error":
				severity = "high"
			case "warning":
				severity = "medium"
			case "note":
				severity = "low"
			}
			line := 1
			if item.Meta.Line != nil {
				line = *item.Meta.Line
			}
			if err := add(item.Rule, severity, item.Meta.Path, line); err != nil {
				return nil, 0, err
			}
		}
	default:
		return nil, 0, fmt.Errorf("unsupported CI scanner")
	}
	return findings, ignored, nil
}

// CIArgs runs the pinned engine offline without repository configuration.
func CIArgs(name, imageID, target string) []string {
	args := append(container.IsolatedArgs(target, "/repo"), "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "--workdir", "/repo", imageID)
	if name == "zizmor" {
		return append(args, "--offline", "--collect", "all", "--no-config", "--strict-collection", "--no-progress", "--color", "never", "--format", "json-v1", "--no-exit-codes", "/repo")
	}
	return append(args, "analyze_local", "/repo", "--format", "json", "--verbose", "--disable-version-check")
}

// ScanCI stages only the selected Git inventory; callers remove no repository files.
func ScanCI(ctx context.Context, runtime container.Runtime, cache Cache, name, root string, files []string, emit func(progress.Event)) (report.Scanner, []report.Finding, error) {
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
	if name == "poutine" {
		for _, file := range files {
			if err := validatePoutineInput(target, file); err != nil {
				return report.Scanner{}, nil, err
			}
		}
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageScanning, Status: progress.StatusRunning, Files: len(files)})
	var data []byte
	if name == "poutine" {
		data, err = runtime.OutputRejecting(ctx, CIArgs(name, asset.ImageID, target), []string{"failed to unmarshal", "invalid github actions metadata", "failed to parse", "error parsing matched file", "error getting relative path", "| error |"})
	} else {
		data, err = runtime.Output(ctx, CIArgs(name, asset.ImageID, target)...)
	}
	if err != nil {
		return report.Scanner{}, nil, fmt.Errorf("CI scanner execution failed: %w", err)
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageReading, Status: progress.StatusRunning, Files: len(files)})
	findings, ignored, err := ParseCI(data, name)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	for _, finding := range findings {
		if !slices.Contains(files, finding.Path) {
			return report.Scanner{}, nil, fmt.Errorf("CI finding outside staged inventory")
		}
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageNormalizing, Status: progress.StatusRunning, Files: len(files)})
	result := report.Scanner{Name: name, Status: "success", Image: asset.ImageID, EngineVersion: Catalog()[name].Version, Coverage: report.Coverage{Read: len(files), Unit: "files"}, Limitations: []string{"repository scanner configuration excluded"}}
	if name == "zizmor" {
		result.Limitations = append(result.Limitations, "local workflows, actions, Dependabot and pre-commit definitions only", "offline: API-dependent audits omitted", fmt.Sprintf("native inline ignored findings excluded: %d", ignored))
	} else {
		result.Limitations = append(result.Limitations, "local GitHub, root .gitlab-ci.yml, Azure pipelines and .tekton definitions only", "file-level findings without a native line are anchored at line 1", "GitLab includes are not staged; local, remote, wildcard and dynamic includes remain unread")
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageDone, Status: progress.StatusSuccess, Files: len(files), Findings: len(findings)})
	return result, findings, nil
}
