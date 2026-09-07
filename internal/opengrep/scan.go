// START_MODULE_CONTRACT
// PURPOSE: Run isolated language analysis with built-in and explicit custom rules.
// SCOPE: Read-only inputs; no network; private custom-rule materialization.
// DEPENDS: internal/opengrep/parser.go, internal/opengrep/rules.go, internal/container/runtime.go
// LINKS: cmd/secscan/rules_test.go#TestAcceptanceRulePacks
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Runner - The consumer boundary for container output.
// Scan - Run the default language rule set.
// ScanWithRules - Add verified custom rules and report their provenance.
// ContainerArgs - Build the default offline invocation.
// END_MODULE_MAP

package opengrep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
	"github.com/sagolubev/secscan/internal/rules"
)

type Runner interface {
	Output(context.Context, ...string) ([]byte, error)
}

func Scan(
	ctx context.Context,
	runner Runner,
	imageID string,
	language string,
	target string,
	fileCount int,
	emit func(progress.Event),
) (report.Scanner, []report.Finding, error) {
	return scanSelected(ctx, runner, imageID, language, target, fileCount, emit, nil)
}

// ScanWithRules adds a verified rule pack to the language's built-in rules.
func ScanWithRules(ctx context.Context, runner Runner, imageID, language, target string, files []string, emit func(progress.Event), pack *rules.Pack) (report.Scanner, []report.Finding, error) {
	for _, file := range files {
		if discovery.SourceLanguage(file) != language {
			return report.Scanner{}, nil, fmt.Errorf("Opengrep inputs do not match the selected language")
		}
	}
	return scanSelected(ctx, runner, imageID, language, target, len(files), emit, pack)
}

func scanSelected(ctx context.Context, runner Runner, imageID, language, target string, fileCount int, emit func(progress.Event), pack *rules.Pack) (report.Scanner, []report.Finding, error) {
	name := language + "-sast"
	emit(progress.Event{
		Scanner: name,
		Stage:   progress.StageScanning,
		Status:  progress.StatusRunning,
		Files:   fileCount,
	})
	customRules := ""
	if pack != nil && len(pack.Rules(language)) > 0 {
		var err error
		customRules, err = os.MkdirTemp(filepath.Dir(target), "custom-rules-")
		if err != nil {
			return report.Scanner{}, nil, err
		}
		defer os.RemoveAll(customRules)
		// This adapter stages one language and selects only rules declaring it.
		if err := pack.Write(customRules, language); err != nil {
			return report.Scanner{}, nil, err
		}
	}
	output, err := runner.Output(ctx, containerArgs(imageID, language, target, customRules)...)
	if err != nil {
		return report.Scanner{}, nil, fmt.Errorf("%s container failed: %w", name, err)
	}
	emit(progress.Event{
		Scanner: name,
		Stage:   progress.StageReading,
		Status:  progress.StatusRunning,
		Files:   fileCount,
	})
	parsed, err := ParseWithRules(output, language, pack)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	emit(progress.Event{
		Scanner: name,
		Stage:   progress.StageNormalizing,
		Status:  progress.StatusRunning,
		Files:   fileCount,
	})
	if parsed.Version != EngineVersion || len(parsed.ReadInputs) == 0 || len(parsed.ReadInputs) > fileCount {
		return report.Scanner{Coverage: report.Coverage{Unit: "files", Unread: fileCount}}, parsed.Findings, fmt.Errorf("Opengrep input coverage is unconfirmed")
	}
	scanner := report.Scanner{
		Name:           name,
		Status:         "success",
		Image:          imageID,
		EngineVersion:  parsed.Version,
		RulePackDigest: RulePackDigest,
		RuleCount:      languageRuleCount(language),
		Coverage: report.Coverage{
			Read:       len(parsed.ReadInputs),
			ReadInputs: parsed.ReadInputs,
			Unread:     fileCount - len(parsed.ReadInputs),
			Failed:     0,
			Unit:       "files",
		},
	}
	scanner.RulePackDigest, scanner.RuleCount, scanner.CustomRulePack = RuleEvidence(language, pack)
	emit(progress.Event{
		Scanner:  name,
		Stage:    progress.StageDone,
		Status:   progress.StatusSuccess,
		Files:    fileCount,
		Findings: len(parsed.Findings),
	})
	return scanner, parsed.Findings, nil
}

func ContainerArgs(imageID, language, target string) []string {
	return containerArgs(imageID, language, target, "")
}

func containerArgs(imageID, language, target, customRules string) []string {
	args := container.IsolatedArgs(target, "/target")
	if customRules != "" {
		args = append(args, "--mount", "type=bind,src="+customRules+",dst=/custom-rules,readonly")
	}
	args = append(args, []string{
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m",
		imageID,
		"scan",
		"--quiet",
		"--disable-version-check",
		"--json",
		"--no-rewrite-rule-ids",
		"--config=/rules/" + language + ".yml",
		"--no-git-ignore",
	}...)
	if customRules != "" {
		args = append(args, "--config=/custom-rules")
	}
	return append(args, "/target")
}

func languageRuleCount(language string) int {
	switch language {
	case "python":
		return 3
	case "typescript":
		return 5
	default:
		return 0
	}
}
