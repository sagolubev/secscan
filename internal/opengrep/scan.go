package opengrep

import (
	"context"
	"fmt"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
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
	name := language + "-sast"
	emit(progress.Event{
		Scanner: name,
		Stage:   progress.StageScanning,
		Status:  progress.StatusRunning,
		Files:   fileCount,
	})
	output, err := runner.Output(ctx, ContainerArgs(imageID, language, target)...)
	if err != nil {
		return report.Scanner{}, nil, fmt.Errorf("%s container failed: %w", name, err)
	}
	emit(progress.Event{
		Scanner: name,
		Stage:   progress.StageReading,
		Status:  progress.StatusRunning,
		Files:   fileCount,
	})
	parsed, err := Parse(output, language)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	emit(progress.Event{
		Scanner: name,
		Stage:   progress.StageNormalizing,
		Status:  progress.StatusRunning,
		Files:   fileCount,
	})
	scanner := report.Scanner{
		Name:           name,
		Status:         "success",
		Image:          imageID,
		EngineVersion:  parsed.Version,
		RulePackDigest: RulePackDigest,
		RuleCount:      languageRuleCount(language),
		Coverage: report.Coverage{
			Read:   fileCount,
			Failed: 0,
			Unit:   "files",
		},
	}
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
	return append(container.IsolatedArgs(target, "/target"), []string{
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m",
		imageID,
		"scan",
		"--quiet",
		"--disable-version-check",
		"--json",
		"--config=/rules/" + language + ".yml",
		"--no-git-ignore",
		"/target",
	}...)
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
