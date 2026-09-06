package gitleaks

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

const Image = "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

func ContainerArgs(repository, output string) []string {
	return append(container.IsolatedArgs(repository, "/repo"), []string{
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--mount", "type=bind,src=" + output + ",dst=/out",
		Image,
		"dir", "/repo",
		"--no-banner", "--no-color", "--redact=100",
		"--exit-code", "0",
		"--report-format", "json",
		"--report-path", "/out/gitleaks.json",
	}...)
}

func Scan(
	ctx context.Context,
	runtime container.Runtime,
	repository string,
	emit func(progress.Event),
	imageIDs ...string,
) (report.Report, error) {
	output, err := createReportDir(os.UserCacheDir)
	if err != nil {
		return report.Report{}, fmt.Errorf("create report directory: %w", err)
	}
	defer os.RemoveAll(output)

	emit(progress.Event{
		Scanner: "gitleaks",
		Stage:   progress.StageScanning,
		Status:  progress.StatusRunning,
	})
	args := ContainerArgs(repository, output)
	imageID := Image
	if len(imageIDs) > 0 {
		imageID = imageIDs[0]
		for i, value := range args {
			if value == Image {
				args[i] = imageID
			}
		}
	}
	if err := runtime.Run(ctx, args); err != nil {
		return report.Report{}, err
	}
	emit(progress.Event{
		Scanner: "gitleaks",
		Stage:   progress.StageReading,
		Status:  progress.StatusRunning,
	})
	file, err := os.Open(filepath.Join(output, "gitleaks.json"))
	if err != nil {
		return report.Report{}, fmt.Errorf("read Gitleaks report: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	if len(data) > 64<<20 {
		return report.Report{}, fmt.Errorf("Gitleaks report exceeds 64 MiB limit")
	}
	if err != nil {
		return report.Report{}, fmt.Errorf("read Gitleaks report: %w", err)
	}
	emit(progress.Event{
		Scanner: "gitleaks",
		Stage:   progress.StageNormalizing,
		Status:  progress.StatusRunning,
	})
	findings, err := Parse(data)
	if err != nil {
		return report.Report{}, err
	}
	result := report.Report{
		SchemaVersion: "1",
		Repository:    repository,
		Scanners: []report.Scanner{{
			Name:   "gitleaks",
			Status: "success",
			Image:  imageID,
			Coverage: report.Coverage{
				Read:   1,
				Failed: 0,
				Unit:   "repository",
			},
		}},
		Findings: findings,
	}
	emit(progress.Event{
		Scanner:  "gitleaks",
		Stage:    progress.StageDone,
		Status:   progress.StatusSuccess,
		Files:    1,
		Findings: len(findings),
	})
	return result, nil
}

func createReportDir(userCacheDir func() (string, error)) (string, error) {
	cache, err := userCacheDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(cache, "secscan")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, "gitleaks-*")
}
