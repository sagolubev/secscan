package gitleaks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/report"
)

const Image = "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

func ContainerArgs(repository, output string) []string {
	return []string{
		"run", "--rm",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--mount", "type=bind,src=" + repository + ",dst=/repo,readonly",
		"--mount", "type=bind,src=" + output + ",dst=/out",
		Image,
		"dir", "/repo",
		"--no-banner", "--no-color", "--redact=100",
		"--exit-code", "0",
		"--report-format", "json",
		"--report-path", "/out/gitleaks.json",
	}
}

func Scan(ctx context.Context, runtime container.Runtime, repository string) (report.Report, error) {
	output, err := createReportDir(os.UserCacheDir)
	if err != nil {
		return report.Report{}, fmt.Errorf("create report directory: %w", err)
	}
	defer os.RemoveAll(output)

	if err := runtime.Run(ctx, ContainerArgs(repository, output)); err != nil {
		return report.Report{}, err
	}
	data, err := os.ReadFile(filepath.Join(output, "gitleaks.json"))
	if err != nil {
		return report.Report{}, fmt.Errorf("read Gitleaks report: %w", err)
	}
	findings, err := Parse(data)
	if err != nil {
		return report.Report{}, err
	}
	return report.Report{
		SchemaVersion: "1",
		Repository:    repository,
		Scanners: []report.Scanner{{
			Name:   "gitleaks",
			Status: "success",
			Image:  Image,
			Coverage: report.Coverage{
				Read:   1,
				Failed: 0,
				Unit:   "repository",
			},
		}},
		Findings: findings,
	}, nil
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
