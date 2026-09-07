// START_MODULE_CONTRACT
// PURPOSE: Run pinned Gitleaks within the shared isolated container boundary.
// SCOPE: Private output directory; bounded regular report reads without following symlinks.
// DEPENDS: internal/container/runtime.go, internal/gitleaks/parser.go, internal/report/report.go
// LINKS: internal/gitleaks/run_test.go#TestContainerArgsEnforceSecurityBoundary, internal/gitleaks/run_test.go#TestReadReportRejectsSymlinksAndOversize
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Image - Identify the pinned scanner artifact.
// ContainerArgs - Build the working-tree scanner's isolated invocation.
// Scan - Run and normalize working-tree Gitleaks results.
// END_MODULE_MAP

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
	"golang.org/x/sys/unix"
)

// Image identifies the pinned Gitleaks release.
const Image = "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

// ContainerArgs builds the isolated working-tree scan invocation.
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

// Scan runs Gitleaks on a prepared working tree and returns sanitized findings.
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
	data, err := readReport(filepath.Join(output, "gitleaks.json"))
	if err != nil {
		return report.Report{}, err
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

func readReport(name string) ([]byte, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open Gitleaks report: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Gitleaks report must be a regular file")
	}
	if info.Size() > 64<<20 {
		return nil, fmt.Errorf("Gitleaks report exceeds 64 MiB limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read Gitleaks report: %w", err)
	}
	if len(data) > 64<<20 {
		return nil, fmt.Errorf("Gitleaks report exceeds 64 MiB limit")
	}
	return data, nil
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
