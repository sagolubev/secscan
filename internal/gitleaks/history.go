// START_MODULE_CONTRACT
// PURPOSE: Scan frozen Git ancestry through an independent bounded bare snapshot.
// SCOPE: Offline source reads; no source config, hooks or shared directories in containers; sanitized evidence only.
// DEPENDS: internal/container/runtime.go, internal/gitleaks/parser.go, internal/gitleaks/run.go, internal/report/report.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model, internal/gitleaks/history_test.go#TestAcceptanceHistoryFindsDeletedSecret, internal/gitleaks/history_test.go#TestHistorySnapshotIsIndependentAndIgnoresSourceConfiguration
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// ScanHistory - Snapshot complete HEAD ancestry and normalize isolated Gitleaks Git results.
// historyWriter.Write - Bound materialized Git output before it reaches memory or disk.
// END_MODULE_MAP

package gitleaks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
	"golang.org/x/sys/unix"
)

type historyLimits struct {
	commits     int
	bundleBytes int64
}

type historySnapshot struct {
	workspace  string
	repository string
	head       string
	commits    map[string]struct{}
}

// ScanHistory scans all ancestry of the current HEAD without mounting source Git
// metadata. The snapshot is capped at 100000 commits and a 512 MiB bundle.
func ScanHistory(ctx context.Context, runtime container.Runtime, repository string, emit func(progress.Event), imageID string) (report.Report, error) {
	emit(progress.Event{Scanner: "gitleaks-history", Stage: progress.StageScanning, Status: progress.StatusRunning})
	snapshot, err := snapshotHistory(ctx, repository, historyLimits{commits: 100000, bundleBytes: 512 << 20})
	if err != nil {
		return report.Report{}, err
	}
	defer os.RemoveAll(snapshot.workspace)
	output := filepath.Join(snapshot.workspace, "out")
	if err := os.Mkdir(output, 0o700); err != nil {
		return report.Report{}, fmt.Errorf("create history report directory: %w", err)
	}
	args := historyContainerArgs(snapshot.repository, output, snapshot.head, imageID)
	markers := []string{"fatal", "error", "err", "[git]"}
	diagnostics, err := runtime.OutputRejecting(ctx, args, markers)
	if err != nil {
		return report.Report{}, err
	}
	// Some runtime wrappers forward scanner diagnostics on stdout.
	lower := bytes.ToLower(diagnostics)
	for _, marker := range markers {
		if bytes.Contains(lower, []byte(marker)) {
			return report.Report{}, fmt.Errorf("Gitleaks history reported an analysis failure")
		}
	}
	emit(progress.Event{Scanner: "gitleaks-history", Stage: progress.StageReading, Status: progress.StatusRunning})
	if err := ctx.Err(); err != nil {
		return report.Report{}, err
	}
	data, err := readReport(filepath.Join(output, "gitleaks.json"))
	if err != nil {
		return report.Report{}, err
	}
	emit(progress.Event{Scanner: "gitleaks-history", Stage: progress.StageNormalizing, Status: progress.StatusRunning})
	findings, err := parseHistory(data, snapshot.commits)
	if err != nil {
		return report.Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return report.Report{}, err
	}
	result := report.Report{
		SchemaVersion: "1", Repository: repository, Findings: findings,
		Scanners: []report.Scanner{{Name: "gitleaks-history", Status: "success", Image: imageID,
			History:  &report.GitHistory{Head: snapshot.head, Commits: len(snapshot.commits)},
			Coverage: report.Coverage{Read: 1, Unit: "repository"},
		}},
	}
	emit(progress.Event{Scanner: "gitleaks-history", Stage: progress.StageDone, Status: progress.StatusSuccess, Files: 1, Findings: len(findings)})
	return result, nil
}

func historyContainerArgs(repository, output, head, imageID string) []string {
	return append(container.IsolatedArgs(repository, "/repo"),
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--mount", "type=bind,src="+output+",dst=/out",
		"--env", "GIT_CONFIG_COUNT=1", "--env", "GIT_CONFIG_KEY_0=safe.directory", "--env", "GIT_CONFIG_VALUE_0=/repo",
		"--env", "GIT_CONFIG_NOSYSTEM=1", "--env", "GIT_CONFIG_GLOBAL=/dev/null", "--env", "GIT_CONFIG_SYSTEM=/dev/null",
		"--env", "GIT_NO_LAZY_FETCH=1", "--env", "GIT_NO_REPLACE_OBJECTS=1", "--env", "GIT_OPTIONAL_LOCKS=0",
		"--env", "GIT_TERMINAL_PROMPT=0", "--env", "GIT_ALLOW_PROTOCOL=",
		imageID, "git", "/repo", "--log-opts", head, "--log-level", "error",
		"--no-banner", "--no-color", "--redact=100", "--exit-code", "0",
		"--report-format", "json", "--report-path", "/out/gitleaks.json")
}

func snapshotHistory(ctx context.Context, repository string, limits historyLimits) (snapshot historySnapshot, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	snapshot.workspace, err = createReportDir(os.UserCacheDir)
	if err != nil {
		return snapshot, fmt.Errorf("create history snapshot directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(snapshot.workspace)
		}
	}()
	output, err := historyGitOutput(ctx, repository, 4096, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return snapshot, fmt.Errorf("resolve history HEAD: %w", err)
	}
	snapshot.head = strings.TrimSpace(string(output))
	if !validCommit(snapshot.head) {
		return snapshot, fmt.Errorf("invalid history HEAD")
	}
	output, err = historyGitOutput(ctx, repository, 4096, "rev-parse", "--is-shallow-repository")
	if err != nil || strings.TrimSpace(string(output)) != "false" {
		return snapshot, fmt.Errorf("history requires a complete non-shallow repository")
	}
	output, err = historyGitOutput(ctx, repository, 64<<10, "rev-parse", "--path-format=absolute", "--git-path", "info/grafts")
	if err != nil {
		return snapshot, err
	}
	if _, statErr := os.Lstat(strings.TrimSpace(string(output))); !errors.Is(statErr, os.ErrNotExist) {
		return snapshot, fmt.Errorf("history rejects grafted or inaccessible Git metadata")
	}
	snapshot.commits, err = historyCommits(ctx, repository, snapshot.head, limits.commits)
	if err != nil {
		return snapshot, err
	}
	bundle := filepath.Join(snapshot.workspace, "history.bundle")
	file, err := os.OpenFile(bundle, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return snapshot, fmt.Errorf("create history bundle: %w", err)
	}
	writeErr := runHistoryGit(ctx, repository, file, limits.bundleBytes, false, "bundle", "create", "-", "HEAD")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return snapshot, fmt.Errorf("create bounded history bundle: %w", errors.Join(writeErr, closeErr))
	}
	output, err = historyGitOutput(ctx, repository, 4096, "bundle", "list-heads", bundle)
	if err != nil || !validBundleHead(output, snapshot.head) {
		return snapshot, fmt.Errorf("history HEAD changed or bundle advertisement is invalid")
	}
	output, err = historyGitOutput(ctx, repository, 4096, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || strings.TrimSpace(string(output)) != snapshot.head {
		return snapshot, fmt.Errorf("history HEAD changed during snapshot creation")
	}
	snapshot.repository = filepath.Join(snapshot.workspace, "repository.git")
	if err := runHistoryGit(ctx, snapshot.workspace, io.Discard, 64<<10, true,
		"clone", "--bare", "--no-local", "--no-hardlinks", "--template=", "--", bundle, snapshot.repository); err != nil {
		return snapshot, fmt.Errorf("clone independent history snapshot: %w", err)
	}
	// A local bundle clone writes its own origin remote; remove that generated
	// remote so the scanner receives no fetch destination at all.
	if err := runHistoryGit(ctx, snapshot.repository, io.Discard, 4096, false, "config", "--remove-section", "remote.origin"); err != nil {
		return snapshot, err
	}
	if err := runHistoryGit(ctx, snapshot.repository, io.Discard, 64<<10, false, "fsck", "--connectivity-only", "--no-dangling"); err != nil {
		return snapshot, fmt.Errorf("incomplete history snapshot: %w", err)
	}
	commits, err := historyCommits(ctx, snapshot.repository, snapshot.head, limits.commits)
	if err != nil || len(commits) != len(snapshot.commits) {
		return snapshot, fmt.Errorf("history snapshot ancestry mismatch")
	}
	for commit := range commits {
		if _, ok := snapshot.commits[commit]; !ok {
			return snapshot, fmt.Errorf("history snapshot ancestry mismatch")
		}
	}
	return snapshot, nil
}

func validBundleHead(data []byte, head string) bool {
	return string(data) == head+" HEAD\n"
}

func historyCommits(ctx context.Context, repository, head string, limit int) (map[string]struct{}, error) {
	data, err := historyGitOutput(ctx, repository, int64(limit+1)*65, "rev-list", "--max-count="+strconv.Itoa(limit+1), head, "--")
	if err != nil {
		return nil, fmt.Errorf("enumerate complete history: %w", err)
	}
	lines := strings.Fields(string(data))
	if len(lines) == 0 || len(lines) > limit {
		return nil, fmt.Errorf("history exceeds commit limit or has no commits")
	}
	commits := make(map[string]struct{}, len(lines))
	for _, commit := range lines {
		if !validCommit(commit) {
			return nil, fmt.Errorf("invalid history commit")
		}
		commits[commit] = struct{}{}
	}
	return commits, nil
}

func historyGitOutput(ctx context.Context, repository string, limit int64, args ...string) ([]byte, error) {
	var output bytes.Buffer
	err := runHistoryGit(ctx, repository, &output, limit, false, args...)
	return output.Bytes(), err
}

// runHistoryGit bounds each owned process group and discards raw diagnostics.
// Only the explicit owned-bundle clone can enable the file transport.
func runHistoryGit(ctx context.Context, repository string, output io.Writer, limit int64, bundleClone bool, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	argv := []string{"--no-pager", "--no-replace-objects", "-C", repository,
		"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.alternateRefsCommand=",
		"-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "pack.threads=1", "-c", "protocol.allow=never"}
	protocol := ""
	if bundleClone {
		protocol = "file"
		argv = append(argv, "-c", "protocol.file.allow=always")
	}
	command := exec.CommandContext(ctx, "git", append(argv, args...)...)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GIT_") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL="+protocol)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	command.Stdout = &historyWriter{writer: output, remaining: limit}
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("Git history operation failed or exceeded its output limit")
	}
	return nil
}

type historyWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *historyWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, fmt.Errorf("Git history output limit exceeded")
	}
	n, err := w.writer.Write(data)
	w.remaining -= int64(n)
	return n, err
}
