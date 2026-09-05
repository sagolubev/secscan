package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/discovery"
	"github.com/sigiuscom/secscan/internal/gitleaks"
	"github.com/sigiuscom/secscan/internal/opengrep"
	"github.com/sigiuscom/secscan/internal/orchestrator"
	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
	"golang.org/x/term"
)

type scanFunc func(context.Context, string, []string, func(progress.Event)) (report.Report, error)

func main() {
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(signalContext, 10*time.Minute)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, scan)
	cancel()
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, scan scanFunc) int {
	flags := flag.NewFlagSet("secscan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	scanners := flags.String("scanners", "all", "comma-separated scanner selection")
	progressValue := flags.String("progress", "auto", "progress mode: auto, tty, plain, or off")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	progressMode, err := progress.ParseMode(*progressValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	selection, err := parseScannerSelection(*scanners)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "expected at most one repository path")
		return 2
	}
	path := "."
	if flags.NArg() == 1 {
		path = flags.Arg(0)
	}

	reporter := progress.New(
		stderr,
		progressMode,
		isTerminal(stderr) && os.Getenv("TERM") != "dumb",
		os.Getenv("NO_COLOR") == "",
		time.Now,
		func() int { return terminalWidth(stderr) },
	)
	closed := false
	closeReporter := func() {
		if !closed {
			_ = reporter.Close()
			closed = true
		}
	}
	defer closeReporter()

	result, err := scan(ctx, path, selection, reporter.Emit)
	if err != nil {
		closeReporter()
		fmt.Fprintln(stderr, err)
		return 1
	}
	data, err := report.Marshal(result)
	if err != nil {
		closeReporter()
		fmt.Fprintln(stderr, err)
		return 1
	}
	closeReporter()
	if _, err := fmt.Fprintln(stdout, string(data)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func scan(
	ctx context.Context,
	path string,
	selection []string,
	emit func(progress.Event),
) (report.Report, error) {
	root, err := gitRoot(path)
	if err != nil {
		return report.Report{}, err
	}
	inventory, err := discovery.Discover(root)
	if err != nil {
		return report.Report{}, err
	}
	for _, name := range selection {
		emit(progress.Event{Scanner: name, Stage: progress.StageQueued, Status: progress.StatusQueued})
	}
	needsRuntime := slices.Contains(selection, "gitleaks") ||
		slices.Contains(selection, "python-sast") && len(inventory.Python) > 0 ||
		slices.Contains(selection, "typescript-sast") && len(inventory.TypeScript) > 0
	var runtime container.Runtime
	if needsRuntime {
		runtime, err = container.DetectDefault(ctx)
		if err != nil {
			return report.Report{}, err
		}
	}

	var jobs []orchestrator.Job
	var skipped []report.Scanner
	if slices.Contains(selection, "gitleaks") {
		jobs = append(jobs, orchestrator.Job{
			Name:    "gitleaks",
			Timeout: 10 * time.Minute,
			Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
				result, err := gitleaks.Scan(ctx, runtime, root, emit)
				if err != nil {
					return report.Scanner{}, nil, err
				}
				return result.Scanners[0], result.Findings, nil
			},
		})
	}

	languages := []struct {
		scanner string
		name    string
		files   []string
	}{
		{scanner: "python-sast", name: "python", files: inventory.Python},
		{scanner: "typescript-sast", name: "typescript", files: inventory.TypeScript},
	}
	needsImage := false
	for _, language := range languages {
		if slices.Contains(selection, language.scanner) && len(language.files) > 0 {
			needsImage = true
		}
	}
	var imageID string
	var imageErr error
	if needsImage {
		for _, language := range languages {
			if slices.Contains(selection, language.scanner) && len(language.files) > 0 {
				emit(progress.Event{
					Scanner: language.scanner,
					Stage:   progress.StagePreparing,
					Status:  progress.StatusRunning,
					Files:   len(language.files),
				})
			}
		}
		imageID, imageErr = opengrep.EnsureImage(ctx, runtime)
	}
	for _, language := range languages {
		if !slices.Contains(selection, language.scanner) {
			continue
		}
		if len(language.files) == 0 {
			emit(progress.Event{
				Scanner: language.scanner,
				Stage:   progress.StageSkipped,
				Status:  progress.StatusSkipped,
			})
			skipped = append(skipped, report.Scanner{
				Name:   language.scanner,
				Status: "skipped",
				Coverage: report.Coverage{
					Unit: "files",
				},
			})
			continue
		}
		language := language
		jobs = append(jobs, orchestrator.Job{
			Name:    language.scanner,
			Timeout: 10 * time.Minute,
			Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
				if imageErr != nil {
					return report.Scanner{}, nil, imageErr
				}
				target, err := discovery.Stage(root, language.files)
				if err != nil {
					return report.Scanner{}, nil, err
				}
				defer os.RemoveAll(target)
				return opengrep.Scan(
					ctx,
					runtime,
					imageID,
					language.name,
					target,
					len(language.files),
					emit,
				)
			},
		})
	}

	result, runErr := orchestrator.Run(ctx, jobs, 3, emit)
	return buildReport(
		root,
		report.Exclusions{
			IgnoredFiles: inventory.Ignored.Files,
			IgnoredBytes: inventory.Ignored.Bytes,
		},
		skipped,
		result,
		runErr,
	)
}

func buildReport(
	root string,
	exclusions report.Exclusions,
	skipped []report.Scanner,
	result orchestrator.Result,
	runErr error,
) (report.Report, error) {
	result.Scanners = append(result.Scanners, skipped...)
	if len(result.Scanners) > len(skipped) && result.Successes == 0 {
		return report.Report{}, orchestrator.ErrAllScannersFailed
	}
	return report.Report{
		SchemaVersion: "1",
		Repository:    root,
		Scanners:      result.Scanners,
		Findings:      result.Findings,
		Exclusions:    exclusions,
	}, runErr
}

func parseScannerSelection(value string) ([]string, error) {
	allowed := []string{"gitleaks", "python-sast", "typescript-sast"}
	if value == "all" {
		return allowed, nil
	}
	seen := make(map[string]bool)
	var selected []string
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if !slices.Contains(allowed, name) {
			return nil, fmt.Errorf("unsupported scanner selection %q", name)
		}
		if !seen[name] {
			selected = append(selected, name)
			seen[name] = true
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("scanner selection is empty")
	}
	return selected, nil
}

func gitRoot(path string) (string, error) {
	command := exec.Command("git", "-C", path, "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve Git worktree: %w", err)
	}
	return filepath.Clean(string(bytes.TrimSpace(output))), nil
}

func isTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func terminalWidth(writer io.Writer) int {
	file, ok := writer.(*os.File)
	if !ok {
		return 100
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 {
		return 100
	}
	return width
}
