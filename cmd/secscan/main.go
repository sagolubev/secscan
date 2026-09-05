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
	"syscall"
	"time"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/gitleaks"
	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
	"golang.org/x/term"
)

type scanFunc func(context.Context, string, func(progress.Event)) (report.Report, error)

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
	scanners := flags.String("scanners", "gitleaks", "scanner selection")
	progressValue := flags.String("progress", "auto", "progress mode: auto, tty, plain, or off")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	progressMode, err := progress.ParseMode(*progressValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *scanners != "gitleaks" && *scanners != "all" {
		fmt.Fprintf(stderr, "unsupported scanner selection %q\n", *scanners)
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

	reporter.Emit(progress.Event{
		Scanner: "gitleaks",
		Stage:   progress.StageQueued,
		Status:  progress.StatusQueued,
	})
	result, err := scan(ctx, path, reporter.Emit)
	if err != nil {
		reporter.Emit(progress.Event{
			Scanner: "gitleaks",
			Stage:   progress.StageFailed,
			Status:  progress.StatusFailed,
			Message: "scan failed",
		})
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

func scan(ctx context.Context, path string, emit func(progress.Event)) (report.Report, error) {
	root, err := gitRoot(path)
	if err != nil {
		return report.Report{}, err
	}
	emit(progress.Event{
		Scanner: "gitleaks",
		Stage:   progress.StagePreparing,
		Status:  progress.StatusRunning,
	})
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		return report.Report{}, err
	}
	return gitleaks.Scan(ctx, runtime, root, emit)
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
