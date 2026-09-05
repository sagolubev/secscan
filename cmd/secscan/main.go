package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/gitleaks"
	"github.com/sigiuscom/secscan/internal/report"
)

type scanFunc func(context.Context, string) (report.Report, error)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, scan))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, scan scanFunc) int {
	flags := flag.NewFlagSet("secscan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	scanners := flags.String("scanners", "gitleaks", "scanner selection")
	if err := flags.Parse(args); err != nil {
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

	fmt.Fprintln(stderr, "scanner=gitleaks status=starting")
	result, err := scan(ctx, path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	data, err := report.Marshal(result)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, string(data)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func scan(ctx context.Context, path string) (report.Report, error) {
	root, err := gitRoot(path)
	if err != nil {
		return report.Report{}, err
	}
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		return report.Report{}, err
	}
	return gitleaks.Scan(ctx, runtime, root)
}

func gitRoot(path string) (string, error) {
	command := exec.Command("git", "-C", path, "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve Git worktree: %w", err)
	}
	return filepath.Clean(string(bytes.TrimSpace(output))), nil
}
