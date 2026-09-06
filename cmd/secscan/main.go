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
	"github.com/sigiuscom/secscan/internal/scanner"
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
	updating := len(args) > 0 && args[0] == "update"
	if updating {
		args = args[1:]
	}
	flags := flag.NewFlagSet("secscan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	scanImages := flags.Bool("scan-images", false, "authorize host runtime image pulls and offline archive scans")
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
	if slices.Contains(selection, "oci-images") && !*scanImages && !updating {
		fmt.Fprintln(stderr, "oci-images scanning requires --scan-images")
		return 2
	}
	if *scanImages && !slices.Contains(selection, "oci-images") {
		selection = append(selection, "oci-images")
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "expected at most one repository path")
		return 2
	}
	path := "."
	if flags.NArg() == 1 {
		path = flags.Arg(0)
	}

	if updating {
		root, err := gitRoot(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		runtime, err := container.DetectDefault(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		cache, err := scanner.DefaultCache()
		if err == nil {
			err = scanner.Update(ctx, runtime, cache, selection, root)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stderr, "scanner assets prepared")
		return 0
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

	result, scanErr := scan(ctx, path, selection, reporter.Emit)
	if scanErr != nil && (result.SchemaVersion == "" || len(result.Scanners) == 0) {
		closeReporter()
		fmt.Fprintln(stderr, scanErr)
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
	if scanErr != nil {
		fmt.Fprintln(stderr, scanErr)
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
	unchecked, _, err := scanner.ScanOCI(ctx, container.Runtime{}, scanner.Cache{}, root, inventory.OCI, false, emit)
	if err != nil {
		return report.Report{}, err
	}
	dependencyFiles, dependencyUnread := scanner.DependencyInputs(inventory.Dependencies)
	needsRuntime := slices.Contains(selection, "oci-images") && len(unchecked.Images) > 0 ||
		slices.Contains(selection, "gradle-catalog") && len(scanner.NativeInputs("gradle-catalog", inventory.Native)) > 0 ||
		slices.Contains(selection, "gradle-scripts") && len(scanner.NativeInputs("gradle-scripts", inventory.Native)) > 0 ||
		slices.Contains(selection, "gitleaks") ||
		slices.Contains(selection, "python-sast") && len(inventory.Python) > 0 ||
		slices.Contains(selection, "typescript-sast") && len(inventory.TypeScript) > 0 ||
		slices.Contains(selection, "zizmor") && len(inventory.Zizmor) > 0 || slices.Contains(selection, "poutine") && len(inventory.Poutine) > 0 ||
		slices.Contains(selection, "checkov") && len(inventory.Checkov) > 0 || slices.Contains(selection, "checkov-terraform") && len(inventory.Terraform) > 0 || slices.Contains(selection, "kics") && len(inventory.KICS) > 0 ||
		(slices.Contains(selection, "trivy") || slices.Contains(selection, "grype") || slices.Contains(selection, "osv-scanner")) && len(dependencyFiles) > 0 ||
		slices.Contains(selection, "semgrep") && len(inventory.Python)+len(inventory.TypeScript) > 0 ||
		slices.Contains(selection, "bearer") && len(inventory.Bearer) > 0 ||
		slices.Contains(selection, "cppcheck") && len(inventory.Cppcheck) > 0
	var runtime container.Runtime
	if needsRuntime {
		runtime, err = container.DetectDefault(ctx)
		if err != nil {
			return report.Report{}, err
		}
	}

	cache, cacheErr := scanner.DefaultCache()
	var jobs []orchestrator.Job
	var skipped []report.Scanner
	preparationErrors := map[string]error{}
	for _, name := range []string{"gradle-catalog", "gradle-scripts", "refresh-versions"} {
		if !slices.Contains(selection, name) {
			continue
		}
		files := scanner.NativeInputs(name, inventory.Native)
		if len(files) == 0 {
			skipped = append(skipped, report.Scanner{Name: name, Status: "skipped", Coverage: report.Coverage{Unit: "declarations"}})
			emit(progress.Event{Scanner: name, Stage: progress.StageSkipped, Status: progress.StatusSkipped})
			continue
		}
		jobs = append(jobs, orchestrator.Job{Name: name, Timeout: 10 * time.Minute, Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
			if cacheErr != nil && name != "refresh-versions" {
				return report.Scanner{}, nil, cacheErr
			}
			return scanner.ScanNative(ctx, runtime, cache, name, root, files, emit)
		}})
	}
	if slices.Contains(selection, "oci-images") && (len(unchecked.Images) > 0 || unchecked.Coverage.Unread > 0 || unchecked.Coverage.FailedFiles > 0) {
		jobs = append(jobs, orchestrator.Job{Name: "oci-images", Timeout: 10 * time.Minute, Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
			return scanner.ScanOCI(ctx, runtime, cache, root, inventory.OCI, true, emit)
		}})
	} else if slices.Contains(selection, "oci-images") || len(unchecked.Images) > 0 || unchecked.Coverage.Unread > 0 || unchecked.Coverage.FailedFiles > 0 {
		skipped = append(skipped, unchecked)
		emit(progress.Event{Scanner: "oci-images", Stage: progress.StageSkipped, Status: progress.StatusSkipped})
	}
	var gitleaksAsset scanner.Asset
	var gitleaksErr error
	if slices.Contains(selection, "gitleaks") {
		if cacheErr != nil {
			gitleaksErr = cacheErr
		} else {
			gitleaksAsset, gitleaksErr = cache.Resolve(ctx, runtime, "gitleaks")
		}
		if gitleaksErr != nil {
			preparationErrors["gitleaks"] = gitleaksErr
		}
		jobs = append(jobs, orchestrator.Job{
			Name:    "gitleaks",
			Timeout: 10 * time.Minute,
			Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
				if gitleaksErr != nil {
					return report.Scanner{}, nil, gitleaksErr
				}
				result, err := gitleaks.Scan(ctx, runtime, root, emit, gitleaksAsset.ImageID)
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
		if cacheErr != nil {
			imageErr = cacheErr
		} else {
			var asset scanner.Asset
			asset, imageErr = cache.Resolve(ctx, runtime, "opengrep")
			imageID = asset.ImageID
		}
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
		if imageErr != nil {
			preparationErrors[language.scanner] = imageErr
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

	for _, name := range []string{"zizmor", "poutine", "checkov", "checkov-terraform", "kics", "trivy", "grype", "osv-scanner", "semgrep", "bearer", "cppcheck"} {
		if !slices.Contains(selection, name) {
			continue
		}
		files := inventory.Zizmor
		switch name {
		case "semgrep":
			files = append(append([]string(nil), inventory.Python...), inventory.TypeScript...)
			slices.Sort(files)
		case "bearer":
			files = inventory.Bearer
		case "cppcheck":
			files = inventory.Cppcheck
		case "poutine":
			files = inventory.Poutine
		case "checkov":
			files = inventory.Checkov
		case "checkov-terraform":
			files = inventory.Terraform
		case "kics":
			files = inventory.KICS
		case "trivy", "grype", "osv-scanner":
			files = inventory.Dependencies
		}
		dependency := name == "trivy" || name == "grype" || name == "osv-scanner"
		if len(files) == 0 || dependency && len(dependencyFiles) == 0 {
			coverage := report.Coverage{Unit: "files"}
			if dependency {
				coverage.Unread = len(dependencyUnread)
				coverage.UnreadInputs = dependencyUnread
			}
			skipped = append(skipped, report.Scanner{Name: name, Status: "skipped", Coverage: coverage})
			emit(progress.Event{Scanner: name, Stage: progress.StageSkipped, Status: progress.StatusSkipped})
			continue
		}
		if name == "bearer" {
			arch, err := scanner.RuntimeArchitecture(ctx, runtime)
			if err != nil {
				return report.Report{}, err
			}
			if arch != "amd64" {
				skipped = append(skipped, report.Scanner{Name: name, Status: "skipped", EngineVersion: scanner.Catalog()[name].Version, Coverage: report.Coverage{Unit: "files", Unread: len(files), UnreadInputs: files}, Limitations: []string{"unsupported_runtime_arch: " + arch + "; Bearer requires native amd64; emulation disabled"}})
				emit(progress.Event{Scanner: name, Stage: progress.StageSkipped, Status: progress.StatusSkipped})
				continue
			}
		}
		if cacheErr != nil {
			preparationErrors[name] = cacheErr
		} else if name == "trivy" || name == "grype" || name == "osv-scanner" {
			if _, _, err := cache.ResolveDependencies(ctx, runtime, name, files); err != nil {
				preparationErrors[name] = err
			}
		} else if _, err := cache.Resolve(ctx, runtime, name); err != nil {
			preparationErrors[name] = err
		}
		jobs = append(jobs, orchestrator.Job{Name: name, Timeout: 10 * time.Minute, Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
			if err := preparationErrors[name]; err != nil {
				return report.Scanner{}, nil, err
			}
			if name == "trivy" || name == "grype" || name == "osv-scanner" {
				return scanner.ScanDependencies(ctx, runtime, cache, name, root, files, emit)
			}
			if name == "checkov" || name == "checkov-terraform" || name == "kics" {
				return scanner.ScanIaC(ctx, runtime, cache, name, root, files, emit)
			}
			if name == "semgrep" || name == "bearer" || name == "cppcheck" {
				return scanner.ScanCode(ctx, runtime, cache, name, root, files, emit)
			}
			return scanner.ScanCI(ctx, runtime, cache, name, root, files, emit)
		}})
	}

	result, runErr := orchestrator.Run(ctx, jobs, 3, emit)

	for i := range result.Scanners {
		name := result.Scanners[i].Name
		if result.Scanners[i].Status == "failed" && (name == "trivy" || name == "grype" || name == "osv-scanner") {
			result.Scanners[i].Coverage.FailedInputs = append([]string(nil), inventory.Dependencies...)
			result.Scanners[i].Coverage.FailedFiles = len(inventory.Dependencies)
		}
		if result.Scanners[i].Status == "failed" && name == "bearer" {
			result.Scanners[i].Coverage.UnreadInputs = append([]string(nil), inventory.Bearer...)
			result.Scanners[i].Coverage.Unread = len(inventory.Bearer)
			result.Scanners[i].Limitations = []string{"Bearer execution failed or coverage_unconfirmed: no positive file analysis evidence; selected inputs remain unread"}
		}
		if preparationErrors[result.Scanners[i].Name] != nil {
			result.Scanners[i].Limitations = []string{"prepared assets unavailable; run secscan update"}
		}
	}
	if result.Successes == 0 && len(preparationErrors) > 0 {
		runErr = fmt.Errorf("prepared assets unavailable; run secscan update: %w", orchestrator.ErrAllScannersFailed)
	}
	if result.Successes == 0 && len(selection) == 1 && selection[0] == "bearer" && len(skipped) == 0 {
		runErr = fmt.Errorf("Bearer execution failed or coverage_unconfirmed: no positive file analysis evidence: %w", orchestrator.ErrAllScannersFailed)
	}
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
	if len(result.Scanners) > len(skipped) && result.Successes == 0 && runErr == nil {
		runErr = orchestrator.ErrAllScannersFailed
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
	allowed := []string{"gitleaks", "python-sast", "typescript-sast", "zizmor", "poutine", "checkov", "checkov-terraform", "kics", "trivy", "grype", "osv-scanner", "semgrep", "bearer", "cppcheck", "gradle-catalog", "gradle-scripts", "refresh-versions"}
	if value == "all" {
		return allowed, nil
	}
	allowed = append(allowed, "oci-images")
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
