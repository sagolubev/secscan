// START_MODULE_CONTRACT
// PURPOSE: Compose CLI validation, isolated scanners and canonical output.
// SCOPE: Keep stdout JSON-only; stage Git-selected files and expose incomplete coverage.
// DEPENDS: internal/discovery/discovery.go, internal/orchestrator/orchestrator.go, internal/report/report.go, cmd/secscan/baseline.go, cmd/secscan/config.go, cmd/secscan/render.go
// LINKS: openspec/changes/build-secscan/trace.json, cmd/secscan/main_test.go#TestRunWritesOneJSONDocument, cmd/secscan/coverage_test.go#TestAcceptanceGitleaksUsesSelectedInventory
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// main - Own process cancellation and exit status.
// scanOptions - Explicit scanner selection and excluded control paths.
// run - Validate policy and outputs, filter visible findings and preserve full exports.
// scan - Compose prepared scanner jobs and inventory evidence.
// buildReport - Preserve successful and partial results.
// parseScannerSelection - Validate the finite scanner set.
// gitRoot - Resolve the containing Git worktree.
// END_MODULE_MAP

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

	"github.com/sagolubev/secscan"
	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/filter"
	"github.com/sagolubev/secscan/internal/gitleaks"
	"github.com/sagolubev/secscan/internal/opengrep"
	"github.com/sagolubev/secscan/internal/orchestrator"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
	"github.com/sagolubev/secscan/internal/scanner"
	"golang.org/x/term"
)

type scanOptions struct {
	Scanners     []string
	TrivyReports bool
	Excluded     []string
}

type scanFunc func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error)

var version = "dev"

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
	showVersion := flags.Bool("version", false, "print build version")
	showLicenses := flags.Bool("licenses", false, "print project and third-party license notices")
	scanImages := flags.Bool("scan-images", false, "authorize host runtime image pulls and offline archive scans")
	scanners := flags.String("scanners", "all", "comma-separated scanner selection")
	trivyReports := flags.String("trivy-reports", "", "write Trivy CycloneDX and SonarQube JSON to a new directory")
	baselineInput := flags.String("baseline", "", "compare findings with a saved baseline")
	baselineOutput := flags.String("write-baseline", "", "write unfiltered findings to a new baseline file")
	htmlOutput := flags.String("html", "", "write the visible report to a new offline HTML file")
	sarifOutput := flags.String("sarif", "", "write complete unfiltered findings to a new SARIF file")
	configFile := flags.String("config", "", "read project filtering policy from this TOML file")
	noConfig := flags.Bool("no-config", false, "ignore project filtering configuration")
	minSeverity := flags.String("min-severity", "", "hide ranked findings below this severity; keep secrets, errors and unknown severity")
	progressValue := flags.String("progress", "auto", "progress mode: auto, tty, plain, or off")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion || *showLicenses {
		if updating || flags.NArg() != 0 || flags.NFlag() != 1 {
			fmt.Fprintln(stderr, "--version and --licenses must be used alone")
			return 2
		}
		text := "secscan " + version + "\n"
		if *showLicenses {
			var err error
			text, err = secscan.Licenses()
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		if _, err := io.WriteString(stdout, text); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
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

	wantReports, readBaselineFlag, writeBaselineFlag := false, false, false
	htmlFlag, sarifFlag := false, false
	configFlag, noConfigFlag, severityFlag := false, false, false
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "trivy-reports":
			wantReports = true
		case "baseline":
			readBaselineFlag = true
		case "write-baseline":
			writeBaselineFlag = true
		case "html":
			htmlFlag = true
		case "sarif":
			sarifFlag = true
		case "config":
			configFlag = true
		case "no-config":
			noConfigFlag = true
		case "min-severity":
			severityFlag = true
		}
	})
	if configFlag && noConfigFlag || configFlag && *configFile == "" || severityFlag && (*minSeverity == "" || !filter.ValidSeverity(*minSeverity)) || updating && (configFlag || noConfigFlag || severityFlag) {
		fmt.Fprintln(stderr, "invalid filtering flags: choose --config or --no-config, a valid --min-severity, and use them only with scan")
		return 2
	}
	project := projectConfiguration{value: filter.Config{Version: 1}}
	if !updating {
		project, err = prepareProjectConfig(path, *configFile, *noConfig)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if severityFlag {
			project.value.MinSeverity = *minSeverity
			project.active = true
		}
	}
	var baselineOptions baselineRequest
	if readBaselineFlag || writeBaselineFlag {
		if updating || readBaselineFlag && writeBaselineFlag || readBaselineFlag && *baselineInput == "" || writeBaselineFlag && *baselineOutput == "" {
			fmt.Fprintln(stderr, "--baseline and --write-baseline require a file, are mutually exclusive and cannot be used with update")
			return 2
		}
		root, err := gitRoot(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		baselineOptions, err = prepareBaseline(root, *baselineInput, *baselineOutput)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if baselineOptions.output != nil {
			defer baselineOptions.output.close()
		}
	}
	var renderedOutputs []renderedOutput
	controlPaths := append([]string(nil), baselineOptions.excluded...)
	controlPaths = append(controlPaths, project.excluded...)
	if htmlFlag || sarifFlag {
		if updating || htmlFlag && *htmlOutput == "" || sarifFlag && *sarifOutput == "" {
			fmt.Fprintln(stderr, "--html and --sarif require a new file and cannot be used with update")
			return 2
		}
		root, err := gitRoot(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		renderedOutputs, err = prepareRenderedOutputs(root, *htmlOutput, *sarifOutput)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		for _, output := range renderedOutputs {
			defer output.destination.close()
			controlPaths = append(controlPaths, output.destination.excluded...)
		}
	}
	var destination *exportDestination
	if wantReports {
		if updating || *trivyReports == "" || !slices.Contains(selection, "trivy") {
			fmt.Fprintln(stderr, "--trivy-reports requires a directory and trivy in the scan selection; it cannot be used with update")
			return 2
		}
		root, err := gitRoot(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		destination, err = prepareExportDestination(root, *trivyReports)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		defer destination.parent.Close()
	}
	var outputNames []outputName
	if baselineOptions.output != nil {
		outputNames = append(outputNames, outputName{parent: baselineOptions.output.parent, name: baselineOptions.output.name})
	}
	for _, output := range renderedOutputs {
		outputNames = append(outputNames, outputName{parent: output.destination.parent, name: output.destination.name})
	}
	if destination != nil {
		outputNames = append(outputNames, outputName{parent: destination.parent, name: destination.name})
	}
	if err := validateOutputNames(outputNames); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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

	result, scanErr := scan(ctx, path, scanOptions{Scanners: selection, TrivyReports: wantReports, Excluded: controlPaths}, reporter.Emit)
	if scanErr != nil && (result.SchemaVersion == "" || len(result.Scanners) == 0) {
		closeReporter()
		fmt.Fprintln(stderr, scanErr)
		return 1
	}
	unfiltered := result
	var baselineData []byte
	var baselineErr error
	if project.active {
		var filtered filter.Result
		filtered, baselineErr = filter.Apply(unfiltered.Findings, project.value, baselineOptions.previous)
		if baselineErr == nil {
			result.Findings, result.Baseline = filtered.Findings, filtered.Baseline
			result.Filtering = &filtered.Summary
		}
	} else if baselineOptions.previous != nil {
		var summary report.BaselineSummary
		result.Findings, summary, baselineErr = baseline.Compare(unfiltered.Findings, *baselineOptions.previous)
		if baselineErr == nil {
			result.Baseline = &summary
		} else {
			result = unfiltered
		}
	}
	if baselineOptions.output != nil && scanErr == nil && baselineErr == nil {
		baselineErr = baselineWritable(unfiltered)
		if baselineErr == nil {
			baselineData, baselineErr = baseline.Encode(unfiltered.Findings)
		}
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
	if err := writeRenderedOutputs(ctx, renderedOutputs, result, unfiltered); err != nil {
		fmt.Fprintln(stderr, err)
		if scanErr != nil {
			fmt.Fprintln(stderr, scanErr)
		}
		return 1
	}
	if scanErr != nil {
		fmt.Fprintln(stderr, scanErr)
		return 1
	}
	if baselineErr != nil {
		fmt.Fprintln(stderr, baselineErr)
		return 1
	}
	if destination != nil {
		if err := destination.write(ctx, unfiltered); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if baselineOptions.output != nil {
		if err := baselineOptions.output.write(ctx, baselineData); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	return 0
}

func scan(
	ctx context.Context,
	path string,
	options scanOptions,
	emit func(progress.Event),
) (report.Report, error) {
	selection, wantReports := options.Scanners, options.TrivyReports
	root, err := gitRoot(path)
	if err != nil {
		return report.Report{}, err
	}
	inventory, err := discovery.Discover(root, options.Excluded...)
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
		slices.Contains(selection, "gitleaks") && len(inventory.Files) > 0 ||
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
	if slices.Contains(selection, "gitleaks") && len(inventory.Files) == 0 {
		skipped = append(skipped, report.Scanner{Name: "gitleaks", Status: "skipped", Coverage: report.Coverage{Unit: "repository"}})
		emit(progress.Event{Scanner: "gitleaks", Stage: progress.StageSkipped, Status: progress.StatusSkipped})
	}
	if slices.Contains(selection, "gitleaks") && len(inventory.Files) > 0 {
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
				target, err := discovery.Stage(root, inventory.Files)
				if err != nil {
					return report.Scanner{}, nil, err
				}
				defer os.RemoveAll(target)
				result, err := gitleaks.Scan(ctx, runtime, target, emit, gitleaksAsset.ImageID)
				if err != nil {
					return report.Scanner{}, nil, err
				}
				for _, finding := range result.Findings {
					if !slices.Contains(inventory.Files, finding.Path) {
						return report.Scanner{}, nil, fmt.Errorf("Gitleaks reported a path outside selected inputs")
					}
				}
				result.Scanners[0].Limitations = []string{"only Git-selected nonignored regular files are staged; symlinks and control files excluded", "Gitleaks reports repository-level completion, not per-file read evidence"}
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
				result, findings, scanErr := opengrep.Scan(
					ctx,
					runtime,
					imageID,
					language.name,
					target,
					len(language.files),
					emit,
				)
				for _, path := range result.Coverage.ReadInputs {
					if !slices.Contains(language.files, path) {
						return report.Scanner{}, nil, fmt.Errorf("Opengrep reported an input outside selection")
					}
				}
				for _, finding := range findings {
					if !slices.Contains(language.files, finding.Path) {
						return report.Scanner{}, nil, fmt.Errorf("Opengrep reported a finding outside selection")
					}
				}
				for _, path := range language.files {
					if !slices.Contains(result.Coverage.ReadInputs, path) {
						result.Coverage.UnreadInputs = append(result.Coverage.UnreadInputs, path)
					}
				}
				return result, findings, scanErr
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
			if name == "trivy" && wantReports {
				return scanner.ScanTrivyReports(ctx, runtime, cache, root, files, emit)
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
	output, err := buildReport(
		root,
		report.Exclusions{
			IgnoredFiles: inventory.Ignored.Files,
			IgnoredBytes: inventory.Ignored.Bytes,
		},
		skipped,
		result,
		runErr,
	)
	output.Inventory = &inventory.Traversal
	output.UncheckedInputs = coverageGaps(inventory, selection, output.Scanners)
	return output, err
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
