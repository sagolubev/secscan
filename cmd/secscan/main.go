// START_MODULE_CONTRACT
// PURPOSE: Compose CLI validation, isolated scanners and canonical output.
// SCOPE: Keep stdout JSON-only; stage Git-selected files and expose incomplete coverage.
// DEPENDS: internal/discovery/discovery.go, internal/orchestrator/orchestrator.go, internal/report/report.go, internal/scanner/platform.go, cmd/secscan/baseline.go, cmd/secscan/config.go, cmd/secscan/render.go, cmd/secscan/scope.go
// LINKS: openspec/changes/build-secscan/trace.json, cmd/secscan/main_test.go#TestRunWritesOneJSONDocument, cmd/secscan/coverage_test.go#TestAcceptanceGitleaksUsesSelectedInventory, cmd/secscan/platform_test.go#TestPlatformSkipsPreserveScopesAndNativeSibling
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// main - Own process cancellation and exit status.
// scanOptions - Explicit scanner/scoped-path selection and excluded control files.
// run - Validate policy and outputs, filter visible findings and preserve full exports.
// scan - Gate actual server platforms before preparing jobs; preserve requested coverage routes.
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
	"github.com/sagolubev/secscan/internal/rules"
	"github.com/sagolubev/secscan/internal/scanner"
	"golang.org/x/term"
)

type scanOptions struct {
	RulePack     *rules.Pack
	Scanners     []string
	Scopes       []string
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
	if len(args) > 0 && args[0] == "rules" {
		return runRules(ctx, args[1:], stdout, stderr)
	}
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
	rulePackID := flags.String("rule-pack", "", "add an explicitly imported rule pack by SHA-256 ID")
	trivyReports := flags.String("trivy-reports", "", "write Trivy CycloneDX and SonarQube JSON to a new directory")
	baselineInput := flags.String("baseline", "", "compare findings with a saved baseline")
	baselineOutput := flags.String("write-baseline", "", "write unfiltered findings to a new baseline file")
	htmlOutput := flags.String("html", "", "write the visible report to a new offline HTML file")
	sarifOutput := flags.String("sarif", "", "write complete unfiltered findings to a new SARIF file")
	configFile := flags.String("config", "", "read project filtering policy from this TOML file")
	noConfig := flags.Bool("no-config", false, "ignore project filtering configuration")
	minSeverity := flags.String("min-severity", "", "hide ranked findings below this severity; keep secrets, errors and unknown severity")
	progressValue := flags.String("progress", "auto", "progress mode: auto, tty, plain, or off")
	var scopes scopeFlags
	flags.Var(&scopes, "scope", "limit file-safe scanners to a Git-relative file or directory; repeat up to 16 times")
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
	rulePackFlag := false
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "rule-pack":
			rulePackFlag = true
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
	var rulePack *rules.Pack
	if rulePackFlag {
		if updating || !rules.ValidID(*rulePackID) || !slices.Contains(selection, "semgrep") && !slices.Contains(selection, "python-sast") && !slices.Contains(selection, "typescript-sast") {
			fmt.Fprintln(stderr, "--rule-pack requires a SHA-256 ID and a compatible SAST scanner; it cannot be used with update")
			return 2
		}
		rulePack, err = loadRulePack(path, *rulePackID)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if !slices.Contains(selection, "semgrep") && !(slices.Contains(selection, "python-sast") && len(rulePack.Rules("python")) > 0) && !(slices.Contains(selection, "typescript-sast") && len(rulePack.Rules("typescript")) > 0) {
			fmt.Fprintln(stderr, "rule pack has no rules for the selected language scanners")
			return 2
		}
	}
	if len(scopes) > 0 && (updating || readBaselineFlag || writeBaselineFlag || slices.Contains(selection, "gitleaks-history")) {
		fmt.Fprintln(stderr, "--scope cannot be combined with update, --baseline, --write-baseline or gitleaks-history")
		return 2
	}
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
		var runtime container.Runtime
		for _, name := range selection {
			if len(scanner.EngineNames(name)) > 0 {
				runtime, err = container.DetectDefault(ctx)
				break
			}
		}
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

	result, scanErr := scan(ctx, path, scanOptions{Scanners: selection, Scopes: scopes, TrivyReports: wantReports, Excluded: controlPaths, RulePack: rulePack}, reporter.Emit)
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
	scopedInventory, scopePaths, err := discovery.SelectScopes(root, inventory, options.Scopes)
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
	runtimeInputs := make(map[string][]string)
	for _, name := range selection {
		if len(scanner.EngineNames(name)) == 0 {
			continue
		}
		source := inventory
		if fileScopedScanner(name) {
			source = scopedInventory
		}
		files := inputsWithRules(name, source, options.RulePack)
		applicable := len(files) > 0
		switch name {
		case "gitleaks-history":
			applicable = true
		case "oci-images":
			applicable = len(unchecked.Images) > 0
		case "trivy", "grype", "osv-scanner":
			applicable = len(dependencyFiles) > 0
		}
		if applicable {
			runtimeInputs[name] = files
		}
	}
	var runtime container.Runtime
	var platform scanner.Platform
	var runtimeErr error
	if len(runtimeInputs) > 0 {
		runtime, runtimeErr = container.DetectDefault(ctx)
		if runtimeErr == nil {
			platform, runtimeErr = scanner.RuntimePlatform(ctx, runtime)
		}
		if runtimeErr != nil && !(slices.Contains(selection, "refresh-versions") && len(scanner.NativeInputs("refresh-versions", inventory.Native)) > 0) {
			return report.Report{}, runtimeErr
		}
	}
	var skipped []report.Scanner
	var compatible []string
	for _, name := range selection {
		files, applicable := runtimeInputs[name]
		reason := ""
		if applicable && runtimeErr == nil {
			reason = platform.UnsupportedReason(name)
		}
		if reason == "" {
			compatible = append(compatible, name)
			continue
		}
		coverage := report.Coverage{Unit: "files", Unread: len(files), UnreadInputs: append([]string(nil), files...)}
		if name == "gitleaks-history" {
			coverage = report.Coverage{Unit: "repository", Unread: 1}
		}
		outcome := report.Scanner{Name: name, Status: "skipped", EngineVersion: scanner.Catalog()[name].Version, Coverage: coverage, Limitations: []string{reason}}
		if name == "oci-images" {
			outcome.Images = unchecked.Images
			outcome.Coverage = unchecked.Coverage
			outcome.Coverage.UnreadInputs = append([]string(nil), files...)
		}
		skipped = append(skipped, outcome)
		emit(progress.Event{Scanner: name, Stage: progress.StageSkipped, Status: progress.StatusSkipped})
	}
	selection = compatible

	cache, cacheErr := scanner.DefaultCache()
	if runtimeErr != nil {
		cacheErr = runtimeErr
	}
	var jobs []orchestrator.Job
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
			if runtimeErr != nil {
				return report.Scanner{}, nil, runtimeErr
			}
			return scanner.ScanOCI(ctx, runtime, cache, root, inventory.OCI, true, emit)
		}})
	} else if slices.Contains(selection, "oci-images") || !slices.Contains(options.Scanners, "oci-images") && (len(unchecked.Images) > 0 || unchecked.Coverage.Unread > 0 || unchecked.Coverage.FailedFiles > 0) {
		skipped = append(skipped, unchecked)
		emit(progress.Event{Scanner: "oci-images", Stage: progress.StageSkipped, Status: progress.StatusSkipped})
	}
	var gitleaksAsset scanner.Asset
	var gitleaksErr error
	if slices.Contains(selection, "gitleaks") && len(scopedInventory.Files) == 0 {
		skipped = append(skipped, report.Scanner{Name: "gitleaks", Status: "skipped", Coverage: report.Coverage{Unit: "repository"}})
		emit(progress.Event{Scanner: "gitleaks", Stage: progress.StageSkipped, Status: progress.StatusSkipped})
	}
	if slices.Contains(selection, "gitleaks") && len(scopedInventory.Files) > 0 || slices.Contains(selection, "gitleaks-history") {
		if cacheErr != nil {
			gitleaksErr = cacheErr
		} else {
			gitleaksAsset, gitleaksErr = cache.Resolve(ctx, runtime, "gitleaks")
		}
	}
	if slices.Contains(selection, "gitleaks") && len(scopedInventory.Files) > 0 {
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
				target, err := discovery.Stage(root, scopedInventory.Files)
				if err != nil {
					return report.Scanner{}, nil, err
				}
				defer os.RemoveAll(target)
				result, err := gitleaks.Scan(ctx, runtime, target, emit, gitleaksAsset.ImageID)
				if err != nil {
					return report.Scanner{}, nil, err
				}
				for _, finding := range result.Findings {
					if !slices.Contains(scopedInventory.Files, finding.Path) {
						return report.Scanner{}, nil, fmt.Errorf("Gitleaks reported a path outside selected inputs")
					}
				}
				result.Scanners[0].Limitations = []string{"only Git-selected nonignored regular files are staged; symlinks and control files excluded", "Gitleaks reports repository-level completion, not per-file read evidence"}
				return result.Scanners[0], result.Findings, nil
			},
		})
	}
	if slices.Contains(selection, "gitleaks-history") {
		if gitleaksErr != nil {
			preparationErrors["gitleaks-history"] = gitleaksErr
		}
		jobs = append(jobs, orchestrator.Job{Name: "gitleaks-history", Timeout: 10 * time.Minute, Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
			if gitleaksErr != nil {
				return report.Scanner{Coverage: report.Coverage{Unit: "repository"}}, nil, gitleaksErr
			}
			history, err := gitleaks.ScanHistory(ctx, runtime, root, emit, gitleaksAsset.ImageID)
			if len(history.Scanners) != 1 {
				if err == nil {
					err = fmt.Errorf("invalid Gitleaks history result")
				}
				return report.Scanner{Coverage: report.Coverage{Unit: "repository"}}, nil, err
			}
			return history.Scanners[0], history.Findings, err
		}})
	}

	languages := []struct {
		scanner string
		name    string
		files   []string
	}{
		{scanner: "python-sast", name: "python", files: scopedInventory.Python},
		{scanner: "typescript-sast", name: "typescript", files: scopedInventory.TypeScript},
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
				result, findings, scanErr := opengrep.ScanWithRules(
					ctx,
					runtime,
					imageID,
					language.name,
					target,
					language.files,
					emit,
					options.RulePack,
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
		source := inventory
		if fileScopedScanner(name) {
			source = scopedInventory
		}
		files := inputsWithRules(name, source, options.RulePack)
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
				return scanner.ScanCodeWithRules(ctx, runtime, cache, name, root, files, emit, options.RulePack, platform)
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
			if runtimeErr != nil {
				result.Scanners[i].Limitations = []string{"container runtime unavailable"}
			}
		}
	}
	if result.Successes == 0 && len(preparationErrors) > 0 {
		runErr = fmt.Errorf("prepared assets unavailable; run secscan update: %w", orchestrator.ErrAllScannersFailed)
		if runtimeErr != nil {
			runErr = fmt.Errorf("container runtime unavailable: %w", orchestrator.ErrAllScannersFailed)
		}
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
	gapInventory := inventory
	if len(scopePaths) > 0 {
		output.Scope = &report.Scope{Paths: scopePaths, SelectedFiles: len(scopedInventory.Files)}
		for i := range output.Scanners {
			source, mode := inventory, "repository"
			if fileScopedScanner(output.Scanners[i].Name) {
				source, mode = scopedInventory, "files"
			}
			output.Scanners[i].Scope = &report.ScannerScope{Mode: mode, CandidateFiles: len(inputsWithRules(output.Scanners[i].Name, source, options.RulePack))}
		}
		gapInventory = scopedCoverageInventory(inventory, scopedInventory, options.Scanners)
	}
	output.UncheckedInputs = coverageGapsWithRules(gapInventory, options.Scanners, output.Scanners, options.RulePack)
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
	allowed = append(allowed, "oci-images", "gitleaks-history")
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
