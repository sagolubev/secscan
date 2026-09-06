package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

var dependencyToken = regexp.MustCompile(`^[a-zA-Z0-9@._+:/%~-]{1,512}$`)
var advisoryToken = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

// DependencyArgs uses immutable feeds and disables network, updates and call analysis.
func DependencyArgs(name, imageID, target, feedRoot string, files []string) []string {
	args := append(container.IsolatedArgs(target, "/repo"), "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--workdir", "/tmp", "--mount", "type=bind,src="+feedRoot+",dst=/cache,readonly")
	switch name {
	case "trivy":
		return append(args, imageID, "fs", "--cache-dir", "/cache", "--cache-backend", "memory", "--scanners", "vuln", "--format", "json", "--list-all-pkgs", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--ignorefile", "/dev/null", "/repo")
	case "grype":
		return append(args, "--env", "GRYPE_DB_CACHE_DIR=/cache", "--env", "GRYPE_DB_AUTO_UPDATE=false", "--env", "GRYPE_CHECK_FOR_APP_UPDATE=false", imageID, "dir:/repo", "--output", "json", "-v")
	case "osv-scanner":
		args = append(args, "--env", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/cache", imageID, "scan", "source", "--offline", "--no-resolve", "--no-call-analysis", "all", "--all-packages", "--format", "json")
		for _, file := range files {
			args = append(args, "--lockfile", "/repo/"+file)
		}
		return args
	}
	return nil
}

// ParseDependencies decodes only package identities, advisory aliases and locations.
// Count is packages for Trivy/OSV and repositories for Grype, whose positive
// package extraction evidence is checked separately at the process boundary.
func ParseDependencies(data []byte, name string, selected ...[]string) ([]report.Finding, int, error) {
	findings, count, _, err := parseDependencyOutput(data, name, selected...)
	return findings, count, err
}

func parseDependencyOutput(data []byte, name string, selected ...[]string) ([]report.Finding, int, []string, error) {
	var findings []report.Finding
	var readInputs []string
	count := 0
	validatePath := func(file string) (string, error) {
		normalized, err := TargetPath(file)
		if err != nil {
			return "", err
		}
		if len(selected) > 0 && !slices.Contains(selected[0], normalized) {
			return "", fmt.Errorf("dependency result outside staged inputs")
		}
		return normalized, nil
	}
	add := func(ecosystem, pkg, version, severity string, ids, paths []string) error {
		ecosystem = canonicalEcosystem(ecosystem)
		if ecosystem == "" || !dependencyToken.MatchString(pkg) || !dependencyToken.MatchString(version) || len(ids) == 0 || len(paths) == 0 {
			return fmt.Errorf("invalid dependency identity")
		}
		for _, id := range ids {
			if !advisoryToken.MatchString(id) {
				return fmt.Errorf("invalid advisory identity")
			}
		}
		severity = strings.ToLower(severity)
		switch severity {
		case "", "unknown", "negligible":
			severity = "unknown"
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid dependency severity")
		}
		var locations []report.Location
		for _, file := range paths {
			if name == "grype" {
				file = strings.TrimPrefix(file, "/")
			}
			normalized, err := validatePath(file)
			if err != nil {
				return err
			}
			locations = append(locations, report.Location{Path: normalized, Line: 1})
		}
		identity := report.Package{Ecosystem: ecosystem, Name: pkg, Version: version, PURL: packageURL(ecosystem, pkg, version)}
		findings = append(findings, report.Finding{Kind: "dependency", Package: &identity, Advisories: ids, Locations: locations, Sources: []string{name}, Severity: severity})
		return nil
	}
	switch name {
	case "trivy":
		var input struct {
			Schema int `json:"SchemaVersion"`
			Trivy  struct {
				Version string `json:"Version"`
			} `json:"Trivy"`
			Type    string `json:"ArtifactType"`
			Results []struct {
				Target   string `json:"Target"`
				Type     string `json:"Type"`
				Packages []struct {
					Name    string `json:"Name"`
					Version string `json:"Version"`
				} `json:"Packages"`
				Vulnerabilities []struct {
					ID       string   `json:"VulnerabilityID"`
					Aliases  []string `json:"VendorIDs"`
					Name     string   `json:"PkgName"`
					Version  string   `json:"InstalledVersion"`
					Severity string   `json:"Severity"`
				} `json:"Vulnerabilities"`
			} `json:"Results"`
		}
		if json.Unmarshal(data, &input) != nil || input.Schema != 2 || input.Trivy.Version != Catalog()[name].Version || input.Type != "filesystem" {
			return nil, 0, nil, fmt.Errorf("invalid Trivy dependency output")
		}
		for _, result := range input.Results {
			if _, err := validatePath(result.Target); err != nil {
				return nil, 0, nil, err
			}
			if canonicalEcosystem(result.Type) == "" {
				return nil, 0, nil, fmt.Errorf("invalid Trivy package ecosystem")
			}
			for _, pkg := range result.Packages {
				if !dependencyToken.MatchString(pkg.Name) || !dependencyToken.MatchString(pkg.Version) {
					return nil, 0, nil, fmt.Errorf("invalid Trivy package identity")
				}
			}
			count += len(result.Packages)
			if len(result.Packages) > 0 {
				path, _ := validatePath(result.Target)
				readInputs = append(readInputs, path)
			}
			for _, v := range result.Vulnerabilities {
				if err := add(result.Type, v.Name, v.Version, v.Severity, append([]string{v.ID}, v.Aliases...), []string{result.Target}); err != nil {
					return nil, 0, nil, err
				}
			}
		}
	case "grype":
		var input struct {
			Matches []struct {
				Vulnerability struct {
					ID       string `json:"id"`
					Severity string `json:"severity"`
				} `json:"vulnerability"`
				Related []struct {
					ID string `json:"id"`
				} `json:"relatedVulnerabilities"`
				Artifact struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Type      string `json:"type"`
					Locations []struct {
						Path string `json:"path"`
					} `json:"locations"`
				} `json:"artifact"`
			} `json:"matches"`
			Source struct {
				Type   string `json:"type"`
				Target string `json:"target"`
			} `json:"source"`
			Descriptor struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				DB      struct {
					Status struct {
						Valid bool `json:"valid"`
					} `json:"status"`
				} `json:"db"`
			} `json:"descriptor"`
		}
		if json.Unmarshal(data, &input) != nil || input.Matches == nil || input.Source.Type != "directory" || input.Source.Target != "/repo" || input.Descriptor.Name != "grype" || input.Descriptor.Version != Catalog()[name].Version || !input.Descriptor.DB.Status.Valid {
			return nil, 0, nil, fmt.Errorf("invalid Grype dependency output")
		}
		count = 1
		for _, match := range input.Matches {
			ids := []string{match.Vulnerability.ID}
			for _, related := range match.Related {
				ids = append(ids, related.ID)
			}
			var paths []string
			for _, loc := range match.Artifact.Locations {
				paths = append(paths, loc.Path)
			}
			if err := add(match.Artifact.Type, match.Artifact.Name, match.Artifact.Version, match.Vulnerability.Severity, ids, paths); err != nil {
				return nil, 0, nil, err
			}
		}
	case "osv-scanner":
		var input struct {
			Results []struct {
				Source struct {
					Path string `json:"path"`
					Type string `json:"type"`
				} `json:"source"`
				Packages []struct {
					Package struct {
						Name      string `json:"name"`
						Version   string `json:"version"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
					Groups []struct {
						IDs     []string `json:"ids"`
						Aliases []string `json:"aliases"`
						Score   string   `json:"max_severity"`
					} `json:"groups"`
				} `json:"packages"`
			} `json:"results"`
		}
		if json.Unmarshal(data, &input) != nil || input.Results == nil {
			return nil, 0, nil, fmt.Errorf("invalid OSV dependency output")
		}
		for _, result := range input.Results {
			if result.Source.Type != "lockfile" {
				return nil, 0, nil, fmt.Errorf("unexpected OSV input type")
			}
			if _, err := validatePath(result.Source.Path); err != nil {
				return nil, 0, nil, err
			}
			count += len(result.Packages)
			if len(result.Packages) > 0 {
				path, _ := validatePath(result.Source.Path)
				readInputs = append(readInputs, path)
			}
			for _, item := range result.Packages {
				if canonicalEcosystem(item.Package.Ecosystem) == "" || !dependencyToken.MatchString(item.Package.Name) || !dependencyToken.MatchString(item.Package.Version) {
					return nil, 0, nil, fmt.Errorf("invalid OSV package identity")
				}
				for _, group := range item.Groups {
					severity, err := advisorySeverity(group.Score)
					if err != nil {
						return nil, 0, nil, err
					}
					if err := add(item.Package.Ecosystem, item.Package.Name, item.Package.Version, severity, append(append([]string(nil), group.IDs...), group.Aliases...), []string{result.Source.Path}); err != nil {
						return nil, 0, nil, err
					}
				}
			}
		}
	default:
		return nil, 0, nil, fmt.Errorf("unsupported dependency scanner")
	}
	if count == 0 {
		return nil, 0, nil, fmt.Errorf("dependency scanner did not extract packages")
	}
	slices.Sort(readInputs)
	return report.Normalize(findings), count, slices.Compact(readInputs), nil
}

// ScanDependencies stages supported manifests only and rejects incomplete feeds,
// operational exits and findings outside the selected input inventory.
func ScanDependencies(ctx context.Context, runtime container.Runtime, cache Cache, name, root string, candidates []string, emit func(progress.Event)) (report.Scanner, []report.Finding, error) {
	files, unread := DependencyInputs(candidates)
	if len(files) == 0 {
		return report.Scanner{}, nil, fmt.Errorf("no supported dependency inputs")
	}
	emit(progress.Event{Scanner: name, Stage: progress.StagePreparing, Status: progress.StatusRunning, Files: len(files)})
	asset, feeds, err := cache.ResolveDependencies(ctx, runtime, name, files)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	groups := [][]string{files}
	if name == "grype" {
		// Grype exposes no per-input package inventory, so each run proves one input.
		groups = nil
		for _, file := range files {
			groups = append(groups, []string{file})
		}
	}
	var findings []report.Finding
	var readInputs, failedInputs []string
	count := 0
	for _, group := range groups {
		emit(progress.Event{Scanner: name, Stage: progress.StageScanning, Status: progress.StatusRunning, Files: len(group)})
		extracted, n, read, err := scanDependencyInputs(ctx, runtime, name, asset.ImageID, feeds, root, group)
		if ctx.Err() != nil {
			return report.Scanner{}, nil, ctx.Err()
		}
		if err != nil {
			if len(groups) == 1 {
				return report.Scanner{}, nil, err
			}
			failedInputs = append(failedInputs, group...)
			continue
		}
		findings = append(findings, extracted...)
		count += n
		readInputs = append(readInputs, read...)
	}
	if count == 0 {
		return report.Scanner{}, nil, fmt.Errorf("dependency scanner did not extract packages")
	}
	for _, file := range files {
		if !slices.Contains(readInputs, file) && !slices.Contains(failedInputs, file) {
			unread = append(unread, file)
		}
	}
	slices.Sort(unread)
	unread = slices.Compact(unread)
	slices.Sort(readInputs)
	readInputs = slices.Compact(readInputs)
	slices.Sort(failedInputs)
	findings = report.Normalize(findings)
	emit(progress.Event{Scanner: name, Stage: progress.StageNormalizing, Status: progress.StatusRunning, Files: len(files)})
	unit := "packages"
	if name == "grype" {
		unit = "files"
	}
	result := report.Scanner{Name: name, Status: "success", Image: asset.ImageID, EngineVersion: Catalog()[name].Version, Coverage: report.Coverage{Read: count, Unit: unit, ReadInputs: readInputs, Unread: len(unread), UnreadInputs: unread, FailedFiles: len(failedInputs), FailedInputs: failedInputs}, Limitations: []string{"only selected lockfiles and static dependency manifests are staged; repository scanner configuration excluded", "readInputs records positive package extraction per input; inputs without extraction remain unread or failed", "source locations without native lines are anchored at line 1", "network, call analysis, project builds and dependency resolution disabled"}}
	keys, err := dependencyFeedKeys(name, files)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	for _, key := range keys {
		feed := asset.Feeds[key]
		built := ""
		if !feed.BuiltAt.IsZero() {
			built = feed.BuiltAt.Format(time.RFC3339Nano)
		}
		result.Feeds = append(result.Feeds, report.Feed{Name: key, Digest: feed.Digest, AcquiredAt: feed.AcquiredAt.Format(time.RFC3339Nano), BuiltAt: built})
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageDone, Status: progress.StatusSuccess, Files: len(files), Findings: len(findings)})
	return result, findings, nil
}

func scanDependencyInputs(ctx context.Context, runtime container.Runtime, name, imageID, feeds, root string, files []string) ([]report.Finding, int, []string, error) {
	target, err := discovery.Stage(root, files)
	if err != nil {
		return nil, 0, nil, err
	}
	defer os.RemoveAll(target)
	if err := validateDependencyInputs(target, files); err != nil {
		return nil, 0, nil, err
	}
	markers := []string{"failed to parse", "failed to extract", "unable to parse", "unable to extract", "error parsing", "error extracting", "failed to analyze", "failed to open", "failed to read", "gathered packages packages=0 ", "gathered packages packages=0\n"}
	var required []string
	if name == "grype" {
		required = []string{"gathered packages packages="}
	}
	data, code, err := runtime.OutputStatus(ctx, DependencyArgs(name, imageID, target, feeds, files), markers, required...)
	if err != nil {
		return nil, 0, nil, err
	}
	if code != 0 && !(name == "osv-scanner" && code == 1) {
		return nil, 0, nil, fmt.Errorf("dependency scanner operational exit %d", code)
	}
	findings, count, readInputs, err := parseDependencyOutput(data, name, files)
	if err != nil {
		return nil, 0, nil, err
	}
	if name == "grype" {
		readInputs = append([]string(nil), files...)
	}
	return findings, count, readInputs, nil
}

// DependencyInputs separates supported static inputs from candidates requiring other analysis.
func DependencyInputs(candidates []string) ([]string, []string) {
	var files, unread []string
	for _, file := range candidates {
		switch filepath.Base(file) {
		case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "go.sum", "requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock", "Cargo.lock", "composer.lock", "Gemfile.lock", "packages.lock.json":
			files = append(files, file)
		default:
			unread = append(unread, file)
		}
	}
	return files, unread
}

func validateDependencyInputs(target string, files []string) error {
	for _, file := range files {
		path := filepath.Join(target, file)
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 || info.Size() > 64<<20 {
			return fmt.Errorf("missing, empty or oversized dependency input")
		}
		if strings.HasSuffix(file, ".json") || filepath.Base(file) == "Pipfile.lock" || filepath.Base(file) == "composer.lock" {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("dependency input unreadable")
			}
			var object map[string]json.RawMessage
			if json.Unmarshal(data, &object) != nil || len(object) == 0 {
				return fmt.Errorf("invalid dependency JSON input")
			}
			switch filepath.Base(file) {
			case "package-lock.json", "npm-shrinkwrap.json":
				if object["lockfileVersion"] == nil || (object["packages"] == nil && object["dependencies"] == nil) {
					return fmt.Errorf("invalid npm lockfile")
				}
			case "Pipfile.lock":
				if object["_meta"] == nil {
					return fmt.Errorf("invalid Pipfile lock")
				}
			case "composer.lock":
				if object["packages"] == nil {
					return fmt.Errorf("invalid Composer lock")
				}
			case "packages.lock.json":
				if object["dependencies"] == nil {
					return fmt.Errorf("invalid NuGet lock")
				}
			}
		}
	}
	return nil
}

func canonicalEcosystem(value string) string {
	switch strings.ToLower(value) {
	case "npm", "yarn", "pnpm":
		return "npm"
	case "go", "gomod", "go-module":
		return "Go"
	case "pypi", "python", "pip", "pipenv", "poetry", "uv":
		return "PyPI"
	case "maven", "java", "gradle":
		return "Maven"
	case "nuget", "dotnet":
		return "NuGet"
	case "packagist", "php-composer", "composer":
		return "Packagist"
	case "rubygems", "gem", "bundler":
		return "RubyGems"
	case "crates.io", "rust-crate", "cargo":
		return "crates.io"
	}
	return ""
}

func packageURL(ecosystem, name, version string) string {
	kind := map[string]string{"npm": "npm", "Go": "golang", "PyPI": "pypi", "Maven": "maven", "NuGet": "nuget", "Packagist": "composer", "RubyGems": "gem", "crates.io": "cargo"}[ecosystem]
	if ecosystem == "Maven" {
		name = strings.ReplaceAll(name, ":", "/")
	}
	segments := strings.Split(name, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	return "pkg:" + kind + "/" + strings.Join(segments, "/") + "@" + url.PathEscape(version)
}
