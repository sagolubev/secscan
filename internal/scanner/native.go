package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/discovery"
	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
)

type nativePackage struct {
	Name      string
	Version   string
	Locations []report.Location
}

type nativeInventory struct {
	Packages []nativePackage
	Unread   int
}

// NativeInputs selects static Gradle metadata for one native persona.
func NativeInputs(name string, candidates []string) []string {
	var files []string
	for _, file := range candidates {
		base := filepath.Base(file)
		if name == "gradle-catalog" && strings.HasSuffix(base, ".versions.toml") || name == "gradle-scripts" && (base == "build.gradle" || base == "build.gradle.kts") || name == "refresh-versions" && base == "versions.properties" {
			files = append(files, file)
		}
	}
	return files
}

// ScanNative reads static metadata only. Maven findings come from the prepared
// offline OSV engine; refresh-versions makes configuration claims only.
func ScanNative(ctx context.Context, runtime container.Runtime, cache Cache, name, root string, files []string, emit func(progress.Event)) (report.Scanner, []report.Finding, error) {
	result := report.Scanner{Name: name, Status: "success", Coverage: report.Coverage{Unit: "declarations"}, Limitations: []string{"static metadata only; Gradle, wrappers, plugins, builds and dependency resolution never execute"}}
	if len(files) == 0 {
		result.Status = "skipped"
		return result, nil, nil
	}
	emit(progress.Event{Scanner: name, Stage: progress.StagePreparing, Status: progress.StatusRunning, Files: len(files)})
	target, err := discovery.Stage(root, files)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	defer os.RemoveAll(target)
	var packages []nativePackage
	var findings []report.Finding
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return report.Scanner{}, nil, err
		}
		info, err := os.Stat(filepath.Join(target, file))
		if err != nil || info.Size() > 16<<20 {
			return report.Scanner{}, nil, fmt.Errorf("native metadata missing or exceeds 16 MiB limit")
		}
		data, err := os.ReadFile(filepath.Join(target, file))
		if err != nil {
			return report.Scanner{}, nil, err
		}
		if name == "refresh-versions" {
			read, unread, found := refreshMetadata(file, data)
			result.Coverage.Read += read
			result.Coverage.Unread += unread
			if read > 0 {
				result.Coverage.ReadInputs = append(result.Coverage.ReadInputs, file)
			}
			if unread > 0 || read == 0 {
				result.Coverage.UnreadInputs = append(result.Coverage.UnreadInputs, file)
			}
			findings = append(findings, found...)
			continue
		}
		inv, err := parseNative(name, file, data)
		if err != nil {
			result.Coverage.FailedFiles++
			result.Coverage.FailedInputs = append(result.Coverage.FailedInputs, file)
			continue
		}
		packages = append(packages, inv.Packages...)
		result.Coverage.Unread += inv.Unread
		if inv.Unread > 0 || len(inv.Packages) == 0 {
			result.Coverage.UnreadInputs = append(result.Coverage.UnreadInputs, file)
		}
	}
	if name == "refresh-versions" {
		result.Limitations = append(result.Limitations, "configuration analysis only; existing update hints are not current registry availability or vulnerability evidence")
		if result.Coverage.Read == 0 {
			return report.Scanner{}, nil, fmt.Errorf("no readable version metadata")
		}
		emit(progress.Event{Scanner: name, Stage: progress.StageDone, Status: progress.StatusSuccess, Findings: len(findings)})
		return result, findings, nil
	}
	if len(packages) == 0 {
		return report.Scanner{}, nil, fmt.Errorf("no statically resolved Maven coordinates; coverage unconfirmed")
	}
	asset, err := cache.Resolve(ctx, runtime, "osv-scanner")
	if err != nil {
		return report.Scanner{}, nil, err
	}
	feeds, err := dependencyFeedRoot(cache, "osv-scanner", asset, []string{"build.gradle"})
	if err != nil {
		return report.Scanner{}, nil, err
	}
	sbom, err := os.MkdirTemp(filepath.Dir(target), "maven-*")
	if err != nil {
		return report.Scanner{}, nil, err
	}
	defer os.RemoveAll(sbom)
	// One coordinate per SBOM preserves group identity: OSV's JSON name omits it.
	expected := make(map[string]nativePackage)
	var sboms []string
	for i, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return report.Scanner{}, nil, err
		}
		file := fmt.Sprintf("package-%d.cdx.json", i)
		group, artifact, _ := strings.Cut(pkg.Name, ":")
		bom := struct {
			Format     string              `json:"bomFormat"`
			Spec       string              `json:"specVersion"`
			Version    int                 `json:"version"`
			Components []map[string]string `json:"components"`
		}{Format: "CycloneDX", Spec: "1.5", Version: 1, Components: []map[string]string{{"type": "library", "group": group, "name": artifact, "version": pkg.Version, "purl": packageURL("Maven", pkg.Name, pkg.Version)}}}
		data, err := json.Marshal(bom)
		if err != nil {
			return report.Scanner{}, nil, err
		}
		if err := os.WriteFile(filepath.Join(sbom, file), data, 0600); err != nil {
			return report.Scanner{}, nil, err
		}
		expected[file] = pkg
		sboms = append(sboms, file)
	}
	args := DependencyArgs("osv-scanner", asset.ImageID, sbom, feeds, sboms)
	emit(progress.Event{Scanner: name, Stage: progress.StageScanning, Status: progress.StatusRunning, Files: len(files)})
	data, code, err := runtime.OutputStatus(ctx, args, []string{"failed to parse", "failed to extract", "failed to load", "error loading", "unable to parse"})
	if err != nil {
		return report.Scanner{}, nil, err
	}
	if code != 0 && code != 1 {
		return report.Scanner{}, nil, fmt.Errorf("offline Maven scanner operational exit %d", code)
	}
	findings, read, err := parseNativeOutput(data, expected)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	for i := range findings {
		findings[i].Sources = append(findings[i].Sources, name)
	}
	result.Coverage.Read = len(read)
	for _, file := range read {
		for _, loc := range expected[file].Locations {
			result.Coverage.ReadInputs = append(result.Coverage.ReadInputs, loc.Path)
		}
	}
	for file, pkg := range expected {
		if !slices.Contains(read, file) {
			result.Coverage.Unread++
			for _, loc := range pkg.Locations {
				result.Coverage.UnreadInputs = append(result.Coverage.UnreadInputs, loc.Path)
			}
		}
	}
	slices.Sort(result.Coverage.ReadInputs)
	result.Coverage.ReadInputs = slices.Compact(result.Coverage.ReadInputs)
	slices.Sort(result.Coverage.UnreadInputs)
	result.Coverage.UnreadInputs = slices.Compact(result.Coverage.UnreadInputs)
	result.Image = asset.ImageID
	result.EngineVersion = Catalog()["osv-scanner"].Version
	result.Feeds = feedEvidence(asset, []string{"osv-scalibr/Maven/all.zip"})
	result.Limitations = append(result.Limitations, "only literal exact coordinates receive offline Maven advisory lookup; dynamic expressions, version ranges and plugins remain unread", "catalog locations without native line metadata are anchored at line 1; script extraction is deliberately limited and does not claim complete Gradle dependency coverage")
	emit(progress.Event{Scanner: name, Stage: progress.StageDone, Status: progress.StatusSuccess, Findings: len(findings)})
	return result, report.Normalize(findings), nil
}

func parseNative(name, file string, data []byte) (nativeInventory, error) {
	if name == "gradle-scripts" {
		return parseGradleScript(file, string(data)), nil
	}
	if name != "gradle-catalog" {
		return nativeInventory{}, fmt.Errorf("unsupported native scanner")
	}
	var catalog struct {
		Versions  map[string]any `toml:"versions"`
		Libraries map[string]any `toml:"libraries"`
		Plugins   map[string]any `toml:"plugins"`
	}
	if err := toml.Unmarshal(data, &catalog); err != nil {
		return nativeInventory{}, fmt.Errorf("invalid Gradle version catalog")
	}
	inv := nativeInventory{Unread: len(catalog.Plugins)}
	var keys []string
	for key := range catalog.Libraries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		value := catalog.Libraries[key]
		coordinate, _ := value.(string)
		if entry, ok := value.(map[string]any); ok {
			module, _ := entry["module"].(string)
			if module == "" {
				group, _ := entry["group"].(string)
				artifact, _ := entry["name"].(string)
				module = group + ":" + artifact
			}
			version, _ := entry["version"].(string)
			if reference, ok := entry["version"].(map[string]any); ok && len(reference) == 1 {
				ref, _ := reference["ref"].(string)
				version, _ = catalog.Versions[ref].(string)
			}
			coordinate = module + ":" + version
		}
		if pkg, ok := literalMaven(coordinate, file, 1); ok {
			inv.Packages = append(inv.Packages, pkg)
		} else {
			inv.Unread++
		}
	}
	return inv, nil
}

var gradleLiteral = regexp.MustCompile(`^(?:([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*["']([^"']+)["']\s*\)|([A-Za-z_][A-Za-z0-9_]*)\s+["']([^"']+)["'])\s*;?$`)
var mavenPart = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}$`)

func literalMaven(coordinate, file string, line int) (nativePackage, bool) {
	parts := strings.Split(coordinate, ":")
	if len(parts) != 3 || !mavenPart.MatchString(parts[0]) || !mavenPart.MatchString(parts[1]) || !mavenPart.MatchString(parts[2]) {
		return nativePackage{}, false
	}
	lower := strings.ToLower(parts[2])
	if lower == "latest" || lower == "release" || strings.HasPrefix(lower, "latest.") || strings.Contains(lower, "snapshot") {
		return nativePackage{}, false
	}
	return nativePackage{Name: parts[0] + ":" + parts[1], Version: parts[2], Locations: []report.Location{{Path: file, Line: line}}}, true
}

// parseGradleScript recognizes direct, one-line literal dependency declarations.
// Every other nonempty statement inside dependencies remains unread.
func parseGradleScript(file, source string) nativeInventory {
	inv := nativeInventory{}
	depth, dependencyDepth := 0, -1
	blockComment := false
	var multiline byte
	for index, line := range strings.Split(source, "\n") {
		// Remove comments and mask quoted braces without interpreting any DSL.
		var clean, structure strings.Builder
		quote := byte(0)
		escaped := false
		for i := 0; i < len(line); i++ {
			c := line[i]
			if multiline != 0 {
				if c == multiline && i+2 < len(line) && line[i+1] == c && line[i+2] == c {
					multiline = 0
					i += 2
				}
				continue
			}
			if blockComment {
				if c == '*' && i+1 < len(line) && line[i+1] == '/' {
					blockComment = false
					i++
				}
				continue
			}
			if quote != 0 {
				clean.WriteByte(c)
				structure.WriteByte(' ')
				if escaped {
					escaped = false
				} else if c == '\\' {
					escaped = true
				} else if c == quote {
					quote = 0
				}
				continue
			}
			if c == '/' && i+1 < len(line) {
				if line[i+1] == '/' {
					break
				}
				if line[i+1] == '*' {
					blockComment = true
					i++
					continue
				}
			}
			if (c == '\'' || c == '"') && i+2 < len(line) && line[i+1] == c && line[i+2] == c {
				multiline = c
				inv.Unread++
				i += 2
				clean.WriteString("<multiline>")
				continue
			}
			clean.WriteByte(c)
			if c == '\'' || c == '"' {
				quote = c
				structure.WriteByte(' ')
			} else {
				structure.WriteByte(c)
			}
		}
		text := strings.TrimSpace(clean.String())
		shape := strings.TrimSpace(structure.String())
		if strings.HasPrefix(shape, "plugins") || strings.HasPrefix(shape, "apply ") || strings.HasPrefix(shape, "apply(") {
			inv.Unread++
		}
		if dependencyDepth < 0 && strings.HasPrefix(shape, "dependencies") {
			rest := strings.TrimSpace(strings.TrimPrefix(shape, "dependencies"))
			if strings.HasPrefix(rest, "{") {
				dependencyDepth = depth + 1
				text = strings.TrimSpace(text[strings.Index(text, "{")+1:])
			} else {
				inv.Unread++
			}
		}
		if dependencyDepth >= 0 && text != "" && text != "}" {
			// A closing brace may finish a one-line dependencies block.
			statement := strings.TrimSpace(strings.TrimSuffix(text, "}"))
			match := gradleLiteral.FindStringSubmatch(statement)
			if len(match) == 5 && match[1] == "" {
				match[1], match[2] = match[3], match[4]
			}
			if len(match) == 5 && supportedGradleDeclaration(match[1]) && (depth == dependencyDepth || strings.HasPrefix(shape, "dependencies")) && quote == 0 {
				if pkg, ok := literalMaven(match[2], file, index+1); ok {
					inv.Packages = append(inv.Packages, pkg)
				} else {
					inv.Unread++
				}
			} else {
				inv.Unread++
			}
		}
		depth += strings.Count(shape, "{") - strings.Count(shape, "}")
		if depth < dependencyDepth {
			dependencyDepth = -1
		}
	}
	return inv
}

// supportedGradleDeclaration is deliberately finite. User-defined dependency
// configurations and arbitrary calls cannot be distinguished without running DSL.
func supportedGradleDeclaration(name string) bool {
	switch name {
	case "api", "implementation", "compileOnly", "compileOnlyApi", "runtimeOnly", "annotationProcessor",
		"testImplementation", "testCompileOnly", "testRuntimeOnly", "testAnnotationProcessor",
		"androidTestImplementation", "androidTestCompileOnly", "androidTestRuntimeOnly", "androidTestAnnotationProcessor",
		"kapt", "kaptTest", "kaptAndroidTest", "ksp", "kspTest", "kspAndroidTest",
		"compile", "runtime", "testCompile", "testRuntime":
		return true
	}
	return false
}

func refreshMetadata(file string, data []byte) (int, int, []report.Finding) {
	read, unread := 0, 0
	var findings []report.Finding
	for i, line := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		hint := strings.HasPrefix(text, "#") && strings.Contains(text, "available=")
		if strings.HasPrefix(text, "#") && !hint {
			continue
		}
		if !hint {
			key, value, ok := strings.Cut(text, "=")
			if !ok || !strings.HasPrefix(strings.TrimSpace(key), "version.") || strings.TrimSpace(value) == "" || strings.ContainsAny(value, "$\\") {
				unread++
				continue
			}
			read++
		}
		rule, message := "refresh-version-entry", "existing version configuration entry"
		if hint {
			rule = "refresh-version-update-hint"
			message = "existing update hint; current version availability is not verified"
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", rule, file, i+1)))
		findings = append(findings, report.Finding{Kind: "configuration", RuleID: rule, Message: message, Path: file, Line: i + 1, Origin: "working_tree", Severity: "informational", Sources: []string{"refresh-versions"}, Fingerprint: hex.EncodeToString(sum[:])})
	}
	return read, unread, findings
}

func parseNativeOutput(data []byte, expected map[string]nativePackage) ([]report.Finding, []string, error) {
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
		return nil, nil, fmt.Errorf("invalid offline Maven output")
	}
	var findings []report.Finding
	var read []string
	for _, result := range input.Results {
		path, err := TargetPath(result.Source.Path)
		pkg, ok := expected[path]
		if err != nil || !ok || result.Source.Type != "sbom" || len(result.Packages) != 1 || slices.Contains(read, path) {
			return nil, nil, fmt.Errorf("unexpected offline Maven source")
		}
		item := result.Packages[0]
		_, artifact, _ := strings.Cut(pkg.Name, ":")
		if (item.Package.Name != artifact && item.Package.Name != pkg.Name) || item.Package.Version != pkg.Version || item.Package.Ecosystem != "Maven" {
			return nil, nil, fmt.Errorf("offline Maven identity mismatch")
		}
		read = append(read, path)
		for _, group := range item.Groups {
			ids := append(append([]string(nil), group.IDs...), group.Aliases...)
			if len(ids) == 0 {
				return nil, nil, fmt.Errorf("missing Maven advisory identity")
			}
			for _, id := range ids {
				if !advisoryToken.MatchString(id) {
					return nil, nil, fmt.Errorf("invalid Maven advisory identity")
				}
			}
			severity, err := advisorySeverity(group.Score)
			if err != nil {
				return nil, nil, err
			}
			identity := report.Package{Ecosystem: "Maven", Name: pkg.Name, Version: pkg.Version, PURL: packageURL("Maven", pkg.Name, pkg.Version)}
			findings = append(findings, report.Finding{Kind: "dependency", Package: &identity, Advisories: ids, Locations: pkg.Locations, Severity: severity, Sources: []string{"osv-scanner"}})
		}
	}
	if len(read) == 0 {
		return nil, nil, fmt.Errorf("offline Maven coverage unconfirmed")
	}
	return findings, read, nil
}

func advisorySeverity(value string) (string, error) {
	if value == "" {
		return "unknown", nil
	}
	score, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(score) || score < 0 || score > 10 {
		return "", fmt.Errorf("invalid advisory severity")
	}
	switch {
	case score >= 9:
		return "critical", nil
	case score >= 7:
		return "high", nil
	case score >= 4:
		return "medium", nil
	case score > 0:
		return "low", nil
	default:
		return "unknown", nil
	}
}

func feedEvidence(asset Asset, keys []string) []report.Feed {
	var feeds []report.Feed
	for _, key := range keys {
		feed := asset.Feeds[key]
		built := ""
		if !feed.BuiltAt.IsZero() {
			built = feed.BuiltAt.Format(time.RFC3339Nano)
		}
		feeds = append(feeds, report.Feed{Name: key, Digest: feed.Digest, AcquiredAt: feed.AcquiredAt.Format(time.RFC3339Nano), BuiltAt: built})
	}
	return feeds
}
