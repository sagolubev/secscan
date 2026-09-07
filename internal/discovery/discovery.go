// START_MODULE_CONTRACT
// PURPOSE: Build safe Git-selected inventories and staged scanner trees.
// SCOPE: Separate metadata counts from analysis; reject symlink traversal.
// DEPENDS: internal/discovery/inventory.go, internal/report/inventory.go
// LINKS: openspec/changes/build-secscan/trace.json, internal/discovery/discovery_test.go#TestTraversalInventory, internal/discovery/discovery_test.go#TestStageRejectsIntermediateSymlink
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Exclusions - Legacy ignored file and byte counts.
// Inventory - Selected paths, scanner candidates and traversal metadata.
// Discover - Classify safe Git entries and disclose omissions.
// Stage - Copy selected regular files into an owned temporary tree.
// DependencyEcosystem - Recognize dependency candidates without executing project code.
// END_MODULE_MAP

package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/sagolubev/secscan/internal/report"
)

var errSymlink = errors.New("symlink is not allowed")

type Exclusions struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

type Inventory struct {
	Files     []string
	Sources   []SourceInput
	Traversal report.Inventory

	Native       []string
	OCI          []string
	Dependencies []string
	Terraform    []string
	Checkov      []string
	KICS         []string
	Python       []string
	TypeScript   []string
	Bearer       []string
	Cppcheck     []string
	CI           []string
	Zizmor       []string
	Poutine      []string
	Ignored      Exclusions
}

// Discover enumerates Git paths; excluded paths are explicit relative control files.
func Discover(root string, excluded ...string) (Inventory, error) {
	selected, traversal, err := enumerate(root, excluded)
	if err != nil {
		return Inventory{}, err
	}
	inventory := Inventory{Files: selected, Traversal: traversal}
	for _, path := range selected {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return Inventory{}, fmt.Errorf("inspect discovered path %q: %w", path, err)
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			continue
		}

		language := SourceLanguage(path)
		if language != "" {
			inventory.Sources = append(inventory.Sources, SourceInput{Path: path, Language: language})
		}
		base := filepath.Base(path)
		if DependencyEcosystem(path) != "" {
			inventory.Dependencies = append(inventory.Dependencies, path)
		}
		yaml := strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")
		native := base == "versions.properties" || base == "build.gradle" || base == "build.gradle.kts" || strings.HasSuffix(base, ".versions.toml")
		if native {
			inventory.Native = append(inventory.Native, path)
		}
		if yaml || base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
			inventory.OCI = append(inventory.OCI, path)
		}
		stem := strings.TrimSuffix(strings.TrimPrefix(base, "."), filepath.Ext(base))
		github := filepath.Dir(path) == ".github/workflows" && yaml || base == "action.yml" || base == "action.yaml"
		zizmor := github || (filepath.Dir(path) == ".github" && (base == "dependabot.yml" || base == "dependabot.yaml")) || (base == ".pre-commit-config.yml" || base == ".pre-commit-config.yaml" || base == ".pre-commit-hooks.yml" || base == ".pre-commit-hooks.yaml")
		poutine := github || path == ".gitlab-ci.yml" || (yaml && (stem == "azure-pipelines" || strings.HasPrefix(stem, "azure-pipelines-") || filepath.Dir(path) == ".tekton"))
		if zizmor {
			inventory.Zizmor = append(inventory.Zizmor, path)
		}
		if poutine {
			inventory.Poutine = append(inventory.Poutine, path)
		}
		if zizmor || poutine {
			inventory.CI = append(inventory.CI, path)
		}

		terraform := strings.HasSuffix(path, ".tf") || strings.HasSuffix(path, ".tofu") || strings.HasSuffix(path, ".tf.json") || strings.HasSuffix(path, ".tofu.json") || strings.HasSuffix(path, ".tfplan.json")
		config := strings.HasPrefix(strings.TrimPrefix(base, "."), "checkov.") || strings.HasPrefix(strings.TrimPrefix(base, "."), "kics.")
		if !terraform && !config && strings.HasSuffix(path, ".json") && info.Mode().IsRegular() {
			terraform, err = isTerraformPlan(root, path)
			if err != nil {
				return Inventory{}, err
			}
		}
		general := !terraform && !config && (yaml || strings.HasSuffix(path, ".json") || base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile."))
		if terraform {
			inventory.Terraform = append(inventory.Terraform, path)
		}
		if general {
			inventory.Checkov = append(inventory.Checkov, path)
		}
		if terraform || general {
			inventory.KICS = append(inventory.KICS, path)
		}
		if language == "" && DependencyEcosystem(path) == "" && !native && !zizmor && !poutine && !terraform && !general {
			inventory.Traversal.Unclassified = append(inventory.Traversal.Unclassified, path)
		}

		switch strings.ToLower(filepath.Ext(path)) {
		case ".java", ".py", ".rb", ".rake", ".js", ".jsx", ".ts", ".tsx", ".php", ".go", ".go2":
			inventory.Bearer = append(inventory.Bearer, path)
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx":
			inventory.Cppcheck = append(inventory.Cppcheck, path)
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".py", ".pyi":
			inventory.Python = append(inventory.Python, path)
		case ".ts", ".tsx", ".mts", ".cts":
			inventory.TypeScript = append(inventory.TypeScript, path)
		}
	}
	sort.Strings(inventory.CI)
	sort.Strings(inventory.Python)
	sort.Strings(inventory.TypeScript)
	inventory.Ignored = Exclusions{Files: traversal.Ignored.Files, Bytes: traversal.Ignored.Bytes}
	return inventory, nil
}

// START_CONTRACT: Stage
// PURPOSE: Give containers only explicitly selected regular files.
// INPUTS: root: string - Worktree root. files: []string - Relative paths.
// OUTPUTS: Owned temporary directory; caller must remove it, or error.
// SIDE_EFFECTS: Creates private files in the user cache; reads no symlink targets.
// LINKS: internal/discovery/discovery_test.go#TestStageRejectsIntermediateSymlink
// END_CONTRACT: Stage

// Stage copies selected regular files into a private tree owned by the caller.
func Stage(root string, files []string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache: %w", err)
	}
	base := filepath.Join(cache, "secscan", "targets")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("create target cache: %w", err)
	}
	target, err := os.MkdirTemp(base, "scan-*")
	if err != nil {
		return "", fmt.Errorf("create target tree: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(target)
		}
	}()

	for _, path := range files {
		clean := filepath.Clean(filepath.FromSlash(path))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("target path escapes repository: %q", path)
		}
		source, err := safeSource(root, clean)
		if err != nil {
			return "", fmt.Errorf("inspect target %q: %w", path, err)
		}
		info, err := os.Lstat(source)
		if err != nil {
			return "", fmt.Errorf("inspect target %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("target %q is not a regular file", path)
		}
		destination := filepath.Join(target, clean)
		if err := copyFile(source, destination); err != nil {
			return "", err
		}
	}
	cleanup = false
	return target, nil
}

func safeSource(root, clean string) (string, error) {
	current := root
	for _, component := range strings.Split(filepath.Clean(clean), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: component %q", errSymlink, component)
		}
	}
	return current, nil
}

func gitPaths(root string, args ...string) ([]string, error) {
	commandArgs := append([]string{"-c", "core.fsmonitor=false", "-C", root, "ls-files", "-z"}, args...)
	output, err := exec.Command("git", commandArgs...).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	fields := bytes.Split(output, []byte{0})
	paths := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field) > 0 {
			paths = append(paths, filepath.ToSlash(string(field)))
		}
	}
	sort.Strings(paths)
	return slices.Compact(paths), nil
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open target %q: %w", source, err)
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create staged target %q: %w", destination, err)
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return fmt.Errorf("copy target %q: %w", source, err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close staged target %q: %w", destination, err)
	}
	return nil
}

// isTerraformPlan recognizes JSON plan exports regardless of their filename.
func isTerraformPlan(root, path string) (bool, error) {
	source, err := safeSource(root, path)
	if err != nil {
		return false, err
	}
	input, err := os.Open(source)
	if err != nil {
		return false, err
	}
	defer input.Close()
	// Read top-level keys without retaining resource values or requiring the full plan.
	decoder := json.NewDecoder(input)
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false, nil
	}
	version, plan := false, false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false, nil
		}
		version = version || key == "format_version"
		plan = plan || key == "planned_values" || key == "resource_changes"
		if version && plan {
			return true, nil
		}
		depth := 0
		for {
			token, err = decoder.Token()
			if err != nil {
				return false, nil
			}
			if delim, ok := token.(json.Delim); ok {
				if delim == '{' || delim == '[' {
					depth++
				} else {
					depth--
				}
			}
			if depth == 0 {
				break
			}
		}
	}
	return false, nil
}

// DependencyEcosystem identifies finite dependency candidates without reading or
// executing project code. Candidates unsupported by an adapter remain unread.
func DependencyEcosystem(file string) string {
	switch filepath.Base(file) {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb":
		return "npm"
	case "go.mod", "go.sum":
		return "Go"
	case "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "pyproject.toml", "setup.py", "setup.cfg":
		return "PyPI"
	case "Cargo.toml", "Cargo.lock":
		return "crates.io"
	case "composer.json", "composer.lock":
		return "Packagist"
	case "Gemfile", "Gemfile.lock":
		return "RubyGems"
	case "packages.lock.json", "packages.config":
		return "NuGet"
	case "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile":
		return "Maven"
	}
	if strings.HasSuffix(file, ".csproj") || strings.HasSuffix(file, ".fsproj") || strings.HasSuffix(file, ".vbproj") {
		return "NuGet"
	}
	if strings.HasSuffix(file, ".versions.toml") {
		return "Maven"
	}
	return ""
}
