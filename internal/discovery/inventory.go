// START_MODULE_CONTRACT
// PURPOSE: Classify enumerated inputs and account for every Git path without following links.
// SCOPE: Counts describe regular files; omitted paths are explicit and never staged.
// DEPENDS: internal/report/inventory.go
// LINKS: internal/discovery/discovery_test.go#TestTraversalInventory, internal/discovery/discovery_test.go#TestTraversalOmitsSymlinksAndMissingEntries
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// SourceInput - A recognized source language candidate.
// SourceLanguage - Finite language classification independent of scanner support.
// END_MODULE_MAP

package discovery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sagolubev/secscan/internal/report"
)

// SourceInput is a recognized source language candidate, not proof of support.
type SourceInput struct {
	Path     string
	Language string
}

func enumerate(root string, excluded []string) ([]string, report.Inventory, error) {
	tracked, err := gitPaths(root, "--cached")
	if err != nil {
		return nil, report.Inventory{}, err
	}
	untracked, err := gitPaths(root, "--others", "--exclude-standard")
	if err != nil {
		return nil, report.Inventory{}, err
	}
	ignored, err := gitPaths(root, "--others", "--ignored", "--exclude-standard")
	if err != nil {
		return nil, report.Inventory{}, err
	}
	var inventory report.Inventory
	var selected []string
	controls := make(map[string]os.FileInfo, len(excluded))
	matched := make(map[string]bool, len(excluded))
	for _, path := range excluded {
		controls[path] = nil
		source, err := safeSource(root, filepath.FromSlash(path))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errSymlink) {
			continue
		}
		if err != nil {
			return nil, report.Inventory{}, fmt.Errorf("inspect control path: %w", err)
		}
		info, err := os.Lstat(source)
		if err != nil {
			return nil, report.Inventory{}, fmt.Errorf("inspect control path: %w", err)
		}
		if info.Mode().IsRegular() {
			controls[path] = info
		}
	}
	seen := map[string]bool{}
	for _, group := range []struct {
		paths   []string
		stats   *report.FileInventory
		ignored bool
	}{{tracked, &inventory.Tracked, false}, {untracked, &inventory.Untracked, false}, {ignored, &inventory.Ignored, true}} {
		directories := map[string]report.DirectoryInventory{}
		for _, path := range group.paths {
			if seen[path] {
				continue
			}
			seen[path] = true
			if _, control := controls[path]; control {
				matched[path] = true
				inventory.Omitted = append(inventory.Omitted, report.OmittedInput{Path: path, Reason: "control_file"})
				continue
			}
			source, err := safeSource(root, filepath.FromSlash(path))
			reason := ""
			switch {
			case errors.Is(err, errSymlink):
				reason = "symlink"
			case errors.Is(err, os.ErrNotExist):
				reason = "missing"
			case err != nil:
				return nil, report.Inventory{}, fmt.Errorf("inspect inventory path %q: %w", path, err)
			}
			if reason != "" {
				inventory.Omitted = append(inventory.Omitted, report.OmittedInput{Path: path, Reason: reason})
				continue
			}
			info, err := os.Lstat(source)
			if err != nil {
				return nil, report.Inventory{}, fmt.Errorf("inspect inventory path %q: %w", path, err)
			}
			if !info.Mode().IsRegular() {
				inventory.Omitted = append(inventory.Omitted, report.OmittedInput{Path: path, Reason: "non_regular"})
				continue
			}
			control := false
			for path, excludedInfo := range controls {
				if excludedInfo != nil && os.SameFile(info, excludedInfo) {
					matched[path] = true
					control = true
				}
			}
			if control {
				inventory.Omitted = append(inventory.Omitted, report.OmittedInput{Path: path, Reason: "control_file"})
				continue
			}
			group.stats.Files++
			group.stats.Bytes += info.Size()
			parent := filepath.ToSlash(filepath.Dir(path))
			directory := directories[parent]
			directory.Path = parent
			directory.Files++
			directory.Bytes += info.Size()
			directories[parent] = directory
			if !group.ignored {
				selected = append(selected, path)
			}
		}
		group.stats.Directories = make([]report.DirectoryInventory, 0, len(directories))
		for _, directory := range directories {
			group.stats.Directories = append(group.stats.Directories, directory)
		}
		slices.SortFunc(group.stats.Directories, func(a, b report.DirectoryInventory) int { return strings.Compare(a.Path, b.Path) })
	}
	for path := range controls {
		if !matched[path] {
			inventory.Omitted = append(inventory.Omitted, report.OmittedInput{Path: path, Reason: "control_file"})
		}
	}
	slices.Sort(selected)
	slices.SortFunc(inventory.Omitted, func(a, b report.OmittedInput) int { return strings.Compare(a.Path, b.Path) })
	return selected, inventory, nil
}

// SourceLanguage recognizes source candidates without claiming scanner support.
func SourceLanguage(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py", ".pyi":
		return "python"
	case ".ts", ".tsx", ".mts", ".cts":
		return "typescript"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".go", ".go2":
		return "go"
	case ".java":
		return "java"
	case ".rb", ".rake":
		return "ruby"
	case ".php":
		return "php"
	case ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx":
		return "c-cpp"
	case ".groovy", ".gradle":
		return "groovy"
	case ".kt", ".kts":
		return "kotlin"
	case ".cs":
		return "csharp"
	case ".fs", ".fsx":
		return "fsharp"
	case ".rs":
		return "rust"
	case ".swift":
		return "swift"
	case ".scala":
		return "scala"
	case ".dart":
		return "dart"
	case ".sh", ".bash", ".zsh":
		return "shell"
	case ".ps1":
		return "powershell"
	case ".lua":
		return "lua"
	case ".pl", ".pm":
		return "perl"
	case ".r":
		return "r"
	case ".html", ".htm":
		return "html"
	case ".css", ".scss", ".sass":
		return "css"
	}
	return ""
}
