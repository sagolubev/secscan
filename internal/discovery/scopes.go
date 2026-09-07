// START_MODULE_CONTRACT
// PURPOSE: Select explicit file and directory scopes from the safe Git inventory.
// SCOPE: Reject unsafe or empty selections; retain full traversal evidence.
// DEPENDS: internal/discovery/discovery.go, internal/discovery/inventory.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-scoped-scans, internal/discovery/scopes_test.go#TestSelectScopesFiltersEveryCandidate, internal/discovery/scopes_test.go#TestSelectScopesRejectsUnsafeOrIneligible
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// SelectScopes - Validate exact Git paths and return independent candidate slices.
// END_MODULE_MAP

package discovery

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// START_CONTRACT: SelectScopes
// PURPOSE: Narrow candidate inputs without rebuilding the Git inventory.
// INPUTS: root: string - Resolved Git root. full: Inventory - Discover result. scopes: []string - At most 16 relative paths.
// OUTPUTS: Independent filtered inventory and sorted unique normalized paths, or error; no scopes returns full and nil paths.
// SIDE_EFFECTS: Checks scope metadata without following symlinks; no filesystem walk or content reads.
// LINKS: internal/discovery/scopes_test.go#TestSelectScopesUnionsAndNormalizes, internal/discovery/scopes_test.go#TestSelectScopesLimit
// END_CONTRACT: SelectScopes

// SelectScopes filters full by exact relative Git paths, preserving its traversal
// metadata. Every explicit scope must contain at least one eligible file.
func SelectScopes(root string, full Inventory, scopes []string) (Inventory, []string, error) {
	if len(scopes) == 0 {
		return full, nil, nil
	}
	if len(scopes) > 16 {
		return Inventory{}, nil, fmt.Errorf("at most 16 scopes are allowed")
	}
	selected := make(map[string]bool)
	paths := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == "" || path.IsAbs(scope) || strings.Contains(scope, "\\") || slices.Contains(strings.Split(scope, "/"), "..") {
			return Inventory{}, nil, fmt.Errorf("scope %q must be a relative path without traversal or backslashes", scope)
		}
		clean := path.Clean(scope)
		source, err := safeSource(root, filepath.FromSlash(clean))
		if err != nil {
			return Inventory{}, nil, fmt.Errorf("inspect scope %q: %w", scope, err)
		}
		info, err := os.Lstat(source)
		if err != nil {
			return Inventory{}, nil, fmt.Errorf("inspect scope %q: %w", scope, err)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return Inventory{}, nil, fmt.Errorf("scope %q is not a regular file or directory", scope)
		}
		matched := false
		for _, file := range full.Files {
			if file == clean || info.IsDir() && (clean == "." || strings.HasPrefix(file, clean+"/")) {
				selected[file] = true
				matched = true
			}
		}
		if !matched {
			return Inventory{}, nil, fmt.Errorf("scope %q selects no eligible files; use exact Git path spelling", scope)
		}
		paths = append(paths, clean)
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)

	narrowed := full
	for _, candidates := range []*[]string{
		&narrowed.Files, &narrowed.Native, &narrowed.OCI, &narrowed.Dependencies,
		&narrowed.Terraform, &narrowed.Checkov, &narrowed.KICS, &narrowed.Python,
		&narrowed.TypeScript, &narrowed.Bearer, &narrowed.Cppcheck, &narrowed.CI,
		&narrowed.Zizmor, &narrowed.Poutine,
	} {
		var filtered []string
		for _, file := range *candidates {
			if selected[file] {
				filtered = append(filtered, file)
			}
		}
		*candidates = filtered
	}
	narrowed.Sources = nil
	for _, source := range full.Sources {
		if selected[source.Path] {
			narrowed.Sources = append(narrowed.Sources, source)
		}
	}
	narrowed.Traversal.Tracked.Directories = slices.Clone(full.Traversal.Tracked.Directories)
	narrowed.Traversal.Untracked.Directories = slices.Clone(full.Traversal.Untracked.Directories)
	narrowed.Traversal.Ignored.Directories = slices.Clone(full.Traversal.Ignored.Directories)
	narrowed.Traversal.Omitted = slices.Clone(full.Traversal.Omitted)
	narrowed.Traversal.Unclassified = slices.Clone(full.Traversal.Unclassified)
	return narrowed, paths, nil
}
