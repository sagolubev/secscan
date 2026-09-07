// START_MODULE_CONTRACT
// PURPOSE: Route scoped inputs only to file-safe scanners and disclose full-context fallbacks.
// SCOPE: Candidate counts are not read evidence; preserve actual finding paths and full inventory.
// DEPENDS: internal/discovery/scopes.go, internal/report/scope.go, internal/scanner/native.go, cmd/secscan/coverage.go
// LINKS: cmd/secscan/scope_test.go#TestScopeKeepsWholeScannerResults, cmd/secscan/scope_test.go#TestScopeAvoidsUnneededRuntime
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// scopeFlags - Collect at most sixteen explicit scopes.
// fileScopedScanner - Identify the finite set of scanners with safe file narrowing.
// inputsForScanner - Map a persona to its candidate inputs for execution and disclosure.
// scopedCoverageInventory - Preserve gaps relevant to scoped and full-context scanners.
// inputsWithRules - Add only matching custom-rule source inputs.
// END_MODULE_MAP

package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/rules"
	"github.com/sagolubev/secscan/internal/scanner"
)

type scopeFlags []string

func (values *scopeFlags) String() string { return strings.Join(*values, ",") }
func (values *scopeFlags) Set(value string) error {
	if value == "" || len(*values) >= 16 {
		return fmt.Errorf("--scope requires a nonempty path, with at most 16 scopes")
	}
	*values = append(*values, value)
	return nil
}

func fileScopedScanner(name string) bool {
	return slices.Contains([]string{"gitleaks", "python-sast", "typescript-sast", "semgrep", "zizmor"}, name)
}

func inputsForScanner(name string, inventory discovery.Inventory) []string {
	switch name {
	case "gitleaks":
		return inventory.Files
	case "python-sast":
		return inventory.Python
	case "typescript-sast":
		return inventory.TypeScript
	case "semgrep":
		files := append(append([]string(nil), inventory.Python...), inventory.TypeScript...)
		slices.Sort(files)
		return slices.Compact(files)
	case "zizmor":
		return inventory.Zizmor
	case "poutine":
		return inventory.Poutine
	case "checkov":
		return inventory.Checkov
	case "checkov-terraform":
		return inventory.Terraform
	case "kics":
		return inventory.KICS
	case "trivy", "grype", "osv-scanner":
		return inventory.Dependencies
	case "bearer":
		return inventory.Bearer
	case "cppcheck":
		return inventory.Cppcheck
	case "gradle-catalog", "gradle-scripts", "refresh-versions":
		return scanner.NativeInputs(name, inventory.Native)
	case "oci-images":
		return inventory.OCI
	default:
		return nil
	}
}

func inputsWithRules(name string, inventory discovery.Inventory, pack *rules.Pack) []string {
	files := inputsForScanner(name, inventory)
	if name != "semgrep" || pack == nil {
		return files
	}
	files = append([]string(nil), files...)
	for _, source := range inventory.Sources {
		if pack.MatchesPath(source.Path) {
			files = append(files, source.Path)
		}
	}
	slices.Sort(files)
	return slices.Compact(files)
}

// Coverage needs both the broad input list and its scanner routes; restoring
// only Sources/Dependencies would discard positive outside-scope read evidence.
func scopedCoverageInventory(full, selected discovery.Inventory, scanners []string) discovery.Inventory {
	for _, name := range scanners {
		switch name {
		case "bearer":
			selected.Sources = full.Sources
			selected.Bearer = full.Bearer
		case "cppcheck":
			selected.Sources = full.Sources
			selected.Cppcheck = full.Cppcheck
		case "trivy", "grype", "osv-scanner":
			selected.Dependencies = full.Dependencies
		case "gradle-catalog", "gradle-scripts":
			selected.Dependencies = full.Dependencies
			selected.Native = full.Native
		}
	}
	return selected
}
