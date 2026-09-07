// START_MODULE_CONTRACT
// PURPOSE: Report code and dependency inputs lacking positive analysis evidence.
// SCOPE: Secret scanning does not establish SAST/SCA coverage; inventory is not read evidence.
// DEPENDS: internal/discovery/discovery.go, internal/report/inventory.go, internal/scanner/dependencies.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-honest-coverage, cmd/secscan/coverage_test.go#TestCoverageGapsSeparateAnalysisKinds
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// coverageGaps - Compare supported input routes with selected scanner read evidence.
// END_MODULE_MAP

package main

import (
	"slices"
	"strings"

	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/report"
	"github.com/sagolubev/secscan/internal/scanner"
)

func coverageGaps(inventory discovery.Inventory, selection []string, results []report.Scanner) []report.UncheckedInput {
	codeRoutes := map[string][]string{}
	dependencyRoutes := map[string][]string{}
	for _, route := range []struct {
		name  string
		files []string
	}{
		{"python-sast", inventory.Python}, {"typescript-sast", inventory.TypeScript},
		{"semgrep", inventory.Python}, {"semgrep", inventory.TypeScript},
		{"bearer", inventory.Bearer}, {"cppcheck", inventory.Cppcheck},
	} {
		for _, file := range route.files {
			codeRoutes[file] = append(codeRoutes[file], route.name)
		}
	}
	supported, _ := scanner.DependencyInputs(inventory.Dependencies)
	for _, file := range supported {
		dependencyRoutes[file] = []string{"trivy", "grype", "osv-scanner"}
	}
	for _, name := range []string{"gradle-catalog", "gradle-scripts"} {
		for _, file := range scanner.NativeInputs(name, inventory.Native) {
			dependencyRoutes[file] = append(dependencyRoutes[file], name)
		}
	}
	selected := map[string]bool{}
	for _, name := range selection {
		selected[name] = true
	}
	byName := map[string]report.Scanner{}
	for _, result := range results {
		byName[result.Name] = result
	}
	read := map[string]map[string]bool{}
	for _, result := range results {
		if result.Status != "success" || result.Coverage.Read <= 0 {
			continue
		}
		blocked := map[string]bool{}
		for _, path := range result.Coverage.UnreadInputs {
			blocked[path] = true
		}
		for _, path := range result.Coverage.FailedInputs {
			blocked[path] = true
		}
		read[result.Name] = map[string]bool{}
		for _, path := range result.Coverage.ReadInputs {
			if !blocked[path] {
				read[result.Name][path] = true
			}
		}
	}
	var gaps []report.UncheckedInput
	add := func(path, category, format string, routes []string) {
		reason := "no_matching_scanner"
		if len(routes) > 0 {
			reason = "scanner_not_selected"
		}
		for _, name := range routes {
			if !selected[name] {
				continue
			}
			if reason == "scanner_not_selected" {
				reason = "no_successful_analysis"
			}
			result, ok := byName[name]
			if !ok || result.Status != "success" {
				continue
			}
			reason = "no_positive_read_evidence"
			if read[name][path] {
				return
			}
		}
		gaps = append(gaps, report.UncheckedInput{Path: path, Category: category, Format: format, Reason: reason})
	}
	for _, source := range inventory.Sources {
		add(source.Path, "code", source.Language, codeRoutes[source.Path])
	}
	for _, path := range inventory.Dependencies {
		add(path, "dependency", discovery.DependencyEcosystem(path), dependencyRoutes[path])
	}
	slices.SortFunc(gaps, func(a, b report.UncheckedInput) int {
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		return strings.Compare(a.Category, b.Category)
	})
	return gaps
}
