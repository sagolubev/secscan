// FILE: internal/filter/filter.go
// START_MODULE_CONTRACT
// PURPOSE: Derive visible findings with ordered, nonduplicating filter counts.
// SCOPE: Preserve fingerprints, unsuppressed pairs and all secret/error findings.
// DEPENDS: internal/report/report.go, internal/report/filter.go, internal/baseline/baseline.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-filtering-and-suppressions, internal/filter/filter_test.go#TestApplyPartialDependency, internal/filter/filter_test.go#TestApplyOrderAndExemptions, internal/filter/filter_test.go#TestApplyImmutable
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Result - Keep visible fragments and stage accounting together.
// Apply - Normalize full input and apply ordered project/baseline/severity/test filters.
// END_MODULE_MAP

package filter

import (
	"errors"
	"path"
	"slices"
	"strings"

	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/report"
)

// Result contains visible fragments, removal counts and optional baseline counts.
type Result struct {
	Findings []report.Finding
	Summary  report.FilterSummary
	Baseline *report.BaselineSummary
}

// Apply derives a visible view without mutating input or recomputing the
// original fingerprints of partial findings.
func Apply(input []report.Finding, cfg Config, previous *baseline.Snapshot) (Result, error) {
	if err := validateConfig(cfg); err != nil {
		return Result{}, err
	}
	for _, f := range input {
		if f.BaselineStatus != "" {
			return Result{}, errors.New("project filtering requires full findings")
		}
	}
	result := Result{Findings: report.Normalize(input)}
	result.Summary = report.FilterSummary{InputFindings: len(result.Findings), Stages: []report.FilterStage{}}
	record := func(name, id string, next []report.Finding) {
		before, after := countElements(result.Findings), countElements(next)
		result.Summary.Stages = append(result.Summary.Stages, report.FilterStage{
			Name: name, RuleID: id, Findings: before.Findings - after.Findings,
			Places: before.Places - after.Places, Advisories: before.Advisories - after.Advisories,
			Occurrences: before.Occurrences - after.Occurrences,
		})
		result.Findings = next
	}
	for _, rule := range cfg.Suppressions {
		record("project", rule.ID, suppress(result.Findings, rule))
	}
	if previous != nil {
		next, summary, err := baseline.CompareFragments(result.Findings, *previous)
		if err != nil {
			return Result{}, err
		}
		result.Baseline = &summary
		record("baseline", "", next)
	}
	if cfg.MinSeverity != "" {
		var next []report.Finding
		for _, f := range result.Findings {
			if exempt(f) || severityRank(f.Severity) <= 0 || severityRank(f.Severity) >= severityRank(cfg.MinSeverity) {
				next = append(next, f)
			}
		}
		record("severity", "", next)
	}
	if len(cfg.TestPaths) > 0 {
		next := result.Findings
		for _, pattern := range cfg.TestPaths {
			next = suppress(next, Rule{Path: pattern})
		}
		record("test-data", "", next)
	}
	if result.Findings == nil {
		result.Findings = []report.Finding{}
	}
	result.Summary.OutputFragments = len(result.Findings)
	return result, nil
}

func suppress(input []report.Finding, rule Rule) []report.Finding {
	var result []report.Finding
	for _, f := range input {
		if exempt(f) || rule.Kind != "" && rule.Kind != f.Kind || rule.RuleID != "" && rule.RuleID != f.RuleID || rule.Fingerprint != "" && rule.Fingerprint != f.Fingerprint || rule.Advisory != "" && (f.Kind != "dependency" || !slices.Contains(f.Advisories, rule.Advisory)) {
			result = append(result, f)
			continue
		}
		if rule.Path == "" && rule.Advisory == "" {
			continue
		}
		var selected, retained []report.Location
		for _, location := range locations(f) {
			if rule.Path == "" || matchesPath(rule.Path, location.Path) {
				selected = append(selected, location)
			} else {
				retained = append(retained, location)
			}
		}
		if len(selected) == 0 {
			result = append(result, f)
			continue
		}
		// Disjoint rectangles preserve all pairs outside the selected intersection.
		if len(retained) > 0 {
			result = append(result, atLocations(f, retained))
		}
		if rule.Advisory != "" {
			remaining := make([]string, 0, len(f.Advisories)-1)
			for _, id := range f.Advisories {
				if id != rule.Advisory {
					remaining = append(remaining, id)
				}
			}
			if len(remaining) > 0 {
				part := atLocations(f, selected)
				part.Advisories = remaining
				result = append(result, part)
			}
		}
	}
	return result
}

func exempt(f report.Finding) bool { return f.Kind == "secret" || f.Kind == "error" }

func matchesPath(pattern, name string) bool {
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(name, pattern)
	}
	matched, _ := path.Match(pattern, name) // Patterns were validated before filtering.
	return matched
}

func locations(f report.Finding) []report.Location {
	if len(f.Locations) > 0 {
		return f.Locations
	}
	if f.Path == "" {
		return nil
	}
	return []report.Location{{Path: f.Path, Line: f.Line, EndLine: f.EndLine}}
}

func atLocations(f report.Finding, selected []report.Location) report.Finding {
	f.Path, f.Line, f.EndLine = selected[0].Path, selected[0].Line, selected[0].EndLine
	if len(f.Locations) > 0 {
		f.Locations = selected
	}
	return f
}

type findingKey struct{ fingerprint, kind, rule string }
type placeKey struct {
	finding  findingKey
	location report.Location
}
type advisoryKey struct {
	finding  findingKey
	advisory string
}

// All stages only subtract elements and preserve original identity, so count
// differences equal set differences. Advisory slices are referenced per place
// to count their union without storing the full advisory/location cross product.
func countElements(input []report.Finding) report.FilterStage {
	findings := make(map[findingKey]struct{})
	places := make(map[placeKey][][]string)
	advisories := make(map[advisoryKey]struct{})
	for _, f := range input {
		key := findingKey{fingerprint: f.Fingerprint, kind: f.Kind, rule: f.RuleID}
		findings[key] = struct{}{}
		for _, id := range f.Advisories {
			advisories[advisoryKey{finding: key, advisory: id}] = struct{}{}
		}
		for _, location := range locations(f) {
			p := placeKey{finding: key, location: location}
			places[p] = append(places[p], f.Advisories)
		}
	}
	counts := report.FilterStage{Findings: len(findings), Places: len(places), Advisories: len(advisories)}
	ids := make(map[string]struct{})
	for place, groups := range places {
		if place.finding.kind != "dependency" {
			counts.Occurrences++
			continue
		}
		clear(ids)
		for _, group := range groups {
			for _, id := range group {
				ids[id] = struct{}{}
			}
		}
		counts.Occurrences += len(ids)
	}
	return counts
}
