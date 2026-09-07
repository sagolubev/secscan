// START_MODULE_CONTRACT
// PURPOSE: Describe how current findings compare with a saved baseline.
// SCOPE: Counts describe findings and fragments, not scanner coverage.
// DEPENDS: none
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-baselines, internal/report/report_test.go#TestMarshalPreservesBaselineFragments
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// BaselineSummary - Partition current findings and count retained fragments.
// END_MODULE_MAP

package report

// BaselineSummary counts normalized current findings before filtering.
// New, Expanded, Unchanged and Exempt partition InputFindings; one expanded
// finding can produce two advisory/location fragments in OutputFragments.
type BaselineSummary struct {
	InputFindings   int `json:"inputFindings"`
	OutputFragments int `json:"outputFragments"`
	New             int `json:"new"`
	Expanded        int `json:"expanded"`
	Unchanged       int `json:"unchanged"`
	Exempt          int `json:"exempt"`
}
