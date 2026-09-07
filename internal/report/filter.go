// FILE: internal/report/filter.go
// START_MODULE_CONTRACT
// PURPOSE: Expose visible-filter accounting without repository policy text.
// SCOPE: Count removed sets by original identity and final fragments separately.
// DEPENDS: none
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-filtering-and-suppressions, internal/filter/filter_test.go#TestApplyPartialDependency
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// FilterSummary - Count normalized inputs and final visible fragments.
// FilterStage - Count elements removed once at an ordered stage.
// END_MODULE_MAP

package report

// FilterSummary counts normalized raw findings and final visible fragments.
type FilterSummary struct {
	InputFindings   int           `json:"inputFindings"`
	OutputFragments int           `json:"outputFragments"`
	Stages          []FilterStage `json:"stages"`
}

// FilterStage counts removed elements by original fingerprint. A place or
// advisory is removed only when it is absent from every surviving fragment.
type FilterStage struct {
	Name        string `json:"name"`
	RuleID      string `json:"ruleId,omitempty"`
	Findings    int    `json:"findings"`
	Places      int    `json:"places"`
	Advisories  int    `json:"advisories"`
	Occurrences int    `json:"occurrences"`
}
