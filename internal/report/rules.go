// START_MODULE_CONTRACT
// PURPOSE: Record the provenance of explicitly imported custom rules.
// SCOPE: License and source are declarations; no rule text or source snippets.
// DEPENDS: none
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-reproducibility
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// RulePack - Describe the immutable custom bundle and applied rule count.
// END_MODULE_MAP

package report

// RulePack records declared provenance and the number of custom rules applied.
type RulePack struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	License   string `json:"license"`
	Revision  string `json:"revision,omitempty"`
	RuleCount int    `json:"ruleCount"`
}
