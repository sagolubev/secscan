// START_MODULE_CONTRACT
// PURPOSE: Describe the immutable Git history selected for a secret scan.
// SCOPE: Reachable commit counts are candidate metadata, not per-commit read evidence.
// DEPENDS: none
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// GitHistory - Record the frozen HEAD and reachable candidate commit count.
// END_MODULE_MAP

package report

// GitHistory identifies a frozen HEAD and its reachable candidate commits.
type GitHistory struct {
	Head    string `json:"head"`
	Commits int    `json:"commits"`
}
