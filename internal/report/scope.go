// START_MODULE_CONTRACT
// PURPOSE: Disclose requested paths and each scanner's actual candidate scope.
// SCOPE: Counts describe candidate inputs, never proof of scanner reads.
// DEPENDS: none
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-scoped-scans, internal/discovery/scopes_test.go#TestSelectScopesUnionsAndNormalizes
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Scope - Requested paths and their union of eligible inputs.
// ScannerScope - Actual scanner mode and candidate count.
// END_MODULE_MAP

package report

// Scope describes the requested paths and their eligible candidate file count.
type Scope struct {
	Paths         []string `json:"paths"`
	SelectedFiles int      `json:"selectedFiles"`
}

// ScannerScope discloses files or repository mode and candidate inputs, not reads.
type ScannerScope struct {
	Mode           string `json:"mode"`
	CandidateFiles int    `json:"candidateFiles"`
}
