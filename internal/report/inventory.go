// START_MODULE_CONTRACT
// PURPOSE: Describe filesystem inventory separately from scanner read evidence.
// SCOPE: Directory counts are non-recursive; omitted inputs are never counted as read.
// DEPENDS: none
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-honest-coverage, internal/discovery/discovery_test.go#TestTraversalInventory
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Inventory - Tracked, untracked, ignored and omitted inputs.
// FileInventory - File and byte counts grouped by immediate directory.
// DirectoryInventory - Non-recursive counts for one directory.
// OmittedInput - A path excluded before staging.
// UncheckedInput - A recognized input without successful applicable analysis.
// END_MODULE_MAP

package report

// Inventory accounts for enumeration, not scanner analysis.
type Inventory struct {
	Tracked      FileInventory  `json:"tracked"`
	Untracked    FileInventory  `json:"untracked"`
	Ignored      FileInventory  `json:"ignored"`
	Omitted      []OmittedInput `json:"omitted,omitempty"`
	Unclassified []string       `json:"unclassified,omitempty"`
}

// FileInventory summarizes regular files in one disjoint Git bucket.
type FileInventory struct {
	Files       int                  `json:"files"`
	Bytes       int64                `json:"bytes"`
	Directories []DirectoryInventory `json:"directories"`
}

// DirectoryInventory counts immediate files only, without double-counting children.
type DirectoryInventory struct {
	Path  string `json:"path"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
}

// OmittedInput records an enumerated path that was not staged.
type OmittedInput struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// UncheckedInput identifies an analysis gap independently of secret scanning.
type UncheckedInput struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Format   string `json:"format"`
	Reason   string `json:"reason"`
}
