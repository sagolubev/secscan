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
