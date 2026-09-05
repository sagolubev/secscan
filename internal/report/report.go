package report

import (
	"encoding/json"
	"sort"
)

type Report struct {
	SchemaVersion string     `json:"schemaVersion"`
	Repository    string     `json:"repository"`
	Scanners      []Scanner  `json:"scanners"`
	Findings      []Finding  `json:"findings"`
	Exclusions    Exclusions `json:"exclusions"`
}

type Scanner struct {
	Name           string   `json:"name"`
	Status         string   `json:"status"`
	Image          string   `json:"image"`
	EngineVersion  string   `json:"engineVersion,omitempty"`
	RulePackDigest string   `json:"rulePackDigest,omitempty"`
	RuleCount      int      `json:"ruleCount,omitempty"`
	Coverage       Coverage `json:"coverage"`
}

type Coverage struct {
	Read   int    `json:"read"`
	Failed int    `json:"failed"`
	Unit   string `json:"unit"`
}

type Exclusions struct {
	IgnoredFiles int   `json:"ignoredFiles"`
	IgnoredBytes int64 `json:"ignoredBytes"`
}

type Finding struct {
	Kind        string   `json:"kind"`
	RuleID      string   `json:"ruleId"`
	Message     string   `json:"message"`
	Path        string   `json:"path"`
	Line        int      `json:"line"`
	EndLine     int      `json:"endLine,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Sources     []string `json:"sources"`
	Origin      string   `json:"origin"`
	Language    string   `json:"language,omitempty"`
	Severity    string   `json:"severity,omitempty"`
}

func Marshal(input Report) ([]byte, error) {
	result := input
	result.Findings = append([]Finding(nil), input.Findings...)
	result.Scanners = append([]Scanner(nil), input.Scanners...)
	if result.Findings == nil {
		result.Findings = []Finding{}
	}
	if result.Scanners == nil {
		result.Scanners = []Scanner{}
	}
	sort.Slice(result.Scanners, func(i, j int) bool {
		return result.Scanners[i].Name < result.Scanners[j].Name
	})
	sort.Slice(result.Findings, func(i, j int) bool {
		left, right := result.Findings[i], result.Findings[j]
		if left.Fingerprint != right.Fingerprint {
			return left.Fingerprint < right.Fingerprint
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		return left.Line < right.Line
	})
	return json.Marshal(result)
}
