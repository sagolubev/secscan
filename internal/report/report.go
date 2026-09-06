package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
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
	Feeds          []Feed   `json:"feeds,omitempty"`
	Limitations    []string `json:"limitations,omitempty"`
	Capabilities   []string `json:"capabilities,omitempty"`
}

// Feed records verified snapshot identity and acquisition time.
type Feed struct {
	Name       string `json:"name"`
	Digest     string `json:"digest"`
	AcquiredAt string `json:"acquiredAt"`
	BuiltAt    string `json:"builtAt,omitempty"`
}

type Coverage struct {
	ReadInputs    []string `json:"readInputs,omitempty"`
	UnreadInputs  []string `json:"unreadInputs,omitempty"`
	FailedInputs  []string `json:"failedInputs,omitempty"`
	Unread        int      `json:"unread,omitempty"`
	FailedFiles   int      `json:"failedFiles,omitempty"`
	FailedQueries int      `json:"failedQueries,omitempty"`
	Skipped       int      `json:"skipped,omitempty"`
	Read          int      `json:"read"`
	Failed        int      `json:"failed"`
	Unit          string   `json:"unit"`
}

type Exclusions struct {
	IgnoredFiles int   `json:"ignoredFiles"`
	IgnoredBytes int64 `json:"ignoredBytes"`
}

// Package is a versioned package identity in its upstream ecosystem.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl,omitempty"`
}

// Location identifies one source occurrence.
type Location struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	EndLine int    `json:"endLine,omitempty"`
}

type Finding struct {
	Package     *Package   `json:"package,omitempty"`
	Advisories  []string   `json:"advisories,omitempty"`
	Locations   []Location `json:"locations,omitempty"`
	Kind        string     `json:"kind"`
	RuleID      string     `json:"ruleId"`
	Message     string     `json:"message"`
	Path        string     `json:"path"`
	Line        int        `json:"line"`
	EndLine     int        `json:"endLine,omitempty"`
	Fingerprint string     `json:"fingerprint"`
	Sources     []string   `json:"sources"`
	Origin      string     `json:"origin"`
	Language    string     `json:"language,omitempty"`
	Severity    string     `json:"severity,omitempty"`
}

func Marshal(input Report) ([]byte, error) {
	result := input
	result.Findings = Normalize(input.Findings)
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

// Normalize merges connected advisory aliases for the same package version.
// It never mutates input findings or their nested collections.
func Normalize(input []Finding) []Finding {
	parents := make([]int, len(input))
	var root func(int) int
	root = func(i int) int {
		if parents[i] != i {
			parents[i] = root(parents[i])
		}
		return parents[i]
	}
	seen := make(map[string]int)
	for i, f := range input {
		parents[i] = i
		if f.Kind == "code" && strings.HasPrefix(f.RuleID, "secscan.") && (slices.Contains(f.Sources, "semgrep") || slices.Contains(f.Sources, "opengrep")) {
			key := fmt.Sprintf("code\x00%s\x00%s\x00%s\x00%d\x00%d", f.RuleID, f.Language, f.Path, f.Line, f.EndLine)
			if prior, ok := seen[key]; ok {
				parents[root(i)] = root(prior)
			} else {
				seen[key] = i
			}
		}
		if f.Kind != "dependency" || f.Package == nil {
			continue
		}
		identity := packageKey(*f.Package)
		for _, id := range f.Advisories {
			key := identity + "\x00" + id
			if prior, ok := seen[key]; ok {
				parents[root(i)] = root(prior)
			} else {
				seen[key] = i
			}
		}
	}
	groups := make(map[int]int)
	result := make([]Finding, 0, len(input))
	for i, f := range input {
		group := root(i)
		if position, ok := groups[group]; ok {
			dest := &result[position]
			dest.Sources = append(dest.Sources, f.Sources...)
			dest.Advisories = append(dest.Advisories, f.Advisories...)
			dest.Locations = append(dest.Locations, f.Locations...)
			if severityRank(f.Severity) > severityRank(dest.Severity) {
				dest.Severity = f.Severity
			}
			if f.Package != nil && dest.Package != nil && f.Package.PURL != "" && (dest.Package.PURL == "" || f.Package.PURL < dest.Package.PURL) {
				dest.Package.PURL = f.Package.PURL
			}
			continue
		}
		groups[group] = len(result)
		f.Sources = append([]string(nil), f.Sources...)
		f.Advisories = append([]string(nil), f.Advisories...)
		f.Locations = append([]Location(nil), f.Locations...)
		if f.Package != nil {
			pkg := *f.Package
			f.Package = &pkg
		}
		result = append(result, f)
	}
	for i := range result {
		f := &result[i]
		slices.Sort(f.Sources)
		f.Sources = slices.Compact(f.Sources)
		if f.Kind != "dependency" || f.Package == nil {
			continue
		}
		slices.Sort(f.Advisories)
		f.Advisories = slices.Compact(f.Advisories)
		slices.SortFunc(f.Locations, func(a, b Location) int {
			if a.Path != b.Path {
				return strings.Compare(a.Path, b.Path)
			}
			if a.Line != b.Line {
				return a.Line - b.Line
			}
			return a.EndLine - b.EndLine
		})
		f.Locations = slices.Compact(f.Locations)
		if len(f.Locations) > 0 {
			f.Path = f.Locations[0].Path
			f.Line = f.Locations[0].Line
			f.EndLine = f.Locations[0].EndLine
		}
		f.RuleID = "dependency-advisory"
		f.Message = "package version has a known security advisory"
		f.Origin = "working_tree"
		sum := sha256.Sum256([]byte(packageKey(*f.Package) + "\x00" + strings.Join(f.Advisories, "\x00")))
		f.Fingerprint = hex.EncodeToString(sum[:])
	}
	return result
}

func packageKey(pkg Package) string { return pkg.Ecosystem + "\x00" + pkg.Name + "\x00" + pkg.Version }
func severityRank(value string) int {
	return slices.Index([]string{"", "unknown", "informational", "low", "medium", "high", "critical"}, value)
}
