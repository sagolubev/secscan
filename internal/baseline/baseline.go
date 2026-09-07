// FILE: internal/baseline/baseline.go
// START_MODULE_CONTRACT
// PURPOSE: Store portable full findings and compare current growth against them.
// SCOPE: Strict bounded JSON; no filesystem access, input mutation or old text output.
// DEPENDS: internal/report/report.go, internal/report/baseline.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-baselines, internal/baseline/baseline_test.go#TestCompareDependencyGrowth, internal/baseline/baseline_test.go#TestCodecBoundary
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// MaxBytes - Bound encoded and decoded snapshot size.
// SchemaVersion - Identify the snapshot wire schema.
// FingerprintAlgorithm - Identify existing canonical finding fingerprints.
// Snapshot - Hold validated prior findings behind an immutable boundary.
// Encode - Normalize full current findings into versioned JSON.
// Decode - Validate untrusted snapshot JSON without echoing its data.
// Compare - Return only current new, expanded and exempt findings.
// CompareFragments - Compare canonical partial findings without remerging them.
// END_MODULE_MAP

// Package baseline compares canonical findings with portable prior snapshots.
package baseline

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sagolubev/secscan/internal/report"
)

// MaxBytes bounds a snapshot before decoding or publishing it.
const MaxBytes = 32 << 20

// SchemaVersion identifies the snapshot JSON shape.
const SchemaVersion = "1"

// FingerprintAlgorithm identifies existing canonical report fingerprints.
const FingerprintAlgorithm = "secscan-v1"

// Snapshot contains validated prior findings. Its zero value is invalid.
// Copies may be compared concurrently; Compare never exposes stored findings.
type Snapshot struct {
	findings []report.Finding
	valid    bool
}

type wireSnapshot struct {
	SchemaVersion        string           `json:"schemaVersion"`
	FingerprintAlgorithm string           `json:"fingerprintAlgorithm"`
	Findings             []report.Finding `json:"findings"`
}

// Encode serializes full, unfiltered findings after canonical normalization.
// It rejects findings already marked by baseline filtering.
func Encode(input []report.Finding) ([]byte, error) {
	findings, err := normalize(input)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(wireSnapshot{SchemaVersion, FingerprintAlgorithm, findings})
	if err != nil {
		return nil, errors.New("cannot encode baseline")
	}
	if len(data) > MaxBytes {
		return nil, errors.New("baseline exceeds size limit")
	}
	return data, nil
}

// START_CONTRACT: Decode
// PURPOSE: Validate persisted findings at the untrusted JSON boundary.
// INPUTS: data: []byte - Versioned JSON, at most MaxBytes.
// OUTPUTS: Snapshot or error; errors never quote input fields or values.
// SIDE_EFFECTS: none
// LINKS: internal/baseline/baseline_test.go#TestCodecBoundary
// END_CONTRACT: Decode

// Decode rejects malformed, ambiguous and incompatible snapshots.
func Decode(data []byte) (Snapshot, error) {
	if len(data) > MaxBytes {
		return Snapshot{}, errors.New("baseline exceeds size limit")
	}
	if !utf8.Valid(data) || !validJSON(json.NewDecoder(bytes.NewReader(data)), 0) {
		return Snapshot{}, errors.New("invalid baseline JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire wireSnapshot
	if err := decoder.Decode(&wire); err != nil {
		return Snapshot{}, errors.New("invalid baseline schema")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Snapshot{}, errors.New("invalid trailing baseline data")
	}
	if wire.SchemaVersion != SchemaVersion || wire.FingerprintAlgorithm != FingerprintAlgorithm {
		return Snapshot{}, errors.New("incompatible baseline schema or fingerprint algorithm")
	}
	if wire.Findings == nil {
		return Snapshot{}, errors.New("missing baseline findings")
	}
	for _, f := range wire.Findings {
		if err := validate(f); err != nil {
			return Snapshot{}, err
		}
	}
	// Re-normalize identities only after validation; old messages remain private.
	findings, err := normalize(wire.Findings)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{findings: findings, valid: true}, nil
}

// START_CONTRACT: Compare
// PURPOSE: Hide known findings while retaining every new growth combination.
// INPUTS: input: full current findings; previous: validated Snapshot from Decode.
// OUTPUTS: Current-only delta fragments and counts of normalized source findings.
// SIDE_EFFECTS: none; input and previous remain unchanged.
// LINKS: internal/baseline/baseline_test.go#TestCompareDependencyGrowth, internal/baseline/baseline_test.go#TestCodecDeterministicAndImmutable
// END_CONTRACT: Compare

// Compare returns new, expanded and exempt current findings. Existing
// fingerprints are preserved even when one finding produces two fragments.
func Compare(input []report.Finding, previous Snapshot) ([]report.Finding, report.BaselineSummary, error) {
	if !previous.valid {
		return nil, report.BaselineSummary{}, errors.New("invalid baseline snapshot")
	}
	current, err := normalize(input)
	if err != nil {
		return nil, report.BaselineSummary{}, err
	}
	return compare(current, previous)
}

// CompareFragments compares validated canonical fragments without merging
// rectangles or recomputing their original fingerprint. Counts describe the
// input fragments; returned nested data never aliases input or previous.
func CompareFragments(input []report.Finding, previous Snapshot) ([]report.Finding, report.BaselineSummary, error) {
	if !previous.valid {
		return nil, report.BaselineSummary{}, errors.New("invalid baseline snapshot")
	}
	current := slices.Clone(input)
	for i, f := range current {
		if err := validate(f); err != nil {
			return nil, report.BaselineSummary{}, err
		}
		f.Sources = slices.Clone(f.Sources)
		f.Advisories = slices.Clone(f.Advisories)
		f.Locations = slices.Clone(f.Locations)
		if f.Package != nil {
			pkg := *f.Package
			f.Package = &pkg
		}
		current[i] = f
	}
	return compare(current, previous)
}

func compare(current []report.Finding, previous Snapshot) ([]report.Finding, report.BaselineSummary, error) {
	codes := make(map[identity]*history)
	dependencies := make(map[identity]map[string]*history)
	for _, f := range previous.findings {
		key := findingIdentity(f)
		if f.Kind == "dependency" {
			if dependencies[key] == nil {
				dependencies[key] = make(map[string]*history)
			}
			h := newHistory()
			h.add(f)
			for _, id := range f.Advisories {
				dependencies[key][id] = h
			}
		} else if f.Kind == "code" || f.Kind == "configuration" {
			if codes[key] == nil {
				codes[key] = newHistory()
			}
			codes[key].add(f)
		}
	}
	result := make([]report.Finding, 0, len(current))
	summary := report.BaselineSummary{InputFindings: len(current)}
	for _, f := range current {
		if f.Kind == "error" || f.Kind == "secret" {
			f.BaselineStatus = "exempt"
			result = append(result, f)
			summary.Exempt++
			continue
		}
		key := findingIdentity(f)
		h := codes[key]
		if f.Kind == "dependency" {
			matched := make(map[*history]bool)
			for _, id := range f.Advisories {
				if old := dependencies[key][id]; old != nil {
					matched[old] = true
				}
			}
			if len(matched) > 0 {
				h = newHistory()
				for old := range matched {
					h.merge(old)
				}
			}
		}
		if h == nil {
			f.BaselineStatus = "new"
			result = append(result, f)
			summary.New++
			continue
		}
		fragments := growth(f, h)
		if len(fragments) == 0 {
			summary.Unchanged++
			continue
		}
		summary.Expanded++
		result = append(result, fragments...)
	}
	summary.OutputFragments = len(result)
	sortFindings(result)
	return result, summary, nil
}

type identity struct {
	kind, rule, language, origin, image, sources string
	ecosystem, name, version, qualifiers         string
}

func findingIdentity(f report.Finding) identity {
	if f.Kind == "dependency" {
		return identity{kind: f.Kind, image: f.ImageDigest, ecosystem: f.Package.Ecosystem, name: f.Package.Name, version: f.Package.Version, qualifiers: f.Package.Qualifiers}
	}
	return identity{kind: f.Kind, rule: f.RuleID, language: f.Language, origin: f.Origin, image: f.ImageDigest, sources: strings.Join(f.Sources, "\x00")}
}

type history struct {
	locations  map[report.Location]int
	advisories map[string]bool
	severity   int
}

func newHistory() *history {
	return &history{locations: make(map[report.Location]int), advisories: make(map[string]bool)}
}

func (h *history) add(f report.Finding) {
	for _, location := range locations(f) {
		h.locations[location] = max(h.locations[location], severityRank(f.Severity))
	}
	for _, id := range f.Advisories {
		h.advisories[id] = true
	}
	h.severity = max(h.severity, severityRank(f.Severity))
}

func (h *history) merge(old *history) {
	for location, severity := range old.locations {
		h.locations[location] = max(h.locations[location], severity)
	}
	for id := range old.advisories {
		h.advisories[id] = true
	}
	h.severity = max(h.severity, old.severity)
}

func growth(f report.Finding, old *history) []report.Finding {
	f.BaselineStatus = "expanded"
	if severityRank(f.Severity) > old.severity {
		return []report.Finding{f}
	}
	var newLocations []report.Location
	for _, location := range locations(f) {
		severity, known := old.locations[location]
		if f.Kind != "dependency" && known && severityRank(f.Severity) > severity {
			return []report.Finding{f}
		}
		if !known {
			newLocations = append(newLocations, location)
		}
	}
	if f.Kind != "dependency" {
		if len(newLocations) == 0 {
			return nil
		}
		return []report.Finding{atLocations(f, newLocations)}
	}
	var knownIDs, newIDs []string
	for _, id := range f.Advisories {
		if old.advisories[id] {
			knownIDs = append(knownIDs, id)
		} else {
			newIDs = append(newIDs, id)
		}
	}
	var result []report.Finding
	if len(newIDs) > 0 {
		part := f
		part.Advisories = newIDs
		result = append(result, part)
	}
	// Two rectangles preserve simultaneous growth without repeating old pairs.
	if len(newLocations) > 0 && len(knownIDs) > 0 {
		part := atLocations(f, newLocations)
		part.Advisories = knownIDs
		result = append(result, part)
	}
	return result
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

func normalize(input []report.Finding) ([]report.Finding, error) {
	for _, f := range input {
		if f.BaselineStatus != "" {
			return nil, errors.New("baseline requires unfiltered findings")
		}
	}
	ordered := slices.Clone(input)
	sortFindings(ordered)
	result := report.Normalize(ordered)
	if result == nil {
		result = []report.Finding{}
	}
	for _, f := range result {
		if err := validate(f); err != nil {
			return nil, err
		}
	}
	sortFindings(result)
	return result, nil
}

func sortFindings(findings []report.Finding) {
	// Struct fields and collections are canonical, so JSON supplies a complete
	// deterministic tie-breaker without changing any scanner fingerprint.
	type keyedFinding struct {
		finding report.Finding
		key     []byte
	}
	ordered := make([]keyedFinding, len(findings))
	for i, f := range findings {
		key, _ := json.Marshal(f) // Finding contains only JSON-supported field types.
		ordered[i] = keyedFinding{finding: f, key: key}
	}
	slices.SortFunc(ordered, func(a, b keyedFinding) int {
		return bytes.Compare(a.key, b.key)
	})
	for i, item := range ordered {
		findings[i] = item.finding
	}
}

func validate(f report.Finding) error {
	invalid := errors.New("invalid baseline finding")
	if !slices.Contains([]string{"code", "configuration", "dependency", "error", "secret"}, f.Kind) || !validIdentity(f.RuleID) || f.BaselineStatus != "" || len(f.Sources) == 0 || severityRank(f.Severity) < 0 {
		return invalid
	}
	for _, source := range f.Sources {
		if !validIdentity(source) {
			return invalid
		}
	}
	if f.Origin != "" && !validIdentity(f.Origin) || f.Language != "" && !validIdentity(f.Language) {
		return invalid
	}
	if f.Kind != "error" && f.Origin == "" {
		return invalid
	}
	if f.Origin == "git_history" {
		commit, err := hex.DecodeString(f.Commit)
		if err != nil || len(commit) != 20 && len(commit) != 32 || strings.ToLower(f.Commit) != f.Commit || f.Kind != "secret" {
			return invalid
		}
	} else if f.Commit != "" {
		return invalid
	}
	if len(f.Fingerprint) != 64 {
		return invalid
	}
	if _, err := hex.DecodeString(f.Fingerprint); err != nil {
		return invalid
	}
	if f.ImageDigest != "" {
		if !strings.HasPrefix(f.ImageDigest, "sha256:") || len(f.ImageDigest) != 71 {
			return invalid
		}
		if _, err := hex.DecodeString(f.ImageDigest[7:]); err != nil {
			return invalid
		}
	}
	if f.Kind == "dependency" {
		if f.Package == nil || !validIdentity(f.Package.Ecosystem) || !validIdentity(f.Package.Name) || !validIdentity(f.Package.Version) || len(f.Advisories) == 0 {
			return invalid
		}
		if f.Package.Qualifiers != "" && !validIdentity(f.Package.Qualifiers) {
			return invalid
		}
		for _, id := range f.Advisories {
			if !validIdentity(id) {
				return invalid
			}
		}
	} else if f.Package != nil || len(f.Advisories) != 0 {
		return invalid
	}
	if f.Kind != "error" && len(locations(f)) == 0 {
		return invalid
	}
	for _, location := range locations(f) {
		if !validLocation(location) {
			return invalid
		}
	}
	if f.Path != "" && !validLocation(report.Location{Path: f.Path, Line: f.Line, EndLine: f.EndLine}) {
		return invalid
	}
	if len(f.Locations) > 0 && (f.Path != f.Locations[0].Path || f.Line != f.Locations[0].Line || f.EndLine != f.Locations[0].EndLine) {
		return invalid
	}
	return nil
}

func validIdentity(value string) bool {
	return value != "" && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}

func validLocation(location report.Location) bool {
	p := location.Path
	return p != "" && p != "." && p != ".." && !strings.HasPrefix(p, "../") && !strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\:\x00\r\n") && path.Clean(p) == p && utf8.ValidString(p) && location.Line >= 1 && (location.EndLine == 0 || location.EndLine >= location.Line)
}

func severityRank(value string) int {
	switch value {
	case "", "unknown":
		return 0
	case "informational", "info":
		return 1
	case "low":
		return 2
	case "medium", "warning":
		return 3
	case "high", "error":
		return 4
	case "critical":
		return 5
	default:
		return -1
	}
}

// validJSON rejects duplicate object keys, excess nesting and noncanonical key
// spelling before encoding/json's permissive case-insensitive struct matching.
func validJSON(decoder *json.Decoder, depth int) bool {
	if depth > 16 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || seen[name] || !slices.Contains([]string{"schemaVersion", "fingerprintAlgorithm", "findings", "imageDigest", "package", "advisories", "locations", "kind", "ruleId", "message", "path", "line", "endLine", "fingerprint", "sources", "origin", "language", "severity", "qualifiers", "ecosystem", "name", "version", "purl", "commit"}, name) {
				return false
			}
			seen[name] = true
			if !validJSON(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case json.Delim('['):
		for decoder.More() {
			if !validJSON(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	}
	_, delimiter := token.(json.Delim)
	return !delimiter
}
