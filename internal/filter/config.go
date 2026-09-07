// FILE: internal/filter/config.go
// START_MODULE_CONTRACT
// PURPOSE: Decode declarative project policy at the untrusted TOML boundary.
// SCOPE: Bounded strict schema; errors never echo input values or reasons.
// DEPENDS: none
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-filtering-and-suppressions, internal/filter/filter_test.go#TestParseBoundary
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// MaxConfigBytes - Bound project configuration bytes.
// Config - Hold versioned visible-report policy.
// Rule - Intersect suppression selectors.
// Parse - Decode and validate strict TOML.
// ValidSeverity - Check a severity floor, including the unset default.
// END_MODULE_MAP

// Package filter applies declarative policy to the visible report.
package filter

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

// MaxConfigBytes bounds project configuration before parsing.
const MaxConfigBytes = 1 << 20

// Config holds versioned policy for visible findings.
type Config struct {
	Version      int      `toml:"version"`
	MinSeverity  string   `toml:"min_severity"`
	TestPaths    []string `toml:"test_paths"`
	Suppressions []Rule   `toml:"suppressions"`
}

// Rule suppresses the intersection of its nonempty selectors.
// Reason is for source review and is never serialized in report output.
type Rule struct {
	ID          string `toml:"id"`
	Reason      string `toml:"reason" json:"-"`
	Kind        string `toml:"kind"`
	RuleID      string `toml:"rule"`
	Fingerprint string `toml:"fingerprint"`
	Path        string `toml:"path"`
	Advisory    string `toml:"advisory"`
}

// Parse decodes strict version 1 TOML without quoting untrusted data in errors.
func Parse(data []byte) (Config, error) {
	if len(data) > MaxConfigBytes || !utf8.Valid(data) {
		return Config{}, errors.New("invalid project configuration encoding or size")
	}
	var cfg Config
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&cfg); err != nil {
		return Config{}, errors.New("invalid project configuration TOML schema")
	}
	// go-toml's strict struct matching still folds key case. A map preserves
	// spelling so aliases cannot silently replace a reviewed setting.
	var fields map[string]any
	if err := toml.Unmarshal(data, &fields); err != nil || !validKeys(fields, []string{"version", "min_severity", "test_paths", "suppressions"}) {
		return Config{}, errors.New("invalid project configuration keys")
	}
	if rules, ok := fields["suppressions"].([]any); ok {
		for _, rule := range rules {
			fields, ok := rule.(map[string]any)
			if !ok || !validKeys(fields, []string{"id", "reason", "kind", "rule", "fingerprint", "path", "advisory"}) {
				return Config{}, errors.New("invalid project suppression keys")
			}
		}
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ValidSeverity accepts supported severity floors and an empty unset value.
func ValidSeverity(value string) bool { return severityRank(value) >= 0 }

func validKeys(fields map[string]any, allowed []string) bool {
	for key := range fields {
		if !slices.Contains(allowed, key) {
			return false
		}
	}
	return true
}

func validateConfig(cfg Config) error {
	if cfg.Version != 1 || !ValidSeverity(cfg.MinSeverity) || len(cfg.Suppressions) > 256 {
		return errors.New("invalid project configuration version, severity or rule count")
	}
	for _, pattern := range cfg.TestPaths {
		if !validPattern(pattern) {
			return errors.New("invalid project test path pattern")
		}
	}
	ids := make(map[string]struct{}, len(cfg.Suppressions))
	for _, rule := range cfg.Suppressions {
		if !validRuleID(rule.ID) || strings.TrimSpace(rule.Reason) == "" || len(rule.Reason) > 1024 || !utf8.ValidString(rule.Reason) {
			return errors.New("invalid project suppression id or reason")
		}
		if _, exists := ids[rule.ID]; exists {
			return errors.New("duplicate project suppression id")
		}
		ids[rule.ID] = struct{}{}
		if rule.Kind == "" && rule.RuleID == "" && rule.Fingerprint == "" && rule.Path == "" && rule.Advisory == "" {
			return errors.New("project suppression requires a selector")
		}
		if rule.Kind != "" && !slices.Contains([]string{"code", "configuration", "dependency", "error", "secret"}, rule.Kind) {
			return errors.New("invalid project suppression kind")
		}
		if rule.Path != "" && !validPattern(rule.Path) {
			return errors.New("invalid project suppression path pattern")
		}
		for _, selector := range []string{rule.RuleID, rule.Advisory} {
			if len(selector) > 4096 || !utf8.ValidString(selector) || strings.ContainsFunc(selector, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
				return errors.New("invalid project suppression selector")
			}
		}
		if rule.Fingerprint != "" {
			if _, err := hex.DecodeString(rule.Fingerprint); err != nil || len(rule.Fingerprint) != 64 {
				return errors.New("invalid project suppression fingerprint")
			}
		}
	}
	return nil
}

func validRuleID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validPattern(pattern string) bool {
	if pattern == "" || len(pattern) > 4096 || !utf8.ValidString(pattern) || strings.ContainsAny(pattern, "\\:") || strings.Contains(pattern, "**") || strings.ContainsFunc(pattern, unicode.IsControl) {
		return false
	}
	p := strings.TrimSuffix(pattern, "/")
	if p == "." || p == ".." || strings.HasPrefix(p, "../") || path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	if strings.HasSuffix(pattern, "/") && strings.ContainsAny(p, "*?[") {
		return false
	}
	_, err := path.Match(p, "")
	return err == nil
}

func severityRank(value string) int {
	switch value {
	case "", "unknown":
		return 0
	case "info", "informational":
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
