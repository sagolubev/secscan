// START_MODULE_CONTRACT
// PURPOSE: Normalize only registered findings and discard dynamic scanner text.
// SCOPE: Validate paths, rule languages and locations; preserve built-in fingerprints.
// DEPENDS: internal/rules/pack.go, internal/report/report.go
// LINKS: internal/opengrep/rules_test.go#TestCustomRuleParserUsesRegisteredMetadata
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Parsed - Sanitized findings and positive input evidence.
// Parse - Normalize the built-in rule set.
// ParseWithRules - Normalize explicitly registered custom rules without copying messages.
// END_MODULE_MAP

package opengrep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/report"
	"github.com/sagolubev/secscan/internal/rules"
)

type scanResult struct {
	Paths struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
	Version string `json:"version"`
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Severity string `json:"severity"`
		} `json:"extra"`
	} `json:"results"`
	Errors []json.RawMessage `json:"errors"`
}

type Parsed struct {
	ReadInputs []string
	Version    string
	Findings   []report.Finding
}

var ruleMessages = map[string]string{
	"secscan.python.dynamic-code-execution":    "dynamic code execution",
	"secscan.python.subprocess-shell":          "shell-enabled subprocess execution",
	"secscan.python.unsafe-yaml-load":          "unsafe YAML loading",
	"secscan.typescript.dynamic-eval":          "dynamic code execution",
	"secscan.typescript.child-process-exec":    "interpolated shell command execution",
	"secscan.typescript.inner-html":            "dynamic HTML assignment",
	"secscan.typescript.insecure-tls":          "TLS certificate verification disabled",
	"secscan.typescript.weak-token-randomness": "weak randomness for security token",
}

// Parse normalizes the shared rule pack. An empty language derives it from the rule.
func Parse(data []byte, language string) (Parsed, error) {
	return ParseWithRules(data, language, nil)
}

// ParseWithRules recognizes only registered IDs and discards all dynamic messages.
func ParseWithRules(data []byte, language string, pack *rules.Pack) (Parsed, error) {
	custom := map[string]rules.Rule{}
	packID := ""
	if pack != nil {
		packID = pack.Metadata().ID
		if !rules.ValidID(packID) {
			return Parsed{}, fmt.Errorf("invalid custom rule pack")
		}
		for _, rule := range pack.Rules(language) {
			custom[rule.ID] = rule
		}
	}
	var input scanResult
	if err := json.Unmarshal(data, &input); err != nil {
		return Parsed{}, fmt.Errorf("decode Opengrep report: %w", err)
	}
	if len(input.Errors) > 0 {
		return Parsed{}, fmt.Errorf("Opengrep reported %d errors", len(input.Errors))
	}

	result := Parsed{Version: input.Version}
	for _, path := range input.Paths.Scanned {
		normalized, err := normalizeTargetPath(path)
		if err != nil {
			return Parsed{}, err
		}
		result.ReadInputs = append(result.ReadInputs, normalized)
	}
	slices.Sort(result.ReadInputs)
	result.ReadInputs = slices.Compact(result.ReadInputs)
	for _, item := range input.Results {
		ruleID := normalizeRuleID(item.CheckID)
		message, ok := ruleMessages[ruleID]
		filePath, err := normalizeTargetPath(item.Path)
		if err != nil {
			return Parsed{}, err
		}
		findingLanguage := language
		severity := strings.ToLower(item.Extra.Severity)
		if rule, exists := custom[item.CheckID]; exists {
			if !rule.MatchesPath(filePath) {
				return Parsed{}, fmt.Errorf("custom rule finding has an incompatible source path")
			}
			ruleID = "secscan.custom." + packID + "." + rule.ID
			message = "custom rule matched"
			severity = rule.Severity
			findingLanguage = discovery.SourceLanguage(filePath)
		} else if !ok {
			return Parsed{}, fmt.Errorf("unknown Opengrep rule")
		} else if findingLanguage == "" {
			findingLanguage = strings.Split(ruleID, ".")[1]
		}
		if item.Start.Line < 1 || item.End.Line < item.Start.Line {
			return Parsed{}, fmt.Errorf("invalid Opengrep finding location")
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf(
			"%s\x00%s\x00%s\x00%d\x00%d",
			ruleID,
			findingLanguage,
			filePath,
			item.Start.Line,
			item.End.Line,
		)))
		result.Findings = append(result.Findings, report.Finding{
			Kind:        "code",
			RuleID:      ruleID,
			Message:     message,
			Path:        filePath,
			Line:        item.Start.Line,
			EndLine:     item.End.Line,
			Fingerprint: hex.EncodeToString(sum[:]),
			Sources:     []string{"opengrep"},
			Origin:      "working_tree",
			Language:    findingLanguage,
			Severity:    severity,
		})
	}
	return result, nil
}

func normalizeRuleID(value string) string {
	if index := strings.Index(value, "secscan."); index >= 0 {
		return value[index:]
	}
	return value
}

func normalizeTargetPath(value string) (string, error) {
	value = strings.ReplaceAll(value, "\\", "/")
	if strings.HasPrefix(value, "/target/") {
		value = strings.TrimPrefix(value, "/target/")
	}
	value = path.Clean(value)
	if value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("Opengrep report contains path outside target")
	}
	return value, nil
}
