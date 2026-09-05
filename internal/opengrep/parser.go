package opengrep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/sigiuscom/secscan/internal/report"
)

type scanResult struct {
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
	Version  string
	Findings []report.Finding
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

func Parse(data []byte, language string) (Parsed, error) {
	var input scanResult
	if err := json.Unmarshal(data, &input); err != nil {
		return Parsed{}, fmt.Errorf("decode Opengrep report: %w", err)
	}
	if len(input.Errors) > 0 {
		return Parsed{}, fmt.Errorf("Opengrep reported %d errors", len(input.Errors))
	}

	result := Parsed{Version: input.Version}
	for _, item := range input.Results {
		ruleID := normalizeRuleID(item.CheckID)
		message, ok := ruleMessages[ruleID]
		if !ok {
			return Parsed{}, fmt.Errorf("unknown Opengrep rule %q", ruleID)
		}
		filePath, err := normalizeTargetPath(item.Path)
		if err != nil {
			return Parsed{}, err
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf(
			"%s\x00%s\x00%s\x00%d\x00%d",
			ruleID,
			language,
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
			Language:    language,
			Severity:    strings.ToLower(item.Extra.Severity),
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
