// START_MODULE_CONTRACT
// PURPOSE: Convert untrusted Gitleaks JSON into canonical findings.
// SCOPE: Reject paths outside the repository; omit Secret and Match fields.
// DEPENDS: internal/report/report.go
// LINKS: openspec/changes/build-secscan/trace.json, internal/gitleaks/parser_test.go#TestParseRedactsSecretMaterial, internal/gitleaks/parser_test.go#TestParseRejectsPathOutsideRepository
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Parse - Decode findings and enforce repository-relative paths.
// END_MODULE_MAP

package gitleaks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/sagolubev/secscan/internal/report"
)

type finding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
}

// START_CONTRACT: Parse
// PURPOSE: Keep raw scanner content behind the adapter boundary.
// INPUTS: data: []byte - Untrusted Gitleaks JSON.
// OUTPUTS: Canonical findings or error; secret values and snippets are omitted.
// SIDE_EFFECTS: none
// LINKS: internal/gitleaks/parser_test.go#TestParseRedactsSecretMaterial
// END_CONTRACT: Parse

// Parse converts Gitleaks JSON into sanitized repository findings.
func Parse(data []byte) ([]report.Finding, error) {
	var input []finding
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("decode Gitleaks report: %w", err)
	}

	result := make([]report.Finding, 0, len(input))
	for _, item := range input {
		rawPath := strings.ReplaceAll(item.File, "\\", "/")
		if strings.HasPrefix(rawPath, "/repo/") {
			rawPath = strings.TrimPrefix(rawPath, "/repo/")
		}
		filePath := path.Clean(rawPath)
		if filePath == "." || filePath == ".." || strings.HasPrefix(filePath, "../") ||
			strings.HasPrefix(filePath, "/") {
			return nil, fmt.Errorf("Gitleaks report contains path outside repository")
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", item.RuleID, filePath, item.StartLine)))
		result = append(result, report.Finding{
			Kind:        "secret",
			RuleID:      item.RuleID,
			Message:     "secret detected",
			Path:        filePath,
			Line:        item.StartLine,
			Fingerprint: hex.EncodeToString(sum[:]),
			Sources:     []string{"gitleaks"},
			Origin:      "working_tree",
		})
	}
	return result, nil
}
