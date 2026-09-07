// START_MODULE_CONTRACT
// PURPOSE: Convert untrusted Gitleaks JSON into canonical findings.
// SCOPE: Preserve working-tree identities; validate history locations and ancestry; omit raw text and secrets.
// DEPENDS: internal/report/report.go
// LINKS: openspec/changes/build-secscan/trace.json, internal/gitleaks/parser_test.go#TestParseRedactsSecretMaterial, internal/gitleaks/parser_test.go#TestParseHistoryRejectsInvalidMetadata
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Parse - Decode findings and enforce repository-relative paths.
// END_MODULE_MAP

package gitleaks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sagolubev/secscan/internal/report"
)

type finding struct {
	StartLine int    `json:"StartLine"`
	File      string `json:"File"`
	RuleID    string `json:"RuleID"`
	Commit    string `json:"Commit"`
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

// parseHistory retains only validated locations and commits in the frozen ancestry.
func parseHistory(data []byte, commits map[string]struct{}) ([]report.Finding, error) {
	var input []finding
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) || json.Unmarshal(data, &input) != nil {
		return nil, fmt.Errorf("invalid Gitleaks history report")
	}
	result := make([]report.Finding, 0, len(input))
	for _, item := range input {
		filePath := strings.TrimPrefix(item.File, "/repo/")
		_, knownCommit := commits[item.Commit]
		if !validCommit(item.Commit) || !knownCommit || item.StartLine < 1 ||
			filePath == "" || filePath == "." || filePath == ".." || len(filePath) > 4096 ||
			strings.HasPrefix(filePath, "/") || strings.HasPrefix(filePath, "../") ||
			path.Clean(filePath) != filePath || strings.ContainsAny(filePath, "\\:") ||
			!utf8.ValidString(filePath) || strings.ContainsFunc(filePath, unicode.IsControl) ||
			item.RuleID == "" || len(item.RuleID) > 256 || strings.ContainsFunc(item.RuleID, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.')
		}) {
			return nil, fmt.Errorf("invalid Gitleaks history finding metadata")
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("git_history\x00%s\x00%s\x00%s\x00%d", item.Commit, item.RuleID, filePath, item.StartLine)))
		result = append(result, report.Finding{
			Kind: "secret", RuleID: item.RuleID, Message: "secret detected",
			Path: filePath, Line: item.StartLine, Fingerprint: hex.EncodeToString(sum[:]),
			Sources: []string{"gitleaks"}, Origin: "git_history", Commit: item.Commit,
		})
	}
	return result, nil
}

func validCommit(value string) bool {
	return (len(value) == 40 || len(value) == 64) && !strings.ContainsFunc(value, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f')
	})
}
