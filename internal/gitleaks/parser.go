package gitleaks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/sigiuscom/secscan/internal/report"
)

type finding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
}

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
