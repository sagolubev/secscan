package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/sagolubev/secscan/internal/report"
)

// TargetPath validates a scanner URI within its staged /target or /repo mount.
func TargetPath(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != "" || (parsed.Scheme != "" && parsed.Scheme != "file") {
		return "", fmt.Errorf("invalid scanner path")
	}
	value = parsed.Path
	if strings.ContainsAny(value, "\\\x00\r\n") {
		return "", fmt.Errorf("invalid scanner path")
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", fmt.Errorf("scanner path escapes target")
		}
	}
	for _, root := range []string{"/target/", "/repo/"} {
		value = strings.TrimPrefix(value, root)
	}
	value = path.Clean(value)
	if value == "." || strings.HasPrefix(value, "/") || strings.Contains(value, ":") {
		return "", fmt.Errorf("invalid scanner path")
	}
	return value, nil
}

// ParseSARIF accepts successful SARIF 2.1.0 runs and discards all free-form messages.
func ParseSARIF(data []byte, source, kind string) ([]report.Finding, error) {
	var input struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				Success       *bool `json:"executionSuccessful"`
				Notifications []struct {
					Level string `json:"level"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI  string `json:"uri"`
							Base string `json:"uriBaseId"`
						} `json:"artifactLocation"`
						Region struct {
							Start int `json:"startLine"`
							End   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("invalid SARIF JSON")
	}
	if input.Version != "2.1.0" || len(input.Runs) == 0 {
		return nil, fmt.Errorf("missing SARIF runs or unsupported version")
	}
	var findings []report.Finding
	for _, run := range input.Runs {
		if run.Tool.Driver.Name == "" || run.Results == nil {
			return nil, fmt.Errorf("incomplete SARIF run")
		}
		for _, invocation := range run.Invocations {
			if invocation.Success == nil || !*invocation.Success {
				return nil, fmt.Errorf("SARIF scanner execution failed")
			}
			for _, notification := range invocation.Notifications {
				if notification.Level == "error" {
					return nil, fmt.Errorf("SARIF scanner reported operational errors")
				}
			}
		}
		for _, result := range run.Results {
			if result.RuleID == "" || len(result.RuleID) > 512 || strings.ContainsAny(result.RuleID, "\r\n\x00") || len(result.Locations) == 0 {
				return nil, fmt.Errorf("invalid SARIF finding")
			}
			severity := "medium"
			switch result.Level {
			case "error":
				severity = "high"
			case "note", "none":
				severity = "low"
			case "warning", "":
			default:
				return nil, fmt.Errorf("invalid SARIF severity")
			}
			for _, location := range result.Locations {
				physical := location.Physical
				if physical.Artifact.Base != "" {
					return nil, fmt.Errorf("unsupported SARIF URI base")
				}
				file, err := TargetPath(physical.Artifact.URI)
				if err != nil {
					return nil, err
				}
				if physical.Region.Start < 1 || (physical.Region.End != 0 && physical.Region.End < physical.Region.Start) {
					return nil, fmt.Errorf("invalid SARIF line")
				}
				sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", source, result.RuleID, file, physical.Region.Start)))
				findings = append(findings, report.Finding{Kind: kind, RuleID: result.RuleID, Message: "scanner detected a potential security issue", Path: file, Line: physical.Region.Start, EndLine: physical.Region.End, Fingerprint: hex.EncodeToString(sum[:]), Sources: []string{source}, Origin: "working_tree", Severity: severity})
			}
		}
	}
	return findings, nil
}
