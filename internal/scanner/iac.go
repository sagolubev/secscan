package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/discovery"
	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
)

const terraformFrameworks = "terraform,terraform_json,terraform_plan"
const excludedFrameworks = terraformFrameworks + ",sca_package,sca_image,secrets,sast,sast_python,sast_java,sast_javascript,sast_typescript,sast_golang,3d_policy"

var checkovRule = regexp.MustCompile(`^CKV2?_[A-Z0-9]+_[0-9]+$`)
var kicsRule = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IaCArgs runs embedded policies only, offline, in a curated repository tree.
func IaCArgs(name, imageID, target, output string) []string {
	args := append(container.IsolatedArgs(target, "/repo"), "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--workdir", "/repo")
	if name == "kics" {
		args = append(args, "--ulimit", "fsize=67108864:67108864", "--mount", "type=bind,src="+output+",dst=/out", imageID)
		return append(args, "scan", "-p", "/repo", "--report-formats", "json", "-o", "/out", "--output-name", "result", "--disable-full-descriptions", "--no-progress", "--no-color", "--silent", "--ignore-on-exit", "results")
	}
	args = append(args, imageID, "--directory", "/repo", "--output", "json", "--skip-download", "--download-external-modules", "false", "--quiet", "--compact", "--soft-fail")
	if name == "checkov-terraform" {
		return append(args, "--framework", terraformFrameworks)
	}
	return append(args, "--skip-framework", excludedFrameworks)
}

// ParseIaC retains measured accounting and validated locations, never raw scanner text.
func ParseIaC(data []byte, name string) ([]report.Finding, report.Coverage, error) {
	var findings []report.Finding
	coverage := report.Coverage{Unit: "checks"}
	add := func(rule, severity, file string, line, end int) error {
		valid := checkovRule.MatchString(rule)
		if name == "kics" {
			valid = kicsRule.MatchString(rule)
		}
		if !valid || line < 1 || line > 1<<30 || end < 0 || (end != 0 && end < line) {
			return fmt.Errorf("invalid IaC finding")
		}
		severity = strings.ToLower(severity)
		switch severity {
		case "", "unknown":
			severity = "unknown"
		case "info":
			severity = "informational"
		case "informational", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid IaC severity")
		}
		var err error
		file, err = TargetPath(file)
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", name, rule, file, line)))
		findings = append(findings, report.Finding{Kind: "configuration", RuleID: rule, Severity: severity, Path: file, Line: line, EndLine: end, Message: "scanner detected a potential infrastructure security issue", Sources: []string{name}, Origin: "working_tree", Fingerprint: hex.EncodeToString(sum[:])})
		return nil
	}
	if name == "kics" {
		coverage.Unit = "files"
		var input struct {
			Scanned          *int `json:"files_scanned"`
			Parsed           *int `json:"files_parsed"`
			Failed           *int `json:"files_failed_to_scan"`
			QueriesFailed    *int `json:"queries_failed_to_execute"`
			SimilarityFailed *int `json:"queries_failed_to_compute_similarity_id"`
			Queries          []struct {
				ID       string `json:"query_id"`
				Severity string `json:"severity"`
				Files    []struct {
					Path string `json:"file_name"`
					Line int    `json:"line"`
				} `json:"files"`
			} `json:"queries"`
		}
		if json.Unmarshal(data, &input) != nil || input.Queries == nil || !validCounts(input.Scanned, input.Parsed, input.Failed, input.QueriesFailed, input.SimilarityFailed) || *input.Parsed > *input.Scanned {
			return nil, coverage, fmt.Errorf("invalid KICS JSON accounting")
		}
		coverage.Read = *input.Parsed
		coverage.Unread = *input.Scanned - *input.Parsed
		coverage.Failed = *input.Failed
		coverage.FailedQueries = *input.QueriesFailed + *input.SimilarityFailed
		for _, query := range input.Queries {
			if len(query.Files) == 0 {
				return nil, coverage, fmt.Errorf("missing KICS locations")
			}
			for _, file := range query.Files {
				if err := add(query.ID, query.Severity, file.Path, file.Line, 0); err != nil {
					return nil, coverage, err
				}
			}
		}
		return findings, coverage, nil
	}
	if name != "checkov" && name != "checkov-terraform" {
		return nil, coverage, fmt.Errorf("unsupported IaC scanner")
	}
	var envelopes []json.RawMessage
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '{' {
		envelopes = []json.RawMessage{trimmed}
	} else if json.Unmarshal(data, &envelopes) != nil {
		return nil, coverage, fmt.Errorf("invalid Checkov JSON")
	}
	if len(envelopes) == 0 {
		return nil, coverage, fmt.Errorf("missing Checkov envelope")
	}
	for _, envelope := range envelopes {
		var input struct {
			Type    string `json:"check_type"`
			Results *struct {
				Failed []struct {
					ID       string `json:"check_id"`
					Severity string `json:"severity"`
					Path     string `json:"file_path"`
					Lines    []int  `json:"file_line_range"`
				} `json:"failed_checks"`
			} `json:"results"`
			Summary struct {
				Passed        *int `json:"passed"`
				Failed        *int `json:"failed"`
				Skipped       *int `json:"skipped"`
				ParsingErrors *int `json:"parsing_errors"`
			} `json:"summary"`
		}
		if json.Unmarshal(envelope, &input) != nil || input.Type == "" || !validCounts(input.Summary.Passed, input.Summary.Failed, input.Summary.Skipped, input.Summary.ParsingErrors) {
			return nil, coverage, fmt.Errorf("invalid Checkov JSON accounting")
		}
		terraform := slices.Contains(strings.Split(terraformFrameworks, ","), input.Type)
		if name == "checkov-terraform" && !terraform || name == "checkov" && slices.Contains(strings.Split(excludedFrameworks, ","), input.Type) {
			return nil, coverage, fmt.Errorf("Checkov framework outside persona")
		}
		failed := 0
		if input.Results != nil {
			failed = len(input.Results.Failed)
		}
		if failed != *input.Summary.Failed {
			return nil, coverage, fmt.Errorf("inconsistent Checkov findings")
		}
		coverage.Read += *input.Summary.Passed + *input.Summary.Failed
		coverage.FailedFiles += *input.Summary.ParsingErrors
		coverage.Skipped += *input.Summary.Skipped
		if input.Results == nil {
			continue
		}
		for _, item := range input.Results.Failed {
			if len(item.Lines) != 2 {
				return nil, coverage, fmt.Errorf("missing Checkov location")
			}
			// Terraform plan checks have no source line; anchor the plan file itself.
			if input.Type == "terraform_plan" && item.Lines[0] == 0 && item.Lines[1] == 0 {
				item.Lines = []int{1, 1}
			}
			// Checkov file_path is root-relative with a leading slash, not a host path.
			if err := add(item.ID, item.Severity, strings.TrimPrefix(item.Path, "/"), item.Lines[0], item.Lines[1]); err != nil {
				return nil, coverage, err
			}
		}
	}
	return findings, coverage, nil
}

func validCounts(values ...*int) bool {
	for _, value := range values {
		if value == nil || *value < 0 || *value > 1<<30 {
			return false
		}
	}
	return true
}

// ScanIaC runs a prepared engine against selected files, then verifies finding membership.
func ScanIaC(ctx context.Context, runtime container.Runtime, cache Cache, name, root string, files []string, emit func(progress.Event)) (report.Scanner, []report.Finding, error) {
	emit(progress.Event{Scanner: name, Stage: progress.StagePreparing, Status: progress.StatusRunning, Files: len(files)})
	asset, err := cache.Resolve(ctx, runtime, name)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	target, err := discovery.Stage(root, files)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	defer os.RemoveAll(target)
	var paths map[string]string
	if name == "checkov-terraform" || name == "kics" {
		paths, err = stageOpenTofu(target, files)
		if err != nil {
			return report.Scanner{}, nil, err
		}
	}
	output, err := os.MkdirTemp(filepath.Dir(target), "iac-output-")
	if err != nil {
		return report.Scanner{}, nil, err
	}
	defer os.RemoveAll(output)
	emit(progress.Event{Scanner: name, Stage: progress.StageScanning, Status: progress.StatusRunning, Files: len(files)})
	data, err := runtime.Output(ctx, IaCArgs(name, asset.ImageID, target, output)...)
	if err != nil {
		return report.Scanner{}, nil, fmt.Errorf("IaC scanner execution failed: %w", err)
	}
	if name == "kics" {
		file := filepath.Join(output, "result.json")
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return report.Scanner{}, nil, fmt.Errorf("missing or oversized KICS report")
		}
		input, err := os.Open(file)
		if err != nil {
			return report.Scanner{}, nil, err
		}
		data, err = io.ReadAll(io.LimitReader(input, (64<<20)+1))
		closeErr := input.Close()
		if err != nil || closeErr != nil || len(data) > 64<<20 {
			return report.Scanner{}, nil, fmt.Errorf("read KICS report failed")
		}
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageReading, Status: progress.StatusRunning, Files: len(files)})
	findings, coverage, err := ParseIaC(data, name)
	if err != nil {
		return report.Scanner{}, nil, err
	}
	for i := range findings {
		finding := &findings[i]
		if original, ok := paths[finding.Path]; ok {
			finding.Path = original
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", name, finding.RuleID, original, finding.Line)))
			finding.Fingerprint = hex.EncodeToString(sum[:])
		}
		if !slices.Contains(files, finding.Path) {
			return report.Scanner{}, nil, fmt.Errorf("IaC finding outside staged inventory")
		}
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageNormalizing, Status: progress.StatusRunning, Files: len(files)})
	result := report.Scanner{Name: name, Status: "success", Image: asset.ImageID, EngineVersion: Catalog()[name].Version, Coverage: coverage, Limitations: []string{"repository scanner configuration and custom policies excluded", "external modules and policy downloads disabled", "only Git-selected Terraform, JSON, YAML and Dockerfile candidates staged; unsupported candidates may remain unread"}}
	if name == "kics" || name == "checkov-terraform" {
		result.Limitations = append(result.Limitations, "OpenTofu suffixes are adapted to Terraform in staging; competing same-stem definitions are rejected")
	}
	if name != "kics" {
		result.Limitations = append(result.Limitations, "coverage counts evaluated checks, not files; native skipped checks are counted separately", "OSS checks without severity remain unknown", "Terraform plan checks without source lines are anchored at line 1")
	}
	if coverage.Read == 0 {
		return report.Scanner{}, nil, fmt.Errorf("IaC scanner did not evaluate selected inputs")
	}
	emit(progress.Event{Scanner: name, Stage: progress.StageDone, Status: progress.StatusSuccess, Files: len(files), Findings: len(findings)})
	return result, findings, nil
}

// stageOpenTofu adapts suffixes for Checkov without changing source content.
// Ambiguous dual definitions fail instead of guessing Terraform/OpenTofu precedence.
func stageOpenTofu(target string, files []string) (map[string]string, error) {
	paths := make(map[string]string)
	for _, file := range files {
		alias := file
		if strings.HasSuffix(file, ".tofu") {
			alias = strings.TrimSuffix(file, ".tofu") + ".tf"
		}
		if strings.HasSuffix(file, ".tofu.json") {
			alias = strings.TrimSuffix(file, ".tofu.json") + ".tf.json"
		}
		if alias == file {
			continue
		}
		if _, err := os.Lstat(filepath.Join(target, alias)); !os.IsNotExist(err) {
			return nil, fmt.Errorf("competing Terraform and OpenTofu definitions")
		}
		if err := os.Rename(filepath.Join(target, file), filepath.Join(target, alias)); err != nil {
			return nil, err
		}
		paths[alias] = file
	}
	return paths, nil
}
