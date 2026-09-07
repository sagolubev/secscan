// START_MODULE_CONTRACT
// PURPOSE: Verify project policy loading, visible filtering and complete exports.
// SCOPE: Synthetic configs and canaries; scanner fixtures are data, never executed.
// DEPENDS: cmd/secscan/config.go, internal/filter/filter.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-filtering-and-suppressions
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestRunProjectFilteringKeepsFullExports - Preserve exemptions, ordering and full SARIF.
// TestConfigValidationPrecedesScan - Reject invalid policy before scanner execution.
// TestProjectConfigFileBoundary - Bound file reads and reject symlinks/non-regular inputs.
// TestProjectFilterDoesNotFilterSnapshot - Keep snapshots full and apply CLI floor overrides.
// TestRunPartialDependencySuppression - Preserve surviving pairs through JSON serialization.
// TestAcceptanceProjectConfig - Exercise real scanners with an excluded config canary.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func TestRunProjectFilteringKeepsFullExports(t *testing.T) {
	root, out := exportTestRepository(t), t.TempDir()
	var findings []report.Finding
	for i := 0; i < 6; i++ {
		f := baselineCode("app.py", i+1)
		f.Fingerprint = strings.Repeat(string(rune('a'+i)), 64)
		findings = append(findings, f)
	}
	findings[2].Severity = "low"
	findings[3].Path = "fixtures/example.py"
	findings[4].Kind = "secret"
	findings[4].Severity = "low"
	findings[5].Kind = "error"
	data, err := baseline.Encode(findings[:2])
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(root, "baseline.json")
	if err := os.WriteFile(snapshot, data, 0600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("version = 1\nmin_severity = 'high'\ntest_paths = ['fixtures/']\n[[suppressions]]\nid = 'fixture'\nreason = 'SYNTHETIC_CONFIG_REASON_CANARY'\nfingerprint = '%s'\n", findings[0].Fingerprint)
	if err := os.WriteFile(filepath.Join(root, ".secscan.toml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	fake := func(_ context.Context, _ string, options scanOptions, _ func(progress.Event)) (report.Report, error) {
		if !slices.Contains(options.Excluded, ".secscan.toml") {
			t.Fatalf("config not excluded: %v", options.Excluded)
		}
		return report.Report{SchemaVersion: "1", Repository: root, Findings: findings, Scanners: []report.Scanner{{Name: "python-sast", Status: "success"}}}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--baseline", snapshot, "--html", filepath.Join(out, "report.html"), "--sarif", filepath.Join(out, "report.sarif"), root}, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("filtered scan exit=%d stderr=%s", code, &stderr)
	}
	var result struct {
		Findings  []report.Finding
		Filtering struct {
			InputFindings, OutputFragments int
			Stages                         []struct {
				Name     string
				Findings int
			}
		}
		Baseline report.BaselineSummary
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 || result.Filtering.InputFindings != 6 || result.Filtering.OutputFragments != 2 || result.Baseline.Unchanged != 1 || result.Baseline.InputFindings != 5 {
		t.Fatalf("filter accounting=%s", &stdout)
	}
	counts := map[string]int{}
	for _, stage := range result.Filtering.Stages {
		counts[stage.Name] += stage.Findings
	}
	for _, name := range []string{"project", "baseline", "severity", "test-data"} {
		if counts[name] != 1 {
			t.Errorf("%s removed=%d, want1", name, counts[name])
		}
	}
	for _, finding := range result.Findings {
		if finding.Kind != "secret" && finding.Kind != "error" {
			t.Errorf("unexpected visible finding: %+v", finding)
		}
	}
	sarif, err := os.ReadFile(filepath.Join(out, "report.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Runs []struct{ Results []json.RawMessage }
	}
	if err := json.Unmarshal(sarif, &document); err != nil || len(document.Runs[0].Results) != 6 {
		t.Fatalf("full SARIF=%s error=%v", sarif, err)
	}
	html, err := os.ReadFile(filepath.Join(out, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stdout.Bytes(), []byte("SYNTHETIC_CONFIG_REASON_CANARY")) || bytes.Contains(html, []byte("SYNTHETIC_CONFIG_REASON_CANARY")) || bytes.Contains(html, []byte("fixtures/example.py")) {
		t.Fatal("config reason or filtered finding leaked into visible output")
	}
}

func TestConfigValidationPrecedesScan(t *testing.T) {
	root := exportTestRepository(t)
	file := filepath.Join(root, ".secscan.toml")
	if err := os.WriteFile(file, []byte("version=1\nunknown_key='SYNTHETIC_CONFIG_DATA_CANARY'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		t.Fatal("invalid config started scan")
		return report.Report{}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{root}, &stdout, &stderr, fake); code != 1 || stdout.Len() != 0 || strings.Contains(stderr.String(), "SYNTHETIC_CONFIG_DATA_CANARY") {
		t.Fatalf("config rejection exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	for _, args := range [][]string{{"--config", file, "--no-config", root}, {"--min-severity", "fatal", root}, {"--config", "", root}, {"update", "--no-config", root}} {
		if code := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}, fake); code != 2 {
			t.Errorf("args=%v exit=%d, want2", args, code)
		}
	}
	stdout.Reset()
	stderr.Reset()
	safe := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1"}, nil
	}
	if code := run(context.Background(), []string{"--no-config", root}, &stdout, &stderr, safe); code != 0 {
		t.Fatalf("no-config exit=%d stderr=%s", code, &stderr)
	}
}

func TestProjectConfigFileBoundary(t *testing.T) {
	root := exportTestRepository(t)
	missing, err := prepareProjectConfig(root, "", false)
	if err != nil || missing.active || len(missing.excluded) != 0 {
		t.Fatalf("missing default=%+v error=%v", missing, err)
	}
	if _, err := prepareProjectConfig(root, filepath.Join(root, "missing.toml"), false); err == nil {
		t.Fatal("accepted missing explicit config")
	}
	file := filepath.Join(root, "valid.toml")
	if err := os.WriteFile(file, []byte("version=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.toml")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, root} {
		if _, err := prepareProjectConfig(root, path, false); err == nil {
			t.Errorf("accepted non-regular config %s", path)
		}
	}
	if err := os.WriteFile(file, bytes.Repeat([]byte(" "), (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareProjectConfig(root, file, false); err == nil {
		t.Fatal("accepted oversized config")
	}
}

func TestProjectFilterDoesNotFilterSnapshot(t *testing.T) {
	root := exportTestRepository(t)
	config := filepath.Join(root, ".secscan.toml")
	if err := os.WriteFile(config, []byte("version=1\nmin_severity='critical'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1", Repository: root, Findings: []report.Finding{baselineCode("app.py", 1)}}, nil
	}
	snapshot := filepath.Join(t.TempDir(), "baseline.json")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--write-baseline", snapshot, root}, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("write filtered scan exit=%d stderr=%s", code, &stderr)
	}
	var view report.Report
	if err := json.Unmarshal(stdout.Bytes(), &view); err != nil || len(view.Findings) != 0 {
		t.Fatalf("visible=%s error=%v", &stdout, err)
	}
	data, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var full struct{ Findings []report.Finding }
	if err := json.Unmarshal(data, &full); err != nil || len(full.Findings) != 1 {
		t.Fatalf("snapshot was filtered: %s %v", data, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--min-severity", "low", root}, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("override exit=%d stderr=%s", code, &stderr)
	}
	if err := json.Unmarshal(stdout.Bytes(), &view); err != nil || len(view.Findings) != 1 {
		t.Fatalf("CLI did not override configured floor: %s %v", &stdout, err)
	}
}

func TestRunPartialDependencySuppression(t *testing.T) {
	root := exportTestRepository(t)
	finding := report.Normalize([]report.Finding{{Kind: "dependency", Package: &report.Package{Ecosystem: "npm", Name: "library", Version: "1"}, Advisories: []string{"CVE-2026-1", "CVE-2026-2"}, Locations: []report.Location{{Path: "a/lock.json", Line: 1}, {Path: "b/lock.json", Line: 1}}, Sources: []string{"trivy"}, Severity: "high"}})[0]
	config := "version=1\n[[suppressions]]\nid='one-occurrence'\nreason='reviewed fixture'\npath='a/lock.json'\nadvisory='CVE-2026-1'\n"
	if err := os.WriteFile(filepath.Join(root, ".secscan.toml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1", Repository: root, Findings: []report.Finding{finding}}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{root}, &stdout, &stderr, fake); code != 0 {
		t.Fatalf("partial filter exit=%d stderr=%s", code, &stderr)
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	var pairs []string
	for _, f := range result.Findings {
		if f.Fingerprint != finding.Fingerprint {
			t.Error("filtered fingerprint changed")
		}
		for _, a := range f.Advisories {
			for _, l := range f.Locations {
				pairs = append(pairs, a+"@"+l.Path)
			}
		}
	}
	slices.Sort(pairs)
	want := []string{"CVE-2026-1@b/lock.json", "CVE-2026-2@a/lock.json", "CVE-2026-2@b/lock.json"}
	if !slices.Equal(pairs, want) {
		t.Fatalf("visible pairs=%v, want %v", pairs, want)
	}
}

func TestAcceptanceProjectConfig(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for real project filtering")
	}
	root := exportTestRepository(t)
	if err := os.Mkdir(filepath.Join(root, "fixtures"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"app.py", "fixtures/example.py"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("eval(user_input)\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	canary := strings.Join([]string{"gl", "pat-", "0123456789", "AbCdEfGhIj"}, "")
	config := "version=1\n[[suppressions]]\nid='fixture'\nreason='token=" + canary + "'\npath='fixtures/'\n"
	if err := os.WriteFile(filepath.Join(root, ".secscan.toml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	selection := "python-sast,gitleaks"
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", selection, root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("update exit=%d stderr=%s", code, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	out := filepath.Join(t.TempDir(), "report.sarif")
	if code := run(context.Background(), []string{"--scanners", selection, "--sarif", out, root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("scan exit=%d stderr=%s", code, &stderr)
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || len(result.Findings) != 1 || result.Findings[0].Path != "app.py" || len(result.Inventory.Omitted) != 1 {
		t.Fatalf("native filter result=%s error=%v", &stdout, err)
	}
	if bytes.Contains(stdout.Bytes(), []byte(canary)) || strings.Contains(stderr.String(), canary) {
		t.Fatal("config canary leaked")
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var sarif struct {
		Runs []struct{ Results []json.RawMessage }
	}
	if err := json.Unmarshal(data, &sarif); err != nil || len(sarif.Runs[0].Results) != 2 || bytes.Contains(data, []byte(canary)) {
		t.Fatalf("unfiltered SARIF=%s error=%v", data, err)
	}
}
