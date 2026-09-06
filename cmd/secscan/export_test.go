package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func TestTrivyReportsRejectUnconfirmedInventory(t *testing.T) {
	root := t.TempDir()
	if err := exec.Command("git", "-C", root, "init", "--quiet").Run(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "reports")
	fake := func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1", Repository: root, Scanners: []report.Scanner{
			{Name: "trivy", Status: "skipped", Coverage: report.Coverage{Unit: "files"}},
			{Name: "gitleaks", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "repository"}},
		}}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--trivy-reports", destination, "--progress", "off", root}, &stdout, &stderr, fake)
	if code != 1 || !json.Valid(stdout.Bytes()) {
		t.Fatalf("run(unconfirmed Trivy) exit=%d stdout=%q stderr=%q, want exit1 with canonical JSON", code, &stdout, &stderr)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("unconfirmed export created destination: %v", err)
	}
}

func TestTrivyReportsWriteBothFilesAndKeepStdoutCanonical(t *testing.T) {
	root := exportTestRepository(t)
	destination := filepath.Join(t.TempDir(), "reports")
	payload := &report.TrivyReports{CycloneDX: []byte(`{"bomFormat":"CycloneDX","components":[]}`), SonarQube: []byte(`{"rules":[],"issues":[]}`)}
	fake := func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1", Repository: root, Scanners: []report.Scanner{{Name: "trivy", Status: "success", Coverage: report.Coverage{Read: 2, Unit: "packages", ReadInputs: []string{"package-lock.json"}}, TrivyReports: payload}}}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--trivy-reports", destination, "--scanners", "trivy", "--progress", "off", root}, &stdout, &stderr, fake)
	if code != 0 {
		t.Fatalf("export exit=%d stderr=%s, want0", code, &stderr)
	}
	if !json.Valid(stdout.Bytes()) || bytes.Count(stdout.Bytes(), []byte("\n")) != 1 || bytes.Contains(stdout.Bytes(), []byte("bomFormat")) {
		t.Fatalf("export changed canonical stdout: %s", &stdout)
	}
	for name, want := range map[string][]byte{"trivy.cdx.json": payload.CycloneDX, "trivy.sonarqube.json": payload.SonarQube} {
		data, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, want) {
			t.Errorf("%s=%s, want%s", name, data, want)
		}
		info, err := os.Stat(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("%s mode=%o,want600", name, info.Mode().Perm())
		}
	}
}

func TestTrivyReportsUsageAndDestinationConflicts(t *testing.T) {
	root := exportTestRepository(t)
	parent := t.TempDir()
	existing := filepath.Join(parent, "existing")
	if err := os.WriteFile(existing, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "repository-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"update", "--trivy-reports", filepath.Join(parent, "new"), root},
		{"--scanners", "gitleaks", "--trivy-reports", filepath.Join(parent, "new"), root},
		{"--trivy-reports", "", root},
		{"--trivy-reports", existing, root},
		{"--trivy-reports", filepath.Join(root, "reports"), root},
		{"--trivy-reports", filepath.Join(alias, "reports"), root},
	} {
		var stdout, stderr bytes.Buffer
		fake := func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
			t.Fatal("invalid request started scanner")
			return report.Report{}, nil
		}
		if code := run(context.Background(), args, &stdout, &stderr, fake); code != 2 || stdout.Len() != 0 {
			t.Errorf("run(%v) exit=%d stdout=%s stderr=%s,want2,noJSON", args, code, &stdout, &stderr)
		}
	}
	data, err := os.ReadFile(existing)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("existing output overwritten: %s %v", data, err)
	}
}

func TestTrivyReportsRefusePartialCoverage(t *testing.T) {
	root := exportTestRepository(t)
	for _, coverage := range []report.Coverage{
		{Read: 1, Unit: "packages", Unread: 1},
		{Read: 1, Unit: "packages", UnreadInputs: []string{"pom.xml"}},
		{Read: 1, Unit: "packages", Failed: 1},
		{Read: 1, Unit: "packages", FailedInputs: []string{"requirements.txt"}},
		{Unit: "packages"},
	} {
		destination := filepath.Join(t.TempDir(), "reports")
		fake := func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
			return report.Report{SchemaVersion: "1", Repository: root, Scanners: []report.Scanner{{Name: "trivy", Status: "success", Coverage: coverage, TrivyReports: &report.TrivyReports{CycloneDX: []byte(`{}`), SonarQube: []byte(`{}`)}}}}, nil
		}
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{"--trivy-reports", destination, root}, &stdout, &stderr, fake); code != 1 || !json.Valid(stdout.Bytes()) {
			t.Errorf("partial coverage=%+v exit=%d stdout=%s,want1withJSON", coverage, code, &stdout)
		}
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			t.Errorf("partial export created output: %v", err)
		}
	}
}

func exportTestRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := exec.Command("git", "-C", root, "init", "--quiet").Run(); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestTrivyReportsCancellationAndLateConflict(t *testing.T) {
	root := exportTestRepository(t)
	for _, mode := range []string{"canceled", "late conflict"} {
		t.Run(mode, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "reports")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := func(context.Context, string, []string, bool, func(progress.Event)) (report.Report, error) {
				if mode == "canceled" {
					cancel()
				} else {
					if err := os.Mkdir(destination, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(destination, "keep"), []byte("existing"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return report.Report{SchemaVersion: "1", Repository: root, Scanners: []report.Scanner{{Name: "trivy", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "packages", ReadInputs: []string{"package-lock.json"}}, TrivyReports: &report.TrivyReports{CycloneDX: []byte(`{}`), SonarQube: []byte(`{}`)}}}}, nil
			}
			var stdout, stderr bytes.Buffer
			if code := run(ctx, []string{"--trivy-reports", destination, root}, &stdout, &stderr, fake); code != 1 || !json.Valid(stdout.Bytes()) {
				t.Fatalf("%s exit=%d stdout=%s stderr=%s", mode, code, &stdout, &stderr)
			}
			for _, name := range []string{"trivy.cdx.json", "trivy.sonarqube.json"} {
				if _, err := os.Lstat(filepath.Join(destination, name)); !os.IsNotExist(err) {
					t.Errorf("%s created %s: %v", mode, name, err)
				}
			}
			if mode == "late conflict" {
				data, err := os.ReadFile(filepath.Join(destination, "keep"))
				if err != nil || string(data) != "existing" {
					t.Errorf("late file changed: %s %v", data, err)
				}
			}
		})
	}
}

func TestAcceptanceTrivyReports(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for real Trivy report generation")
	}
	root := exportTestRepository(t)
	fixture := `{"name":"synthetic-export","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"synthetic-export","version":"1.0.0","dependencies":{"lodash":"4.17.20","is-number":"7.0.0"}},"node_modules/lodash":{"version":"4.17.20"},"node_modules/is-number":{"version":"7.0.0"}}}`
	path := filepath.Join(root, "package-lock.json")
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	var preparation bytes.Buffer
	if code := run(context.Background(), []string{"update", "--scanners", "trivy", root}, &bytes.Buffer{}, &preparation, scan); code != 0 {
		t.Fatalf("prepare Trivy exit=%d: %s", code, &preparation)
	}
	destination := filepath.Join(t.TempDir(), "reports")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--scanners", "trivy", "--trivy-reports", destination, "--progress", "off", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("Trivy export exit=%d: %s", code, &stderr)
	}
	var bom struct {
		SpecVersion string
		Components  []struct{ PURL string }
	}
	data, err := os.ReadFile(filepath.Join(destination, "trivy.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	packages := map[string]bool{}
	for _, pkg := range bom.Components {
		packages[pkg.PURL] = true
	}
	if bom.SpecVersion != "1.6" || !packages["pkg:npm/lodash@4.17.20"] || !packages["pkg:npm/is-number@7.0.0"] {
		t.Fatalf("Trivy SBOM omits clean or vulnerable package: %+v", bom)
	}
	var sonar struct {
		Rules  []struct{ ID string }
		Issues []struct {
			RuleID          string
			PrimaryLocation struct {
				FilePath  string
				TextRange any
			}
		}
	}
	data, err = os.ReadFile(filepath.Join(destination, "trivy.sonarqube.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &sonar); err != nil {
		t.Fatal(err)
	}
	if len(sonar.Rules) == 0 || len(sonar.Issues) == 0 {
		t.Fatalf("vulnerable Trivy export has no issues: %s", data)
	}
	for _, issue := range sonar.Issues {
		if issue.PrimaryLocation.FilePath != "package-lock.json" || issue.PrimaryLocation.TextRange != nil {
			t.Errorf("wrong Sonar location: %+v", issue)
		}
	}
	var canonical report.Report
	if json.Unmarshal(stdout.Bytes(), &canonical) != nil || canonical.Scanners[0].Status != "success" || bytes.Contains(stdout.Bytes(), []byte("bomFormat")) {
		t.Fatalf("unexpected canonical report: %s", &stdout)
	}
	clean := `{"lockfileVersion":3,"packages":{"node_modules/is-number":{"version":"7.0.0"}}}`
	if err := os.WriteFile(path, []byte(clean), 0600); err != nil {
		t.Fatal(err)
	}
	destination = filepath.Join(t.TempDir(), "clean-reports")
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--scanners", "trivy", "--trivy-reports", destination, "--progress", "off", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("clean Trivy export exit=%d: %s", code, &stderr)
	}
	data, err = os.ReadFile(filepath.Join(destination, "trivy.sonarqube.json"))
	if err != nil || string(data) != `{"rules":[],"issues":[]}` {
		t.Fatalf("clean Sonar report=%s err=%v", data, err)
	}
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests\n"), 0600); err != nil {
		t.Fatal(err)
	}
	destination = filepath.Join(t.TempDir(), "partial-reports")
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--scanners", "trivy", "--trivy-reports", destination, root}, &stdout, &stderr, scan); code != 1 || !json.Valid(stdout.Bytes()) {
		t.Fatalf("partial Trivy export exit=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("partial Trivy report published: %v", err)
	}
}
