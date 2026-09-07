package opengrep

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
)

type fakeRunner struct {
	output []byte
	args   []string
}

func (runner *fakeRunner) Output(_ context.Context, args ...string) ([]byte, error) {
	runner.args = append([]string(nil), args...)
	return runner.output, nil
}

func TestScanReturnsPinnedCoverage(t *testing.T) {
	runner := &fakeRunner{output: []byte(`{
		"version":"1.29.0",
		"results":[],
        "paths":{"scanned":["/target/a.py","/target/b.py","/target/c.py"]},
		"errors":[]
	}`)}
	var events []progress.Event

	scanner, findings, err := Scan(
		context.Background(),
		runner,
		"sha256:abc",
		"python",
		"/cache/target",
		3,
		func(event progress.Event) { events = append(events, event) },
	)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Scan() findings = %d, want 0", len(findings))
	}
	if scanner.Name != "python-sast" || scanner.Image != "sha256:abc" ||
		scanner.EngineVersion != EngineVersion || scanner.RulePackDigest != RulePackDigest ||
		scanner.RuleCount != 3 || scanner.Coverage.Read != 3 ||
		scanner.Coverage.Unit != "files" {
		t.Errorf("Scan() scanner = %#v", scanner)
	}
	if !slices.Contains(runner.args, "--config=/rules/python.yml") {
		t.Errorf("Scan() args = %q", runner.args)
	}
	if len(events) == 0 || events[len(events)-1].Status != progress.StatusSuccess {
		t.Errorf("Scan() events = %#v, want final success", events)
	}
}

func TestAcceptanceOpengrepLanguages(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 to run container acceptance")
	}
	runtime, err := container.DetectDefault(context.Background())
	if err != nil {
		t.Fatalf("DetectDefault() error = %v", err)
	}
	imageID, err := EnsureImage(context.Background(), runtime)
	if err != nil {
		t.Fatalf("EnsureImage() error = %v", err)
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "scanner", "opengrep", "testdata"))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		language string
		files    int
		want     int
	}{
		{language: "python", files: 2, want: 3},
		{language: "typescript", files: 2, want: 5},
	} {
		t.Run(test.language, func(t *testing.T) {
			scanner, findings, err := Scan(
				context.Background(),
				runtime,
				imageID,
				test.language,
				filepath.Join(root, test.language),
				test.files,
				func(progress.Event) {},
			)
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if scanner.Coverage.Read != test.files || len(findings) != test.want {
				t.Errorf("Scan() coverage/findings = %#v/%d, want %d/%d", scanner.Coverage, len(findings), test.files, test.want)
			}
			for _, finding := range findings {
				if finding.Language != test.language || strings.Contains(finding.Message, "userInput") {
					t.Errorf("Scan() finding = %#v", finding)
				}
			}
		})
	}
}

func TestScanUsesConfirmedReadPaths(t *testing.T) {
	runner := &fakeRunner{output: []byte(`{"version":"1.29.0","results":[],"errors":[],"paths":{"scanned":["/target/a.py"]}}`)}
	scanner, _, err := Scan(context.Background(), runner, "sha256:abc", "python", "/target", 3, func(progress.Event) {})
	if err != nil || scanner.Coverage.Read != 1 || scanner.Coverage.Unread != 2 || !slices.Equal(scanner.Coverage.ReadInputs, []string{"a.py"}) {
		t.Fatalf("confirmed coverage=%+v err=%v", scanner.Coverage, err)
	}
}

func TestScanRejectsMissingReadEvidence(t *testing.T) {
	runner := &fakeRunner{output: []byte(`{"version":"1.29.0","results":[],"errors":[]}`)}
	if _, _, err := Scan(context.Background(), runner, "sha256:abc", "python", "/target", 1, func(progress.Event) {}); err == nil {
		t.Fatal("scan without read paths accepted")
	}
}
