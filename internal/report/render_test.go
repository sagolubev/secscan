package report

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestSARIFRetainsEvidence(t *testing.T) {
	input := Report{SchemaVersion: "1", Repository: "/repo", Findings: []Finding{
		{Kind: "dependency", Package: &Package{Ecosystem: "npm", Name: "library", Version: "1"}, Advisories: []string{"CVE-2026-1234"}, Locations: []Location{{Path: "src/a b#c.json", Line: 2, EndLine: 4}, {Path: "nested/lock.json"}}, Severity: "high", Sources: []string{"trivy"}},
		{Kind: "secret", RuleID: "test-secret", Message: "redacted secret", Path: "a:b.txt", Fingerprint: strings.Repeat("a", 64), Origin: "working_tree"},
	}, Scanners: []Scanner{{Name: "failed", Status: "failed", Coverage: Coverage{Failed: 1, Unit: "files"}}, {Name: "trivy", Status: "success", Coverage: Coverage{Read: 1, Unread: 1, Unit: "packages", UnreadInputs: []string{"unsupported.lock"}}}}, UncheckedInputs: []UncheckedInput{{Path: "unknown.rs", Category: "code", Reason: "no_matching_scanner"}}}
	before, _ := json.Marshal(input)
	data, err := SARIF(input)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Runs []struct {
			Results []struct {
				RuleID              string
				RuleIndex           int
				PartialFingerprints map[string]string
				Locations           []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
						Region           struct{ StartLine, EndLine int }
					}
				}
				Properties struct{ Secscan Finding }
			}
			Tool struct {
				Driver struct{ Rules []struct{ ID string } }
			}
			Properties struct {
				Scanners        []Scanner
				UncheckedInputs []UncheckedInput
			}
			Invocations []struct {
				ExecutionSuccessful        bool
				ToolExecutionNotifications []json.RawMessage
			}
		}
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	run := document.Runs[0]
	if len(run.Results) != 2 || len(run.Properties.Scanners) != 2 || len(run.Properties.UncheckedInputs) != 1 || run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].ToolExecutionNotifications) != 3 {
		t.Fatalf("missing SARIF evidence: %s", data)
	}
	for _, result := range run.Results {
		if result.RuleID != run.Tool.Driver.Rules[result.RuleIndex].ID {
			t.Fatalf("dangling rule: %+v", result)
		}
		f := result.Properties.Secscan
		if f.Kind == "dependency" && (f.Package == nil || f.Package.Name != "library" || len(f.Advisories) != 1 || len(result.Locations) != 2) {
			t.Fatalf("dependency metadata lost: %+v", result)
		}
		for _, loc := range result.Locations {
			uri, err := url.Parse(loc.PhysicalLocation.ArtifactLocation.URI)
			if err != nil || uri.IsAbs() || uri.Host != "" || uri.Fragment != "" || uri.RawQuery != "" {
				t.Fatalf("unsafe location: %+v %v", loc, err)
			}
		}
		if f.Kind == "secret" && result.PartialFingerprints["secscan/v1"] != strings.Repeat("a", 64) {
			t.Fatal("secret fingerprint changed")
		}
	}
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("SARIF mutated its input")
	}
	again, err := SARIF(input)
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("SARIF not deterministic: %v", err)
	}
}

func TestSARIFRejectsUnsafeLocationsAndFilteredInput(t *testing.T) {
	for _, location := range []Location{{Path: "../outside"}, {Path: "/absolute"}, {Path: "a/../outside"}, {Path: "a\\b"}, {Path: "x", Line: -1}, {Path: "x", Line: 3, EndLine: 2}} {
		if _, err := SARIF(Report{Findings: []Finding{{Kind: "code", Locations: []Location{location}}}}); err == nil {
			t.Errorf("SARIF accepted unsafe location %+v", location)
		}
	}
	if _, err := SARIF(Report{Baseline: &BaselineSummary{}}); err == nil {
		t.Fatal("SARIF accepted filtered report")
	}
	data, err := SARIF(Report{})
	if err != nil || !bytes.Contains(data, []byte(`"results":[]`)) || !bytes.Contains(data, []byte(`"rules":[]`)) {
		t.Fatalf("empty SARIF=%s error=%v", data, err)
	}
}

func TestHTMLContainsEscapedDataAndCoverage(t *testing.T) {
	input := Report{Repository: `<img src="https://attacker.invalid" onerror="run()">`, Findings: []Finding{{RuleID: "rule", Kind: "code", Message: "<script>run()</script>", Path: "<iframe>.py", Line: 4}}, Scanners: []Scanner{{Name: "scanner", Status: "failed", Limitations: []string{"<img src=x>"}}}}
	data, err := HTML(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script>", "<iframe>", "<img src="} {
		if bytes.Contains(data, []byte(bad)) {
			t.Errorf("unescaped HTML contains %q", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "Content-Security-Policy", "default-src 'none'", "failed", "Scanner coverage"} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("HTML missing %q", want)
		}
	}
}
