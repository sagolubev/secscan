package scanner

import (
	"strings"
	"testing"
)

func TestParseSARIFRejectsInvalidAndFailedRuns(t *testing.T) {
	good := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"synthetic"}},"invocations":[{"executionSuccessful":true}],"results":[{"ruleId":"test-rule","message":{"text":"SECRET_CANARY"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///target/app.py"},"region":{"startLine":2}}}]}]}]}`
	findings, err := ParseSARIF([]byte(good), "synthetic", "code")
	if err != nil || len(findings) != 1 {
		t.Fatalf("ParseSARIF()=%v,%v", findings, err)
	}
	if findings[0].Path != "app.py" || strings.Contains(findings[0].Message, "CANARY") {
		t.Fatal("unsafe normalized finding")
	}
	for _, bad := range []string{`null`, `{}`, strings.Replace(good, `true`, `false`, 1), strings.Replace(good, `file:///target/app.py`, `../../escape`, 1), strings.Replace(good, `"startLine":2`, `"startLine":0`, 1)} {
		if _, err := ParseSARIF([]byte(bad), "synthetic", "code"); err == nil {
			t.Fatal("accepted invalid SARIF")
		}
	}
}
