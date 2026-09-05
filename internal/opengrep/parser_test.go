package opengrep

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseDropsUntrustedSourceContent(t *testing.T) {
	const canary = "UNTRUSTED_SOURCE_CANARY"
	input := []byte(`{
		"version":"1.29.0",
		"results":[{
			"check_id":"rules.secscan.python.dynamic-code-execution",
			"path":"/target/app.py",
			"start":{"line":4,"col":1},
			"end":{"line":4,"col":17},
			"extra":{
				"severity":"ERROR",
				"message":"` + canary + `",
				"lines":"` + canary + `",
				"metavars":{"$X":{"abstract_content":"` + canary + `"}}
			}
		}],
		"errors":[]
	}`)

	result, err := Parse(input, "python")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if result.Version != "1.29.0" || len(result.Findings) != 1 {
		t.Fatalf("Parse() = %#v", result)
	}
	finding := result.Findings[0]
	if finding.RuleID != "secscan.python.dynamic-code-execution" ||
		finding.Path != "app.py" ||
		finding.Language != "python" ||
		finding.Message != "dynamic code execution" {
		t.Errorf("Parse() finding = %#v", finding)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) {
		t.Fatal("Parse() retained untrusted source content")
	}
}

func TestParseRejectsScannerErrors(t *testing.T) {
	input := []byte(`{"version":"1.29.0","results":[],"errors":[{"message":"raw source"}]}`)
	if _, err := Parse(input, "typescript"); err == nil {
		t.Fatal("Parse() error = nil, want sanitized scanner error")
	}
}

func TestContainerArgsUseOfflineLanguageRules(t *testing.T) {
	args := ContainerArgs("sha256:abc", "python", "/cache/target")
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--network none",
		"--read-only",
		"--cap-drop ALL",
		"--security-opt no-new-privileges",
		"--tmpfs /tmp:rw,exec,nosuid,nodev,size=256m",
		"type=bind,src=/cache/target,dst=/target,readonly",
		"sha256:abc scan",
		"--config=/rules/python.yml",
		"--no-git-ignore",
		"/target",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("ContainerArgs() missing %q: %s", want, joined)
		}
	}
}
