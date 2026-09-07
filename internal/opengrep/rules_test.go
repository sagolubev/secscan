// START_MODULE_CONTRACT
// PURPOSE: Verify custom rule identity and redaction at the adapter boundary.
// SCOPE: Synthetic imported packs and hostile scanner fields.
// DEPENDS: internal/opengrep/parser.go, internal/opengrep/rules.go, internal/rules/store.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-reproducibility
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestCustomRuleParserUsesRegisteredMetadata - Keep dynamic rule messages out of canonical output.
// TestCustomRuleParserRejectsWrongSource - Bind each rule to its declared source language.
// END_MODULE_MAP

package opengrep

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/rules"
)

func TestCustomRuleParserUsesRegisteredMetadata(t *testing.T) {
	pack := customPack(t)
	data := []byte(`{"version":"1.29.0","paths":{"scanned":["/target/a.py"]},"results":[{"check_id":"custom-call","path":"/target/a.py","start":{"line":1},"end":{"line":1},"extra":{"severity":"UNTRUSTED_CANARY","message":"UNTRUSTED_CANARY","lines":"UNTRUSTED_CANARY","metavars":{"$X":{"abstract_content":"UNTRUSTED_CANARY"}}}}],"errors":[]}`)
	got, err := ParseWithRules(data, "python", &pack)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "secscan.custom."+pack.Metadata().ID+".custom-call" || got.Findings[0].Message != "custom rule matched" || got.Findings[0].Severity != "error" {
		t.Fatalf("custom finding=%+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "UNTRUSTED_CANARY") {
		t.Fatal("dynamic rule content leaked")
	}
	for _, language := range []string{"python", ""} {
		digest, count, meta := RuleEvidence(language, &pack)
		want := 4
		if language == "" {
			want = 9
		}
		if digest == RulePackDigest || count != want || meta == nil || meta.ID != pack.Metadata().ID || meta.RuleCount != 1 {
			t.Fatalf("rule evidence %q=%s,%d,%+v", language, digest, count, meta)
		}
	}
}

func TestCustomLanguageScanRejectsMixedInputs(t *testing.T) {
	pack := customPack(t)
	if _, _, err := ScanWithRules(context.Background(), nil, "", "python", "", []string{"a.py", "b.ts"}, func(progress.Event) {}, &pack); err == nil {
		t.Fatal("language scan accepted mixed inputs before execution")
	}
}

func TestCustomRuleParserRejectsWrongSource(t *testing.T) {
	pack := customPack(t)
	for _, id := range []string{"custom-call", "UNTRUSTED_CANARY"} {
		data := []byte(`{"results":[{"check_id":"` + id + `","path":"/target/a.ts","start":{"line":1},"end":{"line":1},"extra":{}}],"errors":[]}`)
		if _, err := ParseWithRules(data, "", &pack); err == nil || strings.Contains(err.Error(), "UNTRUSTED_CANARY") {
			t.Fatalf("invalid custom source error=%v", err)
		}
	}
}

func customPack(t *testing.T) rules.Pack {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{"rules.toml": "version=1\nsource=\"local\"\nlicense=\"MIT\"\nlicense_file=\"LICENSE\"\nfiles=[\"rules.yml\"]\n", "LICENSE": "Synthetic fixture license", "rules.yml": "rules:\n- id: custom-call\n  languages: [python]\n  message: '$X'\n  severity: ERROR\n  pattern: forbidden($X)\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pack, err := rules.Import(context.Background(), t.TempDir(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return pack
}
