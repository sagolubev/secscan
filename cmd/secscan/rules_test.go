// START_MODULE_CONTRACT
// PURPOSE: Verify explicit rule-pack import and isolated scan integration.
// SCOPE: Synthetic local packs; native acceptance is opt-in.
// DEPENDS: cmd/secscan/rules.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-reproducibility
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestRulesImportAndShowWithoutRepository - Import local rules and inspect their immutable identity.
// TestAcceptanceRulePacks - Prove custom rules, redaction, scopes and rollback with native engines.
// TestRulePackPreflight - Reject invalid selection before scans.
// TestRulePackCacheInsideRepositoryRejected - Keep cached rule bytes outside scanner input.
// TestRulePackInputRoutesAndCoverage - Match dynamic candidates to positive read evidence.
// END_MODULE_MAP

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
	"github.com/sagolubev/secscan/internal/rules"
)

func TestRulesImportAndShowWithoutRepository(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := rulePackFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"rules", "import", dir}, &stdout, &stderr, nil); code != 0 {
		t.Fatalf("rules import exit=%d stderr=%s", code, &stderr)
	}
	var imported struct {
		ID, Source, License string
		RuleCount           int
	}
	if err := json.Unmarshal(stdout.Bytes(), &imported); err != nil || len(imported.ID) != 64 || imported.RuleCount != 1 || imported.Source != "local" || imported.License != "MIT" {
		t.Fatalf("imported metadata=%+v error=%v", imported, err)
	}
	first := append([]byte(nil), stdout.Bytes()...)
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"rules", "show", imported.ID}, &stdout, &stderr, nil); code != 0 || !bytes.Equal(first, stdout.Bytes()) {
		t.Fatalf("rules show exit=%d output=%s stderr=%s", code, &stdout, &stderr)
	}
}

func TestAcceptanceRulePacks(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for native offline rule-pack scans")
	}
	root := exportTestRepository(t)
	const canary = "SYNTHETIC_RULE_VALUE_DO_NOT_EMIT"
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("forbidden(\""+canary+"\")\neval(user_input)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := rulePackFixture(t)
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("package demo\nfunc f() { forbidden(1) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "custom.yml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("- id: forbidden-go\n  languages: [go]\n  message: '$X'\n  severity: ERROR\n  pattern: forbidden($X)\n"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"rules", "import", dir}, &stdout, &stderr, nil); code != 0 {
		t.Fatalf("import exit=%d %s", code, &stderr)
	}
	var info struct{ ID string }
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"update", "--scanners", "python-sast,semgrep", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("prepare exit=%d %s", code, &stderr)
	}
	for _, engine := range []string{"python-sast", "semgrep"} {
		stdout.Reset()
		stderr.Reset()
		if code := run(context.Background(), []string{"--rule-pack", info.ID, "--scanners", engine, root}, &stdout, &stderr, scan); code != 0 {
			t.Fatalf("%s scan exit=%d %s", engine, code, &stderr)
		}
		var result report.Report
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		foundCustom, foundBuiltin := false, false
		for _, f := range result.Findings {
			foundCustom = foundCustom || f.RuleID == "secscan.custom."+info.ID+".forbidden-call"
			foundBuiltin = foundBuiltin || f.RuleID == "secscan.python.dynamic-code-execution"
		}
		if !foundCustom || !foundBuiltin {
			t.Fatalf("%s findings omit custom or built-in rule: %+v", engine, result.Findings)
		}
		if strings.Contains(stdout.String(), canary) {
			t.Fatal("rule message leaked metavariable content")
		}
		if strings.Contains(stderr.String(), canary) {
			t.Fatal("rule diagnostic leaked metavariable content")
		}
		var metadata struct {
			Scanners []struct {
				CustomRulePack *struct{ ID, License string }
				RuleCount      int
			}
		}
		if err := json.Unmarshal(stdout.Bytes(), &metadata); err != nil || len(metadata.Scanners) != 1 || metadata.Scanners[0].CustomRulePack == nil || metadata.Scanners[0].CustomRulePack.ID != info.ID || metadata.Scanners[0].CustomRulePack.License != "MIT" {
			t.Fatalf("missing rule provenance: %s", &stdout)
		}
		wantCount := 4
		if engine == "semgrep" {
			wantCount = 10
			foundGo := false
			for _, f := range result.Findings {
				foundGo = foundGo || f.RuleID == "secscan.custom."+info.ID+".forbidden-go" && f.Path == "app.go"
			}
			if !foundGo || result.Scanners[0].Coverage.Read != 2 || len(result.UncheckedInputs) != 0 {
				t.Fatalf("custom Go analysis missing: %+v", result)
			}
		}
		if metadata.Scanners[0].RuleCount != wantCount {
			t.Fatalf("%s rule count=%d want%d", engine, metadata.Scanners[0].RuleCount, wantCount)
		}
		stdout.Reset()
		stderr.Reset()
		if code := run(context.Background(), []string{"--scanners", engine, root}, &stdout, &stderr, scan); code != 0 {
			t.Fatalf("default rollback exit=%d %s", code, &stderr)
		}
		if strings.Contains(stdout.String(), "secscan.custom.") {
			t.Fatal("custom rules stayed active without explicit flag")
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--rule-pack", info.ID, "--scope", "app.py", "--scanners", "semgrep", root}, &stdout, &stderr, scan); code != 0 {
		t.Fatalf("scoped rules exit=%d %s", code, &stderr)
	}
	var scoped report.Report
	if err := json.Unmarshal(stdout.Bytes(), &scoped); err != nil {
		t.Fatal(err)
	}
	if scoped.Scanners[0].Scope == nil || scoped.Scanners[0].Scope.CandidateFiles != 1 || scoped.Scanners[0].Coverage.Read != 1 {
		t.Fatalf("custom scope=%+v", scoped.Scanners)
	}
	for _, f := range scoped.Findings {
		if f.Path != "app.py" {
			t.Fatalf("custom finding escaped scope: %+v", f)
		}
	}
}

func rulePackFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"rules.toml": "version=1\nsource=\"local\"\nlicense=\"MIT\"\nlicense_file=\"LICENSE\"\nfiles=[\"custom.yml\"]\n",
		"LICENSE":    "Synthetic fixture license\n",
		"custom.yml": "rules:\n- id: forbidden-call\n  languages: [python]\n  message: '$X'\n  severity: ERROR\n  pattern: forbidden($X)\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRulePackPreflight(t *testing.T) {
	root := exportTestRepository(t)
	for _, args := range [][]string{{"--rule-pack", "", root}, {"update", "--rule-pack", strings.Repeat("a", 64), root}, {"--rule-pack", strings.Repeat("a", 64), "--scanners", "gitleaks", root}, {"rules", "show", "../escape"}, {"rules", "import"}} {
		var out, errout bytes.Buffer
		if code := run(context.Background(), args, &out, &errout, nil); code != 2 || out.Len() != 0 {
			t.Errorf("invalid arguments %q exit=%d output=%s", args, code, &out)
		}
	}
	var out, errout bytes.Buffer
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if code := run(context.Background(), []string{"--rule-pack", strings.Repeat("a", 64), root}, &out, &errout, nil); code != 1 || out.Len() != 0 {
		t.Errorf("missing pack exit=%d output=%s", code, &out)
	}
}

func TestRulePackCacheInsideRepositoryRejected(t *testing.T) {
	root := exportTestRepository(t)
	t.Setenv("HOME", root)
	t.Setenv("XDG_CACHE_HOME", root)
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"rules", "import", rulePackFixture(t)}, &out, &errout, nil); code != 0 {
		t.Fatalf("import=%d %s", code, &errout)
	}
	var meta rules.Metadata
	if err := json.Unmarshal(out.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		t.Error("unsafe cache started scan")
		return report.Report{SchemaVersion: "1"}, nil
	}
	if code := run(context.Background(), []string{"--rule-pack", meta.ID, root}, &out, &errout, fake); code != 1 || out.Len() != 0 {
		t.Errorf("inside cache exit=%d output=%s stderr=%s", code, &out, &errout)
	}
}

func TestRulePackInputRoutesAndCoverage(t *testing.T) {
	dir := rulePackFixture(t)
	data := []byte("rules:\n- id: forbidden-go\n  languages: [go]\n  message: unsafe\n  severity: ERROR\n  pattern: forbidden($X)\n")
	if err := os.WriteFile(filepath.Join(dir, "custom.yml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	pack, err := rules.Import(context.Background(), t.TempDir(), dir)
	if err != nil {
		t.Fatal(err)
	}
	inv := discovery.Inventory{Python: []string{"a.py"}, Sources: []discovery.SourceInput{{Path: "a.py", Language: "python"}, {Path: "b.go", Language: "go"}, {Path: "c.rs", Language: "rust"}}}
	got := inputsWithRules("semgrep", inv, &pack)
	if strings.Join(got, ",") != "a.py,b.go" {
		t.Fatalf("custom candidates=%v", got)
	}
	results := []report.Scanner{{Name: "semgrep", Status: "success", Coverage: report.Coverage{Read: 2, ReadInputs: got}}}
	gaps := coverageGapsWithRules(inv, []string{"semgrep"}, results, &pack)
	if len(gaps) != 1 || gaps[0].Path != "c.rs" {
		t.Fatalf("custom coverage=%+v", gaps)
	}
	inv.Sources = inv.Sources[:1]
	if got := inputsWithRules("semgrep", inv, &pack); strings.Join(got, ",") != "a.py" {
		t.Fatalf("narrowed inventory widened: %v", got)
	}
}

func TestRulePackRejectsIncompatibleLanguageSelection(t *testing.T) {
	root := exportTestRepository(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"rules", "import", rulePackFixture(t)}, &out, &errout, nil); code != 0 {
		t.Fatalf("import=%d %s", code, &errout)
	}
	var meta rules.Metadata
	if err := json.Unmarshal(out.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	fake := func(context.Context, string, scanOptions, func(progress.Event)) (report.Report, error) {
		return report.Report{SchemaVersion: "1"}, nil
	}
	if code := run(context.Background(), []string{"--rule-pack", meta.ID, "--scanners", "typescript-sast", root}, &out, &errout, fake); code != 2 || out.Len() != 0 {
		t.Errorf("Python pack with TypeScript selection exit=%d output=%s", code, &out)
	}
}

func TestAcceptanceRulePackLanguageBoundary(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for native mixed-language rules")
	}
	root := exportTestRepository(t)
	for _, name := range []string{"a.js", "b.ts", "dir.ts/a.js", "odd[1]/b.ts"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte("forbidden(value);\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := rulePackFixture(t)
	config := "rules:\n- id: javascript-call\n  languages: [javascript]\n  message: js\n  severity: ERROR\n  pattern: forbidden($X)\n- id: typescript-call\n  languages: [typescript]\n  message: ts\n  severity: ERROR\n  pattern: forbidden($X)\n"
	if err := os.WriteFile(filepath.Join(dir, "custom.yml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"rules", "import", dir}, &out, &errout, nil); code != 0 {
		t.Fatalf("import=%d %s", code, &errout)
	}
	var meta rules.Metadata
	if err := json.Unmarshal(out.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	if code := run(context.Background(), []string{"update", "--scanners", "semgrep", root}, &out, &errout, scan); code != 0 {
		t.Fatalf("prepare=%d %s", code, &errout)
	}
	out.Reset()
	errout.Reset()
	if code := run(context.Background(), []string{"--rule-pack", meta.ID, "--scanners", "semgrep", root}, &out, &errout, scan); code != 0 {
		t.Fatalf("mixed-language scan=%d %s", code, &errout)
	}
	var result report.Report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 4 || result.Scanners[0].Coverage.Read != 4 {
		t.Fatalf("mixed-language result=%+v", result)
	}
	for _, f := range result.Findings {
		if strings.HasSuffix(f.RuleID, "javascript-call") && !strings.HasSuffix(f.Path, ".js") || strings.HasSuffix(f.RuleID, "typescript-call") && !strings.HasSuffix(f.Path, ".ts") {
			t.Fatalf("rule crossed declared language: %+v", f)
		}
	}
}
