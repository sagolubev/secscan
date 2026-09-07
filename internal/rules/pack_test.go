// START_MODULE_CONTRACT
// PURPOSE: Exercise rule-pack grammar, language routing and immutable scanner materialization.
// SCOPE: Synthetic local rules only; reject unsafe input without exposing rule contents.
// DEPENDS: internal/rules/pack.go, internal/rules/store.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-reproducibility
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestPackSelectionAndWrite - Preserve IDs and select only declared languages.
// TestPackRejectsUnsafeGrammar - Reject malformed manifests, provenance and YAML.
// TestPackMatchesPath - Route canonical language tags without widening JS/TS or C/C++.
// TestPackPreservesNormalDSL - Keep local include filters and nested patterns executable.
// TestPackWriteEnforcesLanguageBoundary - Materialized exclusions narrow each rule without mutating snapshots.
// TestPackWriteBoundsLanguageFilters - Reject excessive materialization before creating scanner files.
// fixtureDirectory - Create a synthetic local pack manifest and rules.
// ruleYAML - Produce a minimal engine rule fixture.
// privateDirectory - Return a canonical private test directory.
// writeFixture - Write a synthetic file beneath a test root.
// END_MODULE_MAP

package rules

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestPackSelectionAndWrite(t *testing.T) {
	directory := fixtureDirectory(t, map[string]string{"a.yml": ruleYAML("custom.python", "python"), "b.yaml": ruleYAML("custom.ts", "typescript")})
	pack, err := Import(context.Background(), privateDirectory(t), directory)
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{{ID: "custom.python", Languages: []string{"python"}, Severity: "warning"}}
	if got := pack.Rules("python"); !reflect.DeepEqual(got, want) {
		t.Fatalf("Rules(python) = %+v, want %+v", got, want)
	}
	if !pack.MatchesPath("a.ts") || pack.Rules("python")[0].MatchesPath("a.ts") || !pack.Rules("python")[0].MatchesPath("a.py") {
		t.Fatal("Rule.MatchesPath widened routing to other rules in the same pack")
	}
	metadata := pack.Metadata()
	metadata.Languages[0] = "corrupted"
	selected := pack.Rules("")
	selected[0].ID = "corrupted"
	selected[0].Languages[0] = "corrupted"
	if !reflect.DeepEqual(pack.Rules("python"), want) || pack.Metadata().Languages[0] != "python" {
		t.Fatal("metadata or Rules mutation altered the immutable Pack")
	}
	output := privateDirectory(t)
	if err := pack.WriteForPaths(output, "python", []string{"src/main.py", "src/main.ts"}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".yaml" {
		t.Fatalf("Write(python) files = %v, %v; want exactly one YAML file", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(output, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Rules []struct {
			ID        string   `yaml:"id"`
			Languages []string `yaml:"languages"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Rules) != 1 || document.Rules[0].ID != "custom.python" {
		t.Fatalf("materialized rules = %+v, %v; want original python ID", document, err)
	}
	if err := pack.Write(output, "python"); err == nil {
		t.Fatal("Write overwrote an existing scanner input")
	}
	empty := privateDirectory(t)
	if err := pack.Write(empty, "go"); err != nil {
		t.Fatal(err)
	}
	if files, err := os.ReadDir(empty); err != nil || len(files) != 0 {
		t.Fatalf("Write(go) files = %v, %v; want no files", files, err)
	}
}

func TestPackRejectsUnsafeGrammar(t *testing.T) {
	valid := ruleYAML("custom.rule", "python")
	cases := []struct{ name, manifest, yaml, license string }{
		{name: "unknown manifest", manifest: "unknown = 'CANARY_RULE_SECRET'\n"},
		{name: "duplicate manifest", manifest: "version = 1\n"},
		{name: "duplicate files", manifest: "files = ['a.yml', 'a.yml']\n"},
		{name: "escaping path", manifest: "files = ['../CANARY_RULE_SECRET.yml']\n"},
		{name: "absolute path", manifest: "files = ['/CANARY_RULE_SECRET.yml']\n"},
		{name: "non YAML file", manifest: "files = ['a.json']\n"},
		{name: "empty files", manifest: "files = []\n"},
		{name: "remote credentials", manifest: "source = 'https://CANARY_RULE_SECRET@example.com'\n"},
		{name: "remote query", manifest: "source = 'https://example.com?CANARY_RULE_SECRET'\n"},
		{name: "http", manifest: "source = 'http://example.com'\n"},
		{name: "revision", manifest: "revision = 'CANARY_RULE_SECRET'\n"},
		{name: "empty revision", manifest: "revision = ''\n"},
		{name: "empty license id", manifest: "license = ''\n"},
		{name: "empty license", license: " "},
		{name: "binary license", license: "CANARY_RULE_SECRET\x00"},
		{name: "invalid UTF8 license", license: "\xff"},
		{name: "duplicate YAML", yaml: strings.Replace(valid, "    severity: WARNING", "    severity: ERROR\n    severity: WARNING", 1)},
		{name: "duplicate rule ID", yaml: valid + strings.TrimPrefix(valid, "rules:\n")},
		{name: "root include", yaml: valid + "include: https://example.com/CANARY_RULE_SECRET\n"},
		{name: "multiple documents", yaml: valid + "---\n" + valid},
		{name: "anchor", yaml: strings.Replace(valid, "pattern: test($X)", "pattern: &anchor test($X)", 1)},
		{name: "alias", yaml: strings.Replace(valid, "pattern: test($X)", "pattern: *anchor", 1)},
		{name: "merge key", yaml: valid + "    <<: {message: CANARY_RULE_SECRET}\n"},
		{name: "custom tag", yaml: strings.Replace(valid, "pattern: test($X)", "pattern: !exec CANARY_RULE_SECRET", 1)},
		{name: "executable Python", yaml: valid + "    pattern-where-python: CANARY_RULE_SECRET\n"},
		{name: "validators", yaml: valid + "    validators: []\n"},
		{name: "nested validator", yaml: valid + "    metadata: {validator: CANARY_RULE_SECRET}\n"},
		{name: "remote include", yaml: valid + "    includes: [https://example.com/CANARY_RULE_SECRET]\n"},
		{name: "reserved ID", yaml: strings.Replace(valid, "custom.rule", "prefix.secscan.custom", 1)},
		{name: "invalid ID", yaml: strings.Replace(valid, "custom.rule", "bad/id", 1)},
		{name: "long ID", yaml: strings.Replace(valid, "custom.rule", strings.Repeat("a", 129), 1)},
		{name: "missing message", yaml: strings.Replace(valid, "    message: CANARY_RULE_SECRET\n", "", 1)},
		{name: "numeric message", yaml: strings.Replace(valid, "message: CANARY_RULE_SECRET", "message: 123", 1)},
		{name: "generic language", yaml: strings.Replace(valid, "[python]", "[generic]", 1)},
		{name: "language alias", yaml: strings.Replace(valid, "[python]", "[py]", 1)},
		{name: "empty language", yaml: strings.Replace(valid, "[python]", "[]", 1)},
		{name: "duplicate language", yaml: strings.Replace(valid, "[python]", "[python, python]", 1)},
		{name: "invalid severity", yaml: strings.Replace(valid, "WARNING", "CRITICAL", 1)},
		{name: "no pattern", yaml: strings.Replace(valid, "    pattern: test($X)\n", "", 1)},
		{name: "deep YAML", yaml: valid + "    metadata: " + strings.Repeat("[", 65) + "x" + strings.Repeat("]", 65) + "\n"},
		{name: "wide YAML", yaml: valid + "    metadata: [" + strings.Repeat("x,", 100001) + "]\n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			directory := fixtureDirectory(t, map[string]string{"a.yml": valid})
			if tt.manifest != "" {
				data, err := os.ReadFile(filepath.Join(directory, "rules.toml"))
				if err != nil {
					t.Fatal(err)
				}
				manifest := string(data)
				key, _, _ := strings.Cut(tt.manifest, " =")
				if tt.name != "duplicate manifest" && tt.name != "unknown manifest" {
					lines := strings.Split(manifest, "\n")
					for i, line := range lines {
						if strings.HasPrefix(line, key+" =") {
							lines[i] = ""
						}
					}
					manifest = strings.Join(lines, "\n")
				}
				writeFixture(t, directory, "rules.toml", manifest+tt.manifest)
			}
			if tt.yaml != "" {
				writeFixture(t, directory, "a.yml", tt.yaml)
			}
			if tt.license != "" {
				writeFixture(t, directory, "LICENSE", tt.license)
			}
			_, err := Import(context.Background(), privateDirectory(t), directory)
			if err == nil {
				t.Fatal("Import accepted unsafe grammar")
			}
			if strings.Contains(err.Error(), "CANARY_RULE_SECRET") {
				t.Fatal("Import error exposed untrusted bytes")
			}
		})
	}
	t.Run("duplicate IDs across files", func(t *testing.T) {
		directory := fixtureDirectory(t, map[string]string{"a.yml": valid, "b.yml": valid})
		if _, err := Import(context.Background(), privateDirectory(t), directory); err == nil {
			t.Fatal("Import accepted duplicate rule IDs across separate files")
		}
	})
	t.Run("node count across files", func(t *testing.T) {
		metadata := "    metadata: [" + strings.Repeat("x,", 60000) + "]\n"
		directory := fixtureDirectory(t, map[string]string{"a.yml": ruleYAML("rule.a", "python") + metadata, "b.yml": ruleYAML("rule.b", "python") + metadata})
		if _, err := Import(context.Background(), privateDirectory(t), directory); err == nil {
			t.Fatal("Import accepted an excessive aggregate YAML node count")
		}
	})
}

func TestPackMatchesPath(t *testing.T) {
	for _, tt := range []struct{ language, yes, no string }{
		{"typescript", "src/a.tsx", "src/a.js"}, {"javascript", "src/a.jsx", "src/a.ts"},
		{"c", "src/a.c", "src/a.cpp"}, {"cpp", "src/a.hpp", "src/a.c"},
		{"bash", "src/a.sh", "src/a.ps1"}, {"python", "src/a.pyi", "src/a.txt"},
	} {
		t.Run(tt.language, func(t *testing.T) {
			pack, err := Import(context.Background(), privateDirectory(t), fixtureDirectory(t, map[string]string{"a.yml": ruleYAML("custom.rule", tt.language)}))
			if err != nil {
				t.Fatal(err)
			}
			if !pack.MatchesPath(tt.yes) || pack.MatchesPath(tt.no) || pack.MatchesPath("unknown") {
				t.Fatalf("MatchesPath(%s) widened or lost %s routing", tt.yes, tt.language)
			}
			if (tt.language == "c" || tt.language == "cpp") && !pack.MatchesPath("src/a.h") {
				t.Fatal("MatchesPath(.h) lost C/C++ shared header")
			}
		})
	}
}

func TestPackPreservesNormalDSL(t *testing.T) {
	rule := strings.Replace(ruleYAML("custom.normal", "python"), "    pattern: test($X)\n", "    patterns:\n      - pattern: test($X)\n      - metavariable-regex: {metavariable: '$X', regex: '^danger'}\n    paths:\n      include: ['src/**/*.py']\n      exclude: ['tests/**']\n", 1)
	pack, err := Import(context.Background(), privateDirectory(t), fixtureDirectory(t, map[string]string{"правила/normal.yml": rule}))
	if err != nil {
		t.Fatalf("Import normal Semgrep DSL = %v", err)
	}
	output := privateDirectory(t)
	if err := pack.WriteForPaths(output, "python", []string{"src/main.py", "src/main.ts"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "custom-rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var before, after any
	if err := yaml.Unmarshal([]byte(rule), &before); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &after); err != nil {
		t.Fatal(err)
	}
	beforePaths := before.(map[string]any)["rules"].([]any)[0].(map[string]any)["paths"].(map[string]any)
	afterPaths := after.(map[string]any)["rules"].([]any)[0].(map[string]any)["paths"].(map[string]any)
	priorExcludes := beforePaths["exclude"].([]any)
	materializedExcludes := afterPaths["exclude"].([]any)
	if len(materializedExcludes) < len(priorExcludes) || !reflect.DeepEqual(materializedExcludes[:len(priorExcludes)], priorExcludes) {
		t.Fatal("Write replaced the caller's exclusion filters")
	}
	afterPaths["exclude"] = materializedExcludes[:len(priorExcludes)]
	if !reflect.DeepEqual(after, before) {
		t.Fatal("Write changed ordinary DSL fields")
	}
}

func TestPackWriteEnforcesLanguageBoundary(t *testing.T) {
	for _, tt := range []struct {
		languages        string
		allowed, blocked []string
	}{
		{"javascript", []string{"a.js", "nested/a.jsx", "a.mjs", "a.cjs", "nested/a.ts/a.js", "dir.ts/a.js"}, []string{"a.ts", "nested/a.tsx", "a.mts", "a.cts", "a.Ts", "a.py", "odd[1]/a.ts"}},
		{"typescript", []string{"a.ts", "nested/a.tsx", "a.mts", "a.cts"}, []string{"a.js", "nested/a.jsx", "a.mjs", "a.cjs", "a.go"}},
		{"javascript, typescript", []string{"a.js", "a.ts", "nested/a.jsx", "nested/a.tsx"}, []string{"a.py", "a.c"}},
		{"c", []string{"a.c", "nested/a.h"}, []string{"a.cpp", "a.cc", "a.cxx", "a.hh", "a.hpp", "a.hxx", "a.Cpp"}},
		{"cpp", []string{"a.cpp", "a.cc", "a.cxx", "a.h", "a.hh", "a.hpp", "a.hxx"}, []string{"a.c", "a.C", "a.ts"}},
		{"c, cpp", []string{"a.c", "a.cpp", "a.h", "a.hpp"}, []string{"a.go", "a.js"}},
	} {
		t.Run(tt.languages, func(t *testing.T) {
			pack, err := Import(context.Background(), privateDirectory(t), fixtureDirectory(t, map[string]string{"rule.yml": ruleYAML("custom.bound", tt.languages)}))
			if err != nil {
				t.Fatal(err)
			}
			original, err := yaml.Marshal(pack.nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			output := privateDirectory(t)
			inputs := append(append([]string(nil), tt.allowed...), tt.blocked...)
			if err := pack.WriteForPaths(output, "", inputs); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(output, "custom-rules.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var materialized struct {
				Rules []struct {
					Paths struct {
						Exclude []string `yaml:"exclude"`
					} `yaml:"paths"`
				} `yaml:"rules"`
			}
			if err := yaml.Unmarshal(data, &materialized); err != nil {
				t.Fatal(err)
			}
			if len(materialized.Rules) != 1 {
				t.Fatal("Write lost the selected rule")
			}
			for _, files := range []struct {
				names    []string
				excluded bool
			}{{tt.allowed, false}, {tt.blocked, true}} {
				for _, filename := range files.names {
					excluded := false
					for _, glob := range materialized.Rules[0].Paths.Exclude {
						match, err := path.Match(glob, "/"+filename)
						if err != nil {
							t.Fatal(err)
						}
						excluded = excluded || match
					}
					if excluded != files.excluded {
						t.Errorf("materialized exclusion for %s = %t, want %t", filename, excluded, files.excluded)
					}
				}
			}
			after, err := yaml.Marshal(pack.nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(original) {
				t.Fatal("Write mutated the immutable rule snapshot")
			}
		})
	}
	t.Run("invalid path namespace", func(t *testing.T) {
		pack, err := Import(context.Background(), privateDirectory(t), fixtureDirectory(t, map[string]string{"rule.yml": ruleYAML("custom.bound", "javascript")}))
		if err != nil {
			t.Fatal(err)
		}
		for _, invalid := range []string{"", "/tmp/a.ts", "/target/a.js", "/target/../a.ts", "../a.ts", "/target/a/../../a.ts", "a/../a.ts"} {
			if err := pack.WriteForPaths(privateDirectory(t), "", []string{invalid}); err == nil {
				t.Errorf("WriteForPaths(%q) accepted an invalid root or traversal", invalid)
			}
		}
	})
}

func TestPackWriteBoundsLanguageFilters(t *testing.T) {
	var data strings.Builder
	data.WriteString("rules:\n")
	for i := 0; i < 40; i++ {
		data.WriteString(strings.TrimPrefix(ruleYAML(fmt.Sprintf("rule.%d", i), "python"), "rules:\n"))
	}
	pack, err := Import(context.Background(), privateDirectory(t), fixtureDirectory(t, map[string]string{"rules.yml": data.String()}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		count, length int
	}{{"node count", 3000, 10}, {"byte count", 400, 2000}, {"encoded byte count", 2500, 151}} {
		t.Run(test.name, func(t *testing.T) {
			inputs := make([]string, test.count)
			for i := range inputs {
				inputs[i] = strings.Repeat("x", test.length) + fmt.Sprintf("%d.ts", i)
			}
			output := privateDirectory(t)
			if err := pack.WriteForPaths(output, "", inputs); err == nil {
				t.Fatal("WriteForPaths accepted excessive rule-by-file expansion")
			}
			entries, err := os.ReadDir(output)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed WriteForPaths left output: %v, %v", entries, err)
			}
		})
	}
}

func fixtureDirectory(t *testing.T, files map[string]string) string {
	t.Helper()
	directory := privateDirectory(t)
	var names []string
	for name, data := range files {
		names = append(names, fmt.Sprintf("%q", name))
		writeFixture(t, directory, name, data)
	}
	writeFixture(t, directory, "LICENSE", "Synthetic test license\n")
	writeFixture(t, directory, "rules.toml", "version = 1\nsource = 'local'\nlicense = 'MIT'\nlicense_file = 'LICENSE'\nfiles = ["+strings.Join(names, ",")+"]\n")
	return directory
}

func ruleYAML(id, language string) string {
	return fmt.Sprintf("rules:\n  - id: %s\n    message: CANARY_RULE_SECRET\n    languages: [%s]\n    severity: WARNING\n    pattern: test($X)\n", id, language)
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFixture(t *testing.T, directory, name, data string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
