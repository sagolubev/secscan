package scanner

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func trivyReportsInput(packages, vulnerabilities string) []byte {
	return []byte(`{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},"ArtifactType":"filesystem","Results":[{"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm","Packages":` + packages + `,"Vulnerabilities":` + vulnerabilities + `}]}`)
}

func TestTrivyReportsInventoryGraph(t *testing.T) {
	input := trivyReportsInput(`[
		{"ID":"root","Name":"@example/app","Version":"1.0.0","DependsOn":["clean","vulnerable"]},
		{"ID":"clean","Name":"is-number","Version":"7.0.0"},
		{"ID":"vulnerable","Name":"lodash","Version":"4.17.20","DependsOn":["root"]},
		{"ID":"also-clean","Name":"is-number","Version":"7.0.0"}
	]`, `[{"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20","Severity":"HIGH"}]`)
	result, err := buildTrivyReports(input, []string{"package-lock.json"})
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Format     string `json:"bomFormat"`
		Spec       string `json:"specVersion"`
		Components []struct {
			Ref                        string `json:"bom-ref"`
			Name, Group, Version, PURL string
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(result.CycloneDX, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.Format != "CycloneDX" || bom.Spec != "1.6" || len(bom.Components) != 3 {
		t.Fatalf("inventory = %+v, want CycloneDX 1.6 with three unique packages", bom)
	}
	refs := make(map[string]bool)
	for _, component := range bom.Components {
		if component.Ref != component.PURL || component.PURL == "" || refs[component.Ref] {
			t.Fatalf("invalid or duplicate component: %+v", component)
		}
		refs[component.Ref] = true
		if component.Name == "app" && component.Group != "@example" {
			t.Errorf("scoped group = %q, want @example", component.Group)
		}
	}
	want := map[string][]string{
		"pkg:npm/%40example/app@1.0.0": {"pkg:npm/is-number@7.0.0", "pkg:npm/lodash@4.17.20"},
		"pkg:npm/lodash@4.17.20":       {"pkg:npm/%40example/app@1.0.0"},
	}
	got := make(map[string][]string)
	for _, edge := range bom.Dependencies {
		got[edge.Ref] = edge.DependsOn
		for _, ref := range append([]string{edge.Ref}, edge.DependsOn...) {
			if !refs[ref] {
				t.Errorf("dangling BOM reference %q", ref)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dependency edges = %#v, want %#v", got, want)
	}
	again, err := buildTrivyReports(input, []string{"package-lock.json"})
	if err != nil || !bytes.Equal(result.CycloneDX, again.CycloneDX) || !bytes.Equal(result.SonarQube, again.SonarQube) {
		t.Fatalf("repeat export changed output: %v", err)
	}
}

func TestTrivyReportsSonarSeverityAndSafeFields(t *testing.T) {
	input := trivyReportsInput(`[{"ID":"pkg","Name":"lodash","Version":"4.17.20","Maintainer":"SYNTHETIC_CANARY","Identifier":{"PURL":"pkg:npm/lodash@4.17.20?repository_url=https://user:SYNTHETIC_CANARY@example.test"}}]`, `[
		{"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20","Severity":"CRITICAL","Description":"SYNTHETIC_CANARY","Title":"SYNTHETIC_CANARY","References":["SYNTHETIC_CANARY"]},
		{"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20","Severity":"UNKNOWN"}
	]`)
	result, err := buildTrivyReports(input, []string{"package-lock.json"})
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{result.CycloneDX, result.SonarQube} {
		if bytes.Contains(payload, []byte("SYNTHETIC_CANARY")) || bytes.Contains(payload, []byte("repository_url")) {
			t.Fatal("untrusted free text escaped the scanner boundary")
		}
	}
	var sonar struct {
		Rules []struct {
			ID, EngineID, Type, Severity string
			Impacts                      []struct{ SoftwareQuality, Severity string }
		} `json:"rules"`
		Issues []struct {
			RuleID, Severity, Type string
			PrimaryLocation        struct {
				Message, FilePath string
				TextRange         json.RawMessage
			}
		} `json:"issues"`
	}
	if err := json.Unmarshal(result.SonarQube, &sonar); err != nil {
		t.Fatal(err)
	}
	if len(sonar.Rules) != 2 || len(sonar.Issues) != 2 {
		t.Fatalf("Sonar counts = %d/%d, want 2/2", len(sonar.Rules), len(sonar.Issues))
	}
	ids := make(map[string]bool)
	var severities []string
	for _, rule := range sonar.Rules {
		if rule.EngineID != "trivy" || rule.Type != "VULNERABILITY" || len(rule.Impacts) != 1 || rule.Impacts[0].SoftwareQuality != "SECURITY" {
			t.Fatalf("invalid Sonar rule %+v", rule)
		}
		ids[rule.ID] = true
		severities = append(severities, rule.Severity+"/"+rule.Impacts[0].Severity)
	}
	slices.Sort(severities)
	if !slices.Equal(severities, []string{"BLOCKER/HIGH", "INFO/LOW"}) {
		t.Errorf("severity mapping = %v", severities)
	}
	for _, issue := range sonar.Issues {
		if !ids[issue.RuleID] || issue.Type != "" || issue.Severity != "" || issue.PrimaryLocation.FilePath != "package-lock.json" || issue.PrimaryLocation.TextRange != nil {
			t.Errorf("invalid Sonar issue %+v", issue)
		}
	}
	if !bytes.Contains(result.SonarQube, []byte("unknown")) {
		t.Error("unknown severity is not explained")
	}
}

func TestTrivyReportsCleanArrays(t *testing.T) {
	input := trivyReportsInput(`[{"Name":"is-number","Version":"7.0.0"}]`, `[]`)
	result, err := buildTrivyReports(input, []string{"package-lock.json"})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.SonarQube) != `{"rules":[],"issues":[]}` {
		t.Errorf("clean Sonar report = %s", result.SonarQube)
	}
	if bytes.Contains(result.CycloneDX, []byte(`"dependsOn":[]`)) {
		t.Error("unknown dependencies were asserted empty")
	}
}

func TestTrivyReportsRejectUnsafeOrIncompleteData(t *testing.T) {
	base := string(trivyReportsInput(`[{"ID":"pkg","Name":"lodash","Version":"4.17.20"}]`, `[]`))
	for name, input := range map[string]string{
		"unselected target":        strings.Replace(base, "package-lock.json", "other/package-lock.json", 1),
		"traversal":                strings.Replace(base, "package-lock.json", "../package-lock.json", 1),
		"encoded control":          strings.Replace(base, "package-lock.json", "package%09-lock.json", 1),
		"identity url":             strings.Replace(base, `"Name":"lodash"`, `"Name":"https://user:canary@example.test/pkg"`, 1),
		"encoded identity":         strings.Replace(base, `"Name":"lodash"`, `"Name":"lodash%0Acanary"`, 1),
		"version url":              strings.Replace(base, `"Version":"4.17.20"`, `"Version":"https://example.test/pkg"`, 1),
		"dangling edge":            strings.Replace(base, `"ID":"pkg"`, `"ID":"pkg","DependsOn":["missing"]`, 1),
		"ambiguous id":             string(trivyReportsInput(`[{"ID":"pkg","Name":"lodash","Version":"4.17.20"},{"ID":"pkg","Name":"is-number","Version":"7.0.0"}]`, `[]`)),
		"missing inventory":        string(trivyReportsInput(`[]`, `[]`)),
		"advisory without package": string(trivyReportsInput(`[{"Name":"is-number","Version":"7.0.0"}]`, `[{"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20","Severity":"HIGH"}]`)),
	} {
		t.Run(name, func(t *testing.T) {
			if result, err := buildTrivyReports([]byte(input), []string{"package-lock.json"}); err == nil || result != nil {
				t.Fatalf("unsafe input accepted: result=%v error=%v", result, err)
			}
		})
	}
}

func TestTrivyReportsPackageURLs(t *testing.T) {
	for _, tc := range []struct{ ecosystem, name, version, purl string }{
		{"npm", "@Example/Package", "1.0.0+build", "pkg:npm/%40example/package@1.0.0%2Bbuild"},
		{"gomod", "github.com/Example/Module/v2", "v2.0.0", "pkg:golang/github.com/Example/Module/v2@v2.0.0"},
		{"pip", "Example_Package.Name", "1.0", "pkg:pypi/example-package-name@1.0"},
		{"maven", "org.example:library", "1.0", "pkg:maven/org.example/library@1.0"},
		{"nuget", "Example.Library", "1.0", "pkg:nuget/example.library@1.0"},
		{"composer", "Example/Library", "1.0", "pkg:composer/example/library@1.0"},
		{"gem", "example_library", "1.0", "pkg:gem/example_library@1.0"},
		{"cargo", "example-library", "1.0", "pkg:cargo/example-library@1.0"},
	} {
		t.Run(tc.ecosystem, func(t *testing.T) {
			input := string(trivyReportsInput(`[{"Name":"`+tc.name+`","Version":"`+tc.version+`"}]`, `[]`))
			input = strings.Replace(input, `"Type":"npm"`, `"Type":"`+tc.ecosystem+`"`, 1)
			result, err := buildTrivyReports([]byte(input), []string{"package-lock.json"})
			if err != nil {
				t.Fatal(err)
			}
			var bom struct{ Components []struct{ PURL string } }
			if err := json.Unmarshal(result.CycloneDX, &bom); err != nil {
				t.Fatal(err)
			}
			if len(bom.Components) != 1 || bom.Components[0].PURL != tc.purl {
				t.Errorf("components = %+v, want purl %q", bom.Components, tc.purl)
			}
		})
	}
}

func TestTrivyReportsComposerBranchVersion(t *testing.T) {
	input := string(trivyReportsInput(`[{"Name":"example/library","Version":"dev-feature/my-feature"}]`, `[]`))
	input = strings.Replace(input, `"Type":"npm"`, `"Type":"composer"`, 1)
	input = strings.Replace(input, "package-lock.json", "composer.lock", 1)
	result, err := buildTrivyReports([]byte(input), []string{"composer.lock"})
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Components []struct{ Version, PURL string }
	}
	if err := json.Unmarshal(result.CycloneDX, &bom); err != nil {
		t.Fatal(err)
	}
	if len(bom.Components) != 1 || bom.Components[0].Version != "dev-feature/my-feature" || bom.Components[0].PURL != "pkg:composer/example/library@dev-feature%2Fmy-feature" {
		t.Errorf("Composer branch component = %+v, want preserved version with escaped PURL slash", bom.Components)
	}
	for _, version := range []string{"https://example.test/pkg", "//user@example.test/pkg", "dev-feature%2Fmy-feature", "dev-feature\nmy-feature"} {
		t.Run(version, func(t *testing.T) {
			encoded, err := json.Marshal(version)
			if err != nil {
				t.Fatal(err)
			}
			unsafe := strings.Replace(input, `"dev-feature/my-feature"`, string(encoded), 1)
			if got, err := buildTrivyReports([]byte(unsafe), []string{"composer.lock"}); err == nil || got != nil {
				t.Fatalf("unsafe Composer version accepted: result=%v error=%v", got, err)
			}
		})
	}
}

func TestTrivyReportsInputOrderAndRepeatedIDs(t *testing.T) {
	packages := []string{
		`{"ID":"a","Name":"library-a","Version":"1.0","DependsOn":["b","b"]}`,
		`{"ID":"b","Name":"library-b","Version":"2.0"}`,
		`{"ID":"b","Name":"library-b","Version":"2.0"}`,
	}
	vulnerabilities := []string{
		`{"VulnerabilityID":"CVE-2026-1000","PkgName":"library-a","InstalledVersion":"1.0","Severity":"LOW"}`,
		`{"VulnerabilityID":"CVE-2026-2000","PkgName":"library-b","InstalledVersion":"2.0","Severity":"MEDIUM"}`,
	}
	first, err := buildTrivyReports(trivyReportsInput("["+strings.Join(packages, ",")+"]", "["+strings.Join(vulnerabilities, ",")+"]"), []string{"package-lock.json"})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(packages)
	slices.Reverse(vulnerabilities)
	second, err := buildTrivyReports(trivyReportsInput("["+strings.Join(packages, ",")+"]", "["+strings.Join(vulnerabilities, ",")+"]"), []string{"package-lock.json"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.CycloneDX, second.CycloneDX) || !bytes.Equal(first.SonarQube, second.SonarQube) {
		t.Fatal("input order changed exports")
	}
	var bom struct {
		Dependencies []struct {
			Ref       string
			DependsOn []string
		}
	}
	if err := json.Unmarshal(first.CycloneDX, &bom); err != nil {
		t.Fatal(err)
	}
	if len(bom.Dependencies) != 1 || !slices.Equal(bom.Dependencies[0].DependsOn, []string{"pkg:npm/library-b@2.0"}) {
		t.Errorf("duplicate edges remained: %+v", bom.Dependencies)
	}
}
