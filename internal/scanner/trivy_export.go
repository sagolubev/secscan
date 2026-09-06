package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/sagolubev/secscan/internal/report"
)

type trivyExportInput struct {
	Results []struct {
		Target   string `json:"Target"`
		Type     string `json:"Type"`
		Packages []struct {
			ID        string   `json:"ID"`
			Name      string   `json:"Name"`
			Version   string   `json:"Version"`
			DependsOn []string `json:"DependsOn"`
		} `json:"Packages"`
		Vulnerabilities []struct {
			ID       string `json:"VulnerabilityID"`
			Name     string `json:"PkgName"`
			Version  string `json:"InstalledVersion"`
			Severity string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyComponent struct {
	Type    string `json:"type"`
	Ref     string `json:"bom-ref"`
	Name    string `json:"name"`
	Group   string `json:"group,omitempty"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type trivyDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type trivySonarRule struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name"`
	Description        string             `json:"description"`
	EngineID           string             `json:"engineId"`
	CleanCodeAttribute string             `json:"cleanCodeAttribute"`
	Type               string             `json:"type"`
	Severity           string             `json:"severity"`
	Impacts            []trivySonarImpact `json:"impacts"`
}

type trivySonarImpact struct {
	SoftwareQuality string `json:"softwareQuality"`
	Severity        string `json:"severity"`
}

type trivySonarIssue struct {
	RuleID          string             `json:"ruleId"`
	PrimaryLocation trivySonarLocation `json:"primaryLocation"`
}

type trivySonarLocation struct {
	Message  string `json:"message"`
	FilePath string `json:"filePath"`
}

// buildTrivyReports projects allowlisted data before it crosses the scanner boundary.
func buildTrivyReports(data []byte, selected []string) (*report.TrivyReports, error) {
	if _, _, _, err := parseDependencyOutput(data, "trivy", selected); err != nil {
		return nil, err
	}
	var input trivyExportInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("invalid Trivy report data")
	}
	components := make(map[string]trivyComponent)
	edges := make(map[string][]string)
	rules := make(map[string]trivySonarRule)
	issues := make(map[trivySonarIssue]struct{})
	for _, result := range input.Results {
		target, err := TargetPath(result.Target)
		if err != nil || strings.ContainsFunc(target, unicode.IsControl) || !slices.Contains(selected, target) {
			return nil, fmt.Errorf("invalid Trivy report target")
		}
		ids := make(map[string]string)
		inventory := make(map[string]struct{})
		for _, pkg := range result.Packages {
			component, err := trivyPackageComponent(result.Type, pkg.Name, pkg.Version)
			if err != nil {
				return nil, err
			}
			if len(pkg.ID) > 4096 || strings.ContainsFunc(pkg.ID, unicode.IsControl) {
				return nil, fmt.Errorf("invalid Trivy package ID")
			}
			if prior, ok := ids[pkg.ID]; pkg.ID != "" && ok && prior != component.Ref {
				return nil, fmt.Errorf("ambiguous Trivy package ID")
			}
			if pkg.ID != "" {
				ids[pkg.ID] = component.Ref
			}
			components[component.Ref] = component
			inventory[component.Ref] = struct{}{}
		}
		for _, pkg := range result.Packages {
			if len(pkg.DependsOn) == 0 {
				continue
			}
			if pkg.ID == "" {
				return nil, fmt.Errorf("Trivy dependency source has no package ID")
			}
			for _, id := range pkg.DependsOn {
				ref, ok := ids[id]
				if !ok {
					return nil, fmt.Errorf("unresolved Trivy dependency reference")
				}
				edges[ids[pkg.ID]] = append(edges[ids[pkg.ID]], ref)
			}
		}
		for _, vulnerability := range result.Vulnerabilities {
			component, err := trivyPackageComponent(result.Type, vulnerability.Name, vulnerability.Version)
			if err != nil {
				return nil, err
			}
			if _, ok := inventory[component.Ref]; !ok {
				return nil, fmt.Errorf("Trivy vulnerability has no inventory package")
			}
			severity := strings.ToLower(vulnerability.Severity)
			if severity == "" {
				severity = "unknown"
			}
			rule := trivyRule(vulnerability.ID, severity)
			rules[rule.ID] = rule
			message := fmt.Sprintf("%s in %s@%s; Trivy severity: %s", vulnerability.ID, vulnerability.Name, vulnerability.Version, severity)
			issues[trivySonarIssue{RuleID: rule.ID, PrimaryLocation: trivySonarLocation{Message: message, FilePath: target}}] = struct{}{}
		}
	}
	bom := struct {
		Schema       string            `json:"$schema"`
		Format       string            `json:"bomFormat"`
		Spec         string            `json:"specVersion"`
		Version      int               `json:"version"`
		Components   []trivyComponent  `json:"components"`
		Dependencies []trivyDependency `json:"dependencies,omitempty"`
	}{Schema: "https://cyclonedx.org/schema/bom-1.6.schema.json", Format: "CycloneDX", Spec: "1.6", Version: 1, Components: make([]trivyComponent, 0, len(components))}
	for _, component := range components {
		bom.Components = append(bom.Components, component)
	}
	slices.SortFunc(bom.Components, func(a, b trivyComponent) int { return strings.Compare(a.Ref, b.Ref) })
	for ref, dependencies := range edges {
		slices.Sort(dependencies)
		bom.Dependencies = append(bom.Dependencies, trivyDependency{Ref: ref, DependsOn: slices.Compact(dependencies)})
	}
	slices.SortFunc(bom.Dependencies, func(a, b trivyDependency) int { return strings.Compare(a.Ref, b.Ref) })
	sonar := struct {
		Rules  []trivySonarRule  `json:"rules"`
		Issues []trivySonarIssue `json:"issues"`
	}{Rules: make([]trivySonarRule, 0, len(rules)), Issues: make([]trivySonarIssue, 0, len(issues))}
	for _, rule := range rules {
		sonar.Rules = append(sonar.Rules, rule)
	}
	slices.SortFunc(sonar.Rules, func(a, b trivySonarRule) int { return strings.Compare(a.ID, b.ID) })
	for issue := range issues {
		sonar.Issues = append(sonar.Issues, issue)
	}
	slices.SortFunc(sonar.Issues, func(a, b trivySonarIssue) int {
		if a.RuleID != b.RuleID {
			return strings.Compare(a.RuleID, b.RuleID)
		}
		if a.PrimaryLocation.FilePath != b.PrimaryLocation.FilePath {
			return strings.Compare(a.PrimaryLocation.FilePath, b.PrimaryLocation.FilePath)
		}
		return strings.Compare(a.PrimaryLocation.Message, b.PrimaryLocation.Message)
	})
	cdx, err := json.Marshal(bom)
	if err != nil {
		return nil, fmt.Errorf("encode Trivy CycloneDX: %w", err)
	}
	sonarJSON, err := json.Marshal(sonar)
	if err != nil {
		return nil, fmt.Errorf("encode Trivy SonarQube: %w", err)
	}
	return &report.TrivyReports{CycloneDX: cdx, SonarQube: sonarJSON}, nil
}

var trivyIdentityPart = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+~-]*$`)
var trivyVersion = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+~/-]*$`)
var pythonNameSeparator = regexp.MustCompile(`[-_.]+`)

func trivyPackageComponent(ecosystem, name, version string) (trivyComponent, error) {
	invalid := func() (trivyComponent, error) {
		return trivyComponent{}, fmt.Errorf("invalid Trivy export package identity")
	}
	if !trivyVersion.MatchString(version) || len(version) > 512 || len(name) > 512 {
		return invalid()
	}
	ecosystem = canonicalEcosystem(ecosystem)
	kind := map[string]string{"npm": "npm", "Go": "golang", "PyPI": "pypi", "Maven": "maven", "NuGet": "nuget", "Packagist": "composer", "RubyGems": "gem", "crates.io": "cargo"}[ecosystem]
	if kind == "" {
		return invalid()
	}
	var group string
	switch ecosystem {
	case "npm":
		name = strings.ToLower(name)
		if strings.HasPrefix(name, "@") {
			parts := strings.Split(name, "/")
			if len(parts) != 2 || !trivyIdentityPart.MatchString(strings.TrimPrefix(parts[0], "@")) {
				return invalid()
			}
			group, name = parts[0], parts[1]
		}
	case "Maven":
		parts := strings.Split(name, ":")
		if len(parts) != 2 || !trivyIdentityPart.MatchString(parts[0]) {
			return invalid()
		}
		group, name = parts[0], parts[1]
	case "Go", "Packagist":
		if ecosystem == "Packagist" {
			name = strings.ToLower(name)
		}
		parts := strings.Split(name, "/")
		if ecosystem == "Packagist" && len(parts) != 2 {
			return invalid()
		}
		for _, part := range parts {
			if !trivyIdentityPart.MatchString(part) {
				return invalid()
			}
		}
		if len(parts) > 1 {
			group, name = strings.Join(parts[:len(parts)-1], "/"), parts[len(parts)-1]
		}
	case "PyPI":
		name = pythonNameSeparator.ReplaceAllString(strings.ToLower(name), "-")
	case "NuGet":
		name = strings.ToLower(name)
	}
	if !trivyIdentityPart.MatchString(name) {
		return invalid()
	}
	segments := []string{name}
	if group != "" {
		segments = append(strings.Split(group, "/"), name)
	}
	for i, segment := range segments {
		segments[i] = url.QueryEscape(segment)
	}
	purl := "pkg:" + kind + "/" + strings.Join(segments, "/") + "@" + url.QueryEscape(version)
	return trivyComponent{Type: "library", Ref: purl, Name: name, Group: group, Version: version, PURL: purl}, nil
}

func trivyRule(id, severity string) trivySonarRule {
	standard, impact := "INFO", "LOW"
	switch severity {
	case "critical":
		standard, impact = "BLOCKER", "HIGH"
	case "high":
		standard, impact = "CRITICAL", "HIGH"
	case "medium":
		standard, impact = "MAJOR", "MEDIUM"
	case "low":
		standard = "MINOR"
	}
	return trivySonarRule{ID: id + ":" + severity, Name: id, Description: "Trivy dependency vulnerability; severity: " + severity, EngineID: "trivy", CleanCodeAttribute: "TRUSTWORTHY", Type: "VULNERABILITY", Severity: standard, Impacts: []trivySonarImpact{{SoftwareQuality: "SECURITY", Severity: impact}}}
}
