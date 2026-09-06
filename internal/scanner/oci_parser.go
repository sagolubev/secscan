package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/sagolubev/secscan/internal/report"
)

func parseOCIOutput(data []byte, name, configID, digest string, locations []report.Location) ([]report.Finding, int, error) {
	var findings []report.Finding
	count := 0
	add := func(pkg report.Package, severity string, ids []string) error {
		severity = strings.ToLower(severity)
		switch severity {
		case "", "unknown", "negligible":
			severity = "unknown"
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid image severity")
		}
		if len(ids) == 0 {
			return fmt.Errorf("missing image advisory")
		}
		for _, id := range ids {
			if !advisoryToken.MatchString(id) {
				return fmt.Errorf("invalid image advisory")
			}
		}
		findings = append(findings, report.Finding{Kind: "dependency", Package: &pkg, ImageDigest: digest, Advisories: ids, Locations: locations, Severity: severity, Sources: []string{name}})
		return nil
	}
	switch name {
	case "trivy":
		var input struct {
			Schema int `json:"SchemaVersion"`
			Trivy  struct {
				Version string `json:"Version"`
			} `json:"Trivy"`
			Type     string `json:"ArtifactType"`
			Artifact string `json:"ArtifactName"`
			Metadata struct {
				ID string `json:"ImageID"`
				OS struct {
					Family string `json:"Family"`
					Name   string `json:"Name"`
				} `json:"OS"`
			} `json:"Metadata"`
			Results []struct {
				Type     string `json:"Type"`
				Packages []struct {
					Name       string `json:"Name"`
					Version    string `json:"Version"`
					Identifier struct {
						PURL string `json:"PURL"`
					} `json:"Identifier"`
				} `json:"Packages"`
				Vulnerabilities []struct {
					ID         string   `json:"VulnerabilityID"`
					Aliases    []string `json:"VendorIDs"`
					Name       string   `json:"PkgName"`
					Version    string   `json:"InstalledVersion"`
					Severity   string   `json:"Severity"`
					Identifier struct {
						PURL string `json:"PURL"`
					} `json:"PkgIdentifier"`
				} `json:"Vulnerabilities"`
			} `json:"Results"`
		}
		if json.Unmarshal(data, &input) != nil || input.Schema != 2 || input.Trivy.Version != Catalog()[name].Version || input.Type != "container_image" || input.Artifact != "/repo/image.tar" || input.Metadata.ID != configID {
			return nil, 0, fmt.Errorf("invalid Trivy archive output")
		}
		for _, result := range input.Results {
			for _, item := range result.Packages {
				if _, err := imagePackage(result.Type, item.Name, item.Version, item.Identifier.PURL, input.Metadata.OS.Family, input.Metadata.OS.Name); err != nil {
					return nil, 0, err
				}
				count++
			}
			for _, v := range result.Vulnerabilities {
				pkg, err := imagePackage(result.Type, v.Name, v.Version, v.Identifier.PURL, input.Metadata.OS.Family, input.Metadata.OS.Name)
				if err != nil {
					return nil, 0, err
				}
				if err := add(pkg, v.Severity, append([]string{v.ID}, v.Aliases...)); err != nil {
					return nil, 0, err
				}
			}
		}
	case "grype":
		var input struct {
			Source struct {
				Type   string `json:"type"`
				Target struct {
					Input string `json:"userInput"`
					ID    string `json:"imageID"`
				} `json:"target"`
			} `json:"source"`
			Distro struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"distro"`
			Descriptor struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				DB      struct {
					Status struct {
						Valid bool `json:"valid"`
					} `json:"status"`
				} `json:"db"`
			} `json:"descriptor"`
			Matches []struct {
				Vulnerability struct {
					ID       string `json:"id"`
					Severity string `json:"severity"`
				} `json:"vulnerability"`
				Related []struct {
					ID string `json:"id"`
				} `json:"relatedVulnerabilities"`
				Artifact struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Type    string `json:"type"`
					PURL    string `json:"purl"`
				} `json:"artifact"`
			} `json:"matches"`
		}
		if json.Unmarshal(data, &input) != nil || input.Matches == nil || input.Source.Type != "image" || input.Source.Target.Input != "/repo/image.tar" || input.Source.Target.ID != configID || input.Descriptor.Name != "grype" || input.Descriptor.Version != Catalog()[name].Version || !input.Descriptor.DB.Status.Valid {
			return nil, 0, fmt.Errorf("invalid Grype archive output")
		}
		if len(input.Matches) == 0 {
			switch input.Distro.Name {
			case "alpine", "debian", "ubuntu", "rhel", "centos", "fedora", "amazon", "oracle", "rocky", "almalinux", "sles", "opensuse", "wolfi", "chainguard", "mariner", "azurelinux":
			default:
				return nil, 0, fmt.Errorf("Grype has no supported package or distribution evidence")
			}
		}
		count = 1 // The process boundary separately requires positive package extraction.
		for _, match := range input.Matches {
			pkg, err := imagePackage(match.Artifact.Type, match.Artifact.Name, match.Artifact.Version, match.Artifact.PURL, input.Distro.Name, input.Distro.Version)
			if err != nil {
				return nil, 0, err
			}
			ids := []string{match.Vulnerability.ID}
			for _, related := range match.Related {
				ids = append(ids, related.ID)
			}
			if err := add(pkg, match.Vulnerability.Severity, ids); err != nil {
				return nil, 0, err
			}
		}
	default:
		return nil, 0, fmt.Errorf("unsupported image scanner")
	}
	if count == 0 {
		return nil, 0, fmt.Errorf("image scanner extracted no packages")
	}
	return report.Normalize(findings), count, nil
}

func imagePackage(kind, name, version, purl, distro, distroVersion string) (report.Package, error) {
	if !dependencyToken.MatchString(name) || !dependencyToken.MatchString(version) {
		return report.Package{}, fmt.Errorf("invalid image package identity")
	}
	ecosystem := canonicalEcosystem(kind)
	if ecosystem != "" {
		return report.Package{Ecosystem: ecosystem, Name: name, Version: version, PURL: packageURL(ecosystem, name, version)}, nil
	}
	// OS packages require a typed PURL. Never fold an unknown ecosystem into a
	// language identity or silently report an unknown-only inventory as clean.
	raw, query, _ := strings.Cut(purl, "?")
	if !strings.HasPrefix(raw, "pkg:") || strings.ContainsAny(purl, "#\n\r\t") {
		return report.Package{}, fmt.Errorf("missing or invalid OS package URL")
	}
	packageType, path, ok := strings.Cut(strings.TrimPrefix(raw, "pkg:"), "/")
	if !ok || (packageType != "apk" && packageType != "deb" && packageType != "rpm") {
		return report.Package{}, fmt.Errorf("unsupported image package ecosystem")
	}
	path, encodedVersion, ok := strings.Cut(path, "@")
	if !ok {
		return report.Package{}, fmt.Errorf("unversioned image package URL")
	}
	decodedVersion, err := url.PathUnescape(encodedVersion)
	if err != nil || decodedVersion != version {
		return report.Package{}, fmt.Errorf("image package URL version mismatch")
	}
	segments := strings.Split(path, "/")
	for i, part := range segments {
		segments[i], err = url.PathUnescape(part)
		if err != nil || !dependencyToken.MatchString(segments[i]) || strings.Contains(segments[i], "/") || segments[i] == "." || segments[i] == ".." {
			return report.Package{}, fmt.Errorf("invalid OS package namespace")
		}
	}
	if segments[len(segments)-1] != name {
		return report.Package{}, fmt.Errorf("image package URL name mismatch")
	}
	qualifiers, err := url.ParseQuery(query)
	if err != nil {
		return report.Package{}, fmt.Errorf("invalid OS package qualifiers")
	}
	for key, values := range qualifiers {
		switch key {
		case "arch", "distro", "epoch", "upstream":
		default:
			return report.Package{}, fmt.Errorf("unsupported OS package qualifier")
		}
		if len(values) != 1 || !dependencyToken.MatchString(values[0]) {
			return report.Package{}, fmt.Errorf("invalid OS package qualifier")
		}
	}
	if !dependencyToken.MatchString(distro) || !dependencyToken.MatchString(distroVersion) {
		return report.Package{}, fmt.Errorf("missing OS distribution identity")
	}
	qualifiers.Set("distro", distro+"-"+distroVersion)
	if len(segments) > 1 {
		qualifiers.Set("namespace", strings.Join(segments[:len(segments)-1], "/"))
	}
	identity := report.Package{Ecosystem: packageType, Name: name, Version: version, Qualifiers: qualifiers.Encode()}
	qualifiers.Del("namespace")
	for i, part := range segments {
		segments[i] = url.PathEscape(part)
	}
	identity.PURL = "pkg:" + packageType + "/" + strings.Join(segments, "/") + "@" + url.PathEscape(version) + "?" + qualifiers.Encode()
	return identity, nil
}
