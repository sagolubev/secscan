# Trivy reports for Dependency-Track and SonarQube

Research date: 2026-09-06. Trivy version: `0.74.0`.
This document explains the format choices and their limits.

## Two destinations, two reports

| Destination | Report | Import mechanism |
| --- | --- | --- |
| Dependency-Track 4.12 or later | CycloneDX 1.6 JSON SBOM | Project BOM upload or `/api/v1/bom` |
| SonarQube Server | Current generic issue JSON, with `rules` and `issues` | SonarScanner property `sonar.externalIssuesReportPaths` |

Dependency-Track [added CycloneDX 1.6 ingestion in 4.12.0][dt-412].
Its [BOM endpoint][dt-cicd] accepts a file through multipart POST.
It also accepts a base64 BOM through JSON PUT.
These are import instructions, not authorization for secscan to upload data.

SonarQube [requires no plugin for generic reports][sonar-generic].
The format changed in 10.3. The export supplies SECURITY impacts for MQR Mode.
Explicit rule-level Standard severity is verified against Server 2025.1.
Older importers, including [10.3][sonar-old-importer], derive Standard severity
from impacts and ignore those explicit fields. They merge critical/high and
low/unknown into shared levels. Compatibility from 10.3 means the file imports,
not that every server displays five distinct severity levels.
The user confirmed SonarQube Server, but did not provide its version.
Compatibility with older formats remains outside this implementation.

## Dependency-Track needs the package inventory

Dependency-Track [analyzes components during BOM ingestion and on a schedule][dt-cicd].
A list of vulnerable packages omits dependencies that acquire vulnerabilities later.
The SBOM therefore needs every package that Trivy detected, including clean packages.
An empty findings list does not imply an empty SBOM.

The existing Trivy command already uses `--list-all-pkgs` for repository and
image scans. Its JSON contains package identifiers, versions and known dependency
edges. The [package model][trivy-package] stores edges in `DependsOn`, using package
`ID` values. `Relationship` distinguishes root, workspace, direct, indirect and
unknown dependencies. Not every package format supplies this graph.

CycloneDX components need stable `bom-ref` values and package identities.
Package URLs help Dependency-Track identify components.
Every exported dependency reference must resolve to an exported component.
Only observed dependency edges belong in the graph.
Missing graph information must not become invented direct dependencies or a claim
that a package has no dependencies.

The BOM and the Trivy findings serve different purposes.
Dependency-Track computes findings using its configured data sources.
A BOM upload does not guarantee that its findings match the original Trivy scan.
In Dependency-Track 4.14.0, the [BOM processor][dt-bom] imports components, services
and relationships. Its comment explicitly leaves embedded VEX/VDR synchronization
outside that operation. The proposed SBOM does not depend on embedded findings.

## Why not use `trivy convert` directly?

Trivy [supports conversion from its JSON report to CycloneDX][trivy-convert].
Its converter preserves package inventory and known dependency edges through the
[SBOM encoder][trivy-encoder]. No second vulnerability scan or database is needed.

An offline smoke test used the pinned container image already present locally:

```text
ghcr.io/aquasecurity/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969
```

The input contained three synthetic packages and two dependency edges.
The container had no network, a read-only filesystem and read-only input.
Conversion preserved all three packages and both edges. The report contained an
empty `vulnerabilities` array.

However, this Trivy version emits **CycloneDX 1.7**.
Its `convert --help` exposes no schema-version option.
Some [documentation examples][trivy-sbom] still show older schema versions.
Dependency-Track [added 1.7 support in 5.1.0][dt-510].
The [4.14.0 release uses parser 12.1.0][dt-pom], which [supports up to 1.6][cdx-java].

There is also a data boundary to preserve. Raw Trivy JSON can contain image labels,
maintainers, descriptions and other untrusted text. Writing that JSON to a temporary
file bypasses secscan's rule against serializing secret values and source snippets.

A sanitized Trivy DTO can support native conversion. It needs approved artifact
metadata, result type/class/target and package identity/relationship fields.
The converter can regenerate package UIDs. But conversion still produces 1.7 and
adds another container operation. A small CycloneDX 1.6 writer over the same sanitized
inventory avoids both costs. Go's `encoding/json` is sufficient for this limited format.

The writer is a projection of detected packages, not a new package detector.
It must preserve scoped names, multiple versions and known edges.
It must reject malformed identities or unresolved edges instead of publishing a
silently incomplete BOM. Raw URLs, free-text properties and credentials do not belong
in this projection.

## SonarQube report contract

The [current format][sonar-generic] has two arrays. Both arrays must exist, including
when the report contains no findings.

| Object | Fields used by the export |
| --- | --- |
| Rule | `id`, `name`, `description`, `engineId`, `cleanCodeAttribute`, `type`, `severity`, `impacts` |
| Impact | `softwareQuality: SECURITY`, plus its MQR severity |
| Issue | `ruleId`, `primaryLocation` |
| Primary location | `message`, repository-relative `filePath` |

Rules use `type: VULNERABILITY`. The Standard Experience severity belongs on the
rule, together with the MQR impact. This keeps security findings classified as security
findings in both instance modes.

The [validator][sonar-validator] rejects duplicate rule IDs, missing rule references,
and issue-level `type` or `severity` in the new format.
The actual JSON field is `ruleId`. The documentation's prose spells it `ruleID`
in one place, but its examples and the source use `ruleId`.

Trivy has five severity values. Current SonarQube supports five MQR levels, while
earlier versions used three. `HIGH`, `MEDIUM` and `LOW` provide a shared subset.
The export must document its mapping, retain unknown severity findings, and handle
different severities for the same advisory without an order-dependent result.

A dependency finding can refer to an entire lockfile.
`textRange` is optional, so the export must not invent line 1.
The [importer][sonar-importer] resolves each file against SonarScanner's indexed files.
It ignores findings for unknown files and reports the count in its log.
The SonarScanner analysis must include the affected manifests and lockfiles.
Container image paths cannot stand in for repository files.

SonarQube also [accepts SARIF 2.1.0][sonar-sarif], through `sonar.sarifReportPaths`.
That importer supports project-level findings without a location.
Its severity mapping differs: MQR ignores result-level severity and uses rule defaults.
Generic JSON gives this repository export an explicit security mapping and file contract.
It does not cover locationless image findings.

External issues can affect the SonarQube quality gate.
Their rules remain [managed by the external tool][sonar-about], outside quality profiles.
Marking a finding false positive in SonarQube does not update secscan.

## Checks and remaining compatibility limits

The format checks need to cover clean packages, scoped names, duplicate identities,
multiple versions, known edges, cycles, missing references and empty findings.
Security checks need synthetic secrets in discarded fields, unsafe package URLs,
path traversal and symlink escapes. Export failure must not replace an existing report.

The [official CycloneDX 1.6 schema][cdx-schema] supports an offline shape check.
Its referenced schemas must also be local and pinned.
SonarQube publishes its format and importer source, not a generic-report JSON schema
on the referenced documentation page. Tests can enforce that documented contract.

A schema check does not prove successful ingestion.
A destination check must compare imported component counts and dependency edges in
Dependency-Track, and imported issue counts in SonarQube.
This research did not upload to either service or run their server applications.
The executed runtime check covered only native Trivy conversion.

Before these choices, a local GitHub-card search found Dependency-Track itself.
Its primary documentation and source, Trivy source and SonarSource documentation
provide the evidence here. No third-party conversion package is required.

[dt-412]: https://github.com/DependencyTrack/dependency-track/releases/tag/4.12.0
[dt-510]: https://github.com/DependencyTrack/dependency-track/releases/tag/5.1.0
[dt-cicd]: https://docs.dependencytrack.org/usage/cicd/
[dt-bom]: https://github.com/DependencyTrack/dependency-track/blob/4.14.0/src/main/java/org/dependencytrack/tasks/BomUploadProcessingTask.java
[dt-pom]: https://github.com/DependencyTrack/dependency-track/blob/4.14.0/pom.xml
[cdx-java]: https://github.com/CycloneDX/cyclonedx-core-java/blob/cyclonedx-core-java-12.1.0/src/main/java/org/cyclonedx/Version.java
[cdx-schema]: https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json
[trivy-package]: https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/fanal/types/package.go
[trivy-convert]: https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/commands/convert/run.go
[trivy-encoder]: https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/sbom/io/encode.go
[trivy-sbom]: https://github.com/aquasecurity/trivy/blob/v0.74.0/docs/guide/supply-chain/sbom.md
[sonar-generic]: https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/importing-external-issues/generic-issue-import-format
[sonar-sarif]: https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/importing-external-issues/importing-issues-from-sarif-reports
[sonar-about]: https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/importing-external-issues/about-external-issues
[sonar-validator]: https://github.com/SonarSource/sonarqube/blob/25.1.0.102122/sonar-scanner-engine/src/main/java/org/sonar/scanner/externalissue/ExternalIssueReportValidator.java
[sonar-importer]: https://github.com/SonarSource/sonarqube/blob/25.1.0.102122/sonar-scanner-engine/src/main/java/org/sonar/scanner/externalissue/ExternalIssueImporter.java

[sonar-old-importer]: https://github.com/SonarSource/sonarqube/blob/10.3.0.82913/sonar-scanner-engine/src/main/java/org/sonar/scanner/externalissue/ExternalIssueImporter.java
