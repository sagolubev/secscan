package report

// TrivyReports holds sanitized import payloads from one Trivy dependency scan.
// Scanner excludes these bytes from the canonical JSON report.
type TrivyReports struct {
	CycloneDX []byte
	SonarQube []byte
}
