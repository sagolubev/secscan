package scanner

// Pin records an approved upstream engine reference; catalog membership alone does not imply readiness.
type Pin struct {
	Version string
	Image   string
}

// Catalog returns the finite external scanner pins.
func Catalog() map[string]Pin {
	return map[string]Pin{
		"semgrep":           {Version: "1.176.0", Image: "docker.io/semgrep/semgrep@sha256:e5ea1a270ca5557a114ae7a30a8f860cc16a924f8df85cd975688f17c7c97731"},
		"trivy":             {Version: "0.74.0", Image: "ghcr.io/aquasecurity/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"},
		"grype":             {Version: "0.118.0", Image: "ghcr.io/anchore/grype@sha256:7e89e67dea1955928a967e39e42c133f7705f50587cf640aace84a9df8aba25c"},
		"checkov":           {Version: "3.3.16", Image: "ghcr.io/bridgecrewio/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016"},
		"checkov-terraform": {Version: "3.3.16", Image: "ghcr.io/bridgecrewio/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016"},
		"osv-scanner":       {Version: "2.5.1", Image: "ghcr.io/google/osv-scanner@sha256:8108ae94eadea5a02c9bec6e646909d5b790b44bd62d7f5b7f0b1d6d0ffc7734"},
		"zizmor":            {Version: "1.30.0", Image: "ghcr.io/zizmorcore/zizmor@sha256:1ba0035c343f50e85fde29beb0d78e4db448eaa0c762a11a09805d241424ee03"},
		"bearer":            {Version: "2.1.1", Image: "ghcr.io/bearer/bearer@sha256:41cadcaecee6330b1567b2bf5df9c2342817f68c82418a1a3d888496b92fe426"},
		"kics":              {Version: "2.1.20", Image: "docker.io/checkmarx/kics@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602"},
		"poutine":           {Version: "1.1.6", Image: "ghcr.io/boostsecurityio/poutine@sha256:722a8e0999b583c1540fe2974e691032b2d9d21b9256a17965132b6bfd0081b0"},
	}
}
