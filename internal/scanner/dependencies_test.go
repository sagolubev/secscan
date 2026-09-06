package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
)

func TestParseDependencies(t *testing.T) {
	samples := map[string]string{
		"trivy":       `{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},"ArtifactType":"filesystem","Results":[{"Target":"package-lock.json","Type":"npm","Packages":[{"Name":"lodash","Version":"4.17.20"}],"Vulnerabilities":[{"VulnerabilityID":"CVE-2021-23337","VendorIDs":["GHSA-35jh-r3h4-6jhm"],"PkgName":"lodash","InstalledVersion":"4.17.20","Severity":"HIGH","Description":"SYNTHETIC_CANARY"}]}]}`,
		"grype":       `{"matches":[{"vulnerability":{"id":"CVE-2021-23337","severity":"High","description":"SYNTHETIC_CANARY"},"relatedVulnerabilities":[{"id":"GHSA-35jh-r3h4-6jhm"}],"artifact":{"name":"lodash","version":"4.17.20","type":"npm","locations":[{"path":"/package-lock.json"}]}}],"source":{"type":"directory","target":"/repo"},"descriptor":{"name":"grype","version":"0.118.0","db":{"status":{"valid":true}}}}`,
		"osv-scanner": `{"results":[{"source":{"path":"/repo/package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"lodash","version":"4.17.20","ecosystem":"npm"},"groups":[{"ids":["GHSA-35jh-r3h4-6jhm"],"aliases":["CVE-2021-23337"],"max_severity":"8.1"}],"vulnerabilities":[{"details":"SYNTHETIC_CANARY"}]}]}]}`,
	}
	var all []report.Finding
	for name, sample := range samples {
		findings, count, err := ParseDependencies([]byte(sample), name)
		if err != nil || len(findings) != 1 || count < 1 {
			t.Fatalf("%s: findings=%#v count=%d err=%v", name, findings, count, err)
		}
		data, _ := json.Marshal(findings)
		if strings.Contains(string(data), "SYNTHETIC_CANARY") {
			t.Fatal("raw text leaked")
		}
		all = append(all, findings...)
		for _, bad := range []string{"null", "{}", strings.ReplaceAll(sample, "package-lock.json", "../outside"), strings.ReplaceAll(sample, "4.17.20", "bad\\nversion")} {
			if _, _, err := ParseDependencies([]byte(bad), name); err == nil {
				t.Errorf("%s accepted invalid output", name)
			}
		}
	}
	merged := report.Normalize(all)
	if len(merged) != 1 || len(merged[0].Sources) != 3 {
		t.Fatalf("cross scanner merge=%#v", merged)
	}
}

func TestDependencyArgsBoundary(t *testing.T) {
	for _, name := range []string{"trivy", "grype", "osv-scanner"} {
		args := strings.Join(DependencyArgs(name, "sha256:"+strings.Repeat("a", 64), "/target", "/feeds", []string{"package-lock.json"}), " ")
		for _, flag := range []string{"--pull never", "--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "dst=/repo,readonly", "dst=/cache,readonly"} {
			if !strings.Contains(args, flag) {
				t.Errorf("%s missing %s", name, flag)
			}
		}
		if name == "osv-scanner" && (!strings.Contains(args, "--all-packages") || !strings.Contains(args, "--no-call-analysis all")) {
			t.Fatal("OSV lacks bounded source analysis")
		}
	}
}

func TestDependencyInputSelection(t *testing.T) {
	files, unread := DependencyInputs([]string{"package-lock.json", "build.gradle.kts", "package.json", "requirements.txt"})
	if len(files) != 2 || len(unread) != 2 {
		t.Fatalf("selected=%v unread=%v", files, unread)
	}
}

func TestAcceptanceDependencies(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	write := func(name, version string) {
		t.Helper()
		data := fmt.Sprintf(`{"name":"synthetic","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"synthetic","version":"1.0.0"},"node_modules/%s":{"version":"%s"}}}`, name, version)
		if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("lodash", "4.17.20")
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	cache := Cache{Root: filepath.Join(cacheRoot, "secscan", "acceptance-dependencies")}
	names := []string{"trivy", "grype", "osv-scanner"}
	prepared := true
	for _, name := range names {
		asset, err := cache.Resolve(ctx, runtime, name)
		if err != nil {
			prepared = false
			break
		}
		if _, err := dependencyFeedRoot(cache, name, asset, []string{"package-lock.json"}); err != nil {
			prepared = false
			break
		}
	}
	if !prepared {
		if err := Update(ctx, runtime, cache, names, root); err != nil {
			t.Fatal(err)
		}
	}
	var all []report.Finding
	for _, name := range names {
		result, findings, err := ScanDependencies(ctx, runtime, cache, name, root, []string{"package-lock.json"}, func(progress.Event) {})
		if err != nil || len(findings) == 0 || result.Coverage.Read == 0 {
			t.Fatalf("vulnerable %s: %#v findings=%d err=%v", name, result, len(findings), err)
		}
		all = append(all, findings...)
	}
	merged := report.Normalize(all)
	found := false
	for _, f := range merged {
		if len(f.Sources) == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing all-engine merged finding: %#v", merged)
	}
	write("is-number", "7.0.0")
	for _, name := range names {
		result, findings, err := ScanDependencies(ctx, runtime, cache, name, root, []string{"package-lock.json"}, func(progress.Event) {})
		if err != nil || len(findings) != 0 || result.Coverage.Read == 0 {
			t.Fatalf("clean %s: %#v findings=%d err=%v", name, result, len(findings), err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"trivy", "grype"} {
		result, findings, err := ScanDependencies(ctx, runtime, cache, name, root, []string{"package-lock.json", "requirements.txt"}, func(progress.Event) {})
		unresolved := append(append([]string(nil), result.Coverage.UnreadInputs...), result.Coverage.FailedInputs...)
		if err != nil || len(findings) != 0 || result.Coverage.Read == 0 || !slices.Contains(unresolved, "requirements.txt") {
			t.Errorf("mixed unresolved %s: coverage=%#v findings=%d err=%v", name, result.Coverage, len(findings), err)
		}
	}
	write("lodash", "4.17.20")
	for _, name := range []string{"trivy", "grype"} {
		result, findings, err := ScanDependencies(ctx, runtime, cache, name, root, []string{"package-lock.json", "requirements.txt"}, func(progress.Event) {})
		unresolved := append(append([]string(nil), result.Coverage.UnreadInputs...), result.Coverage.FailedInputs...)
		if err != nil || len(findings) == 0 || !slices.Contains(result.Coverage.ReadInputs, "package-lock.json") || !slices.Contains(unresolved, "requirements.txt") {
			t.Errorf("mixed vulnerable %s lost findings or coverage: result=%#v findings=%d err=%v", name, result, len(findings), err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"broken":`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, _, err := ScanDependencies(ctx, runtime, cache, name, root, []string{"package-lock.json"}, func(progress.Event) {}); err == nil {
			t.Errorf("%s accepted malformed lockfile", name)
		}
	}
	write("lodash", "4.17.20")
	for _, name := range names {
		if _, _, err := ScanDependencies(ctx, runtime, Cache{Root: t.TempDir()}, name, root, []string{"package-lock.json"}, func(progress.Event) {}); err == nil {
			t.Errorf("%s accepted missing cache", name)
		}
	}
	asset, err := cache.Resolve(ctx, runtime, "osv-scanner")
	if err != nil {
		t.Fatal(err)
	}
	broken := Cache{Root: t.TempDir()}
	asset.Feeds = map[string]Feed{"osv-scalibr/npm/all.zip": {Path: "generation-test/osv-scanner/osv-scalibr/npm/all.zip", Digest: strings.Repeat("0", 64), AcquiredAt: time.Now().UTC()}}
	target := filepath.Join(broken.Root, asset.Feeds["osv-scalibr/npm/all.zip"].Path)
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]Asset{"osv-scanner": asset})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken.Root, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ScanDependencies(ctx, runtime, broken, "osv-scanner", root, []string{"package-lock.json"}, func(progress.Event) {}); err == nil {
		t.Fatal("accepted corrupted feed")
	}
}

func TestDependencyOperationalExitWithValidJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"node_modules/synthetic":{"version":"1"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cache := Cache{Root: t.TempDir()}
	id := "sha256:" + strings.Repeat("a", 64)
	if err := cache.Update(context.Background(), func(_ context.Context, stage string) (map[string]Asset, error) {
		path := filepath.Join(stage, "osv-scanner/osv-scalibr/npm/all.zip")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte("synthetic database"), 0600); err != nil {
			return nil, err
		}
		feed, err := snapshotFeed(stage, path, time.Now().UTC())
		return map[string]Asset{"osv-scanner": {ImageID: id, ImageRef: Catalog()["osv-scanner"].Image, Feeds: map[string]Feed{"osv-scalibr/npm/all.zip": feed}}}, err
	}); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "runtime")
	script := `#!/bin/sh
if [ "$1" = image ]; then printf '%s\n' "$SECSCAN_TEST_IMAGE_ID"; exit 0; fi
printf '%s\n' "$SECSCAN_TEST_RESULT"
printf '%s\n' "SYNTHETIC_CANARY" >&2
exit "$SECSCAN_TEST_EXIT"
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSCAN_TEST_IMAGE_ID", id)
	t.Setenv("SECSCAN_TEST_RESULT", `{"results":[{"source":{"path":"/repo/package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"synthetic","version":"1","ecosystem":"npm"}}]}]}`)
	for _, code := range []string{"1", "127"} {
		t.Setenv("SECSCAN_TEST_EXIT", code)
		_, _, err := ScanDependencies(context.Background(), container.Runtime{Binary: binary}, cache, "osv-scanner", root, []string{"package-lock.json"}, func(progress.Event) {})
		if (err != nil) != (code == "127") {
			t.Errorf("code %s error=%v", code, err)
		}
		if err != nil && strings.Contains(err.Error(), "SYNTHETIC_CANARY") {
			t.Fatal("stderr leaked")
		}
	}
}

func TestDependencyCleanPackageValidation(t *testing.T) {
	for _, input := range []string{
		`{"results":[{"source":{"path":"/repo/package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"","version":"1","ecosystem":"npm"}}]}]}`,
		`{"results":[{"source":{"path":"/repo/package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"pkg","version":"1","ecosystem":"npm"},"groups":[{"ids":["CVE-2026-1"],"max_severity":"NaN"}]}]}]}`,
	} {
		if _, _, err := ParseDependencies([]byte(input), "osv-scanner"); err == nil {
			t.Error("accepted invalid clean identity or severity")
		}
	}
}

func TestTrivyRequiresEveryPackageIdentity(t *testing.T) {
	for _, packages := range []string{`[null]`, `[{}]`, `[{"Name":"pkg"}]`, `[{"Name":"pkg","Version":"1"},null]`} {
		input := fmt.Sprintf(`{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},"ArtifactType":"filesystem","Results":[{"Target":"package-lock.json","Type":"npm","Packages":%s}]}`, packages)
		if _, _, err := ParseDependencies([]byte(input), "trivy"); err == nil {
			t.Errorf("accepted invalid packages %s", packages)
		}
	}
	input := `{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},"ArtifactType":"filesystem","Results":[{"Target":"package-lock.json","Type":"unknown","Packages":[{"Name":"pkg","Version":"1"}]}]}`
	if _, _, err := ParseDependencies([]byte(input), "trivy"); err == nil {
		t.Fatal("accepted unknown clean ecosystem")
	}
}

func TestDependencyConfirmedInputsUseCleanPackageInventory(t *testing.T) {
	samples := map[string]string{
		"trivy":       `{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},"ArtifactType":"filesystem","Results":[{"Target":"package-lock.json","Type":"npm","Packages":[{"Name":"is-number","Version":"7.0.0"}]}]}`,
		"osv-scanner": `{"results":[{"source":{"path":"/repo/package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"is-number","version":"7.0.0","ecosystem":"npm"}}]}]}`,
	}
	for name, data := range samples {
		findings, count, read, err := parseDependencyOutput([]byte(data), name, []string{"package-lock.json", "requirements.txt"})
		if err != nil || len(findings) != 0 || count != 1 || !slices.Equal(read, []string{"package-lock.json"}) {
			t.Errorf("%s extraction findings=%v count=%d read=%v err=%v", name, findings, count, read, err)
		}
	}
}
