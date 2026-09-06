package scanner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/opengrep"
	"github.com/sagolubev/secscan/internal/progress"
	"github.com/sagolubev/secscan/internal/report"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCodeArgsOffline(t *testing.T) {
	for _, name := range []string{"semgrep", "bearer", "cppcheck"} {
		args := strings.Join(CodeArgs(name, "sha256:abc", "/staged", "/out", "/rules"), " ")
		for _, want := range []string{"--pull never", "--network none", "--read-only", "--cap-drop ALL", "no-new-privileges"} {
			if !strings.Contains(args, want) {
				t.Errorf("CodeArgs(%s) lacks %s", name, want)
			}
		}
		if strings.Contains(args, "--platform") {
			t.Fatal("emulation override")
		}
		if name == "bearer" {
			for _, want := range []string{"--disable-default-rules", "--disable-domain-resolution", "--disable-version-check", "--no-extract", "--config-file /dev/null", "--ignore-file=", "--external-rule-dir /rules"} {
				if !strings.Contains(args, want) {
					t.Errorf("Bearer args lack %s", want)
				}
			}
		}
	}
}

func TestBearerSkipsServerArm64(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "docker")
	script := `#!/bin/sh
if [ "$1" = version ]; then printf '{"Arch":"arm64"}'; exit 0; fi
exit 99
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	result, findings, err := ScanCode(context.Background(), container.Runtime{Binary: binary}, Cache{Root: dir}, "bearer", dir, []string{"app.py"}, func(progress.Event) {})
	if err != nil || result.Status != "skipped" || len(findings) != 0 || !strings.Contains(strings.Join(result.Limitations, " "), "unsupported_runtime_arch") {
		t.Fatalf("ScanCode Bearer arm64 = %#v,%v,%v", result, findings, err)
	}
}

func TestExtractRulesRejectsUnsafeArchives(t *testing.T) {
	for _, test := range []struct {
		name string
		kind byte
	}{{"../outside", tar.TypeReg}, {"/absolute", tar.TypeReg}, {"root/rules/python/linked.yml", tar.TypeSymlink}, {"root/rules/python/hard.yml", tar.TypeLink}} {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: test.name, Mode: 0600, Typeflag: test.kind, Linkname: "/etc/passwd"}); err != nil {
			t.Fatal(err)
		}
		tw.Close()
		gz.Close()
		archive := filepath.Join(t.TempDir(), "rules.tar.gz")
		os.WriteFile(archive, buf.Bytes(), 0600)
		if err := extractBearerRules(archive, t.TempDir()); err == nil {
			t.Errorf("extractBearerRules accepted %s type %d", test.name, test.kind)
		}
	}
}

func TestStaticAssetsPublicationAndIntegrity(t *testing.T) {
	cache := Cache{Root: t.TempDir()}
	err := cache.Update(context.Background(), func(_ context.Context, stage string) (map[string]Asset, error) {
		path := filepath.Join(stage, "rules.tar.gz")
		if err := os.WriteFile(path, []byte("synthetic static rules"), 0600); err != nil {
			return nil, err
		}
		old := time.Now().Add(-90 * 24 * time.Hour)
		os.Chtimes(path, old, old)
		digest, err := Digest(path)
		if err != nil {
			return nil, err
		}
		return map[string]Asset{"synthetic": {ImageID: "sha256:" + strings.Repeat("a", 64), Static: map[string]StaticFile{"rules": {Path: "rules.tar.gz", Digest: digest}}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := cache.Load()
	if err != nil {
		t.Fatal(err)
	}
	file := manifest["synthetic"].Static["rules"]
	if err := verifyStatic(cache.Root, file); err != nil {
		t.Fatalf("static rules must not expire: %v", err)
	}
	path := filepath.Join(cache.Root, file.Path)
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyStatic(cache.Root, file); err == nil {
		t.Fatal("tampered rules accepted")
	}
	os.Remove(path)
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), path); err != nil {
		t.Fatal(err)
	}
	if err := verifyStatic(cache.Root, file); err == nil {
		t.Fatal("rule symlink accepted")
	}
}

func TestRuntimeArchitectureServerJSON(t *testing.T) {
	for _, test := range []struct{ binary, data, want string }{{"docker", `{"Arch":"x86_64"}`, "amd64"}, {"podman", `{"host":{"arch":"aarch64"}}`, "arm64"}, {"docker", `{"Client":{"Arch":"amd64"}}`, ""}} {
		binary := filepath.Join(t.TempDir(), test.binary)
		if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s' '"+test.data+"'\n"), 0700); err != nil {
			t.Fatal(err)
		}
		got, err := RuntimeArchitecture(context.Background(), container.Runtime{Binary: binary})
		if got != test.want || (err != nil) != (test.want == "") {
			t.Errorf("RuntimeArchitecture(%s)=%q,%v want %q", test.data, got, err, test.want)
		}
	}
}

func TestAcceptanceCodeScanners(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(filepath.Join(base, "secscan"), "code-acceptance-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	for _, language := range []string{"python", "typescript"} {
		source := filepath.Join("..", "..", "scanner", "opengrep", "testdata", language)
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(source, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, entry.Name()), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, data := range map[string]string{"unsafe.cpp": "int main(){ int *p=0; return *p; }\n", "safe.cpp": "int main(){ int value=1; return value; }\n", "Makefile": "all:\n\ttouch EXECUTED\n", "bearer.yml": "invalid configuration", ".semgrepignore": "*\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cache := Cache{Root: filepath.Join(root, "prepared")}
	if err := Update(ctx, runtime, cache, []string{"semgrep", "cppcheck", "python-sast"}, root); err != nil {
		t.Fatal(err)
	}
	inventory, err := discovery.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	files := append(append([]string(nil), inventory.Python...), inventory.TypeScript...)
	semgrep, findings, err := ScanCode(ctx, runtime, cache, "semgrep", root, files, func(progress.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if semgrep.RuleCount != 8 || len(findings) != 8 {
		t.Fatalf("Semgrep=%#v findings=%#v", semgrep, findings)
	}
	opAsset, err := cache.Resolve(ctx, runtime, "opengrep")
	if err != nil {
		t.Fatal(err)
	}
	for _, language := range []struct {
		name  string
		files []string
	}{{"python", inventory.Python}, {"typescript", inventory.TypeScript}} {
		target, err := discovery.Stage(root, language.files)
		if err != nil {
			t.Fatal(err)
		}
		_, more, err := opengrep.Scan(ctx, runtime, opAsset.ImageID, language.name, target, len(language.files), func(progress.Event) {})
		os.RemoveAll(target)
		if err != nil {
			t.Fatal(err)
		}
		findings = append(findings, more...)
	}
	merged := report.Normalize(findings)
	if len(merged) != 8 {
		t.Fatalf("merged findings=%#v, want 8", merged)
	}
	for _, f := range merged {
		if !slices.Equal(f.Sources, []string{"opengrep", "semgrep"}) {
			t.Fatalf("shared sources=%#v", f)
		}
	}
	cpp, findings, err := ScanCode(ctx, runtime, cache, "cppcheck", root, inventory.Cppcheck, func(progress.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if cpp.Coverage.Read != 2 || len(findings) != 1 || findings[0].RuleID != "nullPointer" || findings[0].Path != "unsafe.cpp" {
		t.Fatalf("Cppcheck=%#v findings=%#v", cpp, findings)
	}
	if err := os.WriteFile(filepath.Join(root, "broken.cpp"), []byte("int main( {"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ScanCode(ctx, runtime, cache, "cppcheck", root, []string{"broken.cpp"}, func(progress.Event) {}); err == nil {
		t.Fatal("Cppcheck syntax failure reported success")
	}
	for _, extension := range []string{"h", "hh", "hpp", "hxx"} {
		header := "unsafe." + extension
		if err := os.WriteFile(filepath.Join(root, header), []byte("inline int unsafe_header(){ int *p=0; return *p; }\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, selected := range [][]string{{header}, {"safe.cpp", header}} {
			result, got, err := ScanCode(ctx, runtime, cache, "cppcheck", root, selected, func(progress.Event) {})
			if err != nil || result.Coverage.Read != len(selected) || len(got) != 1 || got[0].Path != header || got[0].RuleID != "nullPointer" {
				t.Fatalf("Cppcheck explicit headers %q: scanner=%#v findings=%#v err=%v", selected, result, got, err)
			}
		}
	}
	cppAsset, err := cache.Resolve(ctx, runtime, "cppcheck")
	if err != nil {
		t.Fatal(err)
	}
	created, err := runtime.Output(ctx, "create", "--network", "none", cppAsset.ImageID, "--version")
	if err != nil {
		t.Fatal(err)
	}
	containerID := strings.TrimSpace(string(created))
	defer runtime.Run(context.Background(), []string{"rm", "-f", containerID})
	for _, path := range []string{"/usr/src/cppcheck.tar.gz", "/usr/src/Dockerfile", "/usr/share/licenses/cppcheck/COPYING", "/usr/share/licenses/cppcheck/GCC-COPYING.RUNTIME"} {
		local := filepath.Join(root, "image-"+filepath.Base(path))
		if err := runtime.Run(ctx, []string{"cp", containerID + ":" + path, local}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(local)
		if err != nil || info.Size() == 0 {
			t.Fatalf("missing packaged %s: %v", path, err)
		}
		if strings.HasSuffix(path, "cppcheck.tar.gz") {
			digest, err := Digest(local)
			if err != nil || digest != cppcheckSourceDigest {
				t.Fatalf("packaged source digest=%s,%v", digest, err)
			}
		}
		if strings.HasSuffix(path, "Dockerfile") {
			data, err := os.ReadFile(local)
			if err != nil || !bytes.Contains(data, []byte(cppcheckSourceDigest)) {
				t.Fatal("packaged recipe does not pin matching source")
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "EXECUTED")); !os.IsNotExist(err) {
		t.Fatal("project build executed")
	}
	// Downloads and validates private static rules only; never executes Bearer on arm64.
	ruleStage := filepath.Join(root, "rule-stage")
	if err := os.MkdirAll(ruleStage, 0700); err != nil {
		t.Fatal(err)
	}
	assets, _, err := prepareCodeAssets(ctx, runtime, "bearer", ruleStage)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCodeAssets(ruleStage, "bearer", Asset{Static: assets}); err != nil {
		t.Fatal(err)
	}
	arch, err := RuntimeArchitecture(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if arch != "amd64" {
		result, _, err := ScanCode(ctx, runtime, cache, "bearer", root, inventory.Bearer, func(progress.Event) {})
		if err != nil || result.Status != "skipped" {
			t.Fatalf("native Bearer skip=%#v %v", result, err)
		}
	}
}

func TestAcceptanceBearerNativeAMD64(t *testing.T) {
	if os.Getenv("SECSCAN_BEARER_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_BEARER_ACCEPTANCE=1 on native amd64")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	arch, err := RuntimeArchitecture(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if arch != "amd64" {
		t.Skip("upstream Bearer has no native image; emulation forbidden")
	}
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(filepath.Join(base, "secscan"), "bearer-acceptance-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "unsafe.py"), []byte("import pickle\ndef load(data):\n    return pickle.loads(data)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cache := Cache{Root: filepath.Join(root, "cache")}
	if err := Update(ctx, runtime, cache, []string{"bearer"}, root); err != nil {
		t.Fatal(err)
	}
	result, findings, err := ScanCode(ctx, runtime, cache, "bearer", root, []string{"unsafe.py"}, func(progress.Event) {})
	if err != nil || result.Status != "success" || len(findings) == 0 || result.Coverage.Read != 1 || result.Coverage.Unread != 0 {
		t.Fatalf("Bearer native acceptance=%#v findings=%#v err=%v", result, findings, err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe.py"), []byte("print('hello')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, findings, err = ScanCode(ctx, runtime, cache, "bearer", root, []string{"safe.py"}, func(progress.Event) {})
	if err == nil || result.Status == "success" || !strings.Contains(err.Error(), "coverage_unconfirmed") {
		t.Fatalf("Bearer empty evidence must fail: scanner=%#v findings=%#v err=%v", result, findings, err)
	}
}

func TestParseCodeSARIFDeduplicatesLocations(t *testing.T) {
	data := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Cppcheck","semanticVersion":"2.21.1"}},"results":[{"ruleId":"nullPointer","locations":[{"physicalLocation":{"artifactLocation":{"uri":"/target/test.cpp"},"region":{"startLine":1}}},{"physicalLocation":{"artifactLocation":{"uri":"/target/test.cpp"},"region":{"startLine":1}}}]}]}]}`)
	got, err := parseCodeSARIF(data, "cppcheck")
	if err != nil || len(got) != 1 {
		t.Fatalf("parseCodeSARIF duplicate source line=%#v,%v", got, err)
	}
	if _, err := parseCodeSARIF(bytes.ReplaceAll(data, []byte("nullPointer"), []byte("syntaxError")), "cppcheck"); err == nil {
		t.Fatal("Cppcheck syntax failure accepted")
	}
}

func TestCodeAssetsRejectMissingOrChangedPins(t *testing.T) {
	for _, name := range []string{"bearer", "cppcheck"} {
		if err := verifyCodeAssets(t.TempDir(), name, Asset{}); err == nil {
			t.Errorf("verifyCodeAssets(%s) accepted missing pins", name)
		}
		asset := Asset{Static: map[string]StaticFile{"rules": {Digest: strings.Repeat("f", 64)}, "source": {Digest: strings.Repeat("f", 64)}}}
		if err := verifyCodeAssets(t.TempDir(), name, asset); err == nil {
			t.Errorf("verifyCodeAssets(%s) accepted changed pin", name)
		}
	}
}

func TestBearerSourceSARIFContract(t *testing.T) {
	clean := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Bearer","rules":[{"id":"python_lang_pickle"}]}},"results":null}]}`)
	findings, err := parseCodeSARIF(clean, "bearer")
	if err != nil || len(findings) != 0 {
		t.Fatalf("Bearer clean SARIF=%#v,%v", findings, err)
	}
	for _, bad := range [][]byte{bytes.ReplaceAll(clean, []byte(`,"results":null`), nil), bytes.ReplaceAll(clean, []byte(`[{"id":"python_lang_pickle"}]`), []byte(`[]`))} {
		if _, err := parseCodeSARIF(bad, "bearer"); err == nil {
			t.Fatal("Bearer incomplete SARIF accepted")
		}
	}
	positive := bytes.ReplaceAll(clean, []byte(`"results":null`), []byte(`"results":[{"ruleId":"python_lang_pickle","message":{"text":"SOURCE_CANARY"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/target/app.py"},"region":{"startLine":1}}}]}]`))
	findings, err = parseCodeSARIF(positive, "bearer")
	if err != nil || len(findings) != 1 || findings[0].Severity != "unknown" || strings.Contains(findings[0].Message, "CANARY") {
		t.Fatalf("Bearer result=%#v,%v", findings, err)
	}
}

func TestCodeReportRejectsSymlinkAndOversize(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "result.sarif")
	if _, err := readCodeReport(path); err == nil {
		t.Fatal("missing report accepted")
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readCodeReport(path); err == nil {
		t.Fatal("report symlink accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readCodeReport(path); err == nil {
		t.Fatal("oversized report accepted")
	}
}

func TestBearerCoverageRequiresPositiveEvidence(t *testing.T) {
	files := []string{"app.py", "bundle.min.js", "bundle-min.js", "large.js", "tests/test_app.py"}
	empty := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Bearer","rules":[{"id":"python_lang_pickle"}]}},"results":null}]}`)
	findings, err := parseCodeSARIF(empty, "bearer")
	if err != nil {
		t.Fatal(err)
	}
	got, err := codeCoverage("bearer", files, findings)
	if err == nil || !strings.Contains(err.Error(), "coverage_unconfirmed") || got.Read != 0 {
		t.Fatalf("empty Bearer coverage=%#v,%v, want no-analysis failure", got, err)
	}
	findings = []report.Finding{{Path: "app.py"}, {Path: "app.py"}, {Path: "tests/test_app.py"}}
	got, err = codeCoverage("bearer", files, findings)
	if err != nil || got.Read != 2 || !slices.Equal(got.ReadInputs, []string{"app.py", "tests/test_app.py"}) || got.Unread != 3 || !slices.Equal(got.UnreadInputs, files[1:4]) {
		t.Fatalf("partial Bearer coverage=%#v,%v", got, err)
	}
	got.ReadInputs[0] = "changed"
	if files[0] != "app.py" {
		t.Fatal("coverage mutated selected inventory")
	}
	if _, err := codeCoverage("bearer", files, []report.Finding{{Path: "outside.py"}}); err == nil {
		t.Fatal("unselected finding counted as positive evidence")
	}
}

func TestCppcheckExplicitSourceArguments(t *testing.T) {
	args := CodeArgs("cppcheck", "sha256:abc", "/staged", "/out", "", "safe.cpp", "include/unsafe.hpp")
	if !slices.Equal(args[len(args)-2:], []string{"/target/safe.cpp", "/target/include/unsafe.hpp"}) {
		t.Fatalf("Cppcheck positional inputs=%q", args)
	}
}
