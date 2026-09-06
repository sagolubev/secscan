package scanner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/progress"
)

func TestParseCI(t *testing.T) {
	for _, name := range []string{"zizmor", "poutine"} {
		data, err := os.ReadFile("testdata/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		findings, _, err := ParseCI(data, name)
		if err != nil || len(findings) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		encoded, _ := json.Marshal(findings)
		if strings.Contains(string(encoded), "SYNTHETIC_CANARY") {
			t.Fatal("free-form output leaked")
		}
		for _, f := range findings {
			if f.Line < 1 || f.Path != ".github/workflows/ci.yml" {
				t.Fatalf("bad location: %#v", f)
			}
		}
		for _, bad := range []string{"null", "{}", "[{}]"} {
			if _, _, err := ParseCI([]byte(bad), name); err == nil {
				t.Fatalf("%s accepted %s", name, bad)
			}
		}
	}
}

func TestAcceptanceCI(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	file := ".github/workflows/ci.yml"
	if err := os.MkdirAll(filepath.Join(root, ".github/workflows"), 0700); err != nil {
		t.Fatal(err)
	}
	content := "name: unsafe\non:\n  pull_request_target:\njobs:\n  unsafe:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo \"${{ github.event.pull_request.title }}\"\n"
	if err := os.WriteFile(filepath.Join(root, file), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	// Scanner config must not suppress the staged workflow.
	if err := os.WriteFile(filepath.Join(root, ".poutine.yml"), []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	inventory, err := discovery.Discover(root)
	if err != nil || len(inventory.CI) != 1 {
		t.Fatalf("inventory=%#v err=%v", inventory, err)
	}
	cache := Cache{Root: filepath.Join(t.TempDir(), "cache")}
	if err := Update(ctx, runtime, cache, []string{"zizmor", "poutine"}, root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zizmor", "poutine"} {
		t.Run(name, func(t *testing.T) {
			result, findings, err := ScanCI(ctx, runtime, cache, name, root, inventory.CI, func(progress.Event) {})
			if err != nil {
				t.Fatal(err)
			}
			if result.Coverage.Read != 1 || len(findings) == 0 {
				t.Fatalf("result=%#v findings=%d", result, len(findings))
			}
			found := false
			for _, finding := range findings {
				if (finding.RuleID == "injection" || finding.RuleID == "template-injection") && finding.Line == 9 {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing injection at line9: %#v", findings)
			}
		})
	}

	fixtures := map[string]string{
		".gitlab-ci.yml":          "variables:\n  CI_DEBUG_TRACE: 'true'\ntest:\n  script: echo synthetic\n",
		"azure-pipelines.yml":     "pr:\n  branches:\n    include: [main]\nvariables:\n  system.debug: 'true'\njobs:\n- job: build\n  steps:\n  - script: echo synthetic\n",
		".tekton/ci.yml":          "apiVersion: tekton.dev/v1beta1\nkind: PipelineRun\nmetadata:\n  name: synthetic\n  annotations:\n    pipelinesascode.tekton.dev/on-event: '[push, pull_request]'\nspec:\n  pipelineSpec:\n    tasks:\n    - name: injection\n      taskSpec:\n        steps:\n        - name: injection\n          image: alpine\n          script: echo {{body.pull_request.body}}\n",
		".pre-commit-config.yaml": "repos:\n- repo: http://github.com/pre-commit/pre-commit-hooks\n  rev: v4.0.0\n  hooks:\n  - id: trailing-whitespace\n",
		".github/dependabot.yml":  "version: 2\nupdates:\n- package-ecosystem: github-actions\n  directory: /\n  schedule:\n    interval: weekly\n",
	}
	for path, content := range fixtures {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	inventory, err = discovery.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zizmor", "poutine"} {
		files := inventory.Zizmor
		if name == "poutine" {
			files = inventory.Poutine
		}
		result, findings, err := ScanCI(ctx, runtime, cache, name, root, files, func(progress.Event) {})
		if err != nil {
			t.Fatalf("multi %s: %v", name, err)
		}
		if result.Coverage.Read != len(files) {
			t.Fatalf("multi coverage: %#v", result)
		}
		if name == "zizmor" {
			found := false
			for _, finding := range findings {
				if finding.Path == ".pre-commit-config.yaml" {
					found = true
				}
			}
			if !found {
				t.Fatal("pre-commit fixture was not audited")
			}
		}
		if name == "poutine" {
			for _, path := range []string{".gitlab-ci.yml", "azure-pipelines.yml", ".tekton/ci.yml"} {
				found := false
				for _, finding := range findings {
					if finding.Path == path {
						found = true
					}
				}
				if !found {
					t.Errorf("no finding for %s: %#v", path, findings)
				}
			}
		}
	}
	unsupportedTekton := "apiVersion: tekton.dev/v1\nkind: Pipeline\nspec:\n  tasks:\n  - name: injection\n    taskSpec:\n      steps:\n      - name: injection\n        image: alpine\n        script: echo {{body.pull_request.body}}\n"
	if err := os.WriteFile(filepath.Join(root, ".tekton/ci.yml"), []byte(unsupportedTekton), 0600); err != nil {
		t.Fatal(err)
	}
	if result, _, err := ScanCI(ctx, runtime, cache, "poutine", root, []string{".tekton/ci.yml"}, func(progress.Event) {}); err == nil || result.Coverage.Read != 0 {
		t.Fatalf("unsupported Pipeline counted as read: %#v %v", result, err)
	}
	if err := os.WriteFile(filepath.Join(root, file), []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zizmor", "poutine"} {
		if _, _, err := ScanCI(ctx, runtime, cache, name, root, []string{file}, func(progress.Event) {}); err == nil {
			t.Fatalf("%s silently accepted malformed workflow", name)
		}
	}

	if err := os.WriteFile(filepath.Join(root, file), []byte("unknown: value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zizmor", "poutine"} {
		if _, _, err := ScanCI(ctx, runtime, cache, name, root, []string{file}, func(progress.Event) {}); err == nil {
			t.Fatalf("%s accepted unknown workflow schema", name)
		}
	}
}

func TestCIArgsBoundary(t *testing.T) {
	for _, name := range []string{"zizmor", "poutine"} {
		args := strings.Join(CIArgs(name, "sha256:"+strings.Repeat("a", 64), "/safe"), " ")
		for _, flag := range []string{"--pull never", "--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "dst=/repo,readonly"} {
			if !strings.Contains(args, flag) {
				t.Fatalf("missing %s", flag)
			}
		}
	}
}

func TestCIMalformedLocationsAndWaivers(t *testing.T) {
	data, err := os.ReadFile("testdata/zizmor.json")
	if err != nil {
		t.Fatal(err)
	}
	base := string(data)
	for _, bad := range []string{strings.ReplaceAll(base, "/repo/.github/workflows/ci.yml", "/repo/../outside"), strings.ReplaceAll(base, `"row": 7`, `"row": -1`), strings.ReplaceAll(base, `"severity": "High"`, `"severity": "unknown"`)} {
		if _, _, err := ParseCI([]byte(bad), "zizmor"); err == nil {
			t.Fatal("accepted invalid finding")
		}
	}
	findings, ignored, err := ParseCI([]byte(strings.ReplaceAll(base, `"ignored": false`, `"ignored": true`)), "zizmor")
	if err != nil || len(findings) != 0 || ignored != 5 {
		t.Fatalf("waivers=%d findings=%d err=%v", ignored, len(findings), err)
	}
}

func TestPoutineMalformedStructuredFields(t *testing.T) {
	data, err := os.ReadFile("testdata/poutine.json")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, bad := range []string{
		strings.ReplaceAll(text, `"line": 9`, `"line": 0`),
		strings.ReplaceAll(text, `"level": "warning"`, `"level": "unknown"`),
		strings.ReplaceAll(text, `.github/workflows/ci.yml`, `../outside`),
		`{"findings":[],"rules":{},"packages":{}}`,
	} {
		if _, _, err := ParseCI([]byte(bad), "poutine"); err == nil {
			t.Fatal("accepted malformed Poutine output")
		}
	}
}

func TestPoutineInputStructure(t *testing.T) {
	for _, path := range []string{".gitlab-ci.yml", "azure-pipelines.yml", ".tekton/ci.yml"} {
		for _, content := range []string{"", "[]", "unknown: value", "invalid: ["} {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if err := validatePoutineInput(root, path); err == nil {
				t.Fatalf("accepted %s content %q", path, content)
			}
		}
	}
}

func TestCICleanReports(t *testing.T) {
	if findings, _, err := ParseCI([]byte("[]"), "zizmor"); err != nil || len(findings) != 0 {
		t.Fatalf("clean Zizmor: %v", err)
	}
	data, err := os.ReadFile("testdata/poutine.json")
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]json.RawMessage
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	output["findings"] = json.RawMessage("[]")
	data, err = json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if findings, _, err := ParseCI(data, "poutine"); err != nil || len(findings) != 0 {
		t.Fatalf("clean Poutine: %v", err)
	}
}

func TestPoutineRejectsUnsupportedTektonShapes(t *testing.T) {
	for _, body := range []string{
		"kind: Pipeline\nspec:\n  tasks: []\n",
		"kind: PipelineRun\nspec: {}\n",
		"kind: PipelineRun\nspec:\n  pipelineRef:\n    name: remote\n",
		"kind: PipelineRun\nspec:\n  pipelineSpec: null\n",
	} {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, ".tekton"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".tekton/ci.yml"), []byte("apiVersion: tekton.dev/v1\n"+body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := validatePoutineInput(root, ".tekton/ci.yml"); err == nil {
			t.Errorf("accepted unsupported Tekton shape: %s", body)
		}
	}
}
