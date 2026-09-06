package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/discovery"
	"github.com/sigiuscom/secscan/internal/progress"
)

func TestParseIaC(t *testing.T) {
	checkov := `{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_AWS_1","severity":null,"file_path":"/main.tf","file_line_range":[1,3],"resource":"SYNTHETIC_CANARY","check_name":"SYNTHETIC_CANARY"}]},"summary":{"passed":2,"failed":1,"skipped":0,"parsing_errors":1}}`
	findings, coverage, err := ParseIaC([]byte(checkov), "checkov-terraform")
	if err != nil || len(findings) != 1 || coverage.Read != 3 || coverage.Unit != "checks" || coverage.FailedFiles != 1 {
		t.Fatalf("parse=%#v %#v %v", findings, coverage, err)
	}
	if findings[0].Severity != "unknown" || findings[0].Path != "main.tf" {
		t.Fatalf("finding=%#v", findings[0])
	}
	data, _ := json.Marshal(findings)
	if strings.Contains(string(data), "SYNTHETIC_CANARY") {
		t.Fatal("raw text leaked")
	}
	if _, _, err := ParseIaC([]byte("["+checkov+"]"), "checkov-terraform"); err != nil {
		t.Fatal(err)
	}
	kics := `{"files_scanned":2,"files_parsed":1,"files_failed_to_scan":1,"queries_failed_to_execute":2,"queries_failed_to_compute_similarity_id":1,"queries":[{"query_id":"12345678-1234-1234-1234-123456789abc","severity":"HIGH","files":[{"file_name":"main.tf","line":1}]}]}`
	findings, coverage, err = ParseIaC([]byte(kics), "kics")
	if err != nil || len(findings) != 1 || coverage.Read != 1 || coverage.Failed != 1 || coverage.FailedQueries != 3 {
		t.Fatalf("kics=%#v %#v %v", findings, coverage, err)
	}
	for _, name := range []string{"checkov", "checkov-terraform", "kics"} {
		for _, bad := range []string{"null", "{}", "[]", "[{}]"} {
			if _, _, err := ParseIaC([]byte(bad), name); err == nil {
				t.Errorf("%s accepted %s", name, bad)
			}
		}
	}
	for _, bad := range []string{strings.ReplaceAll(checkov, `"parsing_errors":1`, `"parsing_errors":-1`), strings.ReplaceAll(checkov, `/main.tf`, `/../outside`), strings.ReplaceAll(checkov, `CKV_AWS_1`, `CANARY`)} {
		if _, _, err := ParseIaC([]byte(bad), "checkov-terraform"); err == nil {
			t.Error("accepted invalid checkov")
		}
	}
	if _, _, err := ParseIaC([]byte(checkov), "checkov"); err == nil {
		t.Error("general Checkov accepted Terraform envelope")
	}
}

func TestIaCArgsBoundary(t *testing.T) {
	for _, name := range []string{"checkov", "checkov-terraform", "kics"} {
		args := strings.Join(IaCArgs(name, "sha256:"+strings.Repeat("a", 64), "/safe", "/output"), " ")
		for _, flag := range []string{"--pull never", "--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "dst=/repo,readonly", "--workdir /repo"} {
			if !strings.Contains(args, flag) {
				t.Errorf("%s missing %s", name, flag)
			}
		}
		if name == "kics" {
			for _, flag := range []string{"--disable-full-descriptions", "--ignore-on-exit results", "dst=/out"} {
				if !strings.Contains(args, flag) {
					t.Error(flag)
				}
			}
		} else {
			for _, flag := range []string{"--skip-download", "--download-external-modules false", "--soft-fail"} {
				if !strings.Contains(args, flag) {
					t.Error(flag)
				}
			}
		}
	}
}

func TestAcceptanceIaC(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unsafe := `resource "aws_s3_bucket_public_access_block" "synthetic" {
 bucket = "synthetic"
 block_public_acls = false
 block_public_policy = false
 ignore_public_acls = false
 restrict_public_buckets = false
}
`
	write("main.tf", unsafe)
	write("Dockerfile", "FROM alpine:3.21\nUSER root\nRUN echo SYNTHETIC_CANARY\n")
	write("pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: synthetic\nspec:\n  containers:\n  - name: synthetic\n    image: nginx:latest\n    securityContext:\n      privileged: true\n")
	write(".checkov.yml", "skip-check: ['*']\nexternal-checks-dir: /repo/checks\n")
	write("kics.config", "exclude-queries: ['*']\n")
	inventory, err := discovery.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	cache := Cache{Root: filepath.Join(t.TempDir(), "cache")}
	names := []string{"checkov", "checkov-terraform", "kics"}
	if err := Update(ctx, runtime, cache, names, root); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			files := inventory.Checkov
			if name == "checkov-terraform" {
				files = inventory.Terraform
			}
			if name == "kics" {
				files = inventory.KICS
			}
			result, findings, err := ScanIaC(ctx, runtime, cache, name, root, files, func(progress.Event) {})
			if err != nil || len(findings) == 0 || result.Coverage.Read == 0 {
				t.Fatalf("result=%#v findings=%d err=%v", result, len(findings), err)
			}
			for _, f := range findings {
				if name == "checkov" && f.Path == "main.tf" || name == "checkov-terraform" && f.Path != "main.tf" {
					t.Fatalf("persona crossed scope: %#v", f)
				}
			}
			encoded, _ := json.Marshal(findings)
			if strings.Contains(string(encoded), "SYNTHETIC_CANARY") {
				t.Fatal("canary leaked")
			}
		})
	}
	write("main.tf", strings.ReplaceAll(unsafe, "false", "true")+"\nresource \"aws_accessanalyzer_analyzer\" \"synthetic\" {\n analyzer_name = \"synthetic\"\n tags = { environment = \"test\" }\n }\n")
	for _, name := range []string{"checkov-terraform", "kics"} {
		result, findings, err := ScanIaC(ctx, runtime, cache, name, root, []string{"main.tf"}, func(progress.Event) {})
		if err != nil || len(findings) != 0 || result.Coverage.Read == 0 {
			t.Errorf("clean %s: %#v findings=%#v err=%v", name, result, findings, err)
		}
	}
	write("main.tf", `resource "aws_s3_bucket" "broken" { broken = [`)
	for _, name := range []string{"checkov-terraform", "kics"} {
		result, _, err := ScanIaC(ctx, runtime, cache, name, root, []string{"main.tf"}, func(progress.Event) {})
		if err == nil || result.Status == "success" {
			t.Errorf("malformed %s false clean: %#v", name, result)
		}
	}
	write("good.tf", unsafe)
	for _, name := range []string{"checkov-terraform", "kics"} {
		result, _, err := ScanIaC(ctx, runtime, cache, name, root, []string{"good.tf", "main.tf"}, func(progress.Event) {})
		if err == nil && result.Coverage.FailedFiles == 0 && result.Coverage.Failed == 0 && result.Coverage.Unread == 0 {
			t.Errorf("mixed malformed %s counted fully read: %#v", name, result)
		}
	}
	write("main.tofu", unsafe)
	for _, name := range []string{"checkov-terraform", "kics"} {
		result, findings, err := ScanIaC(ctx, runtime, cache, name, root, []string{"main.tofu"}, func(progress.Event) {})
		if err != nil || len(findings) == 0 {
			t.Errorf("OpenTofu %s: %#v findings=%d err=%v", name, result, len(findings), err)
		}
		for _, f := range findings {
			if f.Path != "main.tofu" {
				t.Errorf("OpenTofu path=%s", f.Path)
			}
		}
	}
	write("main.tf.json", `{"resource":{"aws_s3_bucket_public_access_block":{"synthetic":{"bucket":"synthetic","block_public_acls":false,"block_public_policy":false,"ignore_public_acls":false,"restrict_public_buckets":false}}}}`)
	write("plan.json", `{"format_version":"1.2","terraform_version":"1.9.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket_public_access_block.synthetic","mode":"managed","type":"aws_s3_bucket_public_access_block","name":"synthetic","provider_name":"registry.terraform.io/hashicorp/aws","values":{"bucket":"synthetic","block_public_acls":false,"block_public_policy":false,"ignore_public_acls":false,"restrict_public_buckets":false}}]}}}`)
	for _, file := range []string{"main.tf.json", "plan.json"} {
		result, findings, err := ScanIaC(ctx, runtime, cache, "checkov-terraform", root, []string{file}, func(progress.Event) {})
		if err != nil || len(findings) == 0 {
			t.Errorf("Terraform JSON %s: %#v findings=%d err=%v", file, result, len(findings), err)
		}
	}

}

func TestKICSUnreadAndInvalidAccounting(t *testing.T) {
	input := `{"files_scanned":2,"files_parsed":1,"files_failed_to_scan":0,"queries_failed_to_execute":0,"queries_failed_to_compute_similarity_id":0,"queries":[]}`
	_, coverage, err := ParseIaC([]byte(input), "kics")
	if err != nil || coverage.Unread != 1 {
		t.Fatalf("coverage=%#v err=%v", coverage, err)
	}
	for _, bad := range []string{strings.ReplaceAll(input, `"files_parsed":1`, `"files_parsed":3`), strings.ReplaceAll(input, `"files_failed_to_scan":0`, `"files_failed_to_scan":-1`), strings.ReplaceAll(input, `"queries":[]`, `"queries":null`)} {
		if _, _, err := ParseIaC([]byte(bad), "kics"); err == nil {
			t.Errorf("accepted invalid KICS %s", bad)
		}
	}
}

func TestStageOpenTofu(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"main.tofu", "data.tofu.json"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mapping, err := stageOpenTofu(root, []string{"main.tofu", "data.tofu.json"})
	if err != nil || mapping["main.tf"] != "main.tofu" || mapping["data.tf.json"] != "data.tofu.json" {
		t.Fatalf("mapping=%#v err=%v", mapping, err)
	}
	if _, err := os.Stat(filepath.Join(root, "main.tf")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.tofu"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageOpenTofu(root, []string{"main.tofu", "main.tf"}); err == nil {
		t.Fatal("accepted competing Terraform and OpenTofu definitions")
	}
}

func TestTerraformPlanFileAnchor(t *testing.T) {
	input := `{"check_type":"terraform_plan","results":{"failed_checks":[{"check_id":"CKV_AWS_1","file_path":"/plan.json","file_line_range":[0,0]}]},"summary":{"passed":0,"failed":1,"skipped":0,"parsing_errors":0}}`
	findings, _, err := ParseIaC([]byte(input), "checkov-terraform")
	if err != nil || len(findings) != 1 || findings[0].Line != 1 {
		t.Fatalf("plan findings=%#v err=%v", findings, err)
	}
	if _, _, err := ParseIaC([]byte(strings.ReplaceAll(input, `"terraform_plan"`, `"terraform"`)), "checkov-terraform"); err == nil {
		t.Fatal("accepted missing Terraform source line")
	}
}

func TestIaCRejectsOperationalExitAndUnstagedPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	cache := Cache{Root: t.TempDir()}
	id := "sha256:" + strings.Repeat("a", 64)
	if err := cache.Update(context.Background(), func(context.Context, string) (map[string]Asset, error) {
		return map[string]Asset{"checkov-terraform": {ImageID: id, ImageRef: Catalog()["checkov-terraform"].Image}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSCAN_TEST_IMAGE_ID", id)
	t.Setenv("SECSCAN_TEST_RESULT", `{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_AWS_1","file_path":"/outside.tf","file_line_range":[1,1]}]},"summary":{"passed":0,"failed":1,"skipped":0,"parsing_errors":0}}`)
	binary := filepath.Join(t.TempDir(), "runtime")
	script := "#!/bin/sh\nif [ \"$1\" = image ]; then printf '%s\\n' \"$SECSCAN_TEST_IMAGE_ID\"; exit 0; fi\nprintf '%s\\n' \"$SECSCAN_TEST_RESULT\"\nexit \"$SECSCAN_TEST_EXIT\"\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"0", "2"} {
		t.Setenv("SECSCAN_TEST_EXIT", code)
		if _, _, err := ScanIaC(context.Background(), container.Runtime{Binary: binary}, cache, "checkov-terraform", root, []string{"main.tf"}, func(progress.Event) {}); err == nil {
			t.Errorf("accepted outside path or operational exit %s", code)
		}
	}
}

func TestIaCRequiresEvaluatedInputs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	id := "sha256:" + strings.Repeat("a", 64)
	cache := Cache{Root: t.TempDir()}
	if err := cache.Update(context.Background(), func(context.Context, string) (map[string]Asset, error) {
		return map[string]Asset{"checkov-terraform": {ImageID: id, ImageRef: Catalog()["checkov-terraform"].Image}, "kics": {ImageID: id, ImageRef: Catalog()["kics"].Image}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSCAN_TEST_IMAGE_ID", id)
	binary := filepath.Join(t.TempDir(), "runtime")
	script := `#!/bin/sh
if [ "$1" = image ]; then printf '%s\n' "$SECSCAN_TEST_IMAGE_ID"; exit 0; fi
for arg in "$@"; do
 case "$arg" in type=bind,src=*,dst=/out) output="${arg#type=bind,src=}"; output="${output%,dst=/out}"; printf '%s\n' "$SECSCAN_TEST_RESULT" > "$output/result.json";; esac
done
printf '%s\n' "$SECSCAN_TEST_RESULT"
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"checkov-terraform", "kics"} {
		for _, read := range []int{0, 1} {
			data := fmt.Sprintf(`{"check_type":"terraform","results":{"failed_checks":[]},"summary":{"passed":%d,"failed":0,"skipped":0,"parsing_errors":1}}`, read)
			if name == "kics" {
				data = fmt.Sprintf(`{"files_scanned":2,"files_parsed":%d,"files_failed_to_scan":0,"queries_failed_to_execute":0,"queries_failed_to_compute_similarity_id":0,"queries":[]}`, read)
			}
			t.Setenv("SECSCAN_TEST_RESULT", data)
			result, _, err := ScanIaC(context.Background(), container.Runtime{Binary: binary}, cache, name, root, []string{"main.tf"}, func(progress.Event) {})
			if read == 0 && (err == nil || result.Status == "success") {
				t.Errorf("%s zero analysis succeeded: %#v err=%v", name, result, err)
			}
			if read == 1 && (err != nil || result.Coverage.Read != 1 || result.Coverage.Unread+result.Coverage.FailedFiles == 0) {
				t.Errorf("%s mixed partial coverage lost: %#v err=%v", name, result, err)
			}
		}
	}
}
