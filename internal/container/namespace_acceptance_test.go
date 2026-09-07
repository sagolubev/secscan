// START_MODULE_CONTRACT
// PURPOSE: Prove private input and current-user output across real container namespaces.
// SCOPE: Native pinned Gitleaks, numeric user, isolation, cache reuse and owned cleanup.
// DEPENDS: internal/container/runtime.go, internal/gitleaks/run.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-container-runtime
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestAcceptanceNamespaceOwnership - Verify final Go transport against the selected real runtime.
// END_MODULE_MAP

package container_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/gitleaks"
	"github.com/sagolubev/secscan/internal/progress"
)

func TestAcceptanceNamespaceOwnership(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for native namespace ownership")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if expected := os.Getenv("SECSCAN_EXPECTED_NAMESPACE"); expected != "" && runtime.NamespaceMode() != expected {
		t.Fatalf("namespace mode=%q want %q", runtime.NamespaceMode(), expected)
	}
	t.Logf("actual namespace mode: %s", runtime.NamespaceMode())
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cache, "secscan"), 0700); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.MkdirTemp(filepath.Join(cache, "secscan"), "namespace-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(fixture) })
	repo := filepath.Join(fixture, "repo")
	output := filepath.Join(fixture, "out")
	for _, dir := range []string{repo, output} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{repo, output} {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	label := fmt.Sprintf("secscan.namespace-test=%d", time.Now().UnixNano())
	individual := filepath.Join(fixture, "input.txt")
	for _, name := range []string{filepath.Join(repo, "input.txt"), individual} {
		if err := os.WriteFile(name, []byte("private input\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	const image = gitleaks.Image
	args := append(container.IsolatedArgs(repo, "/repo"), "--mount", "type=bind,src="+individual+",dst=/individual,readonly", "--mount", "type=bind,src="+output+",dst=/out", "--label", label, "--entrypoint", "/bin/sh", image, "-c", `set -eu
umask 077
 test "$(cat /repo/input.txt)" = "private input"
 test "$(cat /individual)" = "private input"
 test "$(id -u)" = "$1"
 grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
 grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
 ! touch /repo/forbidden
 ! touch /forbidden
 mkdir /out/db
 printf reusable > /out/db/cache
 `, "sh", fmt.Sprint(os.Getuid()))
	if err := runtime.Run(ctx, args); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(output, "db", "cache")
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0600 {
		t.Fatalf("cache owner/mode=%v/%v want %d/0600", info.Sys().(*syscall.Stat_t).Uid, info.Mode().Perm(), os.Getuid())
	}
	second := append(container.IsolatedArgs(output, "/cache"), "--label", label, "--entrypoint", "/bin/sh", image, "-c", `test "$(cat /cache/db/cache)" = reusable && ! touch /cache/forbidden`)
	if err := runtime.Run(ctx, second); err != nil {
		t.Fatalf("cache re-read: %v", err)
	}
	// Only synthetic material enters this native scanner. Normalized output must
	// contain the finding, while raw secret bytes never leave the adapter.
	canary := "ghp_" + strings.Repeat("aB1cD2eF3gH4", 3) + "abcd"
	if err := os.WriteFile(filepath.Join(repo, "synthetic.txt"), []byte("token="+canary), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := gitleaks.Scan(ctx, runtime, repo, func(progress.Event) {})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 || strings.Contains(string(encoded), canary) {
		t.Fatal("native Gitleaks did not return a redacted finding")
	}
	if _, err := os.Stat(filepath.Join(repo, "forbidden")); !os.IsNotExist(err) {
		t.Fatal("repository was modified")
	}
	// Cancel a running container with payload mounts, after daemon readiness.
	cancelOutput := filepath.Join(fixture, "cancel-out")
	if err := os.Mkdir(cancelOutput, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cancelOutput, 0700); err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	cancelLabel := label + "-cancel"
	cancelArgs := append(container.IsolatedArgs(repo, "/repo"), "--mount", "type=bind,src="+cancelOutput+",dst=/out", "--label", cancelLabel, "--entrypoint", "/bin/sleep", image, "30")
	done := make(chan error, 1)
	go func() { done <- runtime.Run(cancelCtx, cancelArgs) }()
	ready := false
	for ctx.Err() == nil {
		data, err := runtime.Output(ctx, "ps", "--filter", "label="+cancelLabel, "--format", "{{.ID}}")
		if err == nil && len(strings.TrimSpace(string(data))) > 0 {
			ready = true
			break
		}
		select {
		case err := <-done:
			t.Fatalf("container exited before cancellation readiness: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancelRun()
	runErr := <-done
	if !ready || !errors.Is(runErr, context.Canceled) {
		t.Fatalf("namespace cancellation ready=%v error=%v", ready, runErr)
	}
	for _, ownedLabel := range []string{label, cancelLabel} {
		for _, args := range [][]string{{"ps", "--all", "--filter", "label=" + ownedLabel, "--format", "{{.ID}}"}, {"volume", "ls", "--filter", "label=" + ownedLabel, "--format", "{{.Name}}"}} {
			data, err := runtime.Output(ctx, args...)
			if err != nil || len(strings.TrimSpace(string(data))) != 0 {
				t.Fatalf("owned namespace resources remained: %q, %v", data, err)
			}
		}
	}
}
