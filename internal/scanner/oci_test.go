package scanner

import (
	"archive/tar"
	"context"
	"fmt"
	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/progress"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOCIReferences(t *testing.T) {
	refs, unread, err := parseOCIReferences("Dockerfile", []byte("FROM alpine:3.18 AS base\nFROM base AS final\nFROM scratch\nFROM ${BASE}\n"))
	if err != nil || len(refs) != 1 || refs[0].Reference != "alpine:3.18" || unread != 1 {
		t.Fatalf("Docker refs=%v unread=%d err=%v", refs, unread, err)
	}
	data := `apiVersion: v1
kind: Pod
spec:
 containers:
 - name: one
   image: &image alpine:3.18
 - name: two
   image: *image
---
services:
 app:
  image: "${APP_IMAGE}"
 other:
  image: nginx:1.20
metadata:
 image: ignored:1
`
	refs, unread, err = parseOCIReferences("compose.yaml", []byte(data))
	if err != nil || len(refs) != 3 || unread != 1 {
		t.Fatalf("YAML refs=%v unread=%d err=%v", refs, unread, err)
	}
	for _, ref := range refs {
		if strings.Contains(ref.Reference, "ignored") {
			t.Fatal("arbitrary image key selected")
		}
	}
	for _, bad := range []string{"--help", "https://example/image", "user:pass@host/image", "alpine\nsecret", "../image", "alpine@sha256:bad"} {
		if validImageReference(bad) {
			t.Errorf("accepted image %q", bad)
		}
	}
}

func TestOCIOptIn(t *testing.T) {
	result, findings, err := ScanOCI(context.Background(), container.Runtime{Binary: "must-not-run"}, Cache{}, t.TempDir(), nil, false, func(progress.Event) {})
	if err != nil || len(findings) != 0 || result.Status != "skipped" {
		t.Fatalf("disabled OCI result=%#v err=%v", result, err)
	}
}

func TestAcceptanceOCI(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ref := fmt.Sprintf("secscan-oci-test-%d:synthetic", time.Now().UnixNano())
	archive := filepath.Join(root, "rootfs.tar")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tarball := tar.NewWriter(file)
	for path, data := range map[string]string{"etc/os-release": "ID=alpine\nVERSION_ID=3.18.0\nNAME=Alpine\n", "lib/apk/db/installed": "P:busybox\nV:1.36.0-r9\nA:aarch64\nL:GPL-2.0-only\no:busybox\nT:Synthetic canary fixture\nF:bin\nR:busybox\n\n"} {
		if err := tarball.WriteHeader(&tar.Header{Name: path, Size: int64(len(data)), Mode: 0644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarball.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarball.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx, []string{"import", archive, ref}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		_ = runtime.Run(clean, []string{"image", "rm", "--no-prune", ref})
	})
	id, err := inspectTarget(ctx, runtime, ref)
	if err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(root, "saved.tar")
	if err := runtime.Run(ctx, []string{"save", "--output", saved, ref}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM "+ref+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	cache := Cache{Root: filepath.Join(base, "secscan", "acceptance-dependencies")}
	for _, name := range []string{"trivy", "grype"} {
		asset, err := cache.Resolve(ctx, runtime, name)
		if err != nil {
			t.Fatalf("prepare dependency acceptance cache first: %v", err)
		}
		if _, err := dependencyFeedRoot(cache, name, asset, []string{"package-lock.json"}); err != nil {
			t.Fatal(err)
		}
	}
	disabled, _, err := ScanOCI(ctx, container.Runtime{Binary: "never-run"}, Cache{}, root, []string{"Dockerfile"}, false, func(progress.Event) {})
	if err != nil || disabled.Coverage.Unread != 1 {
		t.Fatalf("no-consent OCI=%#v err=%v", disabled, err)
	}
	result, findings, err := ScanOCI(ctx, runtime, cache, root, []string{"Dockerfile"}, true, func(progress.Event) {})
	if err != nil || result.Coverage.Read != 1 || len(findings) == 0 || len(result.Engines) != 2 {
		t.Fatalf("OCI archive result=%#v findings=%d err=%v", result, len(findings), err)
	}
	for _, engine := range result.Engines {
		if engine.Status != "success" || engine.Read != 1 || len(engine.Feeds) != 2 {
			t.Errorf("archive engine=%#v", engine)
		}
	}
	merged := false
	for _, finding := range findings {
		if finding.ImageDigest != id || finding.Origin != "image" || finding.Path != "Dockerfile" {
			t.Errorf("image finding identity=%#v", finding)
		}
		if len(finding.Sources) == 2 {
			merged = true
		}
	}
	if !merged {
		t.Errorf("OS qualifier normalization did not merge engines: %#v", findings)
	}
	if got, err := inspectTarget(ctx, runtime, ref); err != nil || got != id {
		t.Fatalf("preexisting image not preserved: %q %v", got, err)
	}
	// Load is a local stand-in for a successful pull, while real runtime export,
	// isolated scanner execution and owned-image removal are exercised unchanged.
	wrapper := filepath.Join(root, "runtime")
	script := `#!/bin/sh
if [ "$1" = pull ]; then exec "$SECSCAN_OCI_RUNTIME" load --input "$SECSCAN_OCI_ARCHIVE"; fi
if [ "$1" = run ] && [ "$SECSCAN_OCI_MODE" = fail ]; then exit 27; fi
if [ "$1" = run ] && [ "$SECSCAN_OCI_MODE" = partial ]; then
 case "$*" in *docker-archive:*) exit 27;; esac
fi
if [ "$1" = run ] && [ "$SECSCAN_OCI_MODE" = cancel ]; then exec sleep 30; fi
exec "$SECSCAN_OCI_RUNTIME" "$@"
`
	if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSCAN_OCI_RUNTIME", runtime.Binary)
	t.Setenv("SECSCAN_OCI_ARCHIVE", saved)
	for _, mode := range []string{"success", "partial", "fail", "cancel"} {
		if err := runtime.Run(ctx, []string{"image", "rm", "--no-prune", ref}); err != nil && mode == "success" {
			t.Fatal(err)
		}
		t.Setenv("SECSCAN_OCI_MODE", mode)
		runCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		if mode == "cancel" {
			stop()
			runCtx, stop = context.WithTimeout(ctx, 3*time.Second)
		}
		got, found, scanErr := ScanOCI(runCtx, container.Runtime{Binary: wrapper}, cache, root, []string{"Dockerfile"}, true, func(progress.Event) {})
		stop()
		if mode == "success" && (scanErr != nil || len(found) == 0 || got.Coverage.Read != 1) {
			t.Errorf("owned success=%#v findings=%d err=%v", got, len(found), scanErr)
		}
		if mode == "partial" && (scanErr != nil || len(found) == 0 || got.Coverage.Failed != 1 || got.Engines[0].Status != "success" || got.Engines[1].Failed != 1) {
			t.Errorf("partial engine results lost: %#v findings=%d err=%v", got, len(found), scanErr)
		}
		if (mode == "fail" || mode == "cancel") && scanErr == nil {
			t.Errorf("%s unexpectedly succeeded", mode)
		}
		if _, err := inspectTarget(ctx, runtime, ref); err == nil {
			t.Fatalf("owned image remained after %s", mode)
		}
	}
}

func TestOCIArchiveBoundaryAndInvalidOutput(t *testing.T) {
	for _, name := range []string{"trivy", "grype"} {
		args := strings.Join(OCIArgs(name, "sha256:"+strings.Repeat("a", 64), "/target", "/feeds"), " ")
		for _, required := range []string{"--network none", "--pull never", "--read-only", "no-new-privileges", "dst=/repo,readonly", "dst=/cache,readonly"} {
			if !strings.Contains(args, required) {
				t.Errorf("%s missing %q", name, required)
			}
		}
		if strings.Contains(args, "docker.sock") || strings.Contains(args, "--privileged") {
			t.Errorf("unsafe %s archive arguments", name)
		}
		for _, data := range []string{"{}", "null", `{"matches":[],"source":{"type":"directory"}}`} {
			if _, _, err := parseOCIOutput([]byte(data), name, "sha256:config", "sha256:target", nil); err == nil {
				t.Errorf("%s accepted invalid archive output", name)
			}
		}
	}
	for _, purl := range []string{"pkg:apk/alpine/busybox@1?arch=arm64&arch=evil", "pkg:apk/alpine/busybox@2", "pkg:apk/alpine/busybox@1?url=https%3A%2F%2Fevil", "pkg:unknown/busybox@1"} {
		if _, err := imagePackage("alpine", "busybox", "1", purl, "alpine", "3.18"); err == nil {
			t.Errorf("accepted unsafe package URL %q", purl)
		}
	}
}

func TestOCIYAMLAliasAndMergeBounds(t *testing.T) {
	data := `common: &common
 image: alpine:3.18
services:
 app:
  <<: *common
  image: nginx:1.20
`
	refs, unread, err := parseOCIReferences("compose.yml", []byte(data))
	if err != nil || len(refs) != 1 || refs[0].Reference != "nginx:1.20" || unread != 0 {
		t.Fatalf("merge refs=%v unread=%d err=%v", refs, unread, err)
	}
	cycle := []byte("services: &self\n  <<: *self\n")
	if _, _, err := parseOCIReferences("compose.yml", cycle); err == nil {
		t.Fatal("cyclic YAML accepted")
	}
}

func TestAcceptanceOCIRegistryOptIn(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Only this synthetic Dockerfile is scanned; the public base image is never run.
	ref := "docker.io/library/alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
	before, beforeErr := inspectTarget(ctx, runtime, ref)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM "+ref+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	cache := Cache{Root: filepath.Join(base, "secscan", "acceptance-dependencies")}
	disabled, _, err := ScanOCI(ctx, container.Runtime{Binary: "never-run"}, cache, root, []string{"Dockerfile"}, false, func(progress.Event) {})
	if err != nil || disabled.Coverage.Unread != 1 {
		t.Fatalf("registry opt-out=%#v err=%v", disabled, err)
	}
	result, _, err := ScanOCI(ctx, runtime, cache, root, []string{"Dockerfile"}, true, func(progress.Event) {})
	if err != nil || result.Coverage.Read != 1 || len(result.Images) != 1 || !ValidImageID(result.Images[0].Digest) {
		t.Fatalf("registry opt-in=%#v err=%v", result, err)
	}
	for _, engine := range result.Engines {
		if engine.Status != "success" {
			t.Errorf("registry archive engine=%#v", engine)
		}
	}
	after, afterErr := inspectTarget(ctx, runtime, ref)
	if beforeErr == nil {
		if afterErr != nil || after != before {
			t.Fatalf("preexisting registry image changed: %s %v", after, afterErr)
		}
	} else if afterErr == nil {
		t.Fatal("new registry image remains")
	}
	t.Logf("resolved target digest=%s; preexisting=%t", result.Images[0].Digest, beforeErr == nil)
}

func TestOCIGrypeUnknownOnlyCannotSucceed(t *testing.T) {
	data := `{"matches":[],"source":{"type":"image","target":{"userInput":"/repo/image.tar","imageID":"sha256:config"}},"distro":{"name":"unknown","version":"unknown"},"descriptor":{"name":"grype","version":"0.118.0","db":{"status":{"valid":true}}}}`
	if _, _, err := parseOCIOutput([]byte(data), "grype", "sha256:config", "sha256:target", nil); err == nil {
		t.Fatal("unknown-only Grype inventory succeeded")
	}
}

func TestOCIUnreadableInputDoesNotDiscardOtherReferences(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM alpine:3.18\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(root, "broken.yaml")); err != nil {
		t.Fatal(err)
	}
	result, _, err := ScanOCI(context.Background(), container.Runtime{Binary: "never-run"}, Cache{}, root, []string{"Dockerfile", "broken.yaml"}, false, func(progress.Event) {})
	if err != nil || result.Coverage.Unread != 1 || result.Coverage.FailedFiles != 1 {
		t.Fatalf("partial discovery result=%#v err=%v", result, err)
	}
}
