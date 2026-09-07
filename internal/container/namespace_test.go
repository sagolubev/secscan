// START_MODULE_CONTRACT
// PURPOSE: Check runtime selection, bounded payloads and namespace lifecycle failures.
// SCOPE: Synthetic runtime fixtures and hostile archive entries; no real daemon required.
// DEPENDS: internal/container/runtime.go, internal/container/namespace.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-container-runtime
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestNamespaceSelectionRejectsUnknownBackend - Reject invalid explicit backend without invoking clients.
// TestNamespaceMetadata - Reject malformed daemon namespace metadata.
// TestNamespacePayloadRejectsUnsafeInputs - Bound source trees and require private empty output staging.
// TestNamespaceArchiveBoundary - Reject traversal, links, duplicate paths and oversize archives.
// TestNamespaceLifecycleRejectsCopyAndCleanupFailures - Preserve finding exits only after successful transfer and cleanup.
// TestNamespaceSelectionDoesNotFallback - Honor an explicit unavailable backend.
// TestNamespaceInputArchivePinsSourceAndRejectsLateLinks - Read pinned sources and reject later link replacement.
// TestNamespaceOutputProtectsExistingFilesAndCancellation - Protect existing files and cancel extraction.
// TestNamespaceArchiveRejectsSizeOverflowBeforeCreatingFile - Bound malicious tar sizes before addition.
// TestNamespacePodmanCancellationUsesZeroStopGrace - Remove owned Podman containers within the cancellation budget.
// TestNamespacePodmanCanonicalImageIDs - Normalize only immutable formatted Podman image IDs.
// TestNamespacePodmanBuildOmitsOnlyDisabledProvenance - Preserve the generated build policy across backends.

// END_MODULE_MAP

package container

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNamespaceSelectionRejectsUnknownBackend(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"docker", "podman"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nprintf '[]'\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("SECSCAN_RUNTIME", "unexpected")
	if _, err := DetectDefault(context.Background()); err == nil {
		t.Fatal("DetectDefault(unexpected backend) succeeded, want rejection")
	}
}

func TestNamespaceMetadata(t *testing.T) {
	for _, tc := range []struct {
		backend, data, want string
		bad                 bool
	}{
		{"docker", `[]`, "", false}, {"docker", `["name=userns"]`, "docker-userns", false},
		{"docker", `["name=rootless","name=seccomp,profile=builtin"]`, "docker-rootless", false},
		{"podman", `true`, "podman-rootless", false}, {"podman", `false`, "", false},
		{"docker", `null`, "", true}, {"docker", `{}`, "", true}, {"docker", `[true]`, "", true},
		{"docker", `["name=rootless","bad\nfield"]`, "", true}, {"podman", `null`, "", true},
	} {
		t.Run(tc.backend+tc.data, func(t *testing.T) {
			got, err := parseNamespace(tc.backend, []byte(tc.data))
			if (err != nil) != tc.bad || got != tc.want {
				t.Fatalf("parseNamespace = %q,%v want %q bad=%v", got, err, tc.want, tc.bad)
			}
		})
	}
}

func TestNamespacePayloadRejectsUnsafeInputs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{link, dir} {
		if _, err := validatePayload(context.Background(), source, false); err == nil {
			t.Fatalf("validatePayload(%s) accepted symlink", source)
		}
	}
	if _, err := validatePayload(context.Background(), file, true); err == nil {
		t.Fatal("accepted writable file")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePayload(context.Background(), dir, true); err == nil {
		t.Fatal("accepted nonempty writable directory")
	}
	f, err := os.OpenFile(file, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxPayloadBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := validatePayload(context.Background(), file, false); err == nil {
		t.Fatal("accepted oversize input")
	}
}

func TestNamespaceArchiveBoundary(t *testing.T) {
	cases := []struct {
		name    string
		headers []*tar.Header
		bad     bool
	}{
		{"regular", []*tar.Header{{Name: ".", Typeflag: tar.TypeDir}, {Name: "./nested/", Typeflag: tar.TypeDir}, {Name: "./nested/file", Typeflag: tar.TypeReg, Size: 2}}, false},
		{"traversal", []*tar.Header{{Name: "../escape", Typeflag: tar.TypeReg}}, true},
		{"absolute", []*tar.Header{{Name: "/escape", Typeflag: tar.TypeReg}}, true},
		{"symlink", []*tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "outside"}}, true},
		{"hardlink", []*tar.Header{{Name: "link", Typeflag: tar.TypeLink, Linkname: "outside"}}, true},
		{"device", []*tar.Header{{Name: "dev", Typeflag: tar.TypeChar}}, true},
		{"duplicate", []*tar.Header{{Name: "./file", Typeflag: tar.TypeReg}, {Name: "file", Typeflag: tar.TypeReg}}, true},
		{"oversize", []*tar.Header{{Name: "file", Typeflag: tar.TypeReg, Size: maxPayloadBytes + 1}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			tw := tar.NewWriter(&data)
			for _, h := range tc.headers {
				if err := tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				if h.Size < 10 {
					tw.Write(make([]byte, h.Size))
				}
			}
			_ = tw.Close()
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			err = extractPayload(context.Background(), root, &data)
			if (err != nil) != tc.bad {
				t.Fatalf("extractPayload(%s) error=%v want bad=%v", tc.name, err, tc.bad)
			}
			if !tc.bad {
				info, err := root.Stat("nested/file")
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("private output = %v, %v", info, err)
				}
			}
		})
	}
}

func TestNamespaceLifecycleRejectsCopyAndCleanupFailures(t *testing.T) {
	for _, failure := range []string{"", "copy-in", "copy-out", "cleanup", "run"} {
		t.Run(failure, func(t *testing.T) {
			bin := t.TempDir()
			log := filepath.Join(bin, "calls")
			archive := filepath.Join(bin, "output.tar")
			var data bytes.Buffer
			tw := tar.NewWriter(&data)
			tw.WriteHeader(&tar.Header{Name: ".", Typeflag: tar.TypeDir, Mode: 0700})
			tw.WriteHeader(&tar.Header{Name: "result", Typeflag: tar.TypeReg, Mode: 0600, Size: 2})
			tw.Write([]byte("ok"))
			tw.Close()
			if err := os.WriteFile(archive, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SECSCAN_TEST_NS_FAILURE", failure)
			t.Setenv("SECSCAN_TEST_NS_LOG", log)
			t.Setenv("SECSCAN_TEST_NS_TAR", archive)
			script := `#!/bin/sh
printf '%s\n' "$*" >> "$SECSCAN_TEST_NS_LOG"
case "$1 $2" in
 "volume inspect") printf '/daemon/owned-volume'; exit 0;;
 "volume create"|"volume rm") exit 0;;
esac
case "$1" in
 create) exit 0;;
 cp) case "$3" in -) /bin/cat >/dev/null; [ "$SECSCAN_TEST_NS_FAILURE" != copy-in ];; *) [ "$SECSCAN_TEST_NS_FAILURE" != copy-out ] || exit 1; /bin/cat "$SECSCAN_TEST_NS_TAR";; esac;;
 run) [ "$SECSCAN_TEST_NS_FAILURE" != run ] || exit 7;;
 rm) [ "$SECSCAN_TEST_NS_FAILURE" != cleanup ];;
esac
`
			binary := filepath.Join(bin, "docker")
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			runtime := Runtime{Binary: binary, namespace: "docker-userns"}
			input, output := t.TempDir(), t.TempDir()
			if err := os.Chmod(output, 0700); err != nil {
				t.Fatal(err)
			}
			args := append(IsolatedArgs(input, "/repo"), "--mount", "type=bind,src="+output+",dst=/out", "image", "check")
			parsed, parseErr := parseNamespaceRun(context.Background(), args)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			for _, p := range parsed.mounts {
				p.root.Close()
			}
			_, code, err := runtime.OutputStatus(context.Background(), args, nil)
			if failure == "" && (err != nil || code != 0) {
				t.Fatalf("successful lifecycle=%d,%v", code, err)
			}
			if failure == "run" && (err != nil || code != 7) {
				t.Fatalf("scanner exit=%d,%v want7,nil", code, err)
			}
			if failure != "" && failure != "run" && err == nil {
				t.Fatalf("%s treated as success/code=%d", failure, code)
			}
			calls, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(calls), "rm --force secscan-helper-") || !strings.Contains(string(calls), "volume rm secscan-volume-") {
				t.Fatalf("missing owned cleanup: %s", calls)
			}
			if strings.Contains(string(calls), "start ") || strings.Contains(string(calls), "--userns") || strings.Contains(string(calls), "--privileged") {
				t.Fatal("helper started or isolation bypassed")
			}
		})
	}
}

func TestNamespaceSelectionDoesNotFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte("#!/bin/sh\nprintf true\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SECSCAN_RUNTIME", "docker")
	if _, err := DetectDefault(context.Background()); err == nil {
		t.Fatal("explicit failed Docker fell back")
	}
	t.Setenv("SECSCAN_RUNTIME", "")
	runtime, err := DetectDefault(context.Background())
	if err != nil || runtime.NamespaceMode() != "podman-rootless" {
		t.Fatalf("fallback runtime=%+v err=%v", runtime, err)
	}
}

func TestNamespaceInputArchivePinsSourceAndRejectsLateLinks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := validatePayload(context.Background(), dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.root.Close()
	moved := dir + "-moved"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(moved)
	if err := os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := writePayload(context.Background(), p, &archive); err != nil {
		t.Fatalf("pinned input failed: %v", err)
	}
	tr := tar.NewReader(&archive)
	var found bool
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "payload/file" {
			data, err := io.ReadAll(tr)
			if err != nil || string(data) != "safe" {
				t.Fatalf("pinned file=%q err=%v", data, err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("pinned input missing")
	}
	if err := os.Remove(filepath.Join(moved, "file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(moved, "file")); err != nil {
		t.Fatal(err)
	}
	if err := writePayload(context.Background(), p, io.Discard); err == nil {
		t.Fatal("accepted link inserted after validation")
	}
}

func TestNamespaceOutputProtectsExistingFilesAndCancellation(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.OpenFile("existing", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString("preserve")
	file.Close()
	var data bytes.Buffer
	tw := tar.NewWriter(&data)
	tw.WriteHeader(&tar.Header{Name: "existing", Typeflag: tar.TypeReg})
	tw.Close()
	if err := extractPayload(context.Background(), root, &data); err == nil {
		t.Fatal("overwrote existing output")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := extractPayload(canceled, root, bytes.NewReader([]byte("invalid"))); err == nil {
		t.Fatal("ignored canceled archive extraction")
	}
}

func TestNamespaceArchiveRejectsSizeOverflowBeforeCreatingFile(t *testing.T) {
	var data bytes.Buffer
	tw := tar.NewWriter(&data)
	if err := tw.WriteHeader(&tar.Header{Name: "small", Typeflag: tar.TypeReg, Size: 1}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("a"))
	if err := tw.WriteHeader(&tar.Header{Name: "overflow", Typeflag: tar.TypeReg, Size: math.MaxInt64}); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := extractPayload(context.Background(), root, &data); err == nil {
		t.Fatal("accepted overflow archive")
	}
	if _, err := root.Stat("overflow"); !os.IsNotExist(err) {
		t.Fatalf("overflow file created: %v", err)
	}
}

func TestNamespacePodmanCancellationUsesZeroStopGrace(t *testing.T) {
	for _, rootless := range []string{"true", "false"} {
		t.Run(rootless, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			t.Setenv("PATH", dir)
			t.Setenv("SECSCAN_RUNTIME", "podman")
			t.Setenv("SECSCAN_TEST_NS_ROOTLESS", rootless)
			t.Setenv("SECSCAN_TEST_NS_LOG", log)
			script := `#!/bin/sh
case "$1" in
 info) printf '%s' "$SECSCAN_TEST_NS_ROOTLESS";;
 run) exec /bin/sleep 30;;
 rm) printf '%s\n' "$*" >> "$SECSCAN_TEST_NS_LOG"; [ "$3" = --time ] && [ "$4" = 0 ];;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "podman"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			runtime, err := DetectDefault(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			err = runtime.Run(ctx, []string{"run", "--rm", "image"})
			if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "cleanup") {
				t.Fatalf("Podman rootless=%s cancellation=%v, want context deadline and confirmed cleanup", rootless, err)
			}
			calls, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(calls), "rm --force --time 0 secscan-run-") {
				t.Fatalf("Podman removal=%q, want zero stop grace", calls)
			}
		})
	}
}

func TestNamespacePodmanCanonicalImageIDs(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s' \"$SECSCAN_TEST_IMAGE_OUTPUT\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	inspect := []string{"image", "inspect", "--format", "{{.Id}}", "image"}
	for _, tc := range []struct {
		name, backend, output, want string
		args                        []string
		bad                         bool
	}{
		{"bare", "podman", id + "\n", "sha256:" + id + "\n", inspect, false},
		{"canonical", "podman", "sha256:" + id, "sha256:" + id, inspect, false},
		{"labels", "podman", id + " 1.29.0 rule-digest\n", "sha256:" + id + " 1.29.0 rule-digest\n", []string{"image", "inspect", "--format", "{{.Id}} {{index .Config.Labels \"version\"}}", "image"}, false},
		{"short", "podman", "abcdef", "", inspect, true},
		{"malformed", "podman", strings.Repeat("z", 64), "", inspect, true},
		{"short-prefixed", "podman", "sha256:abcdef", "", inspect, true},
		{"docker-unchanged", "docker", id, id, inspect, false},
		{"other-command", "podman", id, id, []string{"image", "ls"}, false},
		{"other-format", "podman", id, id, []string{"image", "inspect", "--format", "{{.Size}}", "image"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECSCAN_TEST_IMAGE_OUTPUT", tc.output)
			output, err := (Runtime{Binary: binary, backend: tc.backend}).Output(context.Background(), tc.args...)
			if (err != nil) != tc.bad || string(output) != tc.want {
				t.Fatalf("Output(%s)=%q,%v want%q bad=%v", tc.name, output, err, tc.want, tc.bad)
			}
		})
	}
}

func TestNamespacePodmanBuildOmitsOnlyDisabledProvenance(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		backend    string
		args, want []string
	}{
		{"podman", []string{"build", "--provenance=false", "--pull=false", "--tag", "fixture", "."}, []string{"build", "--pull=missing", "--tag", "fixture", "."}},
		{"docker", []string{"build", "--provenance=false", "."}, []string{"build", "--provenance=false", "."}},
		{"podman", []string{"build", "--pull=never", "."}, []string{"build", "--pull=never", "."}},
		{"podman", []string{"build", "--build-arg", "--provenance=false", "."}, []string{"build", "--build-arg", "--provenance=false", "."}},
		{"podman", []string{"build", "--provenance=true", "."}, []string{"build", "--provenance=true", "."}},
		{"podman", []string{"image", "inspect", "--provenance=false"}, []string{"image", "inspect", "--provenance=false"}},
	} {
		before := strings.Join(tc.args, "\n")
		got, err := (Runtime{Binary: binary, backend: tc.backend}).Output(context.Background(), tc.args...)
		if err != nil || string(got) != strings.Join(tc.want, "\n")+"\n" || strings.Join(tc.args, "\n") != before {
			t.Fatalf("build compatibility=%q,%v want%q; caller argv must be unchanged", got, err, tc.want)
		}
	}
}
