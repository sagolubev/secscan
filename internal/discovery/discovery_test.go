package discovery

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiscoverSplitsTrackedAndUntrackedLanguages(t *testing.T) {
	root := newGitRepository(t)
	writeFile(t, root, "app.py", "print('tracked')\n")
	writeFile(t, root, "types/index.ts", "export const value = 1;\n")
	writeFile(t, root, "types/view.tsx", "export const View = () => null;\n")
	writeFile(t, root, "ignored.py", "print('ignored')\n")
	writeFile(t, root, ".gitignore", "ignored.py\n")
	runGit(t, root, "add", "app.py", ".gitignore")

	got, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if want := []string{"app.py"}; !reflect.DeepEqual(got.Python, want) {
		t.Errorf("Discover() Python = %q, want %q", got.Python, want)
	}
	if want := []string{"types/index.ts", "types/view.tsx"}; !reflect.DeepEqual(got.TypeScript, want) {
		t.Errorf("Discover() TypeScript = %q, want %q", got.TypeScript, want)
	}
	if got.Ignored.Files != 1 || got.Ignored.Bytes == 0 {
		t.Errorf("Discover() ignored = %#v, want one file and bytes", got.Ignored)
	}
}

func TestStageRejectsSymlink(t *testing.T) {
	root := newGitRepository(t)
	outside := filepath.Join(t.TempDir(), "outside.py")
	if err := os.WriteFile(outside, []byte("print('outside')"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.py")); err != nil {
		t.Fatal(err)
	}

	if _, err := Stage(root, []string{"link.py"}); err == nil {
		t.Fatal("Stage() error = nil, want symlink rejection")
	}
}

func TestStageRejectsIntermediateSymlink(t *testing.T) {
	root := newGitRepository(t)
	outside := t.TempDir()
	writeFile(t, outside, "app.py", "print('outside')\n")
	if err := os.Symlink(outside, filepath.Join(root, "pkg")); err != nil {
		t.Fatal(err)
	}

	if _, err := Stage(root, []string{"pkg/app.py"}); err == nil {
		t.Fatal("Stage() error = nil, want intermediate symlink rejection")
	}
}

func TestDiscoverSkipsDeletedTrackedFiles(t *testing.T) {
	root := newGitRepository(t)
	writeFile(t, root, "deleted.py", "print('gone')\n")
	runGit(t, root, "add", "deleted.py")
	if err := os.Remove(filepath.Join(root, "deleted.py")); err != nil {
		t.Fatal(err)
	}

	got, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(got.Python) != 0 {
		t.Errorf("Discover() Python = %q, want deleted file omitted", got.Python)
	}
}

func newGitRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "--quiet")
	return root
}

func writeFile(t *testing.T, root, path, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func TestCIDiscoveryAndNoFSMonitor(t *testing.T) {
	root := newGitRepository(t)
	for _, path := range []string{".github/workflows/ci.yml", ".github/workflows/ignored.yml", ".pre-commit-config.yaml", ".github/dependabot.yml", ".gitlab-ci.yml", "azure-pipelines.yml", ".tekton/run.yml", ".poutine.yml", "azure-pipelinesfake.yml"} {
		writeFile(t, root, path, "synthetic")
	}
	writeFile(t, root, ".gitignore", ".github/workflows/ignored.yml\n")
	runGit(t, root, "add", ".gitignore", ".github/workflows/ci.yml")
	hook := filepath.Join(root, "monitor.sh")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\ntouch \""+filepath.Join(root, "executed")+"\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "config", "core.fsmonitor", hook)
	got, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "executed")); !os.IsNotExist(err) {
		t.Fatal("repository fsmonitor executed")
	}
	if len(got.Zizmor) != 3 || len(got.Poutine) != 4 || got.Ignored.Files != 1 {
		t.Fatalf("unexpected inventory %#v", got)
	}
}

func TestZizmorPreCommitExactNames(t *testing.T) {
	root := newGitRepository(t)
	for _, path := range []string{".pre-commit-config.yml", ".pre-commit-config.yaml", ".pre-commit-hooks.yml", ".pre-commit-hooks.yaml", "pre-commit-config.yml", "pre-commit-config.yaml", "pre-commit-hooks.yml", "pre-commit-hooks.yaml", ".github/dependabot.yml"} {
		writeFile(t, root, path, "synthetic")
	}
	got, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".github/dependabot.yml", ".pre-commit-config.yaml", ".pre-commit-config.yml", ".pre-commit-hooks.yaml", ".pre-commit-hooks.yml"}
	if !reflect.DeepEqual(got.Zizmor, want) {
		t.Fatalf("Zizmor=%q, want %q", got.Zizmor, want)
	}
}
