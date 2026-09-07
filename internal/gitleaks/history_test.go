// START_MODULE_CONTRACT
// PURPOSE: Verify complete, bounded and independent Git-history snapshots.
// SCOPE: Synthetic repositories, malicious configuration and native deleted-secret acceptance.
// DEPENDS: internal/gitleaks/history.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// historyGit - Build synthetic Git fixtures without user hooks or signing.
// historyFixture - Create two commits with a deleted synthetic secret.
// TestHistorySnapshotIsIndependentAndIgnoresSourceConfiguration - Keep source settings and hooks outside the snapshot.
// TestHistorySnapshotLinkedWorktree - Avoid mounting linked worktree shared metadata.
// TestHistorySnapshotRejectsIncompleteAndBoundedInputs - Reject incomplete and oversized histories and clean failures.
// TestHistorySnapshotRejectsMovingHead - Detect HEAD movement during bundle creation.
// TestHistorySnapshotNeverFetchesMissingPromisorObjects - Reject missing objects without a transport helper.
// TestHistoryBundleAdvertisementRequiresFrozenHead - Accept only the selected immutable HEAD advertisement.
// TestHistoryContainerArgsKeepBoundary - Verify offline, unprivileged Git scan arguments.
// TestAcceptanceHistoryFindsDeletedSecret - Prove deleted-secret commit provenance through native Gitleaks.
// END_MODULE_MAP

package gitleaks

import (
	"context"
	"errors"
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

func historyGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	argv := append([]string{"-C", dir, "-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"}, args...)
	cmd := exec.Command("git", argv...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture git %v: %v", args, err)
	}
	return strings.TrimSpace(string(data))
}

func historyFixture(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	historyGit(t, dir, "init", "--template=")
	canary := strings.Join([]string{"gl", "pat-", "0123456789", "AbCdEfGhIj"}, "")
	if err := os.WriteFile(filepath.Join(dir, "deleted.txt"), []byte("token="+canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	historyGit(t, dir, "add", "deleted.txt")
	historyGit(t, dir, "commit", "-m", "synthetic history fixture")
	first := historyGit(t, dir, "rev-parse", "HEAD")
	historyGit(t, dir, "rm", "deleted.txt")
	if err := os.WriteFile(filepath.Join(dir, "current.txt"), []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	historyGit(t, dir, "add", "current.txt")
	historyGit(t, dir, "commit", "-m", "remove synthetic fixture")
	return dir, first, canary
}

func TestHistorySnapshotIsIndependentAndIgnoresSourceConfiguration(t *testing.T) {
	dir, first, _ := historyFixture(t)
	head := historyGit(t, dir, "rev-parse", "HEAD")
	marker := filepath.Join(t.TempDir(), "executed")
	hookDir := t.TempDir()
	script := "#!/bin/sh\ntouch '" + marker + "'\nexit 1\n"
	for _, name := range []string{"reference-transaction", "post-checkout", "post-index-change", "fsmonitor"} {
		if err := os.WriteFile(filepath.Join(hookDir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	historyGit(t, dir, "config", "core.hooksPath", hookDir)
	historyGit(t, dir, "config", "core.fsmonitor", filepath.Join(hookDir, "fsmonitor"))
	historyGit(t, dir, "config", "init.templateDir", hookDir)
	historyGit(t, dir, "config", "remote.origin.url", "https://example.invalid/never-fetch")
	before, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_DIR", "/nonexistent-override")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", hookDir)
	snapshot, err := snapshotHistory(context.Background(), dir, historyLimits{commits: 100000, bundleBytes: 512 << 20})
	if err != nil {
		t.Fatalf("snapshotHistory() = %v", err)
	}
	defer os.RemoveAll(snapshot.workspace)
	if snapshot.head != head || len(snapshot.commits) != 2 {
		t.Errorf("snapshot = %s / %d commits, want %s / 2", snapshot.head, len(snapshot.commits), head)
	}
	if _, ok := snapshot.commits[first]; !ok {
		t.Errorf("snapshot omitted first commit")
	}
	config, err := os.ReadFile(filepath.Join(snapshot.repository, "config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"example.invalid", hookDir, "hooksPath", "fsmonitor", "templateDir", "[remote"} {
		if strings.Contains(string(config), forbidden) {
			t.Errorf("snapshot copied source configuration %q", forbidden)
		}
	}
	if _, err := os.Stat(filepath.Join(snapshot.repository, "hooks")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshot hooks exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snapshot.repository, "objects", "info", "alternates")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshot has object alternates: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("source hook was executed: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil || string(after) != string(before) {
		t.Errorf("snapshot mutated source config: %v", err)
	}
}

func TestHistorySnapshotLinkedWorktree(t *testing.T) {
	dir, _, _ := historyFixture(t)
	linked := filepath.Join(t.TempDir(), "linked")
	historyGit(t, dir, "worktree", "add", "--detach", linked, "HEAD")
	snapshot, err := snapshotHistory(context.Background(), linked, historyLimits{commits: 100000, bundleBytes: 512 << 20})
	if err != nil {
		t.Fatalf("snapshotHistory(linked) = %v", err)
	}
	defer os.RemoveAll(snapshot.workspace)
	if len(snapshot.commits) != 2 || strings.HasPrefix(snapshot.repository, dir) {
		t.Errorf("linked snapshot = %+v", snapshot)
	}
	args := historyContainerArgs(snapshot.repository, filepath.Join(snapshot.workspace, "out"), snapshot.head, Image)
	for _, arg := range args {
		if strings.Contains(arg, dir) || strings.Contains(arg, linked) {
			t.Errorf("container args expose source metadata: %q", arg)
		}
	}
}

func TestHistorySnapshotRejectsIncompleteAndBoundedInputs(t *testing.T) {
	for _, mode := range []string{"unborn", "shallow", "grafts", "missing object", "commit limit", "bundle limit", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			dir, _, _ := historyFixture(t)
			limits := historyLimits{commits: 100000, bundleBytes: 512 << 20}
			ctx := context.Background()
			switch mode {
			case "unborn":
				dir = t.TempDir()
				historyGit(t, dir, "init", "--template=")
			case "shallow":
				if err := os.WriteFile(filepath.Join(dir, ".git", "shallow"), []byte(historyGit(t, dir, "rev-parse", "HEAD")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "grafts":
				if err := os.MkdirAll(filepath.Join(dir, ".git", "info"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".git", "info", "grafts"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing object":
				id := historyGit(t, dir, "rev-parse", "HEAD:current.txt")
				if err := os.Remove(filepath.Join(dir, ".git", "objects", id[:2], id[2:])); err != nil {
					t.Fatal(err)
				}
			case "commit limit":
				limits.commits = 1
			case "bundle limit":
				limits.bundleBytes = 1
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			snapshot, err := snapshotHistory(ctx, dir, limits)
			if err == nil {
				t.Errorf("snapshotHistory(%s) succeeded, want rejection", mode)
			}
			if snapshot.workspace != "" {
				if _, err := os.Lstat(snapshot.workspace); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("snapshotHistory(%s) left workspace behind: %v", mode, err)
				}
			}
		})
	}
}

func TestHistorySnapshotRejectsMovingHead(t *testing.T) {
	dir, first, _ := historyFixture(t)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	script := `#!/bin/sh
for arg do
  if [ "$arg" = create ]; then
    "$SECSCAN_TEST_GIT" "$@" || exit $?
    "$SECSCAN_TEST_GIT" -C "$SECSCAN_TEST_REPO" update-ref HEAD "$SECSCAN_TEST_HEAD"
    exit $?
  fi
done
exec "$SECSCAN_TEST_GIT" "$@"
`
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSCAN_TEST_GIT", realGit)
	t.Setenv("SECSCAN_TEST_REPO", dir)
	t.Setenv("SECSCAN_TEST_HEAD", first)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	snapshot, err := snapshotHistory(context.Background(), dir, historyLimits{commits: 100000, bundleBytes: 512 << 20})
	if err == nil || !strings.Contains(err.Error(), "HEAD changed") {
		t.Errorf("snapshotHistory(moving HEAD) = %v, want changed HEAD error", err)
	}
	if _, err := os.Lstat(snapshot.workspace); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshotHistory(moving HEAD) left workspace: %v", err)
	}
}

func TestHistorySnapshotNeverFetchesMissingPromisorObjects(t *testing.T) {
	dir, _, _ := historyFixture(t)
	id := historyGit(t, dir, "rev-parse", "HEAD:current.txt")
	historyGit(t, dir, "config", "core.repositoryFormatVersion", "1")
	historyGit(t, dir, "config", "extensions.partialClone", "origin")
	historyGit(t, dir, "config", "remote.origin.promisor", "true")
	historyGit(t, dir, "config", "remote.origin.url", "secscanprobe::never")
	if err := os.Remove(filepath.Join(dir, ".git", "objects", id[:2], id[2:])); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	marker := filepath.Join(bin, "fetched")
	if err := os.WriteFile(filepath.Join(bin, "git-remote-secscanprobe"), []byte("#!/bin/sh\ntouch \"$SECSCAN_TEST_FETCH_MARKER\"\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSCAN_TEST_FETCH_MARKER", marker)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := snapshotHistory(context.Background(), dir, historyLimits{commits: 100000, bundleBytes: 512 << 20}); err == nil {
		t.Error("snapshotHistory(missing promisor object) succeeded")
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshotHistory invoked remote helper: %v", err)
	}
}

func TestHistoryBundleAdvertisementRequiresFrozenHead(t *testing.T) {
	head := strings.Repeat("a", 40)
	for _, data := range []string{"", strings.Repeat("b", 40) + " HEAD\n", head + " refs/heads/main\n", head + " HEAD\n" + head + " refs/tags/extra\n"} {
		if validBundleHead([]byte(data), head) {
			t.Errorf("validBundleHead(%q) accepted changed or ambiguous HEAD", data)
		}
	}
	if !validBundleHead([]byte(head+" HEAD\n"), head) {
		t.Error("validBundleHead() rejected sole frozen HEAD")
	}
}

func TestHistoryContainerArgsKeepBoundary(t *testing.T) {
	head := strings.Repeat("a", 40)
	args := historyContainerArgs("/owned/snapshot", "/owned/out", head, "sha256:prepared")
	for _, required := range []string{"--pull", "never", "--network", "none", "--read-only", "--user", "--cap-drop", "ALL", "no-new-privileges", "type=bind,src=/owned/snapshot,dst=/repo,readonly", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=/repo", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_NO_LAZY_FETCH=1", "--log-opts", head, "--log-level", "error", "git", "sha256:prepared"} {
		if !slices.Contains(args, required) {
			t.Errorf("historyContainerArgs() missing %q", required)
		}
	}
}

func TestAcceptanceHistoryFindsDeletedSecret(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 to run container acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir, first, canary := historyFixture(t)
	got, err := ScanHistory(ctx, runtime, dir, func(progress.Event) {}, Image)
	if err != nil {
		t.Fatalf("ScanHistory() = %v", err)
	}
	found := false
	for _, finding := range got.Findings {
		if finding.Path == "deleted.txt" && finding.Commit == first && finding.Origin == "git_history" {
			found = true
		}
	}
	if !found {
		t.Errorf("ScanHistory() omitted deleted synthetic secret at original commit")
	}
	if len(got.Scanners) != 1 || got.Scanners[0].History == nil || got.Scanners[0].History.Commits != 2 || got.Scanners[0].Coverage.Read != 1 || got.Scanners[0].Coverage.Unit != "repository" {
		t.Errorf("ScanHistory() coverage = %+v", got.Scanners)
	}
	data, err := report.Marshal(got)
	if err != nil || strings.Contains(string(data), canary) {
		t.Errorf("ScanHistory() retained synthetic secret or marshal failed: %v", err)
	}
}
