// FILE: internal/tracecheck/git_test.go
// START_MODULE_CONTRACT
// PURPOSE: Exercise Git snapshot and phase guards against real synthetic repositories.
// SCOPE: Cover staged-only changes, immutable anchors, commit stability and safe reads.
// DEPENDS: internal/tracecheck/git.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability, internal/tracecheck/git.go#StateIdentity
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestAuditStagedChangeMustRemainVisible - Preserve the audited index-only regression.
// TestChangesIncludesCommittedIndexAndWorktree - Require the complete deduplicated union.
// TestChangesRejectsMovingOrInvalidBaseline - Reject mutable or non-commit anchors.
// TestStateIdentityStableAcrossCommit - Keep matching staged/committed state identical.
// TestStateIdentityTracksStagedDeletionRenameAndMode - Bind staged metadata and bytes.
// TestStateIdentityCanonicalGitModes - Ignore permissions Git does not track.
// TestStateIdentityRejectsOtherEvidenceSinks - Limit evidence exemptions to Beads.
// TestStateIdentityRejectsUnsafePaths - Reject traversal, symlink parents and FIFO reads.
// TestStateIdentitySymlinkContentAndBoundary - Bind safe symlink bytes and reject escape.
// TestChangesRejectsUnmergedIndex - Reject unresolved index stages.
// TestValidateBaselineRejectsEitherImplementationPath - Enforce preimplementation state.
// TestValidateIndexAgreement - Require equal content, existence and modes for execution.
// TestStateIdentityStableAfterRevertedHeadCommit - Exclude restored HEAD-only history.
// TestStateIdentityIgnoresOnlyBeadsContent - Ignore metadata while tracking sink renames.
// TestChangesDisablesExternalGitHelpers - Prevent diff, textconv and fsmonitor execution.
// TestChangesDetectsModeWithFilemodeDisabled - Prevent config from hiding executable bits.
// TestStateIdentityRejectsUnsafeEvidenceSink - Keep exempted paths regular and root-bound.
// TestStateIdentityRejectsEmptyChangePath - Reject malformed change records.
// TestChangesRejectsHiddenIndexPaths - Reject assume-unchanged and sparse index flags.
// gitFixture - Create a local repository with synthetic baseline bytes.
// fixtureGit - Run Git only against the fixture repository.
// writeGitFile - Write synthetic fixture files.
// gitIdentity - Obtain an identity from freshly enumerated changes.
// TestChangesRejectsContentTransforms - Reject Git normalization that can hide raw changes.
// TestChangesDetectsRawLineEndingsWithAutocrlf - Ignore autocrlf when finding raw edits.
// TestChangesNeverRunsLiteralUnsetFilter - Reject named filters before executing Git diff.
// END_MODULE_MAP

package tracecheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAuditStagedChangeMustRemainVisible(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"outside.txt": "before"})
	before := gitIdentity(t, root, baseline, Scope{})
	writeGitFile(t, root, "outside.txt", "staged replacement")
	fixtureGit(t, root, "add", "outside.txt")
	writeGitFile(t, root, "outside.txt", "before")
	if got := fixtureGit(t, root, "diff", "--cached", "--name-only"); got != "outside.txt" {
		t.Fatalf("staged fixture = %q, want outside.txt", got)
	}
	changes, err := Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) == 0 || ValidateScope(Scope{Implementation: []string{"inside.go"}}, changes) == nil {
		t.Errorf("Changes(staged outside.txt) = %v, want visible out-of-scope change", changes)
	}
	if got := gitIdentity(t, root, baseline, Scope{}); got == before {
		t.Error("StateIdentity(staged bytes, restored worktree) unchanged")
	}
}

func TestChangesIncludesCommittedIndexAndWorktree(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"committed": "before", "staged": "before", "working": "before"})
	writeGitFile(t, root, "committed", "committed edit")
	fixtureGit(t, root, "add", "committed")
	fixtureGit(t, root, "commit", "--quiet", "-m", "committed")
	writeGitFile(t, root, "committed", "before")
	writeGitFile(t, root, "staged", "staged edit")
	fixtureGit(t, root, "add", "staged")
	writeGitFile(t, root, "staged", "before")
	writeGitFile(t, root, "working", "working edit")
	writeGitFile(t, root, "untracked\n\tname", "untracked")
	writeGitFile(t, root, ".gitignore", "ignored\n")
	writeGitFile(t, root, "ignored", "ignored")
	changes, err := Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{{Status: "??", Path: ".gitignore"}, {Status: "M", Path: "committed"}, {Status: "M", Path: "staged"}, {Status: "??", Path: "untracked\n\tname"}, {Status: "M", Path: "working"}}
	if !reflect.DeepEqual(changes, want) {
		t.Errorf("Changes(union) = %#v, want %#v", changes, want)
	}
}

func TestChangesRejectsMovingOrInvalidBaseline(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before"})
	fixtureGit(t, root, "tag", "moving")
	for _, anchor := range []string{"HEAD", "moving", baseline[:12], strings.Repeat("a", 40), fixtureGit(t, root, "rev-parse", "HEAD:file")} {
		t.Run(anchor, func(t *testing.T) {
			if _, err := Changes(root, anchor); err == nil {
				t.Errorf("Changes(%q) accepted non-full-commit anchor", anchor)
			}
		})
	}
}

func TestStateIdentityStableAcrossCommit(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"old": "original content", "deleted": "delete me", "mode": "mode"})
	fixtureGit(t, root, "mv", "old", "new")
	fixtureGit(t, root, "rm", "deleted")
	if err := os.Chmod(filepath.Join(root, "mode"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, root, "add", "mode")
	before := gitIdentity(t, root, baseline, Scope{})
	fixtureGit(t, root, "commit", "--quiet", "-m", "matching reviewed state")
	if got := gitIdentity(t, root, baseline, Scope{}); got != before {
		t.Errorf("StateIdentity(after matching commit) = %s, want %s", got, before)
	}
}

func TestStateIdentityTracksStagedDeletionRenameAndMode(t *testing.T) {
	for _, operation := range []string{"delete", "rename", "mode"} {
		t.Run(operation, func(t *testing.T) {
			root, baseline := gitFixture(t, map[string]string{"old": "before"})
			before := gitIdentity(t, root, baseline, Scope{})
			switch operation {
			case "delete":
				fixtureGit(t, root, "rm", "--cached", "old")
			case "rename":
				fixtureGit(t, root, "mv", "old", "new")
				if err := os.Rename(filepath.Join(root, "new"), filepath.Join(root, "old")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				fixtureGit(t, root, "update-index", "--chmod=+x", "old")
			}
			if got := gitIdentity(t, root, baseline, Scope{}); got == before {
				t.Errorf("StateIdentity(staged %s, restored worktree) unchanged", operation)
			}
			changes, err := Changes(root, baseline)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "rename" && ValidateScope(Scope{Implementation: []string{"new"}}, changes) == nil {
				t.Errorf("ValidateScope(staged rename) accepted source old outside scope: %#v", changes)
			}
		})
	}
}

func TestStateIdentityCanonicalGitModes(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before"})
	writeGitFile(t, root, "file", "after")
	before := gitIdentity(t, root, baseline, Scope{})
	if err := os.Chmod(filepath.Join(root, "file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitIdentity(t, root, baseline, Scope{}); got != before {
		t.Errorf("StateIdentity(non-executable permissions) = %s, want %s", got, before)
	}
}

func TestStateIdentityRejectsOtherEvidenceSinks(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before"})
	for _, sink := range []string{"file", ".beads/", ".beads/../file", ".beads/issues.jsonl/"} {
		if _, err := StateIdentity(root, baseline, Scope{EvidenceSinks: []string{sink}}, nil); err == nil {
			t.Errorf("StateIdentity(evidence sink %q) accepted unsupported exemption", sink)
		}
	}
}

func TestStateIdentityRejectsUnsafePaths(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before"})
	outside := t.TempDir()
	writeGitFile(t, outside, "fixture", "synthetic outside value")
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../fixture", "/absolute", "./file", "file/../file", ".git/config", "linked/fixture", "fifo", "directory"} {
		t.Run(path, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(root, "directory"), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := StateIdentity(root, baseline, Scope{}, []Change{{Status: "M", Path: path}}); err == nil {
				t.Errorf("StateIdentity(%q) accepted unsafe path", path)
			}
		})
	}
}

func TestStateIdentitySymlinkContentAndBoundary(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"first": "same", "second": "same"})
	path := filepath.Join(root, "link")
	if err := os.Symlink("first", path); err != nil {
		t.Fatal(err)
	}
	before := gitIdentity(t, root, baseline, Scope{})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("second", path); err != nil {
		t.Fatal(err)
	}
	if got := gitIdentity(t, root, baseline, Scope{}); got == before {
		t.Error("StateIdentity(symlink target changed) unchanged")
	}
	fixtureGit(t, root, "add", "link")
	before = gitIdentity(t, root, baseline, Scope{})
	fixtureGit(t, root, "commit", "--quiet", "-m", "link")
	if got := gitIdentity(t, root, baseline, Scope{}); got != before {
		t.Errorf("StateIdentity(committed symlink) = %s, want %s", got, before)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside", path); err != nil {
		t.Fatal(err)
	}
	if _, err := StateIdentity(root, baseline, Scope{}, []Change{{Status: "M", Path: "link"}}); err == nil {
		t.Error("StateIdentity(escaping symlink) accepted")
	}
}

func TestChangesRejectsUnmergedIndex(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before"})
	object := fixtureGit(t, root, "rev-parse", "HEAD:file")
	command := exec.Command("git", "-C", root, "update-index", "--index-info")
	command.Stdin = strings.NewReader("0 " + strings.Repeat("0", 40) + "\tfile\n100644 " + object + " 1\tfile\n100644 " + object + " 2\tfile\n")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unmerged fixture: %v: %s", err, output)
	}
	if _, err := Changes(root, baseline); err == nil {
		t.Error("Changes(unmerged index) accepted")
	}
}

func TestValidateBaselineRejectsEitherImplementationPath(t *testing.T) {
	scope := Scope{Implementation: []string{"internal/"}, Governance: []string{"design.md"}, EvidenceSinks: []string{".beads/issues.jsonl"}}
	for _, change := range []Change{
		{Status: "M", Path: "internal/file.go"},
		{Status: "R100", OldPath: "internal/file.go", Path: "design.md"},
		{Status: "R100", OldPath: "design.md", Path: "internal/file.go"},
	} {
		if err := ValidateBaseline(scope, []Change{change}); err == nil {
			t.Errorf("ValidateBaseline(%#v) accepted implementation edit", change)
		}
	}
	if err := ValidateBaseline(scope, []Change{{Status: "M", Path: "design.md"}, {Status: "M", Path: ".beads/issues.jsonl"}}); err != nil {
		t.Errorf("ValidateBaseline(governance and Beads) = %v, want nil", err)
	}
}

func TestValidateIndexAgreement(t *testing.T) {
	for _, operation := range []string{"content", "delete", "rename", "mode", "untracked"} {
		t.Run(operation, func(t *testing.T) {
			root, baseline := gitFixture(t, map[string]string{"file": "before"})
			switch operation {
			case "content":
				writeGitFile(t, root, "file", "staged bytes")
				fixtureGit(t, root, "add", "file")
				writeGitFile(t, root, "file", "before")
			case "delete":
				fixtureGit(t, root, "rm", "--cached", "file")
			case "rename":
				fixtureGit(t, root, "mv", "file", "renamed")
				if err := os.Rename(filepath.Join(root, "renamed"), filepath.Join(root, "file")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				fixtureGit(t, root, "update-index", "--chmod=+x", "file")
			case "untracked":
				writeGitFile(t, root, "untracked", "review me")
			}
			changes, err := Changes(root, baseline)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateIndexAgreement(root, Scope{}, changes); err == nil {
				t.Errorf("ValidateIndexAgreement(%s) accepted different planes", operation)
			}
			fixtureGit(t, root, "add", "--all")
			changes, err = Changes(root, baseline)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateIndexAgreement(root, Scope{}, changes); err != nil {
				t.Errorf("ValidateIndexAgreement(staged %s) = %v, want nil", operation, err)
			}
		})
	}
}

func TestStateIdentityStableAfterRevertedHeadCommit(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"old": "baseline"})
	fixtureGit(t, root, "mv", "old", "intermediate")
	fixtureGit(t, root, "commit", "--quiet", "-m", "intermediate")
	fixtureGit(t, root, "mv", "intermediate", "old")
	writeGitFile(t, root, "new", "reviewed")
	fixtureGit(t, root, "add", "--all")
	before := gitIdentity(t, root, baseline, Scope{})
	fixtureGit(t, root, "commit", "--quiet", "-m", "restore old and add new")
	if got := gitIdentity(t, root, baseline, Scope{}); got != before {
		t.Errorf("StateIdentity(after reverted HEAD commit) = %s, want %s", got, before)
	}
}

func TestStateIdentityIgnoresOnlyBeadsContent(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{".beads/issues.jsonl": "before", "file": "before"})
	scope := Scope{EvidenceSinks: []string{".beads/issues.jsonl"}}
	before := gitIdentity(t, root, baseline, scope)
	writeGitFile(t, root, ".beads/issues.jsonl", "staged metadata")
	fixtureGit(t, root, "add", ".beads/issues.jsonl")
	writeGitFile(t, root, ".beads/issues.jsonl", "new metadata")
	changes, err := Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if got := gitIdentity(t, root, baseline, scope); got != before {
		t.Errorf("StateIdentity(Beads metadata only) = %s, want %s", got, before)
	}
	if err := ValidateIndexAgreement(root, scope, changes); err != nil {
		t.Errorf("ValidateIndexAgreement(Beads metadata only) = %v, want nil", err)
	}
	fixtureGit(t, root, "mv", ".beads/issues.jsonl", "renamed")
	if got := gitIdentity(t, root, baseline, scope); got == before {
		t.Error("StateIdentity(Beads renamed outside sink) unchanged")
	}
}

func TestChangesDisablesExternalGitHelpers(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before", ".gitattributes": "file diff=fixture\n"})
	marker := filepath.Join(t.TempDir(), "executed")
	helper := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, root, "config", "diff.external", helper)
	fixtureGit(t, root, "config", "diff.fixture.textconv", helper)
	fixtureGit(t, root, "config", "core.fsmonitor", helper)
	writeGitFile(t, root, "file", "after")
	if _, err := Changes(root, baseline); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("Changes() executed external Git helper: %v", err)
	}
}

func TestChangesDetectsModeWithFilemodeDisabled(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before"})
	fixtureGit(t, root, "config", "core.filemode", "false")
	if err := os.Chmod(filepath.Join(root, "file"), 0o755); err != nil {
		t.Fatal(err)
	}
	changes, err := Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) == 0 {
		t.Error("Changes(executable bit changed with core.filemode=false) omitted mode change")
	}
}

func TestStateIdentityRejectsUnsafeEvidenceSink(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{".beads/issues.jsonl": "synthetic before"})
	if err := os.Remove(filepath.Join(root, ".beads/issues.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside", filepath.Join(root, ".beads/issues.jsonl")); err != nil {
		t.Fatal(err)
	}
	changes := []Change{{Status: "M", Path: ".beads/issues.jsonl"}}
	if _, err := StateIdentity(root, baseline, Scope{EvidenceSinks: []string{".beads/issues.jsonl"}}, changes); err == nil {
		t.Error("StateIdentity(symlink evidence sink) accepted unsafe exemption")
	}
}

func TestStateIdentityRejectsEmptyChangePath(t *testing.T) {
	root, baseline := gitFixture(t, nil)
	if _, err := StateIdentity(root, baseline, Scope{}, []Change{{Status: "M"}}); err == nil {
		t.Error("StateIdentity(empty change path) accepted")
	}
}

func TestChangesRejectsHiddenIndexPaths(t *testing.T) {
	for _, flag := range []string{"--assume-unchanged", "--skip-worktree"} {
		t.Run(flag, func(t *testing.T) {
			root, baseline := gitFixture(t, map[string]string{"file": "before"})
			fixtureGit(t, root, "update-index", flag, "file")
			writeGitFile(t, root, "file", "hidden worktree change")
			if _, err := Changes(root, baseline); err == nil {
				t.Errorf("Changes(%s) accepted hidden index path", flag)
			}
			if err := ValidateIndexAgreement(root, Scope{}, nil); err == nil {
				t.Errorf("ValidateIndexAgreement(%s) accepted hidden index path", flag)
			}
		})
	}
}

func TestChangesRejectsContentTransforms(t *testing.T) {
	for _, attribute := range []string{"text", "crlf", "eol=crlf", "ident", "filter=custom", "filter=unset", "filter=unspecified", "working-tree-encoding=UTF-8"} {
		t.Run(attribute, func(t *testing.T) {
			root, baseline := gitFixture(t, map[string]string{"file": "before\n", ".gitattributes": "file " + attribute + "\n"})
			writeGitFile(t, root, "file", "before\r\n")
			if _, err := Changes(root, baseline); err == nil {
				t.Errorf("Changes(%q) accepted content normalization", attribute)
			}
		})
	}
}

func TestChangesNeverRunsLiteralUnsetFilter(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before\n", ".gitattributes": "file filter=unset\n"})
	marker := filepath.Join(t.TempDir(), "ran")
	helper := filepath.Join(t.TempDir(), "clean")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf ran > \"$TRACECHECK_FILTER_MARKER\"\nprintf 'before\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRACECHECK_FILTER_MARKER", marker)
	fixtureGit(t, root, "config", "filter.unset.clean", helper)
	writeGitFile(t, root, "file", "hidden change\n")
	if _, err := Changes(root, baseline); err == nil {
		t.Error("Changes(filter=unset) accepted clean filter")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("Changes executed an external clean filter")
	}
}

func TestChangesDetectsRawLineEndingsWithAutocrlf(t *testing.T) {
	root, baseline := gitFixture(t, map[string]string{"file": "before\n"})
	fixtureGit(t, root, "config", "core.autocrlf", "true")
	writeGitFile(t, root, "file", "before\r\n")
	changes, err := Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) == 0 {
		t.Error("Changes(core.autocrlf) hid raw line endings")
	}
}

func gitFixture(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	root := t.TempDir()
	fixtureGit(t, root, "init", "--quiet")
	fixtureGit(t, root, "config", "user.name", "Trace fixture")
	fixtureGit(t, root, "config", "user.email", "trace@example.invalid")
	fixtureGit(t, root, "config", "commit.gpgsign", "false")
	fixtureGit(t, root, "config", "core.filemode", "true")
	fixtureGit(t, root, "config", "core.hooksPath", filepath.Join(root, ".no-hooks"))
	for path, data := range files {
		writeGitFile(t, root, path, data)
	}
	fixtureGit(t, root, "add", "--all")
	fixtureGit(t, root, "commit", "--quiet", "--allow-empty", "-m", "baseline")
	return root, fixtureGit(t, root, "rev-parse", "HEAD")
}

func fixtureGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeGitFile(t *testing.T, root, path, data string) {
	t.Helper()
	fullPath := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitIdentity(t *testing.T, root, baseline string, scope Scope) string {
	t.Helper()
	changes, err := Changes(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := StateIdentity(root, baseline, scope, changes)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
