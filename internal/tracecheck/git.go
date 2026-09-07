// FILE: internal/tracecheck/git.go
// START_MODULE_CONTRACT
// PURPOSE: Bind verification to immutable Git anchors and index/worktree bytes.
// SCOPE: Preserve both rename paths; reject conflicts, unsafe reads and secret paths.
// DEPENDS: internal/tracecheck/tracecheck.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability, internal/tracecheck/git_test.go#TestAuditStagedChangeMustRemainVisible
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// StateAlgorithm - Identify the canonical index/worktree digest format.
// Changes - Collect committed, staged, working and untracked changes.
// StateIdentity - Hash distinct index/worktree states against the original anchor.
// ValidateBaseline - Reject implementation changes in preimplementation evidence.
// ValidateIndexAgreement - Require matching index/worktree outside the Beads sink.
// END_MODULE_MAP

package tracecheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// StateAlgorithm identifies the Git state digest format.
const StateAlgorithm = "git-index-worktree-v2"

const beadsEvidenceSink = ".beads/issues.jsonl"

type gitEntry struct {
	Mode string
	OID  string
}

type fileState struct {
	Mode   string `json:"mode"`
	Digest string `json:"digest"`
}

// Changes returns the union of baseline-to-HEAD, index, worktree and untracked paths.
func Changes(root, baseline string) ([]Change, error) {
	if err := validateGitBaseline(root, baseline); err != nil {
		return nil, err
	}
	if _, err := readIndex(root); err != nil {
		return nil, err
	}
	unique := make(map[Change]struct{})
	for _, revisions := range [][]string{{baseline, "HEAD"}, {"--cached", baseline}, {baseline}} {
		args := append([]string{"diff", "--no-ext-diff", "--no-textconv", "--name-status", "-z", "--find-renames"}, revisions...)
		diff, err := gitOutput(root, append(args, "--")...)
		if err != nil {
			return nil, err
		}
		changes, err := parseChanges(diff)
		if err != nil {
			return nil, err
		}
		for _, change := range changes {
			unique[change] = struct{}{}
		}
	}

	untracked, err := gitOutput(root, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	for _, path := range splitNull(untracked) {
		unique[Change{Status: "??", Path: path}] = struct{}{}
	}
	changes := make([]Change, 0, len(unique))
	for change := range unique {
		changes = append(changes, change)
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path == changes[j].Path {
			if changes[i].OldPath == changes[j].OldPath {
				return changes[i].Status < changes[j].Status
			}
			return changes[i].OldPath < changes[j].OldPath
		}
		return changes[i].Path < changes[j].Path
	})
	return changes, nil
}

// StateIdentity hashes each changed path's index and worktree bytes and Git mode.
// Matching staged bytes retain their identity after commit; HEAD alone is not a plane.
func StateIdentity(root, baseline string, scope Scope, changes []Change) (string, error) {
	if err := validateGitBaseline(root, baseline); err != nil {
		return "", err
	}
	baselineTree, err := readBaselineTree(root, baseline)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	writeIdentityRecord(hash, []byte(StateAlgorithm))
	writeIdentityRecord(hash, []byte(baseline))
	err = visitStates(root, scope, changes, func(path string, entry gitEntry, index, worktree fileState) error {
		// HEAD-only history that has been restored in both planes is not final state.
		if entry == baselineTree[path] && index == worktree {
			return nil
		}
		record, err := json.Marshal(struct {
			Index    fileState `json:"index"`
			Worktree fileState `json:"worktree"`
		}{Index: index, Worktree: worktree})
		if err != nil {
			return err
		}
		writeIdentityRecord(hash, []byte(path))
		writeIdentityRecord(hash, record)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ValidateBaseline rejects implementation paths on either side of a change.
func ValidateBaseline(scope Scope, changes []Change) error {
	if err := validateEvidenceSinks(scope); err != nil {
		return err
	}
	for _, change := range changes {
		for _, path := range []string{change.OldPath, change.Path} {
			if path != "" && inScope(Scope{Implementation: scope.Implementation}, path) {
				return fmt.Errorf("baseline already contains implementation change %q", path)
			}
		}
	}
	return nil
}

// ValidateIndexAgreement requires matching staged and worktree content and modes.
func ValidateIndexAgreement(root string, scope Scope, changes []Change) error {
	return visitStates(root, scope, changes, func(path string, _ gitEntry, index, worktree fileState) error {
		if index != worktree {
			return fmt.Errorf("index and worktree differ at %q; stage the reviewed state", path)
		}
		return nil
	})
}

func validateEvidenceSinks(scope Scope) error {
	for _, path := range scope.EvidenceSinks {
		if path != beadsEvidenceSink {
			return fmt.Errorf("unsupported evidence sink %q", path)
		}
	}
	return nil
}

func visitStates(root string, scope Scope, changes []Change, visit func(string, gitEntry, fileState, fileState) error) error {
	if err := validateEvidenceSinks(scope); err != nil {
		return err
	}
	paths := make(map[string]struct{})
	for _, change := range changes {
		if change.Path == "" {
			return fmt.Errorf("change requires a repository path")
		}
		for _, path := range []string{change.OldPath, change.Path} {
			if path == "" {
				continue
			}
			if err := validateSnapshotPath(path); err != nil {
				return err
			}
			if forbiddenContentPath(path) {
				return fmt.Errorf("refuse to hash sensitive path %q", path)
			}
			paths[path] = struct{}{}
		}
	}
	index, err := readIndex(root)
	if err != nil {
		return err
	}
	directory, err := os.Open(root)
	if err != nil {
		return fmt.Errorf("open repository: %w", err)
	}
	defer directory.Close()
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	for _, path := range ordered {
		entry := index[path]
		if path == beadsEvidenceSink {
			if entry.Mode != "" && entry.Mode != "100644" && entry.Mode != "100755" {
				return fmt.Errorf("evidence sink must be a regular file")
			}
			if _, err := worktreeState(directory, path, false); err != nil {
				return fmt.Errorf("evidence sink: %w", err)
			}
			continue
		}
		staged, err := indexState(root, entry)
		if err != nil {
			return fmt.Errorf("index %q: %w", path, err)
		}
		working, err := worktreeState(directory, path, true)
		if err != nil {
			return fmt.Errorf("worktree %q: %w", path, err)
		}
		if err := visit(path, entry, staged, working); err != nil {
			return err
		}
	}
	return nil
}

func validateSnapshotPath(path string) error {
	if path == "." || !filepath.IsLocal(path) || filepath.ToSlash(filepath.Clean(path)) != path || strings.ContainsAny(path, "\\\x00") {
		return fmt.Errorf("unsafe repository path %q", path)
	}
	for _, part := range strings.Split(path, "/") {
		if strings.EqualFold(part, ".git") {
			return fmt.Errorf("unsafe repository path %q", path)
		}
	}
	return nil
}

func validateGitBaseline(root, baseline string) error {
	if !validObjectID(baseline) {
		return fmt.Errorf("baseline must be an immutable full commit ID")
	}
	kind, err := gitOutput(root, "cat-file", "-t", baseline)
	if err != nil || strings.TrimSpace(string(kind)) != "commit" {
		return fmt.Errorf("baseline %q does not resolve to a commit", baseline)
	}
	if err := runGit(root, "merge-base", "--is-ancestor", baseline, "HEAD"); err != nil {
		return fmt.Errorf("baseline %q is not an ancestor of HEAD: %w", baseline, err)
	}
	return nil
}

func validObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readIndex(root string) (map[string]gitEntry, error) {
	output, err := gitOutput(root, "ls-files", "--stage", "-v", "-z")
	if err != nil {
		return nil, err
	}
	index := make(map[string]gitEntry)
	for _, record := range splitNull(output) {
		header, path, ok := strings.Cut(record, "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 4 || !validObjectID(fields[2]) {
			return nil, fmt.Errorf("invalid Git index record")
		}
		if fields[3] != "0" {
			return nil, fmt.Errorf("unresolved Git index conflict at %q", path)
		}
		// These flags can hide worktree edits from diff; sparse checkouts are unsupported.
		if fields[0] == "S" || strings.ToLower(fields[0]) == fields[0] {
			return nil, fmt.Errorf("unsupported assume-unchanged or skip-worktree index path %q", path)
		}
		if err := validateSnapshotPath(path); err != nil {
			return nil, err
		}
		index[path] = gitEntry{Mode: fields[1], OID: fields[2]}
	}
	if err := rejectContentTransforms(root, index); err != nil {
		return nil, err
	}
	return index, nil
}

// Git diff applies clean filters and text normalization before comparing bytes.
// Reject those attributes instead of claiming that a normalized diff is raw state.
func rejectContentTransforms(root string, index map[string]gitEntry) error {
	paths := make([]string, 0, len(index))
	for path := range index {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, cached := range []bool{false, true} {
		args := []string{"check-attr", "--all", "-z", "--stdin"}
		if cached {
			args = append(args, "--cached")
		}
		command := gitCommand(root, args...)
		if len(paths) > 0 {
			command.Stdin = strings.NewReader(strings.Join(paths, "\x00") + "\x00")
		}
		output, err := command.Output()
		if err != nil {
			return fmt.Errorf("read Git attributes: %w", err)
		}
		fields := splitNull(output)
		if len(fields)%3 != 0 {
			return fmt.Errorf("invalid Git attribute records")
		}
		for i := 0; i < len(fields); i += 3 {
			switch fields[i+1] {
			case "text", "crlf", "eol", "ident", "filter", "working-tree-encoding":
				return fmt.Errorf("unsupported Git content-transform attribute %q on %q", fields[i+1], fields[i])
			}
		}
	}
	return nil
}

func readBaselineTree(root, baseline string) (map[string]gitEntry, error) {
	output, err := gitOutput(root, "ls-tree", "-r", "-z", baseline)
	if err != nil {
		return nil, err
	}
	tree := make(map[string]gitEntry)
	for _, record := range splitNull(output) {
		header, path, ok := strings.Cut(record, "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 || !validObjectID(fields[2]) {
			return nil, fmt.Errorf("invalid Git tree record")
		}
		tree[path] = gitEntry{Mode: fields[0], OID: fields[2]}
	}
	return tree, nil
}

func indexState(root string, entry gitEntry) (fileState, error) {
	if entry == (gitEntry{}) {
		return fileState{}, nil
	}
	if entry.Mode != "100644" && entry.Mode != "100755" && entry.Mode != "120000" {
		return fileState{}, fmt.Errorf("unsupported Git mode %q", entry.Mode)
	}
	hash := sha256.New()
	command := gitCommand(root, "cat-file", "blob", entry.OID)
	command.Stdout = hash
	if err := command.Run(); err != nil {
		return fileState{}, fmt.Errorf("read Git blob: %w", err)
	}
	return fileState{Mode: entry.Mode, Digest: hex.EncodeToString(hash.Sum(nil))}, nil
}

func worktreeState(root *os.File, path string, readContent bool) (fileState, error) {
	// Go 1.24 has no Root.Readlink. Pin each parent and never follow symlinks.
	directory := root
	defer func() {
		if directory != root {
			directory.Close()
		}
	}()
	parts := strings.Split(path, "/")
	for _, part := range parts[:len(parts)-1] {
		fd, err := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) {
			return fileState{}, nil
		}
		if err != nil {
			return fileState{}, err
		}
		if directory != root {
			directory.Close()
		}
		directory = os.NewFile(uintptr(fd), part)
	}
	name := parts[len(parts)-1]
	var stat unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fileState{}, nil
		}
		return fileState{}, err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		if !readContent {
			return fileState{}, fmt.Errorf("evidence sink must be a regular file")
		}
		buffer := make([]byte, 65536)
		n, err := unix.Readlinkat(int(directory.Fd()), name, buffer)
		if err != nil {
			return fileState{}, err
		}
		if n == len(buffer) {
			return fileState{}, fmt.Errorf("symlink target exceeds read limit")
		}
		target := string(buffer[:n])
		if filepath.IsAbs(target) || validateSnapshotPath(filepath.ToSlash(filepath.Join(filepath.Dir(path), target))) != nil {
			return fileState{}, fmt.Errorf("symlink target escapes repository")
		}
		digest := sha256.Sum256(buffer[:n])
		return fileState{Mode: "120000", Digest: hex.EncodeToString(digest[:])}, nil
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fileState{}, fmt.Errorf("expected regular file or symlink")
	}
	if !readContent {
		return fileState{}, nil
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fileState{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fileState{}, err
	}
	if !info.Mode().IsRegular() {
		return fileState{}, fmt.Errorf("expected regular file")
	}
	mode := "100644"
	if info.Mode()&0o100 != 0 {
		mode = "100755"
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fileState{}, err
	}
	return fileState{Mode: mode, Digest: hex.EncodeToString(hash.Sum(nil))}, nil
}

func writeIdentityRecord(hash io.Writer, record []byte) {
	_ = binary.Write(hash, binary.BigEndian, uint64(len(record)))
	_, _ = hash.Write(record)
}

func parseChanges(data []byte) ([]Change, error) {
	fields := splitNull(data)
	var changes []Change
	for i := 0; i < len(fields); {
		status := fields[i]
		i++
		if i >= len(fields) {
			return nil, fmt.Errorf("missing path after git status %q", status)
		}
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			if i+1 >= len(fields) {
				return nil, fmt.Errorf("missing rename paths after git status %q", status)
			}
			changes = append(changes, Change{Status: status, OldPath: fields[i], Path: fields[i+1]})
			i += 2
			continue
		}
		changes = append(changes, Change{Status: status, Path: fields[i]})
		i++
	}
	return changes, nil
}

func splitNull(data []byte) []string {
	raw := bytes.Split(data, []byte{0})
	result := make([]string, 0, len(raw))
	for _, field := range raw {
		if len(field) > 0 {
			result = append(result, string(field))
		}
	}
	return result
}

func runGit(root string, args ...string) error {
	_, err := gitOutput(root, args...)
	return err
}

func gitOutput(root string, args ...string) ([]byte, error) {
	command := gitCommand(root, args...)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}

func gitCommand(root string, args ...string) *exec.Cmd {
	options := []string{"--no-replace-objects", "--no-optional-locks", "-C", root, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.filemode=true", "-c", "core.autocrlf=false"}
	return exec.Command("git", append(options, args...)...)
}

func forbiddenContentPath(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(name, ".env") ||
		strings.Contains(name, "credential") ||
		name == "id_rsa" ||
		strings.HasSuffix(name, ".key") ||
		strings.HasSuffix(name, ".pem")
}
