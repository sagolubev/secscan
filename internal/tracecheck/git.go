package tracecheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func Changes(root, baseline string) ([]Change, error) {
	if err := runGit(root, "merge-base", "--is-ancestor", baseline, "HEAD"); err != nil {
		return nil, fmt.Errorf("baseline %q is not an ancestor of HEAD: %w", baseline, err)
	}

	diff, err := gitOutput(root, "diff", "--name-status", "-z", "--find-renames", baseline, "--")
	if err != nil {
		return nil, err
	}
	changes, err := parseChanges(diff)
	if err != nil {
		return nil, err
	}

	untracked, err := gitOutput(root, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	for _, path := range splitNull(untracked) {
		changes = append(changes, Change{Status: "??", Path: path})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path == changes[j].Path {
			return changes[i].OldPath < changes[j].OldPath
		}
		return changes[i].Path < changes[j].Path
	})
	return changes, nil
}

func StateIdentity(root, baseline string, scope Scope, changes []Change) (string, error) {
	hash := sha256.New()
	writeIdentityRecord(hash, []byte(baseline))

	for _, change := range changes {
		for _, path := range []string{change.OldPath, change.Path} {
			if path != "" && forbiddenContentPath(path) {
				return "", fmt.Errorf("refuse to hash sensitive path %q", path)
			}
		}
		if inList(scope.EvidenceSinks, change.Path) &&
			(change.OldPath == "" || inList(scope.EvidenceSinks, change.OldPath)) {
			continue
		}

		fullPath := filepath.Join(root, filepath.FromSlash(change.Path))
		info, err := os.Lstat(fullPath)
		if os.IsNotExist(err) {
			record, _ := json.Marshal(struct {
				Change Change `json:"change"`
			}{Change: change})
			writeIdentityRecord(hash, record)
			continue
		}
		if err != nil {
			return "", fmt.Errorf("inspect %q: %w", change.Path, err)
		}
		var content []byte
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(fullPath)
			if err != nil {
				return "", fmt.Errorf("read symlink %q: %w", change.Path, err)
			}
			content = []byte(target)
		} else {
			content, err = os.ReadFile(fullPath)
			if err != nil {
				return "", fmt.Errorf("read %q: %w", change.Path, err)
			}
		}
		contentHash := sha256.Sum256(content)
		record, _ := json.Marshal(struct {
			Change Change      `json:"change"`
			Mode   os.FileMode `json:"mode"`
			Digest string      `json:"digest"`
		}{
			Change: change,
			Mode:   info.Mode(),
			Digest: hex.EncodeToString(contentHash[:]),
		})
		writeIdentityRecord(hash, record)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
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
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return nil
}

func gitOutput(root string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}

func forbiddenContentPath(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(name, ".env") ||
		strings.Contains(name, "credential") ||
		name == "id_rsa" ||
		strings.HasSuffix(name, ".key") ||
		strings.HasSuffix(name, ".pem")
}
