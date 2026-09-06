package tracecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type staleState struct {
	Version   int                      `json:"version"`
	UpdatedAt time.Time                `json:"updated_at"`
	Artifacts map[string]staleArtifact `json:"artifacts"`
}

type staleArtifact struct {
	SHA256    string    `json:"sha256"`
	SyncedAt  time.Time `json:"synced_at"`
	DependsOn []string  `json:"depends_on"`
}

// ValidateStaleness checks the existing opsx-stale inventory, hashes and
// dependency metadata without changing files or requiring the external tool.
func ValidateStaleness(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open artifact directory: %w", err)
	}
	defer root.Close()
	file, err := root.Open(".stale.json")
	if err != nil {
		return fmt.Errorf("open staleness metadata: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var state staleState
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode staleness metadata: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("staleness metadata must contain one JSON document")
	}
	if state.Version != 1 || state.UpdatedAt.IsZero() || len(state.Artifacts) == 0 {
		return fmt.Errorf("staleness metadata requires version 1, updated_at and artifacts")
	}

	paths, err := artifactPaths(dir)
	if err != nil {
		return err
	}
	if len(paths) != len(state.Artifacts) {
		return fmt.Errorf("staleness artifact set differs from files on disk")
	}
	for _, path := range paths {
		artifact, ok := state.Artifacts[path]
		if !ok {
			return fmt.Errorf("missing staleness metadata for %q", path)
		}
		if artifact.SyncedAt.IsZero() || artifact.SyncedAt.After(state.UpdatedAt) {
			return fmt.Errorf("invalid staleness timestamp for %q", path)
		}
		deps := artifactDependencies(path)
		slices.Sort(artifact.DependsOn)
		if artifact.DependsOn == nil || !slices.Equal(artifact.DependsOn, deps) {
			return fmt.Errorf("invalid staleness dependencies for %q", path)
		}
		for _, dep := range deps {
			upstream, ok := state.Artifacts[dep]
			if !ok || upstream.SyncedAt.After(artifact.SyncedAt) {
				return fmt.Errorf("stale artifact %q: dependency %q is missing or newer", path, dep)
			}
		}
		file, err := root.Open(path)
		if err != nil {
			return fmt.Errorf("open artifact %q: %w", path, err)
		}
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		file.Close()
		if err != nil {
			return fmt.Errorf("hash artifact %q: %w", path, err)
		}
		if hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
			return fmt.Errorf("stale artifact %q: SHA256 differs from metadata", path)
		}
	}
	return nil
}

func artifactPaths(dir string) ([]string, error) {
	paths := []string{"proposal.md", "design.md"}
	for _, name := range []string{"failures.md", "decisions.md"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			paths = append(paths, name)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect artifact %q: %w", name, err)
		}
	}
	err := filepath.WalkDir(filepath.Join(dir, "specs"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact symlinks are not allowed: %q", path)
		}
		if !entry.IsDir() && entry.Name() == "spec.md" {
			relative, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			paths = append(paths, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list spec artifacts: %w", err)
	}
	for _, path := range paths {
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			return nil, fmt.Errorf("inspect artifact %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("artifact %q must be a regular file", path)
		}
	}
	slices.Sort(paths)
	return paths, nil
}

func artifactDependencies(path string) []string {
	switch {
	case path == "design.md":
		return []string{"proposal.md"}
	case path == "failures.md" || strings.HasPrefix(path, "specs/"):
		return []string{"design.md"}
	case path == "decisions.md":
		return []string{"design.md", "proposal.md"}
	default:
		return []string{}
	}
}
