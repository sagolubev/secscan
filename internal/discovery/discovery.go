package discovery

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Exclusions struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

type Inventory struct {
	Python     []string
	TypeScript []string
	Ignored    Exclusions
}

func Discover(root string) (Inventory, error) {
	selected, err := gitPaths(root, "--cached", "--others", "--exclude-standard")
	if err != nil {
		return Inventory{}, err
	}
	ignored, err := gitPaths(root, "--others", "--ignored", "--exclude-standard")
	if err != nil {
		return Inventory{}, err
	}

	inventory := Inventory{}
	for _, path := range selected {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return Inventory{}, fmt.Errorf("inspect discovered path %q: %w", path, err)
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".py", ".pyi":
			inventory.Python = append(inventory.Python, path)
		case ".ts", ".tsx", ".mts", ".cts":
			inventory.TypeScript = append(inventory.TypeScript, path)
		}
	}
	sort.Strings(inventory.Python)
	sort.Strings(inventory.TypeScript)
	for _, path := range ignored {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		inventory.Ignored.Files++
		inventory.Ignored.Bytes += info.Size()
	}
	return inventory, nil
}

func Stage(root string, files []string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache: %w", err)
	}
	base := filepath.Join(cache, "secscan", "targets")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("create target cache: %w", err)
	}
	target, err := os.MkdirTemp(base, "scan-*")
	if err != nil {
		return "", fmt.Errorf("create target tree: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(target)
		}
	}()

	for _, path := range files {
		clean := filepath.Clean(filepath.FromSlash(path))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("target path escapes repository: %q", path)
		}
		source, err := safeSource(root, clean)
		if err != nil {
			return "", fmt.Errorf("inspect target %q: %w", path, err)
		}
		info, err := os.Lstat(source)
		if err != nil {
			return "", fmt.Errorf("inspect target %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("target %q is not a regular file", path)
		}
		destination := filepath.Join(target, clean)
		if err := copyFile(source, destination); err != nil {
			return "", err
		}
	}
	cleanup = false
	return target, nil
}

func safeSource(root, clean string) (string, error) {
	current := root
	for _, component := range strings.Split(filepath.Clean(clean), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink component %q is not allowed", component)
		}
	}
	return current, nil
}

func gitPaths(root string, args ...string) ([]string, error) {
	commandArgs := append([]string{"-C", root, "ls-files", "-z"}, args...)
	output, err := exec.Command("git", commandArgs...).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	fields := bytes.Split(output, []byte{0})
	paths := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field) > 0 {
			paths = append(paths, filepath.ToSlash(string(field)))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open target %q: %w", source, err)
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create staged target %q: %w", destination, err)
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return fmt.Errorf("copy target %q: %w", source, err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close staged target %q: %w", destination, err)
	}
	return nil
}
