// START_MODULE_CONTRACT
// PURPOSE: Publish complete files under a pinned parent without replacing user data.
// SCOPE: Explicit in-worktree outputs are excluded before scanning; no pathname reopens at publication.
// DEPENDS: cmd/secscan/export.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-report-rendering, cmd/secscan/baseline_test.go#TestBaselinePinsOutputParent
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// fileDestination - Pinned parent, new filename and control exclusions.
// resolveControlPath - Resolve an explicit control path and worktree membership.
// prepareOutputFile - Validate a new file destination without creating it.
// validateOutputNames - Reject filesystem-equivalent names across output formats.
// close - Release opened directory handles.
// write - Atomically publish complete bytes without overwriting.
// END_MODULE_MAP

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type fileDestination struct {
	parent   *os.Root
	dir      *os.File
	name     string
	excluded []string
}

type outputName struct {
	parent *os.Root
	name   string
}

// validateOutputNames uses a private sibling directory to apply the filesystem's
// actual case/Unicode rules without creating any requested output.
func validateOutputNames(outputs []outputName) error {
	var groups []struct {
		parent *os.Root
		info   os.FileInfo
		names  []string
	}
	for _, output := range outputs {
		info, err := output.parent.Stat(".")
		if err != nil {
			return fmt.Errorf("inspect output parent: %w", err)
		}
		found := false
		for i := range groups {
			if os.SameFile(info, groups[i].info) {
				groups[i].names = append(groups[i].names, output.name)
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, struct {
				parent *os.Root
				info   os.FileInfo
				names  []string
			}{output.parent, info, []string{output.name}})
		}
	}
	for _, group := range groups {
		if len(group.names) > 1 {
			if err := checkOutputNames(group.parent, group.names); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkOutputNames(parent *os.Root, names []string) (resultErr error) {
	probe := ".secscan-output-check-" + rand.Text()
	if err := parent.Mkdir(probe, 0700); err != nil {
		return fmt.Errorf("prepare output name check: %w", err)
	}
	dir, err := parent.OpenRoot(probe)
	if err != nil {
		return errors.Join(err, parent.Remove(probe))
	}
	created, err := dir.Stat(".")
	var written []string
	defer func() {
		for _, name := range written {
			resultErr = errors.Join(resultErr, dir.Remove(name))
		}
		resultErr = errors.Join(resultErr, dir.Close())
		current, err := parent.Lstat(probe)
		if err == nil && created != nil && os.SameFile(created, current) {
			resultErr = errors.Join(resultErr, parent.Remove(probe))
		} else {
			resultErr = errors.Join(resultErr, fmt.Errorf("output name check directory changed"))
		}
	}()
	if err != nil {
		return err
	}
	for _, name := range names {
		file, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output destinations refer to the same filesystem entry; choose distinct paths")
		}
		if err != nil {
			return fmt.Errorf("check output names: %w", err)
		}
		written = append(written, name)
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

func resolveControlPath(root, path string) (string, []string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve output path: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", nil, fmt.Errorf("parent directory must exist: %w", err)
	}
	resolved := filepath.Join(parent, filepath.Base(absolute))
	repository, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, err
	}
	relative, err := repositoryRelativePath(repository, resolved)
	if err != nil {
		return "", nil, err
	}
	var excluded []string
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		excluded = []string{filepath.ToSlash(relative)}
	}
	return resolved, excluded, nil
}

func prepareOutputFile(root, path string) (*fileDestination, error) {
	resolved, excluded, err := resolveControlPath(root, path)
	if err != nil {
		return nil, err
	}
	directory, err := os.OpenRoot(filepath.Dir(resolved))
	if err != nil {
		return nil, fmt.Errorf("open output parent: %w", err)
	}
	name := filepath.Base(resolved)
	if _, err := directory.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		directory.Close()
		if err == nil {
			return nil, fmt.Errorf("output already exists; choose a new file")
		}
		return nil, fmt.Errorf("inspect output: %w", err)
	}
	dir, err := directory.Open(".")
	if err != nil {
		directory.Close()
		return nil, fmt.Errorf("pin output parent: %w", err)
	}
	return &fileDestination{parent: directory, dir: dir, name: name, excluded: excluded}, nil
}

func (destination *fileDestination) close() {
	destination.dir.Close()
	destination.parent.Close()
}

// START_CONTRACT: write
// PURPOSE: Publish complete output without a pathname race or replacement of user data.
// INPUTS: ctx: cancellation; data: serialized report bytes.
// OUTPUTS: New complete file or error; an existing destination remains untouched.
// SIDE_EFFECTS: Creates and removes an owned staging file under the pinned parent.
// LINKS: cmd/secscan/baseline_test.go#TestBaselinePinsOutputParent, cmd/secscan/baseline_test.go#TestBaselinePublicationFailuresPreserveData
// END_CONTRACT: write

func (destination *fileDestination) write(ctx context.Context, data []byte) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	temporary := ".secscan-baseline-" + rand.Text()
	file, err := destination.parent.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("stage output: %w", err)
	}
	defer func() {
		if err := destination.parent.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove output staging file: %w", err))
		}
	}()
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Both paths stay relative to the opened directory, including after parent replacement.
	fd := int(destination.dir.Fd())
	if err := unix.Linkat(fd, temporary, fd, destination.name, 0); err != nil {
		return fmt.Errorf("publish new output: %w", err)
	}
	return nil
}
