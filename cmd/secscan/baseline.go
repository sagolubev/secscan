// START_MODULE_CONTRACT
// PURPOSE: Load baseline data and publish complete snapshots without clobbering files.
// SCOPE: Snapshot contents are untrusted data; in-worktree control paths are excluded from scans.
// DEPENDS: internal/baseline/baseline.go, internal/report/report.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-baselines, cmd/secscan/baseline_test.go#TestRunWritesAndComparesBaseline
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// baselineRequest - Validated snapshot input or new output and control paths.
// baselineDestination - Pinned parent and a new output name.
// close - Release the destination handles after scanning and publication.
// prepareBaseline - Validate paths and decode a bounded snapshot before scanning.
// readBaseline - Read only regular files without following a leaf symlink.
// publishBaseline - Atomically create a complete new snapshot without overwriting.
// baselineWritable - Reject failed scanner outcomes as a new baseline.
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
	"syscall"

	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/report"
	"golang.org/x/sys/unix"
)

type baselineRequest struct {
	previous *baseline.Snapshot
	output   *baselineDestination
	excluded []string
}

type baselineDestination struct {
	parent *os.Root
	dir    *os.File
	name   string
}

func (destination *baselineDestination) close() {
	destination.dir.Close()
	destination.parent.Close()
}

func prepareBaseline(root, input, output string) (baselineRequest, error) {
	var request baselineRequest
	path := input
	if output != "" {
		path = output
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return request, fmt.Errorf("resolve baseline path: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return request, fmt.Errorf("baseline parent directory must exist: %w", err)
	}
	resolved := filepath.Join(parent, filepath.Base(absolute))
	repository, err := filepath.EvalSymlinks(root)
	if err != nil {
		return request, err
	}
	relative, err := repositoryRelativePath(repository, resolved)
	if err != nil {
		return request, err
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		request.excluded = []string{filepath.ToSlash(relative)}
	}
	if output != "" {
		directory, err := os.OpenRoot(parent)
		if err != nil {
			return request, fmt.Errorf("open baseline parent: %w", err)
		}
		name := filepath.Base(absolute)
		if _, err := directory.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			directory.Close()
			if err == nil {
				return request, fmt.Errorf("baseline output already exists; choose a new file")
			}
			return request, fmt.Errorf("inspect baseline output: %w", err)
		}
		dir, err := directory.Open(".")
		if err != nil {
			directory.Close()
			return request, fmt.Errorf("pin baseline parent: %w", err)
		}
		request.output = &baselineDestination{parent: directory, dir: dir, name: name}
	} else {
		snapshot, err := readBaseline(resolved)
		if err != nil {
			return request, err
		}
		request.previous = &snapshot
	}
	return request, nil
}

// START_CONTRACT: readBaseline
// PURPOSE: Prevent snapshot paths from becoming executable input or unbounded reads.
// INPUTS: path: string - Explicit user-selected baseline file.
// OUTPUTS: Validated Snapshot or a diagnostic that never quotes snapshot data.
// SIDE_EFFECTS: Reads at most baseline.MaxBytes plus one byte from a regular file.
// LINKS: internal/baseline/baseline_test.go#TestCodecBoundary
// END_CONTRACT: readBaseline

func readBaseline(path string) (baseline.Snapshot, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return baseline.Snapshot{}, fmt.Errorf("open baseline: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return baseline.Snapshot{}, fmt.Errorf("baseline must be a regular file")
	}
	if info.Size() > baseline.MaxBytes {
		return baseline.Snapshot{}, fmt.Errorf("baseline exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, baseline.MaxBytes+1))
	if err != nil {
		return baseline.Snapshot{}, fmt.Errorf("read baseline: %w", err)
	}
	return baseline.Decode(data)
}

// START_CONTRACT: publishBaseline
// PURPOSE: Publish one complete snapshot without replacing existing user data.
// INPUTS: destination: pinned parent and new filename; data: bytes produced by baseline.Encode.
// OUTPUTS: Complete file or error; existing destinations remain untouched.
// SIDE_EFFECTS: Creates and removes an owned staging file on the destination filesystem.
// LINKS: cmd/secscan/baseline_test.go#TestBaselinePublicationFailuresPreserveData
// END_CONTRACT: publishBaseline

func publishBaseline(ctx context.Context, destination *baselineDestination, data []byte) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	temporary := ".secscan-baseline-" + rand.Text()
	file, err := destination.parent.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("stage baseline: %w", err)
	}
	defer func() {
		if err := destination.parent.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove baseline staging file: %w", err))
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
		return fmt.Errorf("write baseline: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Linkat pins both paths to the opened parent and refuses a concurrently created target.
	fd := int(destination.dir.Fd())
	if err := unix.Linkat(fd, temporary, fd, destination.name, 0); err != nil {
		return fmt.Errorf("publish new baseline: %w", err)
	}
	return nil
}

func baselineWritable(result report.Report) error {
	for _, scanner := range result.Scanners {
		c := scanner.Coverage
		if scanner.Status == "failed" || c.Failed > 0 || c.FailedFiles > 0 || c.FailedQueries > 0 {
			return fmt.Errorf("cannot write a baseline with failed scanner analysis; inspect coverage")
		}
	}
	return nil
}
