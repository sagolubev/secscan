// START_MODULE_CONTRACT
// PURPOSE: Load bounded baseline data and prepare safe snapshot output.
// SCOPE: Snapshot contents are untrusted data; in-worktree control paths are excluded from scans.
// DEPENDS: internal/baseline/baseline.go, internal/report/report.go, cmd/secscan/output.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-baselines, cmd/secscan/baseline_test.go#TestRunWritesAndComparesBaseline
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// baselineRequest - Validated snapshot input or new output and control paths.
// prepareBaseline - Validate paths and decode a bounded snapshot before scanning.
// readBaseline - Read only regular files without following a leaf symlink.
// baselineWritable - Reject failed scanner outcomes as a new baseline.
// END_MODULE_MAP

package main

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/sagolubev/secscan/internal/baseline"
	"github.com/sagolubev/secscan/internal/report"
)

type baselineRequest struct {
	previous *baseline.Snapshot
	output   *fileDestination
	excluded []string
}

func prepareBaseline(root, input, output string) (baselineRequest, error) {
	var request baselineRequest
	if output != "" {
		destination, err := prepareOutputFile(root, output)
		if err != nil {
			return request, err
		}
		request.output, request.excluded = destination, destination.excluded
		return request, nil
	}
	path, excluded, err := resolveControlPath(root, input)
	if err != nil {
		return request, err
	}
	snapshot, err := readBaseline(path)
	if err != nil {
		return request, err
	}
	request.previous, request.excluded = &snapshot, excluded
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

func baselineWritable(result report.Report) error {
	for _, scanner := range result.Scanners {
		c := scanner.Coverage
		if scanner.Status == "failed" || c.Failed > 0 || c.FailedFiles > 0 || c.FailedQueries > 0 {
			return fmt.Errorf("cannot write a baseline with failed scanner analysis; inspect coverage")
		}
	}
	return nil
}
