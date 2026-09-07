package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagolubev/secscan/internal/report"
)

type exportDestination struct {
	parent *os.Root
	name   string
}

// repositoryRelativePath recognizes directory aliases on case-insensitive filesystems.
// Both inputs have already had parent symlinks resolved by the caller.
func repositoryRelativePath(repository, path string) (string, error) {
	root, err := os.Stat(repository)
	if err != nil {
		return "", err
	}
	for ancestor := path; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err == nil && os.SameFile(root, info) {
			return filepath.Rel(ancestor, path)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if filepath.Dir(ancestor) == ancestor {
			return filepath.Rel(repository, path)
		}
	}
}

// prepareExportDestination pins the existing parent without creating output.
func prepareExportDestination(repository, destination string) (*exportDestination, error) {
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return nil, fmt.Errorf("resolve report destination: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("report parent directory must exist: %w", err)
	}
	root, err := filepath.EvalSymlinks(repository)
	if err != nil {
		return nil, fmt.Errorf("resolve repository: %w", err)
	}
	relative, err := repositoryRelativePath(root, parent)
	if err != nil {
		return nil, fmt.Errorf("compare report destination: %w", err)
	}
	if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("Trivy reports directory must be outside the Git worktree")
	}
	directory, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open report parent: %w", err)
	}
	name := filepath.Base(absolute)
	if _, err := directory.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		directory.Close()
		if err == nil {
			return nil, fmt.Errorf("report destination already exists; choose a new directory")
		}
		return nil, fmt.Errorf("inspect report destination: %w", err)
	}
	return &exportDestination{parent: directory, name: name}, nil
}

func (destination *exportDestination) write(ctx context.Context, result report.Report) (resultErr error) {
	var payload *report.TrivyReports
	for _, scanner := range result.Scanners {
		if scanner.Name != "trivy" {
			continue
		}
		c := scanner.Coverage
		if payload != nil || scanner.Status != "success" || c.Unit != "packages" || c.Read <= 0 || len(c.ReadInputs) == 0 || c.Unread != 0 || len(c.UnreadInputs) != 0 || c.Failed != 0 || c.FailedFiles != 0 || len(c.FailedInputs) != 0 || c.FailedQueries != 0 || c.Skipped != 0 || scanner.TrivyReports == nil {
			return fmt.Errorf("Trivy export requires complete successful package extraction; inspect scanner coverage in JSON stdout")
		}
		payload = scanner.TrivyReports
	}
	if payload == nil || !json.Valid(payload.CycloneDX) || !json.Valid(payload.SonarQube) {
		return fmt.Errorf("Trivy export has no verified report payloads")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := destination.parent.Mkdir(destination.name, 0700); err != nil {
		return fmt.Errorf("create new report directory: %w", err)
	}
	created, err := destination.parent.Lstat(destination.name)
	if err != nil {
		return fmt.Errorf("inspect new report directory: %w", err)
	}
	var directory *os.Root
	complete := false
	var written []string
	defer func() {
		if !complete {
			for _, name := range written {
				if err := directory.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
					resultErr = errors.Join(resultErr, fmt.Errorf("remove incomplete Trivy export: %w", err))
				}
			}
			if current, err := destination.parent.Lstat(destination.name); err == nil && os.SameFile(created, current) {
				if err := destination.parent.Remove(destination.name); err != nil {
					resultErr = errors.Join(resultErr, fmt.Errorf("remove incomplete report directory: %w", err))
				}
			}
		}
		if directory != nil {
			resultErr = errors.Join(resultErr, directory.Close())
		}
	}()
	directory, err = destination.parent.OpenRoot(destination.name)
	if err != nil {
		return fmt.Errorf("open new report directory: %w", err)
	}
	opened, err := directory.Stat(".")
	if err != nil || !os.SameFile(created, opened) {
		return fmt.Errorf("report directory changed before publication")
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"trivy.cdx.json", payload.CycloneDX}, {"trivy.sonarqube.json", payload.SonarQube}} {
		if err := ctx.Err(); err != nil {
			return err
		}
		output, err := directory.OpenFile(file.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("create Trivy export file: %w", err)
		}
		written = append(written, file.name)
		n, writeErr := output.Write(file.data)
		if writeErr == nil && n != len(file.data) {
			writeErr = io.ErrShortWrite
		}
		err = errors.Join(writeErr, output.Close())
		if err != nil {
			return fmt.Errorf("write Trivy export file: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	complete = true
	return nil
}
