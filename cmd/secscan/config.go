// START_MODULE_CONTRACT
// PURPOSE: Load declarative project filtering policy before scanner execution.
// SCOPE: Bounded regular-file reads; no symlink leaf, executable config or raw parser diagnostics.
// DEPENDS: internal/filter/config.go, cmd/secscan/output.go
// LINKS: cmd/secscan/config_test.go#TestConfigValidationPrecedesScan
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// projectConfiguration - Parsed policy and selected control exclusions.
// prepareProjectConfig - Resolve, bound and validate an optional project config.
// END_MODULE_MAP

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sagolubev/secscan/internal/filter"
)

type projectConfiguration struct {
	value    filter.Config
	excluded []string
	active   bool
}

func prepareProjectConfig(repositoryPath, explicit string, disabled bool) (projectConfiguration, error) {
	result := projectConfiguration{value: filter.Config{Version: 1}}
	if disabled {
		return result, nil
	}
	root, err := gitRoot(repositoryPath)
	if err != nil {
		return result, err
	}
	selected := explicit
	if selected == "" {
		selected = filepath.Join(root, ".secscan.toml")
	}
	resolved, excluded, err := resolveControlPath(root, selected)
	if err != nil {
		return result, fmt.Errorf("resolve project config: %w", err)
	}
	file, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) && explicit == "" {
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("open project config: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return result, fmt.Errorf("project config must be a regular file")
	}
	if info.Size() > filter.MaxConfigBytes {
		return result, fmt.Errorf("project config exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, filter.MaxConfigBytes+1))
	if err != nil {
		return result, fmt.Errorf("read project config: %w", err)
	}
	result.value, err = filter.Parse(data)
	if err != nil {
		return result, err
	}
	result.excluded, result.active = excluded, true
	return result, nil
}
