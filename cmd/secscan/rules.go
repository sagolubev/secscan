// START_MODULE_CONTRACT
// PURPOSE: Import explicit local rule packs and select verified cached rules.
// SCOPE: No rule downloads or repository-driven rule selection.
// DEPENDS: internal/rules/pack.go, internal/rules/store.go, internal/scanner/cache.go
// LINKS: cmd/secscan/rules_test.go#TestRulesImportAndShowWithoutRepository
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// runRules - Import or inspect a private immutable rule pack.
// loadRulePack - Resolve an explicitly selected pack before scanning.
// END_MODULE_MAP

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/sagolubev/secscan/internal/rules"
	"github.com/sagolubev/secscan/internal/scanner"
)

func runRules(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[1] == "" || strings.HasPrefix(args[1], "-") || args[0] != "import" && args[0] != "show" {
		fmt.Fprintln(stderr, "use secscan rules import DIR or secscan rules show ID")
		return 2
	}
	if args[0] == "show" && !rules.ValidID(args[1]) {
		fmt.Fprintln(stderr, "rule-pack ID must be a lowercase SHA-256 digest")
		return 2
	}
	cache, err := scanner.DefaultCache()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var pack rules.Pack
	if args[0] == "import" {
		pack, err = rules.Import(ctx, cache.Root, args[1])
	} else {
		pack, err = rules.Load(cache.Root, args[1])
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(pack.Metadata()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func loadRulePack(repository, id string) (*rules.Pack, error) {
	cache, err := scanner.DefaultCache()
	if err != nil {
		return nil, err
	}
	root, err := gitRoot(repository)
	if err != nil {
		return nil, err
	}
	cachePath, err := filepath.EvalSymlinks(cache.Root)
	if err != nil {
		return nil, fmt.Errorf("rule-pack cache is unavailable")
	}
	relative, err := repositoryRelativePath(root, cachePath)
	if err != nil {
		return nil, err
	}
	if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("rule-pack cache must be outside the scanned repository")
	}
	pack, err := rules.Load(cache.Root, id)
	if err != nil {
		return nil, err
	}
	return &pack, nil
}
