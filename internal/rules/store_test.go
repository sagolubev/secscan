// START_MODULE_CONTRACT
// PURPOSE: Verify deterministic offline storage and hostile filesystem boundaries.
// SCOPE: Preserve previous IDs, private modes and immutable loaded snapshots.
// DEPENDS: internal/rules/store.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-reproducibility
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestImportDeterministicAndRollback - Identity is stable across ordering and changes with content/license.
// TestLoadRejectsTamperAndKeepsSnapshot - Reject cache changes while loaded rules stay immutable.
// TestImportRejectsUnsafeFiles - Reject symlinks, FIFOs, oversized files and invalid IDs.
// TestImportCanceledPreservesCache - Cancellation and failed publication preserve prior bundles.
// TestImportAcceptsParentAliases - Explicit roots can have normal platform aliases in their parents.
// TestConcurrentImportAndWrite - Concurrent publication converges and immutable snapshots support concurrent readers.
// TestCacheAndWriteRejectUnsafeDestinations - Reject cache links, exposed directories and nonregular bundles.
// TestTemporaryCleanupPreservesReplacement - Cleanup must not unlink another file placed at its temporary name.
// END_MODULE_MAP

package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestImportDeterministicAndRollback(t *testing.T) {
	cache := privateDirectory(t)
	files := map[string]string{"z.yml": ruleYAML("custom.z", "python"), "nested/a.yaml": ruleYAML("custom.a", "go")}
	directory := fixtureDirectory(t, files)
	writeFixture(t, directory, "rules.toml", "version = 1\nsource = 'local'\nlicense = 'MIT'\nlicense_file = 'LICENSE'\nfiles = ['z.yml', 'nested/a.yaml']\n")
	first, err := Import(context.Background(), cache, directory)
	if err != nil {
		t.Fatal(err)
	}
	secondDirectory := fixtureDirectory(t, files)
	writeFixture(t, secondDirectory, "rules.toml", "version = 1\nsource = 'local'\nlicense = 'MIT'\nlicense_file = 'LICENSE'\nfiles = ['nested/a.yaml', 'z.yml']\n")
	second, err := Import(context.Background(), cache, secondDirectory)
	if err != nil || first.Metadata().ID != second.Metadata().ID {
		t.Fatalf("deterministic import IDs differ: %v", err)
	}
	metadata := first.Metadata()
	if !ValidID(metadata.ID) || metadata.Source != "local" || metadata.License != "MIT" || metadata.RuleCount != 2 || !reflect.DeepEqual(metadata.Languages, []string{"go", "python"}) {
		t.Fatalf("Metadata = %+v, want exact provenance and counts", metadata)
	}
	path := filepath.Join(cache, "rule-packs", metadata.ID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != metadata.ID || bytes.Contains(data, []byte(directory)) {
		t.Fatal("cache ID does not hash exact portable bundle bytes")
	}
	for _, path := range []string{filepath.Dir(path), path} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("cache mode = %v, %v; want private", info, err)
		}
	}
	writeFixture(t, directory, "LICENSE", "Changed synthetic license\n")
	changedLicense, err := Import(context.Background(), cache, directory)
	if err != nil || changedLicense.Metadata().ID == metadata.ID {
		t.Fatalf("license change failed to change ID: %v", err)
	}
	writeFixture(t, directory, "z.yml", ruleYAML("custom.z", "python")+"# content change\n")
	changedRules, err := Import(context.Background(), cache, directory)
	if err != nil || changedRules.Metadata().ID == changedLicense.Metadata().ID {
		t.Fatalf("rule-byte change failed to change ID: %v", err)
	}
	old, err := Load(cache, metadata.ID)
	if err != nil || !reflect.DeepEqual(old.Metadata(), metadata) {
		t.Fatalf("rollback Load = %+v, %v; want original metadata", old.Metadata(), err)
	}
}

func TestLoadRejectsTamperAndKeepsSnapshot(t *testing.T) {
	cache := privateDirectory(t)
	directory := fixtureDirectory(t, map[string]string{"a.yml": ruleYAML("original.rule", "python")})
	imported, err := Import(context.Background(), cache, directory)
	if err != nil {
		t.Fatal(err)
	}
	id := imported.Metadata().ID
	loaded, err := Load(cache, id)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cache, "rule-packs", id+".json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Dir(path), filepath.Base(path), "CANARY_RULE_SECRET")
	if _, err := Load(cache, id); err == nil || strings.Contains(err.Error(), "CANARY_RULE_SECRET") {
		t.Fatalf("Load tampered cache = %v, want sanitized error", err)
	}
	if _, err := Import(context.Background(), cache, directory); err == nil {
		t.Fatal("Import silently replaced a corrupted existing ID")
	}
	stillTampered, err := os.ReadFile(path)
	if err != nil || string(stillTampered) != "CANARY_RULE_SECRET" {
		t.Fatal("failed import mutated preexisting cache")
	}
	output := privateDirectory(t)
	if err := loaded.Write(output, "python"); err != nil {
		t.Fatalf("immutable Pack.Write = %v", err)
	}
	for _, data := range [][]byte{append(original, '\n'), []byte(`{"version":1}`)} {
		digest := sha256.Sum256(data)
		newID := hex.EncodeToString(digest[:])
		writeFixture(t, cache, "rule-packs/"+newID+".json", string(data))
		if _, err := Load(cache, newID); err == nil {
			t.Fatal("Load accepted noncanonical or invalid correctly hashed JSON")
		}
	}
}

func TestImportRejectsUnsafeFiles(t *testing.T) {
	for _, name := range []string{"manifest symlink", "license symlink", "rule symlink", "parent symlink", "root symlink", "rule FIFO", "manifest size", "license size", "rule size", "file count", "rule count", "bundle size"} {
		t.Run(name, func(t *testing.T) {
			directory := fixtureDirectory(t, map[string]string{"nested/a.yml": ruleYAML("custom.a", "python")})
			outside := privateDirectory(t)
			switch name {
			case "manifest symlink", "license symlink", "rule symlink":
				path := map[string]string{"manifest symlink": "rules.toml", "license symlink": "LICENSE", "rule symlink": "nested/a.yml"}[name]
				data, err := os.ReadFile(filepath.Join(directory, path))
				if err != nil {
					t.Fatal(err)
				}
				writeFixture(t, outside, "input", string(data))
				if err := os.Remove(filepath.Join(directory, path)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "input"), filepath.Join(directory, path)); err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				if err := os.Rename(filepath.Join(directory, "nested"), filepath.Join(outside, "nested")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "nested"), filepath.Join(directory, "nested")); err != nil {
					t.Fatal(err)
				}
			case "root symlink":
				if err := os.Symlink(directory, filepath.Join(outside, "link")); err != nil {
					t.Fatal(err)
				}
				directory = filepath.Join(outside, "link")
			case "rule FIFO":
				if err := os.Remove(filepath.Join(directory, "nested/a.yml")); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(filepath.Join(directory, "nested/a.yml"), 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest size":
				writeFixture(t, directory, "rules.toml", strings.Repeat(" ", 65537))
			case "license size":
				writeFixture(t, directory, "LICENSE", strings.Repeat("a", 65537))
			case "rule size":
				writeFixture(t, directory, "nested/a.yml", strings.Repeat(" ", 2*1024*1024+1))
			case "file count":
				files := map[string]string{}
				for i := 0; i < 257; i++ {
					files[fmt.Sprintf("rule-%d.yml", i)] = ruleYAML(fmt.Sprintf("rule%d", i), "python")
				}
				directory = fixtureDirectory(t, files)
			case "rule count":
				var text strings.Builder
				text.WriteString("rules:\n")
				for i := 0; i < 4097; i++ {
					text.WriteString(strings.TrimPrefix(ruleYAML(fmt.Sprintf("r%d", i), "python"), "rules:\n"))
				}
				writeFixture(t, directory, "nested/a.yml", text.String())
			case "bundle size":
				files := map[string]string{}
				for i := 0; i < 9; i++ {
					files[string(rune('a'+i))+".yml"] = ruleYAML(string(rune('a'+i)), "python") + "#" + strings.Repeat("a", 1500000)
				}
				directory = fixtureDirectory(t, files)
			}
			if _, err := Import(context.Background(), privateDirectory(t), directory); err == nil {
				t.Fatal("Import accepted unsafe files")
			}
		})
	}
	for _, id := range []string{"", "../escape", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		if ValidID(id) {
			t.Fatalf("ValidID(%q) = true, want false", id)
		}
		if _, err := Load(privateDirectory(t), id); err == nil {
			t.Fatalf("Load(%q) accepted invalid ID", id)
		}
	}
}

func TestImportCanceledPreservesCache(t *testing.T) {
	cache := privateDirectory(t)
	directory := fixtureDirectory(t, map[string]string{"a.yml": ruleYAML("custom.a", "python")})
	pack, err := Import(context.Background(), cache, directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Import(ctx, cache, directory); !errors.Is(err, context.Canceled) {
		t.Fatalf("Import canceled = %v, want context.Canceled", err)
	}
	if _, err := Load(cache, pack.Metadata().ID); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(cache, "rule-packs"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("canceled import left files = %v, %v", entries, err)
	}
	blocked := privateDirectory(t)
	writeFixture(t, blocked, "rule-packs", "preserve")
	if _, err := Import(context.Background(), blocked, directory); err == nil {
		t.Fatal("Import accepted non-directory cache")
	}
	data, err := os.ReadFile(filepath.Join(blocked, "rule-packs"))
	if err != nil || string(data) != "preserve" {
		t.Fatal("failed publication changed prior cache file")
	}
}

func TestImportAcceptsParentAliases(t *testing.T) {
	directory := fixtureDirectory(t, map[string]string{"a.yml": ruleYAML("custom.a", "python")})
	aliasParent := privateDirectory(t)
	if err := os.Symlink(filepath.Dir(directory), filepath.Join(aliasParent, "alias")); err != nil {
		t.Fatal(err)
	}
	aliased := filepath.Join(aliasParent, "alias", filepath.Base(directory))
	pack, err := Import(context.Background(), privateDirectory(t), aliased)
	if err != nil {
		t.Fatalf("Import through parent alias = %v, want success", err)
	}
	output := filepath.Join(aliased, "output")
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	if err := pack.Write(output, "python"); err != nil {
		t.Fatalf("Write through parent alias = %v, want success", err)
	}
}

func TestConcurrentImportAndWrite(t *testing.T) {
	cache := privateDirectory(t)
	directory := fixtureDirectory(t, map[string]string{"a.yml": ruleYAML("custom.a", "python")})
	results := make(chan struct {
		pack Pack
		err  error
	})
	for i := 0; i < 8; i++ {
		go func() {
			pack, err := Import(context.Background(), cache, directory)
			results <- struct {
				pack Pack
				err  error
			}{pack, err}
		}()
	}
	var first Pack
	for i := 0; i < 8; i++ {
		result := <-results
		if result.err != nil {
			t.Errorf("concurrent Import = %v", result.err)
			continue
		}
		if i == 0 {
			first = result.pack
		} else if result.pack.Metadata().ID != first.Metadata().ID {
			t.Error("concurrent imports returned different IDs")
		}
	}
	entries, err := os.ReadDir(filepath.Join(cache, "rule-packs"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("concurrent Import files = %v, %v; want one bundle", entries, err)
	}
	writes := make(chan error)
	for i := 0; i < 4; i++ {
		output := privateDirectory(t)
		go func() { writes <- first.WriteForPaths(output, "python", []string{"a.py", "a.ts", "nested/a.ts/a.py"}) }()
	}
	for i := 0; i < 4; i++ {
		if err := <-writes; err != nil {
			t.Errorf("concurrent Write = %v", err)
		}
	}
}

func TestCacheAndWriteRejectUnsafeDestinations(t *testing.T) {
	cache := privateDirectory(t)
	directory := fixtureDirectory(t, map[string]string{"a.yml": ruleYAML("custom.a", "python")})
	pack, err := Import(context.Background(), cache, directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bundle symlink", "bundle FIFO", "cache symlink", "cache public", "bundle oversized", "output symlink", "output public"} {
		t.Run(name, func(t *testing.T) {
			root := privateDirectory(t)
			store := filepath.Join(root, "rule-packs")
			if err := os.Mkdir(store, 0700); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(store, pack.Metadata().ID+".json")
			switch name {
			case "bundle symlink":
				if err := os.Symlink(filepath.Join(cache, "rule-packs", pack.Metadata().ID+".json"), filename); err != nil {
					t.Fatal(err)
				}
			case "bundle FIFO":
				if err := unix.Mkfifo(filename, 0600); err != nil {
					t.Fatal(err)
				}
			case "cache symlink":
				if err := os.Remove(store); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(cache, "rule-packs"), store); err != nil {
					t.Fatal(err)
				}
			case "cache public":
				if err := os.Chmod(store, 0755); err != nil {
					t.Fatal(err)
				}
			case "bundle oversized":
				writeFixture(t, store, filepath.Base(filename), strings.Repeat("x", 16*1024*1024+1))
			case "output symlink":
				if err := os.Remove(store); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(privateDirectory(t), store); err != nil {
					t.Fatal(err)
				}
			case "output public":
				if err := os.Chmod(store, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(name, "output") {
				if err := pack.Write(store, "python"); err == nil {
					t.Fatal("Write accepted unsafe destination")
				}
				return
			}
			if _, err := Load(root, pack.Metadata().ID); err == nil {
				t.Fatal("Load accepted unsafe cache")
			}
		})
	}
}

func TestTemporaryCleanupPreservesReplacement(t *testing.T) {
	directory := privateDirectory(t)
	root, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := os.OpenFile(filepath.Join(directory, ".temporary"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(filepath.Join(directory, ".temporary"), filepath.Join(directory, ".moved")); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, directory, ".temporary", "preserve replacement")
	removeTemporary(root, file, ".temporary")
	data, err := os.ReadFile(filepath.Join(directory, ".temporary"))
	if err != nil || string(data) != "preserve replacement" {
		t.Fatal("temporary cleanup removed an unowned replacement")
	}
	removeTemporary(root, file, ".moved")
	if _, err := os.Stat(filepath.Join(directory, ".moved")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned cleanup = %v, want removed file", err)
	}
}
