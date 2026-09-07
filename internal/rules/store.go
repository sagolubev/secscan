// START_MODULE_CONTRACT
// PURPOSE: Import and load content-addressed offline rules through pinned private storage.
// SCOPE: No network; reject links/nonregular inputs, verify canonical bytes, publish without clobbering.
// DEPENDS: internal/rules/pack.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-reproducibility, internal/rules/store_test.go#TestLoadRejectsTamperAndKeepsSnapshot
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Import - Validate a local manifest and atomically publish its immutable canonical bundle.
// Load - Verify hash, canonical encoding and grammar before returning a snapshot.
// ValidID - Accept only lowercase full SHA-256 identifiers.
// END_MODULE_MAP

package rules

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
)

type manifest struct {
	Version     int      `toml:"version"`
	Source      string   `toml:"source"`
	License     string   `toml:"license"`
	Revision    *string  `toml:"revision"`
	LicenseFile string   `toml:"license_file"`
	Files       []string `toml:"files"`
}

// Import validates a local pack and publishes under cacheRoot/rule-packs without replacement.
func Import(ctx context.Context, cacheRoot, directory string) (Pack, error) {
	if err := ctx.Err(); err != nil {
		return Pack{}, err
	}
	root, err := openDirectory(directory, false)
	if err != nil {
		return Pack{}, err
	}
	defer root.Close()
	data, err := readRegular(root, "rules.toml", maxManifest)
	if err != nil {
		return Pack{}, err
	}
	var m manifest
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&m); err != nil {
		return Pack{}, errors.New("invalid rule-pack manifest")
	}
	if !validRelative(m.LicenseFile) || len(m.Files) == 0 || len(m.Files) > maxFiles {
		return Pack{}, errors.New("invalid rule-pack manifest paths")
	}
	license, err := readRegular(root, m.LicenseFile, maxManifest)
	if err != nil {
		return Pack{}, err
	}
	b := bundle{Version: m.Version, Source: m.Source, License: m.License, LicenseText: string(license)}
	if m.Revision != nil {
		if !lowerHex(*m.Revision, 40) && !lowerHex(*m.Revision, 64) {
			return Pack{}, errors.New("invalid rule-pack revision")
		}
		b.Revision = *m.Revision
	}
	slices.Sort(m.Files)
	total := len(license)
	for i, name := range m.Files {
		if !validRelative(name) || (filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml") || i > 0 && name == m.Files[i-1] {
			return Pack{}, errors.New("invalid rule-pack manifest file")
		}
		if err := ctx.Err(); err != nil {
			return Pack{}, err
		}
		data, err := readRegular(root, name, maxRuleFile)
		if err != nil {
			return Pack{}, err
		}
		total += len(data)
		if total > maxBundle {
			return Pack{}, errors.New("rule-pack bundle exceeds limit")
		}
		b.Files = append(b.Files, bundleFile{Name: name, Data: data})
	}
	pack, err := validateBundle(b)
	if err != nil {
		return Pack{}, err
	}
	canonical, err := json.Marshal(b)
	if err != nil || len(canonical) > maxBundle {
		return Pack{}, errors.New("rule-pack canonical bundle exceeds limit")
	}
	digest := sha256.Sum256(canonical)
	pack.metadata.ID = hex.EncodeToString(digest[:])
	if err := ctx.Err(); err != nil {
		return Pack{}, err
	}
	store, err := openDirectory(filepath.Join(cacheRoot, "rule-packs"), true)
	if err != nil {
		return Pack{}, err
	}
	defer store.Close()
	if err := requirePrivate(store); err != nil {
		return Pack{}, err
	}
	name := pack.metadata.ID + ".json"
	if err := unix.Fstatat(int(store.Fd()), name, &unix.Stat_t{}, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		existing, err := loadFrom(store, pack.metadata.ID)
		if err != nil {
			return Pack{}, err
		}
		return existing, nil
	} else if !errors.Is(err, unix.ENOENT) {
		return Pack{}, errors.New("inspect existing rule-pack bundle")
	}
	if err := publish(ctx, store, name, canonical); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return loadFrom(store, pack.metadata.ID)
		}
		return Pack{}, err
	}
	return pack, nil
}

// Load verifies the selected bundle before returning an immutable in-memory snapshot.
func Load(cacheRoot, id string) (Pack, error) {
	if !ValidID(id) {
		return Pack{}, errors.New("invalid rule-pack ID")
	}
	root, err := openDirectory(filepath.Join(cacheRoot, "rule-packs"), false)
	if err != nil {
		return Pack{}, err
	}
	defer root.Close()
	if err := requirePrivate(root); err != nil {
		return Pack{}, err
	}
	return loadFrom(root, id)
}

// ValidID accepts the exact lowercase hexadecimal SHA-256 content identity.
func ValidID(id string) bool { return lowerHex(id, 64) }

func lowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func loadFrom(root *os.File, id string) (Pack, error) {
	data, err := readRegular(root, id+".json", maxBundle)
	if err != nil {
		return Pack{}, err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != id {
		return Pack{}, errors.New("rule-pack integrity mismatch")
	}
	var b bundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&b); err != nil {
		return Pack{}, errors.New("invalid rule-pack bundle")
	}
	canonical, err := json.Marshal(b)
	if err != nil || !bytes.Equal(data, canonical) {
		return Pack{}, errors.New("noncanonical rule-pack bundle")
	}
	pack, err := validateBundle(b)
	if err != nil {
		return Pack{}, err
	}
	pack.metadata.ID = id
	return pack, nil
}

func openDirectory(directory string, create bool) (*os.File, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.New("invalid rule-pack directory")
	}
	// The caller explicitly selects this root. Resolve normal parent aliases
	// (for example macOS /var), but never follow the root leaf or paths below it.
	parent := filepath.Dir(abs)
	parts := []string{filepath.Base(abs)}
	var resolved string
	for {
		resolved, err = filepath.EvalSymlinks(parent)
		if err == nil {
			break
		}
		if !create || !errors.Is(err, os.ErrNotExist) || filepath.Dir(parent) == parent {
			return nil, errors.New("resolve rule-pack parent directory")
		}
		parts = append([]string{filepath.Base(parent)}, parts...)
		parent = filepath.Dir(parent)
	}
	current, err := os.Open(resolved)
	if err != nil {
		return nil, errors.New("open rule-pack parent directory")
	}
	for _, part := range parts {
		if create {
			if err := unix.Mkdirat(int(current.Fd()), part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				current.Close()
				return nil, errors.New("create rule-pack directory")
			}
		}
		fd, err := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		current.Close()
		if err != nil {
			return nil, errors.New("open rule-pack directory without symlinks")
		}
		current = os.NewFile(uintptr(fd), "rule-pack directory")
	}
	return current, nil
}

func readRegular(root *os.File, name string, limit int64) ([]byte, error) {
	if !validRelative(name) {
		return nil, errors.New("invalid rule-pack relative path")
	}
	directory := root
	defer func() {
		if directory != root {
			directory.Close()
		}
	}()
	parts := strings.Split(name, "/")
	for _, part := range parts[:len(parts)-1] {
		fd, err := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, errors.New("open rule-pack input directory")
		}
		if directory != root {
			directory.Close()
		}
		directory = os.NewFile(uintptr(fd), "rule-pack input directory")
	}
	base := parts[len(parts)-1]
	var before, opened, after unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), base, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("rule-pack input must be a regular file")
	}
	fd, err := unix.Openat(int(directory.Fd()), base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open rule-pack input file")
	}
	file := os.NewFile(uintptr(fd), "rule-pack input")
	defer file.Close()
	if err := unix.Fstat(fd, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Dev != before.Dev || opened.Ino != before.Ino {
		return nil, errors.New("rule-pack input changed during open")
	}
	info, err := file.Stat()
	if err != nil || info.Size() > limit {
		return nil, errors.New("rule-pack input exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("read rule-pack input within size limit")
	}
	last, err := file.Stat()
	if err != nil || last.Size() != info.Size() || !last.ModTime().Equal(info.ModTime()) || int64(len(data)) != info.Size() {
		return nil, errors.New("rule-pack input changed during read")
	}
	if err := unix.Fstatat(int(directory.Fd()), base, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || after.Mode&unix.S_IFMT != unix.S_IFREG || after.Dev != opened.Dev || after.Ino != opened.Ino {
		return nil, errors.New("rule-pack input replaced during read")
	}
	return data, nil
}

func requirePrivate(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("rule-pack directory must be private")
	}
	return nil
}

func publish(ctx context.Context, directory *os.File, name string, data []byte) error {
	temp := ".rule-pack-" + rand.Text()
	fd, err := unix.Openat(int(directory.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("create private rule-pack temporary file")
	}
	file := os.NewFile(uintptr(fd), "rule-pack temporary file")
	defer file.Close()
	defer removeTemporary(directory, file, temp)
	if _, err := file.Write(data); err != nil {
		return errors.New("write rule-pack temporary file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync rule-pack temporary file")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Linkat(int(directory.Fd()), temp, int(directory.Fd()), name, 0); err != nil {
		return fmt.Errorf("publish rule-pack bundle: %w", err)
	}
	return nil
}

func removeTemporary(directory, file *os.File, name string) {
	var owned, current unix.Stat_t
	if unix.Fstat(int(file.Fd()), &owned) != nil || unix.Fstatat(int(directory.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return
	}
	if current.Mode&unix.S_IFMT == unix.S_IFREG && current.Dev == owned.Dev && current.Ino == owned.Ino {
		// A failed cleanup leaves only our private temporary file; never remove a replacement.
		_ = unix.Unlinkat(int(directory.Fd()), name, 0)
	}
}

func writeScannerInput(directory string, data []byte) error {
	root, err := openDirectory(directory, false)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := requirePrivate(root); err != nil {
		return err
	}
	return publish(context.Background(), root, "custom-rules.yaml", data)
}
