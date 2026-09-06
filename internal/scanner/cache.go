// Package scanner manages explicitly prepared, immutable scanner assets.
package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Cache holds generations outside scanned repositories.
type Cache struct{ Root string }

// Asset identifies one prepared engine and its optional advisory feeds.
type Asset struct {
	ImageID    string          `json:"imageID"`
	ImageRef   string          `json:"imageRef"`
	PreparedAt time.Time       `json:"preparedAt"`
	Feeds      map[string]Feed `json:"feeds,omitempty"`
}

// Feed describes a file within a published cache generation.
type Feed struct {
	Path       string    `json:"path"`
	Digest     string    `json:"digest"`
	AcquiredAt time.Time `json:"acquiredAt"`
	BuiltAt    time.Time `json:"builtAt,omitempty"`
}

// Prepare populates a staging directory and returns feed paths relative to it.
type Prepare func(context.Context, string) (map[string]Asset, error)

// DefaultCache locates the current user's cache.
func DefaultCache() (Cache, error) {
	root, err := os.UserCacheDir()
	return Cache{Root: filepath.Join(root, "secscan", "prepared")}, err
}

// Load reads one atomically published manifest.
func (c Cache) Load() (map[string]Asset, error) {
	data, err := os.ReadFile(filepath.Join(c.Root, "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Asset{}, nil
	}
	if err != nil {
		return nil, err
	}
	var result map[string]Asset
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid preparation manifest; run secscan update")
	}
	if result == nil {
		return nil, fmt.Errorf("invalid preparation manifest; run secscan update")
	}
	return result, nil
}

// Update serializes writers across processes; failed preparation never replaces the manifest.
func (c Cache) Update(ctx context.Context, prepare Prepare) error {
	if err := os.MkdirAll(c.Root, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(c.Root, "update.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	prior, err := c.Load()
	if err != nil {
		return err
	}
	staging, err := os.MkdirTemp(c.Root, "generation-")
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			os.RemoveAll(staging)
		}
	}()
	assets, err := prepare(ctx, staging)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now().UTC()
	for name, asset := range assets {
		if !ValidImageID(asset.ImageID) {
			return fmt.Errorf("invalid prepared image ID")
		}
		asset.PreparedAt = now
		for key, feed := range asset.Feeds {
			if err := VerifyFeed(staging, feed, now); err != nil {
				return err
			}
			feed.Path = filepath.Join(filepath.Base(staging), feed.Path)
			asset.Feeds[key] = feed
		}
		prior[name] = asset
	}
	data, err := json.Marshal(prior)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(c.Root, ".manifest-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(c.Root, "manifest.json")); err != nil {
		return err
	}
	published = true
	return nil
}

// ValidImageID accepts only immutable SHA-256 engine IDs.
func ValidImageID(id string) bool {
	if !strings.HasPrefix(id, "sha256:") || len(id) != 71 {
		return false
	}
	_, err := hex.DecodeString(id[7:])
	return err == nil
}

// Digest hashes a regular file without following symlinks.
func Digest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("snapshot is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// VerifyFeed checks integrity and acquisition/upstream age with a five-day ceiling.
func VerifyFeed(root string, feed Feed, now time.Time) error {
	if !filepath.IsLocal(feed.Path) {
		return fmt.Errorf("invalid snapshot path; run secscan update")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, feed.Path))
	if err != nil {
		return fmt.Errorf("missing snapshot; run secscan update")
	}
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	if rootErr != nil {
		return rootErr
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || !filepath.IsLocal(rel) {
		return fmt.Errorf("snapshot escapes cache")
	}
	for _, date := range []time.Time{feed.AcquiredAt, feed.BuiltAt} {
		if date.IsZero() {
			continue
		}
		if date.After(now) || now.Sub(date) > 5*24*time.Hour {
			return fmt.Errorf("snapshot is stale or future-dated; run secscan update")
		}
	}
	if feed.AcquiredAt.IsZero() {
		return fmt.Errorf("snapshot acquisition time missing")
	}
	digest, err := Digest(resolved)
	if err != nil {
		return err
	}
	if digest != feed.Digest {
		return fmt.Errorf("snapshot integrity mismatch; run secscan update")
	}
	return nil
}
