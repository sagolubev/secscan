package scanner

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/discovery"
)

func dependencyUpdateArgs(name, imageID, dir string) []string {
	args := []string{"run", "--rm", "--pull", "never", "--read-only", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m", "--env", "HOME=/tmp", "--mount", "type=bind,src=" + dir + ",dst=/cache"}
	if name == "grype" {
		return append(args, "--env", "GRYPE_DB_CACHE_DIR=/cache", "--env", "GRYPE_CHECK_FOR_APP_UPDATE=false", imageID, "db", "update")
	}
	return append(args, imageID, "image", "--cache-dir", "/cache", "--download-db-only", "--no-progress")
}

func prepareDependencyFeeds(ctx context.Context, runtime container.Runtime, name, imageID, staging string, files []string) (map[string]Feed, error) {
	dir := filepath.Join(staging, name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	keys, err := dependencyFeedKeys(name, files)
	if err != nil {
		return nil, err
	}
	feeds := make(map[string]Feed)
	if len(keys) == 0 {
		return feeds, nil
	}
	built := time.Time{}
	if name == "osv-scanner" {
		client := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 || req.URL.Scheme != "https" || req.URL.Host != "osv-vulnerabilities.storage.googleapis.com" {
				return fmt.Errorf("unexpected advisory redirect")
			}
			return nil
		}}
		for _, key := range keys {
			ecosystem := strings.TrimSuffix(strings.TrimPrefix(key, "osv-scalibr/"), "/all.zip")
			destination := filepath.Join(dir, key)
			timestamp, err := downloadOSV(ctx, client, "https://osv-vulnerabilities.storage.googleapis.com/"+url.PathEscape(ecosystem)+"/all.zip", destination)
			if err != nil {
				return nil, err
			}
			feed, err := snapshotFeed(staging, destination, timestamp)
			if err != nil {
				return nil, err
			}
			feeds[key] = feed
		}
		return feeds, nil
	}
	if _, err := runtime.Output(ctx, dependencyUpdateArgs(name, imageID, dir)...); err != nil {
		return nil, fmt.Errorf("advisory database download failed: %w", err)
	}
	if name == "trivy" {
		data, err := os.ReadFile(filepath.Join(dir, "db", "metadata.json"))
		if err != nil {
			return nil, err
		}
		var metadata struct {
			UpdatedAt time.Time `json:"UpdatedAt"`
		}
		if json.Unmarshal(data, &metadata) != nil || metadata.UpdatedAt.IsZero() {
			return nil, fmt.Errorf("invalid Trivy database timestamp")
		}
		built = metadata.UpdatedAt
	} else {
		args := []string{"run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--env", "GRYPE_DB_CACHE_DIR=/cache", "--env", "GRYPE_DB_AUTO_UPDATE=false", "--env", "GRYPE_CHECK_FOR_APP_UPDATE=false", "--mount", "type=bind,src=" + dir + ",dst=/cache,readonly", imageID, "db", "status", "-o", "json"}
		data, err := runtime.Output(ctx, args...)
		if err != nil {
			return nil, err
		}
		var metadata struct {
			Built time.Time `json:"built"`
			Valid bool      `json:"valid"`
		}
		if json.Unmarshal(data, &metadata) != nil || metadata.Built.IsZero() || !metadata.Valid {
			return nil, fmt.Errorf("invalid Grype database timestamp")
		}
		built = metadata.Built
	}
	for _, key := range keys {
		feed, err := snapshotFeed(staging, filepath.Join(dir, key), built)
		if err != nil {
			return nil, err
		}
		feeds[key] = feed
	}
	return feeds, nil
}

func snapshotFeed(staging, file string, built time.Time) (Feed, error) {
	digest, err := Digest(file)
	if err != nil {
		return Feed{}, err
	}
	rel, err := filepath.Rel(staging, file)
	if err != nil {
		return Feed{}, err
	}
	return Feed{Path: rel, Digest: digest, AcquiredAt: time.Now().UTC(), BuiltAt: built}, nil
}

func downloadOSV(ctx context.Context, client *http.Client, source, destination string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return time.Time{}, err
	}
	response, err := client.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("OSV advisory download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("OSV advisory download returned HTTP %d", response.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return time.Time{}, err
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return time.Time{}, err
	}
	count, copyErr := io.Copy(file, io.LimitReader(response.Body, (1<<30)+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || count == 0 || count > 1<<30 {
		return time.Time{}, fmt.Errorf("invalid or oversized OSV advisory download")
	}
	archive, err := zip.OpenReader(destination)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid OSV advisory archive")
	}
	valid := len(archive.File) > 0
	for _, entry := range archive.File {
		if !filepath.IsLocal(entry.Name) || !strings.HasSuffix(entry.Name, ".json") || entry.Mode()&os.ModeSymlink != 0 {
			valid = false
			break
		}
	}
	closeErr = archive.Close()
	if !valid || closeErr != nil {
		return time.Time{}, fmt.Errorf("invalid OSV advisory archive entries")
	}
	built := time.Time{}
	if value := response.Header.Get("Last-Modified"); value != "" {
		built, err = http.ParseTime(value)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid OSV advisory timestamp")
		}
	}
	return built, nil
}

func dependencyFeedKeys(name string, files []string) ([]string, error) {
	if len(files) == 0 {
		return nil, nil
	}
	switch name {
	case "trivy":
		return []string{"db/metadata.json", "db/trivy.db"}, nil
	case "grype":
		return []string{"6/import.json", "6/vulnerability.db"}, nil
	case "osv-scanner":
		var keys []string
		for _, file := range files {
			ecosystem := discovery.DependencyEcosystem(file)
			if ecosystem == "" {
				return nil, fmt.Errorf("unsupported dependency ecosystem")
			}
			keys = append(keys, "osv-scalibr/"+ecosystem+"/all.zip")
		}
		slices.Sort(keys)
		return slices.Compact(keys), nil
	}
	return nil, fmt.Errorf("unsupported dependency scanner")
}

// dependencyFeedRoot requires the complete engine-specific layout in one generation.
func dependencyFeedRoot(cache Cache, name string, asset Asset, files []string) (string, error) {
	keys, err := dependencyFeedKeys(name, files)
	if err != nil {
		return "", err
	}
	root := ""
	for _, key := range keys {
		feed, ok := asset.Feeds[key]
		suffix := filepath.Join(name, filepath.FromSlash(key))
		if !ok || !strings.HasSuffix(feed.Path, string(filepath.Separator)+suffix) || !filepath.IsLocal(feed.Path) {
			return "", fmt.Errorf("required advisory snapshot missing; run secscan update")
		}
		candidate := strings.TrimSuffix(filepath.Join(cache.Root, feed.Path), string(filepath.Separator)+filepath.FromSlash(key))
		if root != "" && root != candidate {
			return "", fmt.Errorf("advisory snapshots span generations; run secscan update")
		}
		if (name == "trivy" || name == "grype") && feed.BuiltAt.IsZero() {
			return "", fmt.Errorf("advisory build timestamp missing; run secscan update")
		}
		root = candidate
	}
	if root == "" {
		return "", fmt.Errorf("required advisory snapshot missing; run secscan update")
	}
	return root, nil
}

// ResolveDependencies verifies the prepared engine and every feed needed by the
// selected supported inputs, returning the common read-only mount directory.
func (cache Cache) ResolveDependencies(ctx context.Context, runtime container.Runtime, name string, candidates []string) (Asset, string, error) {
	files, _ := DependencyInputs(candidates)
	if len(files) == 0 {
		return Asset{}, "", fmt.Errorf("no supported dependency inputs")
	}
	asset, err := cache.Resolve(ctx, runtime, name)
	if err != nil {
		return Asset{}, "", err
	}
	root, err := dependencyFeedRoot(cache, name, asset, files)
	return asset, root, err
}
