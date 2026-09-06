package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"github.com/sigiuscom/secscan/internal/container"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRequiredDependencyFeeds(t *testing.T) {
	cache := Cache{Root: t.TempDir()}
	asset := Asset{Feeds: map[string]Feed{}}
	for _, name := range []string{"trivy", "grype", "osv-scanner"} {
		if _, err := dependencyFeedRoot(cache, name, asset, []string{"package-lock.json"}); err == nil {
			t.Errorf("%s accepted missing feed", name)
		}
	}
	now := time.Now().UTC()
	for _, file := range []string{"trivy/db/trivy.db", "trivy/db/metadata.json"} {
		path := filepath.Join(cache.Root, "generation-test", file)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
		digest, err := Digest(path)
		if err != nil {
			t.Fatal(err)
		}
		asset.Feeds[strings.TrimPrefix(file, "trivy/")] = Feed{Path: filepath.Join("generation-test", file), Digest: digest, AcquiredAt: now, BuiltAt: now}
	}
	root, err := dependencyFeedRoot(cache, "trivy", asset, []string{"package-lock.json"})
	if err != nil || root != filepath.Join(cache.Root, "generation-test", "trivy") {
		t.Fatalf("root=%q err=%v", root, err)
	}
	feed := asset.Feeds["db/trivy.db"]
	feed.Path = "generation-other/trivy/db/trivy.db"
	asset.Feeds["db/trivy.db"] = feed
	if _, err := dependencyFeedRoot(cache, "trivy", asset, []string{"package-lock.json"}); err == nil {
		t.Fatal("accepted split generation")
	}
}

func TestDependencyUpdateArgsNoRepository(t *testing.T) {
	for _, name := range []string{"trivy", "grype"} {
		args := strings.Join(dependencyUpdateArgs(name, "sha256:"+strings.Repeat("a", 64), "/snapshot"), " ")
		if strings.Contains(args, "/repo") || strings.Contains(args, "--network none") || !strings.Contains(args, "--pull never") || !strings.Contains(args, "no-new-privileges") || !strings.Contains(args, "size=512m") {
			t.Fatalf("%s unsafe update args: %s", name, args)
		}
	}
}

func TestPrepareDependenciesRejectsUnknownEcosystem(t *testing.T) {
	_, err := prepareDependencyFeeds(context.Background(), container.Runtime{}, "osv-scanner", "unused", t.TempDir(), []string{"unknown.lock"})
	if err == nil {
		t.Fatal("accepted unknown ecosystem")
	}
}

func TestOSVDownloadValidatesArchiveAndTimestamp(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("SYNTHETIC-1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(`{"id":"SYNTHETIC-1"}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	body := archive.Bytes()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Sun, 06 Sep 2026 07:00:00 GMT")
		w.Write(body)
	}))
	defer server.Close()
	timestamp, err := downloadOSV(context.Background(), server.Client(), server.URL, filepath.Join(t.TempDir(), "all.zip"))
	if err != nil || timestamp.IsZero() {
		t.Fatalf("download=%v %v", timestamp, err)
	}
	body = []byte("not an archive")
	if _, err := downloadOSV(context.Background(), server.Client(), server.URL, filepath.Join(t.TempDir(), "all.zip")); err == nil {
		t.Fatal("accepted invalid OSV archive")
	}
}
