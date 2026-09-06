package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUpdateAtomicRollbackAndConcurrentRetention(t *testing.T) {
	c := Cache{Root: t.TempDir()}
	prepare := func(name string) Prepare {
		return func(ctx context.Context, dir string) (map[string]Asset, error) {
			return map[string]Asset{name: {ImageID: "sha256:" + strings.Repeat("a", 64)}}, nil
		}
	}
	if err := c.Update(context.Background(), prepare("old")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(c.Root, "manifest.json"))
	err := c.Update(context.Background(), func(context.Context, string) (map[string]Asset, error) { return nil, errors.New("failed") })
	after, _ := os.ReadFile(filepath.Join(c.Root, "manifest.json"))
	if err == nil || string(before) != string(after) {
		t.Fatal("failed update changed manifest")
	}
	var wg sync.WaitGroup
	for _, name := range []string{"one", "two"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Update(context.Background(), prepare(name)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	m, err := c.Load()
	if err != nil || len(m) != 3 {
		t.Fatalf("Load()=%v,%v", m, err)
	}
}
func TestFeedIntegrityAndFreshness(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "db")
	os.WriteFile(file, []byte("canary"), 0600)
	now := time.Now().UTC()
	digest, err := Digest(file)
	if err != nil {
		t.Fatal(err)
	}
	feed := Feed{Path: "db", Digest: digest, AcquiredAt: now, BuiltAt: now}
	if err := VerifyFeed(dir, feed, now); err != nil {
		t.Fatal(err)
	}
	for _, age := range []time.Duration{-time.Second, 6 * 24 * time.Hour} {
		bad := feed
		bad.BuiltAt = now.Add(-age)
		if VerifyFeed(dir, bad, now) == nil {
			t.Fatal("accepted invalid feed age")
		}
	}
	os.WriteFile(file, []byte("corrupt"), 0600)
	if VerifyFeed(dir, feed, now) == nil {
		t.Fatal("accepted corrupt feed")
	}
}

func TestUpdatePublishesVerifiedFeedAndCancellationKeepsPrior(t *testing.T) {
	c := Cache{Root: t.TempDir()}
	err := c.Update(context.Background(), func(ctx context.Context, dir string) (map[string]Asset, error) {
		file := filepath.Join(dir, "db")
		if err := os.WriteFile(file, []byte("synthetic database"), 0600); err != nil {
			return nil, err
		}
		digest, err := Digest(file)
		if err != nil {
			return nil, err
		}
		return map[string]Asset{"engine": {ImageID: "sha256:" + strings.Repeat("a", 64), Feeds: map[string]Feed{"db": {Path: "db", Digest: digest, AcquiredAt: time.Now().UTC()}}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(c.Root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := c.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFeed(c.Root, manifest["engine"].Feeds["db"], time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err = c.Update(ctx, func(context.Context, string) (map[string]Asset, error) { cancel(); return map[string]Asset{}, nil })
	after, readErr := os.ReadFile(filepath.Join(c.Root, "manifest.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !errors.Is(err, context.Canceled) || string(before) != string(after) {
		t.Fatal("cancelled update replaced published generation")
	}
}
