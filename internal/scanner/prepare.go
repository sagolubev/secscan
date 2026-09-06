package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/discovery"
	"github.com/sigiuscom/secscan/internal/gitleaks"
	"github.com/sigiuscom/secscan/internal/opengrep"
)

// Update prepares selected engines and feeds required by repository inputs.
func Update(ctx context.Context, runtime container.Runtime, cache Cache, selection []string, path string) error {
	inventory, err := discovery.Discover(path)
	if err != nil {
		return err
	}
	return cache.Update(ctx, func(ctx context.Context, staging string) (map[string]Asset, error) {
		result := map[string]Asset{}
		for _, name := range selection {
			key := name
			if name == "python-sast" || name == "typescript-sast" {
				key = "opengrep"
			}
			if _, ok := result[key]; ok {
				continue
			}
			var id, ref string
			var err error
			switch key {
			case "gitleaks", "zizmor", "poutine", "checkov", "checkov-terraform", "kics", "trivy", "grype", "osv-scanner":
				ref = gitleaks.Image
				if key != "gitleaks" {
					ref = Catalog()[key].Image
				}
				if err = runtime.RunDiagnostic(ctx, []string{"pull", ref}); err == nil {
					var data []byte
					data, err = runtime.Output(ctx, "image", "inspect", "--format", "{{.Id}}", ref)
					id = strings.TrimSpace(string(data))
				}
			case "opengrep":
				ref = opengrep.ImageTag
				id, err = opengrep.EnsureImage(ctx, runtime)
			default:
				return nil, fmt.Errorf("preparation unavailable for %s", name)
			}
			if err != nil {
				return nil, fmt.Errorf("prepare %s: %w", name, err)
			}
			asset := Asset{ImageID: id, ImageRef: ref}
			if key == "trivy" || key == "grype" || key == "osv-scanner" {
				files, _ := DependencyInputs(inventory.Dependencies)
				asset.Feeds, err = prepareDependencyFeeds(ctx, runtime, key, id, staging, files)
				if err != nil {
					return nil, fmt.Errorf("prepare %s feeds: %w", key, err)
				}
			}
			result[key] = asset
		}
		return result, nil
	})
}

// Resolve verifies the prepared immutable engine locally, without pulling or building.
func (c Cache) Resolve(ctx context.Context, runtime container.Runtime, name string) (Asset, error) {
	manifest, err := c.Load()
	if err != nil {
		return Asset{}, err
	}
	asset, ok := manifest[name]
	if !ok || !ValidImageID(asset.ImageID) {
		return Asset{}, fmt.Errorf("%s is not prepared; run secscan update", name)
	}
	expected := Catalog()[name].Image
	switch name {
	case "gitleaks":
		expected = gitleaks.Image
	case "opengrep":
		expected = opengrep.ImageTag
	}
	if expected != "" && asset.ImageRef != expected {
		return Asset{}, fmt.Errorf("%s pin changed; run secscan update", name)
	}
	data, err := runtime.Output(ctx, "image", "inspect", "--format", "{{.Id}}", asset.ImageID)
	if err != nil || strings.TrimSpace(string(data)) != asset.ImageID {
		return Asset{}, fmt.Errorf("%s prepared image is missing; run secscan update", name)
	}
	if name == "opengrep" {
		args := opengrep.InspectArgs()
		args[len(args)-1] = asset.ImageID
		data, err := runtime.Output(ctx, args...)
		if err != nil {
			return Asset{}, fmt.Errorf("Opengrep metadata unavailable; run secscan update")
		}
		metadata, err := opengrep.ParseImageMetadata(data)
		if err != nil || metadata.ID != asset.ImageID || metadata.RuleDigest != opengrep.RulePackDigest || metadata.EngineVersion != opengrep.EngineVersion {
			return Asset{}, fmt.Errorf("Opengrep metadata mismatch; run secscan update")
		}
	}
	for _, feed := range asset.Feeds {
		if err := VerifyFeed(c.Root, feed, time.Now().UTC()); err != nil {
			return Asset{}, err
		}
	}
	return asset, nil
}
