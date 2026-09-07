// START_MODULE_CONTRACT
// PURPOSE: Prepare and resolve immutable scanner assets without implicit scan downloads.
// SCOPE: Publish successful generations only; history and working-tree Gitleaks share one asset.
// DEPENDS: internal/scanner/cache.go, internal/gitleaks/run.go, internal/opengrep/image.go
// LINKS: cmd/secscan/history_test.go#TestAcceptanceHistoryCLI, openspec/changes/build-secscan/specs/secscan/spec.md#requirement-scanner-preparation
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Update - Prepare the selected engines and feeds as an atomic generation.
// Cache.Resolve - Verify a prepared immutable engine and its assets locally.
// END_MODULE_MAP

package scanner

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/discovery"
	"github.com/sagolubev/secscan/internal/gitleaks"
	"github.com/sagolubev/secscan/internal/opengrep"
)

// Update prepares selected engines and feeds required by repository inputs.
func Update(ctx context.Context, runtime container.Runtime, cache Cache, selection []string, path string) error {
	inventory, err := discovery.Discover(path)
	if err != nil {
		return err
	}
	preparedSelection := append([]string(nil), selection...)
	if slices.Contains(selection, "oci-images") {
		preparedSelection = append(preparedSelection, "trivy", "grype")
	}
	return cache.Update(ctx, func(ctx context.Context, staging string) (map[string]Asset, error) {
		result := map[string]Asset{}
		for _, name := range preparedSelection {
			if name == "refresh-versions" || name == "oci-images" {
				continue
			}
			key := name
			if key == "gitleaks-history" {
				key = "gitleaks"
			}
			if name == "gradle-catalog" || name == "gradle-scripts" {
				key = "osv-scanner"
			}
			if name == "python-sast" || name == "typescript-sast" {
				key = "opengrep"
			}
			if _, ok := result[key]; ok {
				continue
			}
			if key == "bearer" {
				arch, err := RuntimeArchitecture(ctx, runtime)
				if err != nil {
					return nil, err
				}
				if arch != "amd64" {
					continue
				}
			}
			var id, ref string
			var err error
			var static map[string]StaticFile
			switch key {
			case "semgrep", "bearer", "gitleaks", "zizmor", "poutine", "checkov", "checkov-terraform", "kics", "trivy", "grype", "osv-scanner":
				ref = gitleaks.Image
				if key != "gitleaks" {
					ref = Catalog()[key].Image
				}
				if err = runtime.RunDiagnostic(ctx, []string{"pull", ref}); err == nil {
					var data []byte
					data, err = runtime.Output(ctx, "image", "inspect", "--format", "{{.Id}}", ref)
					id = strings.TrimSpace(string(data))
				}
			case "cppcheck":
				ref = cppcheckImage
				static, id, err = prepareCodeAssets(ctx, runtime, key, staging)
			case "opengrep":
				ref = opengrep.ImageTag
				id, err = opengrep.EnsureImage(ctx, runtime)
			default:
				return nil, fmt.Errorf("preparation unavailable for %s", name)
			}
			if err != nil {
				return nil, fmt.Errorf("prepare %s: %w", name, err)
			}
			asset := Asset{ImageID: id, ImageRef: ref, Static: static}
			if key == "bearer" {
				asset.Static, _, err = prepareCodeAssets(ctx, runtime, key, staging)
				if err != nil {
					return nil, err
				}
			}
			if key == "trivy" || key == "grype" || key == "osv-scanner" {
				files, _ := DependencyInputs(inventory.Dependencies)
				if key == "osv-scanner" {
					for _, native := range []string{"gradle-catalog", "gradle-scripts"} {
						if slices.Contains(selection, native) {
							files = append(files, NativeInputs(native, inventory.Dependencies)...)
						}
					}
				}
				if (key == "trivy" || key == "grype") && slices.Contains(selection, "oci-images") && len(files) == 0 {
					files = []string{"package-lock.json"}
				}
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
	if err := verifyCodeAssets(c.Root, name, asset); err != nil {
		return Asset{}, err
	}
	return asset, nil
}
