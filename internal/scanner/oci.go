package scanner

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sigiuscom/secscan/internal/container"
	"github.com/sigiuscom/secscan/internal/discovery"
	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
)

// OCIArgs scans a runtime-exported archive offline without a daemon socket.
func OCIArgs(name, imageID, target, feeds string) []string {
	args := append(container.IsolatedArgs(target, "/repo"), "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m", "--workdir", "/tmp", "--mount", "type=bind,src="+feeds+",dst=/cache,readonly")
	if name == "trivy" {
		return append(args, imageID, "image", "--input", "/repo/image.tar", "--cache-dir", "/cache", "--cache-backend", "memory", "--scanners", "vuln", "--format", "json", "--list-all-pkgs", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-version-check", "--ignorefile", "/dev/null")
	}
	if name == "grype" {
		return append(args, "--env", "GRYPE_DB_CACHE_DIR=/cache", "--env", "GRYPE_DB_AUTO_UPDATE=false", "--env", "GRYPE_CHECK_FOR_APP_UPDATE=false", imageID, "docker-archive:/repo/image.tar", "--output", "json", "-v")
	}
	return nil
}

// ScanOCI discovers targets without network. When enabled it exports targets
// using the host runtime and removes only newly loaded target images after use.
func ScanOCI(ctx context.Context, runtime container.Runtime, cache Cache, root string, files []string, enabled bool, emit func(progress.Event)) (report.Scanner, []report.Finding, error) {
	result := report.Scanner{Name: "oci-images", Status: "skipped", Coverage: report.Coverage{Unit: "images"}, Limitations: []string{"literal Dockerfile FROM and Kubernetes/Compose image fields only; dynamic references remain unread", "target images are never executed; image platform selectors and build stages are not evaluated"}}
	var refs []imageReference
	if len(files) > 0 {
		merged := make(map[string]int)
		for _, file := range files {
			if err := ctx.Err(); err != nil {
				return result, nil, err
			}
			found, unread, err := readImageReferences(root, file)
			if err != nil {
				result.Coverage.FailedFiles++
				result.Coverage.FailedInputs = append(result.Coverage.FailedInputs, file)
				continue
			}
			result.Coverage.Unread += unread
			if unread > 0 {
				result.Coverage.UnreadInputs = append(result.Coverage.UnreadInputs, file)
			}
			for _, ref := range found {
				if index, ok := merged[ref.Reference]; ok {
					refs[index].Locations = append(refs[index].Locations, ref.Locations...)
				} else {
					merged[ref.Reference] = len(refs)
					refs = append(refs, ref)
				}
			}
		}
	}
	slices.SortFunc(refs, func(a, b imageReference) int { return strings.Compare(a.Reference, b.Reference) })
	if !enabled {
		result.Coverage.Unread += len(refs)
		result.Limitations = append(result.Limitations, "image scanning disabled; pass --scan-images to authorize host runtime registry access")
		for _, ref := range refs {
			result.Images = append(result.Images, report.Image{Reference: ref.Reference, Status: "unchecked"})
		}
		return result, nil, nil
	}
	if len(refs) == 0 {
		if result.Coverage.Unread > 0 || result.Coverage.FailedFiles > 0 {
			return result, nil, fmt.Errorf("no statically resolved OCI images; coverage unconfirmed")
		}
		return result, nil, nil
	}
	emit(progress.Event{Scanner: "oci-images", Stage: progress.StagePreparing, Status: progress.StatusRunning, Files: len(refs)})
	result.Capabilities = []string{"host-runtime-registry-access"}
	result.Limitations = append(result.Limitations, "scanner containers have no network or runtime socket; only host inspect/pull/save accesses target images", "Grype read count uses positive package extraction diagnostics; Trivy uses package inventory", "preexisting image IDs are never removed; newly attached aliases to those IDs are retained to protect untagged images")
	assets := make(map[string]Asset)
	feedRoots := make(map[string]string)
	for _, name := range []string{"trivy", "grype"} {
		asset, err := cache.Resolve(ctx, runtime, name)
		feedroot := ""
		if err == nil {
			feedroot, err = dependencyFeedRoot(cache, name, asset, []string{"package-lock.json"})
		}
		engine := report.Engine{Name: name, Image: asset.ImageID, Version: Catalog()[name].Version, Status: "failed"}
		if err == nil {
			assets[name] = asset
			feedRoots[name] = feedroot
			keys, _ := dependencyFeedKeys(name, []string{"package-lock.json"})
			engine.Feeds = feedEvidence(asset, keys)
		} else {
			engine.Failed = len(refs)
		}
		result.Engines = append(result.Engines, engine)
	}
	if len(assets) == 0 {
		return result, nil, fmt.Errorf("OCI engines unavailable; run secscan update --scanners oci-images")
	}
	data, err := runtime.Output(ctx, "image", "ls", "--all", "--no-trunc", "--quiet")
	if err != nil {
		return result, nil, fmt.Errorf("cannot snapshot existing image ownership")
	}
	prior := make(map[string]bool)
	for _, id := range strings.Fields(string(data)) {
		if !ValidImageID(id) {
			return result, nil, fmt.Errorf("invalid preexisting image identity")
		}
		prior[id] = true
	}
	var findings []report.Finding
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return result, findings, err
		}
		emit(progress.Event{Scanner: "oci-images", Stage: progress.StageScanning, Status: progress.StatusRunning, Files: len(refs)})
		image, engineRead, found, err := scanOCIImage(ctx, runtime, ref, prior, assets, feedRoots)
		result.Images = append(result.Images, image)
		findings = append(findings, found...)
		successful := false
		for i := range result.Engines {
			engine := &result.Engines[i]
			if _, ok := assets[engine.Name]; !ok {
				continue
			}
			if engineRead[engine.Name] > 0 {
				engine.Read++
				engine.Status = "success"
				successful = true
			} else {
				engine.Failed++
			}
		}
		if successful {
			result.Coverage.Read++
			for _, loc := range ref.Locations {
				result.Coverage.ReadInputs = append(result.Coverage.ReadInputs, loc.Path)
			}
		}
		if err != nil || !successful || image.Status != "success" {
			result.Coverage.Failed++
			result.Limitations = append(result.Limitations, "a target export, analysis or owned-image cleanup failed; inspect image and engine statuses")
		}
	}
	if result.Coverage.Read == 0 {
		return result, findings, fmt.Errorf("OCI scanners did not confirm image analysis")
	}
	result.Status = "success"
	slices.Sort(result.Coverage.ReadInputs)
	result.Coverage.ReadInputs = slices.Compact(result.Coverage.ReadInputs)
	slices.Sort(result.Limitations)
	result.Limitations = slices.Compact(result.Limitations)
	emit(progress.Event{Scanner: "oci-images", Stage: progress.StageDone, Status: progress.StatusSuccess, Findings: len(findings)})
	return result, report.Normalize(findings), nil
}

func readImageReferences(root, file string) ([]imageReference, int, error) {
	target, err := discovery.Stage(root, []string{file})
	if err != nil {
		return nil, 0, err
	}
	defer os.RemoveAll(target)
	info, err := os.Stat(filepath.Join(target, file))
	if err != nil || info.Size() > 16<<20 {
		return nil, 0, fmt.Errorf("image manifest missing or exceeds 16 MiB limit")
	}
	data, err := os.ReadFile(filepath.Join(target, file))
	if err != nil {
		return nil, 0, err
	}
	return parseOCIReferences(file, data)
}

func scanOCIImage(ctx context.Context, runtime container.Runtime, ref imageReference, prior map[string]bool, assets map[string]Asset, feeds map[string]string) (image report.Image, read map[string]int, findings []report.Finding, err error) {
	image = report.Image{Reference: ref.Reference, Status: "failed"}
	read = make(map[string]int)
	id, inspectErr := inspectTarget(ctx, runtime, ref.Reference)
	missing := inspectErr != nil
	if ctx.Err() != nil {
		return image, read, nil, ctx.Err()
	}
	// Cleanup is installed before pull so interrupted pulls receive the same guard.
	if missing {
		listed, listErr := runtime.Output(ctx, "image", "ls", "--no-trunc", "--quiet", ref.Reference)
		if listErr != nil || strings.TrimSpace(string(listed)) != "" {
			return image, read, nil, fmt.Errorf("cannot establish target absence before pull")
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if cleanupErr := cleanupTarget(cleanupCtx, runtime, ref.Reference, prior); cleanupErr != nil {
				image.Status = "cleanup_failed"
				err = errors.Join(err, cleanupErr)
			}
		}()
		if err = runtime.Run(ctx, []string{"pull", ref.Reference}); err != nil {
			return image, read, nil, fmt.Errorf("target image pull failed")
		}
		id, err = inspectTarget(ctx, runtime, ref.Reference)
		if err != nil {
			return image, read, nil, err
		}
	}
	image.Digest = id
	base, err := os.UserCacheDir()
	if err != nil {
		return image, read, nil, err
	}
	base = filepath.Join(base, "secscan", "targets")
	if err = os.MkdirAll(base, 0700); err != nil {
		return image, read, nil, err
	}
	target, err := os.MkdirTemp(base, "image-*")
	if err != nil {
		return image, read, nil, err
	}
	defer os.RemoveAll(target)
	if err = runtime.Run(ctx, []string{"save", "--output", filepath.Join(target, "image.tar"), id}); err != nil {
		return image, read, nil, fmt.Errorf("target image export failed")
	}
	configID, err := archiveConfigID(filepath.Join(target, "image.tar"))
	if err != nil {
		return image, read, nil, err
	}
	for _, name := range []string{"trivy", "grype"} {
		asset, ok := assets[name]
		if !ok {
			continue
		}
		var required []string
		markers := []string{"failed to analyze", "unable to catalog", "failed to catalog", "gathered packages packages=0 ", "gathered packages packages=0\n"}
		if name == "grype" {
			required = []string{"gathered packages packages="}
		}
		data, code, runErr := runtime.OutputStatus(ctx, OCIArgs(name, asset.ImageID, target, feeds[name]), markers, required...)
		if runErr != nil || code != 0 {
			continue
		}
		found, count, parseErr := parseOCIOutput(data, name, configID, id, ref.Locations)
		if parseErr != nil {
			continue
		}
		read[name] = count
		findings = append(findings, found...)
	}
	if len(read) == 2 {
		image.Status = "success"
	} else if len(read) > 0 {
		image.Status = "partial"
	} else {
		err = fmt.Errorf("image analysis failed")
	}
	return image, read, findings, err
}

func inspectTarget(ctx context.Context, runtime container.Runtime, ref string) (string, error) {
	data, err := runtime.Output(ctx, "image", "inspect", "--format", "{{.Id}}", ref)
	if err != nil {
		return "", fmt.Errorf("target image is unavailable")
	}
	id := strings.TrimSpace(string(data))
	if !ValidImageID(id) {
		return "", fmt.Errorf("invalid target image identity")
	}
	return id, nil
}

func cleanupTarget(ctx context.Context, runtime container.Runtime, ref string, prior map[string]bool) error {
	id, err := inspectTarget(ctx, runtime, ref)
	if err != nil {
		data, listErr := runtime.Output(ctx, "image", "ls", "--no-trunc", "--quiet", ref)
		if listErr != nil || len(strings.TrimSpace(string(data))) > 0 {
			return fmt.Errorf("cannot verify target absence during cleanup")
		}
		return nil
	}
	if prior[id] {
		return nil
	} // Removing a new tag can destroy a preexisting untagged ID.
	if err := runtime.Run(ctx, []string{"image", "rm", "--no-prune", ref}); err != nil {
		return fmt.Errorf("owned target image cleanup failed")
	}
	data, err := runtime.Output(ctx, "image", "ls", "--no-trunc", "--quiet", ref)
	if err != nil || len(strings.TrimSpace(string(data))) > 0 {
		return fmt.Errorf("owned target image removal could not be verified")
	}
	return nil
}

func archiveConfigID(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	archive := tar.NewReader(file)
	for entries := 0; entries < 100000; entries++ {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("invalid runtime image archive")
		}
		if header.Name != "manifest.json" {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size > 1<<20 {
			return "", fmt.Errorf("invalid image archive manifest")
		}
		data, err := io.ReadAll(io.LimitReader(archive, 1<<20))
		if err != nil {
			return "", err
		}
		var manifest []struct {
			Config string `json:"Config"`
		}
		if json.Unmarshal(data, &manifest) != nil || len(manifest) != 1 {
			return "", fmt.Errorf("ambiguous image archive manifest")
		}
		config := manifest[0].Config
		if !filepath.IsLocal(config) {
			return "", fmt.Errorf("unsafe image config path")
		}
		id := "sha256:" + strings.TrimSuffix(filepath.Base(config), ".json")
		if !ValidImageID(id) {
			return "", fmt.Errorf("invalid image archive config identity")
		}
		return id, nil
	}
	return "", fmt.Errorf("image archive manifest missing")
}
