package opengrep

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sagolubev/secscan/internal/container"
	scannerassets "github.com/sagolubev/secscan/scanner/opengrep/assets"
)

const (
	ImageTag       = "secscan-opengrep:1.29.0-rules-6389f1f651ce"
	EngineVersion  = "1.29.0"
	RulePackDigest = "6389f1f651ceaa52527e17a7ed0675f2c0b2c1933ede4f3e80ac167b886851e8"
	RuleCount      = 8
)

var upstreamAssets = []struct {
	Name   string
	URL    string
	SHA256 string
}{
	{
		Name:   "opengrep-amd64",
		URL:    "https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_musllinux_x86",
		SHA256: "1b474bf207905a3cffe4e915fe36895835bc89de2620cb2ffd88ca512d9ea31b",
	},
	{
		Name:   "opengrep-arm64",
		URL:    "https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_musllinux_aarch64",
		SHA256: "6cccb7466a98608e308204e17b259f4ca3a9028c6eb71e6b07ea21b89026c484",
	},
	{
		Name:   "OPENGREP-LICENSE",
		URL:    "https://raw.githubusercontent.com/opengrep/opengrep/344509d693c852eaac4fc1eeffaf2f655c531b5a/LICENSE",
		SHA256: "20c17d8b8c48a600800dfd14f95d5cb9ff47066a9641ddeab48dc54aec96e331",
	},
}

type ImageMetadata struct {
	ID            string
	EngineVersion string
	RuleDigest    string
}

type imageRuntime interface {
	Output(context.Context, ...string) ([]byte, error)
	RunDiagnostic(context.Context, []string) error
}

type RuleMetadata struct {
	Digest    string
	RuleCount int
}

func BuildArgs(assetsDir string) []string {
	return []string{
		"build",
		"--pull=false",
		"--provenance=false",
		"--build-arg", "SOURCE_DATE_EPOCH=1787938317",
		"--build-context", "opengrep-assets=" + assetsDir,
		"--tag", ImageTag,
		"--file", filepath.Join(assetsDir, "Dockerfile"),
		assetsDir,
	}
}

func EnsureImage(ctx context.Context, runtime container.Runtime) (string, error) {
	assetsDir, err := EnsureAssets(ctx)
	if err != nil {
		return "", err
	}
	return ensureImage(ctx, runtime, assetsDir)
}

func ensureImage(ctx context.Context, runtime imageRuntime, assetsDir string) (string, error) {
	if err := runtime.RunDiagnostic(ctx, BuildArgs(assetsDir)); err != nil {
		return "", fmt.Errorf("build Opengrep image: %w", err)
	}
	output, err := runtime.Output(ctx, InspectArgs()...)
	if err != nil {
		return "", fmt.Errorf("inspect Opengrep image: %w", err)
	}
	metadata, err := ParseImageMetadata(output)
	if err != nil {
		return "", err
	}
	if metadata.EngineVersion != EngineVersion || metadata.RuleDigest != RulePackDigest {
		return "", fmt.Errorf("built Opengrep image metadata does not match source")
	}
	return metadata.ID, nil
}

func EnsureAssets(ctx context.Context) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache: %w", err)
	}
	directory := filepath.Join(cache, "secscan", "opengrep", EngineVersion)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create Opengrep asset cache: %w", err)
	}
	for _, asset := range upstreamAssets {
		path := filepath.Join(directory, asset.Name)
		if verifyAsset(path, asset.SHA256) == nil {
			continue
		}
		if err := downloadAsset(ctx, path, asset.URL, asset.SHA256); err != nil {
			return "", fmt.Errorf("prepare %s: %w", asset.Name, err)
		}
	}
	if err := prepareBuildContext(directory); err != nil {
		return "", err
	}
	return directory, nil
}

func prepareBuildContext(directory string) error {
	epoch := time.Unix(1787938317, 0)
	dockerfile, err := scannerassets.Files.ReadFile("Dockerfile")
	if err != nil {
		return fmt.Errorf("read embedded Dockerfile: %w", err)
	}
	if err := copyBytes(dockerfile, filepath.Join(directory, "Dockerfile"), 0o444, epoch); err != nil {
		return err
	}
	notice, err := scannerassets.Files.ReadFile("THIRD_PARTY_NOTICES.md")
	if err != nil {
		return fmt.Errorf("read embedded notices: %w", err)
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		target := filepath.Join(directory, "rootfs-"+architecture)
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("reset %s rootfs: %w", architecture, err)
		}
		files := []struct {
			source string
			target string
			mode   os.FileMode
		}{
			{filepath.Join(directory, "opengrep-"+architecture), "usr/local/bin/opengrep", 0o555},
			{filepath.Join(directory, "OPENGREP-LICENSE"), "etc/OPENGREP-LGPL-2.1.txt", 0o444},
		}
		for _, file := range files {
			if err := copyAsset(file.source, filepath.Join(target, file.target), file.mode, epoch); err != nil {
				return err
			}
		}
		if err := copyBytes(notice, filepath.Join(target, "etc", "SECSCAN-THIRD-PARTY-NOTICES.md"), 0o444, epoch); err != nil {
			return err
		}
		if err := fs.WalkDir(scannerassets.Files, "rules", func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			content, err := scannerassets.Files.ReadFile(path)
			if err != nil {
				return err
			}
			relative := strings.TrimPrefix(path, "rules/")
			return copyBytes(content, filepath.Join(target, "rules", relative), 0o444, epoch)
		}); err != nil {
			return fmt.Errorf("prepare rules rootfs: %w", err)
		}
		if err := normalizeDirectoryTimes(target, epoch); err != nil {
			return err
		}
	}
	return nil
}

func copyBytes(content []byte, target string, mode os.FileMode, modified time.Time) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create asset directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".asset-*")
	if err != nil {
		return fmt.Errorf("create temporary asset %q: %w", target, err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write asset %q: %w", target, err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, mode); err != nil {
		return err
	}
	if err := os.Chtimes(temporaryPath, modified, modified); err != nil {
		return err
	}
	return os.Rename(temporaryPath, target)
}

func copyAsset(source, target string, mode os.FileMode, modified time.Time) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open asset %q: %w", source, err)
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create asset directory: %w", err)
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create asset %q: %w", target, err)
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return fmt.Errorf("copy asset %q: %w", target, err)
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Chmod(target, mode); err != nil {
		return err
	}
	return os.Chtimes(target, modified, modified)
}

func normalizeDirectoryTimes(root string, modified time.Time) error {
	var directories []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(directories)))
	for _, directory := range directories {
		if err := os.Chtimes(directory, modified, modified); err != nil {
			return err
		}
	}
	return nil
}

func verifyAsset(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("checksum mismatch")
	}
	return nil
}

func downloadAsset(ctx context.Context, path, url, expected string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", response.StatusCode)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(temporary, hash), response.Body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("download checksum mismatch")
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func InspectArgs() []string {
	return []string{
		"image", "inspect",
		"--format",
		`{{.Id}} {{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "io.secscan.rules.digest"}}`,
		ImageTag,
	}
}

func ParseImageMetadata(output []byte) (ImageMetadata, error) {
	fields := strings.Fields(string(output))
	if len(fields) != 3 {
		return ImageMetadata{}, fmt.Errorf("invalid Opengrep image metadata")
	}
	id := fields[0]
	if !strings.HasPrefix(id, "sha256:") || len(id) <= len("sha256:") {
		return ImageMetadata{}, fmt.Errorf("invalid immutable image ID %q", id)
	}
	return ImageMetadata{
		ID:            id,
		EngineVersion: fields[1],
		RuleDigest:    fields[2],
	}, nil
}

func RulePackMetadata(root string) (RuleMetadata, error) {
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		extension := filepath.Ext(path)
		if extension == ".yml" || extension == ".yaml" {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		return RuleMetadata{}, fmt.Errorf("walk rule pack: %w", err)
	}
	sort.Strings(paths)

	hash := sha256.New()
	count := 0
	for _, path := range paths {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return RuleMetadata{}, fmt.Errorf("resolve rule path: %w", err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return RuleMetadata{}, fmt.Errorf("read rule file %q: %w", relative, err)
		}
		writeRuleRecord(hash, []byte(filepath.ToSlash(relative)))
		writeRuleRecord(hash, content)
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "  - id: ") {
				count++
			}
		}
		if err := scanner.Err(); err != nil {
			return RuleMetadata{}, fmt.Errorf("scan rule file %q: %w", relative, err)
		}
	}
	return RuleMetadata{
		Digest:    hex.EncodeToString(hash.Sum(nil)),
		RuleCount: count,
	}, nil
}

func writeRuleRecord(writer io.Writer, value []byte) {
	_ = binary.Write(writer, binary.BigEndian, uint64(len(value)))
	_, _ = writer.Write(value)
}
