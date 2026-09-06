package scanner

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigiuscom/secscan/internal/container"
	cppassets "github.com/sigiuscom/secscan/scanner/cppcheck"
)

const (
	bearerRulesCommit    = "30a6919acec715bf915ff4704d1b4ffeac998eab"
	bearerRulesDigest    = "790e2a9bdfc26d9447a1f3038c4079c7ed56bb6e61c49a924a96d61b5e5fbfd5"
	cppcheckSourceCommit = "904cfdcf774c44b17db789c8a212e2f1c69fc833"
	cppcheckSourceDigest = "90ae3b938521d49b2c583e3b04e75a805517a486a99143f77982067688b7b305"
	cppcheckImage        = "secscan-cppcheck:2.21.1-source-90ae3b938521"
)

// StaticFile identifies pinned source or rules without vulnerability-feed expiry.
type StaticFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

func verifyStatic(root string, file StaticFile) error {
	if !filepath.IsLocal(file.Path) {
		return fmt.Errorf("invalid static asset path")
	}
	current := root
	for _, part := range strings.Split(filepath.Clean(file.Path), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("missing static asset; run secscan update")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("static asset symlink rejected")
		}
	}
	digest, err := Digest(current)
	if err != nil {
		return err
	}
	if digest != file.Digest {
		return fmt.Errorf("static asset integrity mismatch; run secscan update")
	}
	return nil
}

func downloadStatic(ctx context.Context, url, path, digest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("static asset download HTTP %d", response.StatusCode)
	}
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(response.Body, (64<<20)+1))
	closeErr := output.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if n > 64<<20 || hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("static asset download integrity mismatch")
	}
	return nil
}

func prepareCodeAssets(ctx context.Context, runtime container.Runtime, name, staging string) (map[string]StaticFile, string, error) {
	directory := filepath.Join(staging, name)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, "", err
	}
	if name == "bearer" {
		archive := filepath.Join(directory, "rules.tar.gz")
		if err := downloadStatic(ctx, "https://codeload.github.com/Bearer/bearer-rules/tar.gz/refs/tags/v0.48.4", archive, bearerRulesDigest); err != nil {
			return nil, "", err
		}
		// Validate the full archive and retain its original ELv2 license in the private cache.
		rules := filepath.Join(directory, "rules")
		if err := extractBearerRules(archive, rules); err != nil {
			return nil, "", err
		}
		license, err := os.ReadFile(filepath.Join(rules, "LICENSE.txt"))
		if err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(filepath.Join(directory, "LICENSE.txt"), license, 0600); err != nil {
			return nil, "", err
		}
		if err := os.RemoveAll(rules); err != nil {
			return nil, "", err
		}
		digest, err := Digest(filepath.Join(directory, "LICENSE.txt"))
		if err != nil {
			return nil, "", err
		}
		return map[string]StaticFile{"rules": {Path: filepath.Join(name, "rules.tar.gz"), Digest: bearerRulesDigest}, "license": {Path: filepath.Join(name, "LICENSE.txt"), Digest: digest}}, "", nil
	}
	source := filepath.Join(directory, "source.tar.gz")
	if err := downloadStatic(ctx, "https://codeload.github.com/danmar/cppcheck/tar.gz/"+cppcheckSourceCommit, source, cppcheckSourceDigest); err != nil {
		return nil, "", err
	}
	assets := map[string]StaticFile{"source": {Path: filepath.Join(name, "source.tar.gz"), Digest: cppcheckSourceDigest}}
	for _, file := range []string{"Dockerfile", "THIRD_PARTY_NOTICES.md", "GCC-COPYING.RUNTIME"} {
		content, err := cppassets.Files.ReadFile(file)
		if err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(filepath.Join(directory, file), content, 0600); err != nil {
			return nil, "", err
		}
		sum := sha256.Sum256(content)
		assets[file] = StaticFile{Path: filepath.Join(name, file), Digest: hex.EncodeToString(sum[:])}
	}
	args := []string{"build", "--pull=false", "--provenance=false", "--build-arg", "SOURCE_DATE_EPOCH=1781913600", "--tag", cppcheckImage, "--file", filepath.Join(directory, "Dockerfile"), directory}
	if err := runtime.RunDiagnostic(ctx, args); err != nil {
		return nil, "", err
	}
	data, err := runtime.Output(ctx, "image", "inspect", "--format", "{{.Id}}", cppcheckImage)
	if err != nil {
		return nil, "", err
	}
	return assets, strings.TrimSpace(string(data)), nil
}

// extractBearerRules rejects unsafe archive entries even when they would be discarded.
// Only static YAML rules and their licenses are copied; source/build files never execute.
func extractBearerRules(archive, destination string) error {
	input, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer input.Close()
	gz, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, (128<<20)+1))
	if err := os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	count := 0
	license := false
	var total int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := header.Name
		if !filepath.IsLocal(name) || strings.ContainsAny(name, "\\\x00") {
			return fmt.Errorf("unsafe rule archive path")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return fmt.Errorf("unsafe rule archive traversal")
			}
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			if len(header.PAXRecords) != 1 || header.PAXRecords["comment"] != bearerRulesCommit {
				return fmt.Errorf("unexpected rule archive source commit")
			}
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			return fmt.Errorf("unsafe rule archive entry")
		}
		if header.Size < 0 || header.Size > 8<<20 {
			return fmt.Errorf("oversized rule archive entry")
		}
		total += header.Size
		if total > 128<<20 {
			return fmt.Errorf("oversized rule archive")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		_, relative, ok := strings.Cut(name, "/")
		if !ok {
			continue
		}
		target := ""
		if relative == "LICENSE.txt" {
			target = "LICENSE.txt"
			license = true
		} else if strings.HasPrefix(relative, "rules/") {
			relative = strings.TrimPrefix(relative, "rules/")
			if strings.HasSuffix(relative, ".yml") || strings.HasSuffix(relative, ".yaml") {
				target = relative
				count++
			} else if strings.HasSuffix(relative, "/LICENSE") || strings.HasSuffix(relative, "/README.md") {
				target = relative
			}
		}
		if target == "" {
			continue
		}
		path := filepath.Join(destination, target)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(file, tr)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if !license || count != 552 {
		return fmt.Errorf("incomplete Bearer rules archive")
	}
	return nil
}

func verifyCodeAssets(root, name string, asset Asset) error {
	required := map[string]string{}
	switch name {
	case "bearer":
		required["rules"] = bearerRulesDigest
		required["license"] = "48255018b41fc0e965b1115af7e6779bc218bb8a6747d561da800d5022622aa2"
		if _, ok := asset.Static["license"]; !ok {
			return fmt.Errorf("missing Bearer license; run secscan update")
		}
	case "cppcheck":
		required["source"] = cppcheckSourceDigest
		for _, name := range []string{"Dockerfile", "THIRD_PARTY_NOTICES.md", "GCC-COPYING.RUNTIME"} {
			data, err := cppassets.Files.ReadFile(name)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			required[name] = hex.EncodeToString(sum[:])
		}
	}
	for key, digest := range required {
		if asset.Static[key].Digest != digest {
			return fmt.Errorf("static asset pin changed; run secscan update")
		}
	}
	for _, file := range asset.Static {
		if err := verifyStatic(root, file); err != nil {
			return err
		}
	}
	return nil
}
