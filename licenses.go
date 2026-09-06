// Package secscan provides the license notices distributed with the executable.
package secscan

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed LICENSE THIRD_PARTY_NOTICES.md LICENSES/*.txt
var notices embed.FS

// Licenses returns the project license and complete embedded third-party notices.
func Licenses() (string, error) {
	paths, err := fs.Glob(notices, "LICENSES/*.txt")
	if err != nil {
		return "", fmt.Errorf("list license notices: %w", err)
	}
	paths = append([]string{"LICENSE", "THIRD_PARTY_NOTICES.md"}, paths...)
	var text strings.Builder
	for _, path := range paths {
		data, err := notices.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read license notice %q: %w", path, err)
		}
		fmt.Fprintf(&text, "== %s ==\n%s\n", path, data)
	}
	return text.String(), nil
}
