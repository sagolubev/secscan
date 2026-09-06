package secscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLicensesIncludeCompleteDistributedNotices(t *testing.T) {
	paths, err := filepath.Glob("LICENSES/*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no dependency license files")
	}
	paths = append([]string{"LICENSE", "THIRD_PARTY_NOTICES.md"}, paths...)
	text, err := Licenses()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 || !strings.Contains(text, string(data)) {
			t.Errorf("Licenses() lacks complete %s", path)
		}
	}
}
