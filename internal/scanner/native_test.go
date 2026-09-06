package scanner

import (
	"context"
	"github.com/sagolubev/secscan/internal/container"
	"github.com/sagolubev/secscan/internal/progress"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNativeCatalog(t *testing.T) {
	data := []byte(`[versions]
 stable = "1.2.3"
 [libraries]
 inline = "org.example:inline:2.0"
 dotted = { module = "org.example:dotted", version.ref = "stable" }
 separate = { group = "org.example", name = "separate", version = "3.1" }
 missing = { module = "org.example:missing", version.ref = "absent" }
 range = "org.example:range:[1,2)"
 [plugins]
 android = { id = "com.android.application", version = "8.0" }
`)
	inv, err := parseNative("gradle-catalog", "gradle/libs.versions.toml", data)
	if err != nil || len(inv.Packages) != 3 || inv.Unread != 3 {
		t.Fatalf("parseNative catalog: packages=%v unread=%d err=%v; want3/3/nil", inv.Packages, inv.Unread, err)
	}
	for _, p := range inv.Packages {
		if len(p.Locations) != 1 || p.Locations[0].Path != "gradle/libs.versions.toml" {
			t.Errorf("catalog locations=%v", p.Locations)
		}
	}
	if _, err := parseNative("gradle-catalog", "bad.versions.toml", []byte("[libraries\nbad")); err == nil {
		t.Fatal("malformed TOML accepted")
	}
}

func TestNativeScriptsLiteralOnly(t *testing.T) {
	data := []byte("// implementation(\"fake:comment:1\")\nplugins { id(\"java\") }\ndependencies {\n implementation(\"org.example:one:1.0\")\n testImplementation 'org.example:two:2.0'\n implementation(\"org.example:dynamic:$version\")\n implementation(libs.other)\n implementation(\"org.example:range:1.+\")\n}\nprintln(\"fake:outside:1\")\n")
	inv, err := parseNative("gradle-scripts", "build.gradle.kts", data)
	if err != nil || len(inv.Packages) != 2 || inv.Unread < 4 {
		t.Fatalf("script packages=%v unread=%d err=%v", inv.Packages, inv.Unread, err)
	}
	if inv.Packages[0].Locations[0].Line != 4 {
		t.Errorf("literal line=%d want4", inv.Packages[0].Locations[0].Line)
	}
}

func TestNativeRefreshMetadata(t *testing.T) {
	root := t.TempDir()
	data := "version.synthetic=1.0\n## # available=2.0\nversion.dynamic=_\n"
	if err := os.WriteFile(filepath.Join(root, "versions.properties"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	result, findings, err := ScanNative(context.Background(), container.Runtime{}, Cache{}, "refresh-versions", root, []string{"versions.properties"}, func(progress.Event) {})
	if err != nil || result.Status != "success" || len(findings) == 0 {
		t.Fatalf("refresh result=%#v findings=%v err=%v", result, findings, err)
	}
	for _, f := range findings {
		if f.Kind != "configuration" || f.Package != nil || strings.Contains(f.Message, "vulnerab") {
			t.Errorf("refresh claims vulnerability: %#v", f)
		}
	}
}

func TestAcceptanceNative(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	runtime, err := container.DetectDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	inputs := map[string]string{"libs.versions.toml": "[versions]\nlog4j = \"2.14.1\"\n[libraries]\nlog4j = {module=\"org.apache.logging.log4j:log4j-core\", version.ref=\"log4j\"}\n", "build.gradle.kts": "dependencies {\n implementation(\"org.apache.logging.log4j:log4j-core:2.14.1\")\n implementation(libs.dynamic)\n}\n", "gradlew": "#!/bin/sh\ntouch WRAPPER_EXECUTED\n"}
	for file, data := range inputs {
		if err := os.WriteFile(filepath.Join(root, file), []byte(data), 0700); err != nil {
			t.Fatal(err)
		}
	}
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	cache := Cache{Root: filepath.Join(base, "secscan", "acceptance-native")}
	asset, err := cache.Resolve(ctx, runtime, "osv-scanner")
	if err == nil {
		_, err = dependencyFeedRoot(cache, "osv-scanner", asset, []string{"build.gradle"})
	}
	if err != nil {
		if err := Update(ctx, runtime, cache, []string{"gradle-catalog", "gradle-scripts"}, root); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"gradle-catalog", "gradle-scripts"} {
		files := NativeInputs(name, []string{"libs.versions.toml", "build.gradle.kts"})
		result, findings, err := ScanNative(ctx, runtime, cache, name, root, files, func(progress.Event) {})
		if err != nil || result.Coverage.Read != 1 {
			t.Fatalf("%s result=%#v err=%v", name, result, err)
		}
		found := false
		for _, f := range findings {
			if f.Package.Name == "org.apache.logging.log4j:log4j-core" && slices.Contains(f.Advisories, "CVE-2021-44228") && f.Path == files[0] {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s missing real Log4Shell lookup/source identity: %#v", name, findings)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "WRAPPER_EXECUTED")); !os.IsNotExist(err) {
		t.Fatal("Gradle wrapper executed")
	}
}

func TestNativeScriptsDoNotReadStringBodies(t *testing.T) {
	for _, data := range []string{"val text = \"\"\"\ndependencies {\nimplementation(\"org.fake:not-a-dependency:1\")\n}\n\"\"\"", "dependencies {\n implementation(\"org.fake:mismatched:1')\n}"} {
		inv, err := parseNative("gradle-scripts", "build.gradle.kts", []byte(data))
		if err != nil || len(inv.Packages) != 0 || inv.Unread == 0 {
			t.Errorf("string body parsed: packages=%v unread=%d err=%v", inv.Packages, inv.Unread, err)
		}
	}
}

func TestNativeScriptsRequireDependencyDeclarations(t *testing.T) {
	data := []byte("dependencies {\n println(\"org.apache.logging.log4j:log4j-core:2.14.1\")\n customFunction(\"org.fake:other:1\")\n implementation(\"org.example:actual:1\")\n api 'org.example:api:2'\n}\n")
	inv, err := parseNative("gradle-scripts", "build.gradle.kts", data)
	if err != nil || len(inv.Packages) != 2 || inv.Unread != 2 {
		t.Fatalf("declaration extraction packages=%v unread=%d err=%v; want2/2/nil", inv.Packages, inv.Unread, err)
	}
	for _, pkg := range inv.Packages {
		if !strings.HasPrefix(pkg.Name, "org.example:") {
			t.Errorf("non-dependency call extracted: %#v", pkg)
		}
	}
}

func TestNativeScriptsRejectMalformedDeclarations(t *testing.T) {
	for _, statement := range []string{`implementation("org.fake:bad:1"`, `implementation "org.fake:bad:1")`, `implementation"org.fake:bad:1"`} {
		inv, err := parseNative("gradle-scripts", "build.gradle.kts", []byte("dependencies {\n"+statement+"\n}\n"))
		if err != nil || len(inv.Packages) != 0 || inv.Unread != 1 {
			t.Errorf("malformed declaration %q packages=%v unread=%d err=%v", statement, inv.Packages, inv.Unread, err)
		}
	}
}
