package container

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDetectFallsBackToPodman(t *testing.T) {
	lookPath := func(name string) (string, error) {
		if name == "docker" {
			return "", errors.New("missing")
		}
		return "/usr/bin/podman", nil
	}
	probe := func(context.Context, string) error { return nil }

	got, err := Detect(context.Background(), lookPath, probe)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if got.Binary != "/usr/bin/podman" {
		t.Errorf("Detect() binary = %q, want podman", got.Binary)
	}
}

func TestDetectReportsRuntimeFailures(t *testing.T) {
	lookPath := func(name string) (string, error) { return "/usr/bin/" + name, nil }
	probe := func(_ context.Context, name string) error {
		return errors.New(name + " daemon refused connection")
	}

	_, err := Detect(context.Background(), lookPath, probe)
	if err == nil || !strings.Contains(err.Error(), "docker daemon refused connection") ||
		!strings.Contains(err.Error(), "podman daemon refused connection") {
		t.Fatalf("Detect() error = %v, want both runtime reasons", err)
	}
}

func TestIsolatedArgsAndBoundedOutput(t *testing.T) {
	args := strings.Join(IsolatedArgs("/safe", "/target"), " ")
	for _, required := range []string{"--pull never", "--network none", "--read-only", "--user ", "--cap-drop ALL", "no-new-privileges", "dst=/target,readonly"} {
		if !strings.Contains(args, required) {
			t.Errorf("missing boundary %q", required)
		}
	}
	var output limitedBuffer
	chunk := make([]byte, 1<<20)
	for i := 0; i < 65; i++ {
		output.Write(chunk)
	}
	if !output.exceeded || output.Len() != 64<<20 {
		t.Fatal("output cap not enforced")
	}
}

func TestIsolatedArgsPreservesRootOwner(t *testing.T) {
	args := isolatedArgs("/root-owned-stage", "/target", 0, 0)
	found := false
	for i, arg := range args {
		if arg == "--user" && i+1 < len(args) {
			found = true
			if args[i+1] != "0:0" {
				t.Errorf("isolatedArgs(root) user = %q, want 0:0", args[i+1])
			}
		}
	}
	if !found {
		t.Fatal("isolatedArgs(root) missing explicit user")
	}
}
