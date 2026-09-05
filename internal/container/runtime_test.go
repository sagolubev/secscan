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
