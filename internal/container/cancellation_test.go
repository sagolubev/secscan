package container_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sigiuscom/secscan/internal/container"
)

func TestAcceptanceCancellation(t *testing.T) {
	if os.Getenv("SECSCAN_ACCEPTANCE") != "1" {
		t.Skip("set SECSCAN_ACCEPTANCE=1 for the real container boundary")
	}
	control, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	runtime, err := container.DetectDefault(control)
	if err != nil {
		t.Fatal(err)
	}
	// This pinned runtime fixture contains /bin/sleep; it never reads host files.
	const image = "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
	checks := []struct {
		name string
		run  func(context.Context, []string) error
	}{
		{"Run", runtime.Run},
		{"RunDiagnostic", runtime.RunDiagnostic},
		{"Output", func(ctx context.Context, args []string) error { _, err := runtime.Output(ctx, args...); return err }},
		{"OutputRejecting", func(ctx context.Context, args []string) error {
			_, err := runtime.OutputRejecting(ctx, args, nil)
			return err
		}},
		{"OutputStatus", func(ctx context.Context, args []string) error {
			_, _, err := runtime.OutputStatus(ctx, args, nil)
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(control)
			defer cancel()
			label := fmt.Sprintf("secscan.cancel-test=%d", time.Now().UnixNano())
			started := make(chan string, 1)
			go func() {
				defer cancel()
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) && control.Err() == nil {
					data, err := runtime.Output(control, "ps", "--filter", "label="+label, "--format", "{{.ID}}")
					if err == nil && strings.TrimSpace(string(data)) != "" {
						started <- strings.TrimSpace(string(data))
						return
					}
					time.Sleep(30 * time.Millisecond)
				}
				started <- ""
			}()
			err := check.run(ctx, []string{"run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--label", label, "--entrypoint", "/bin/sleep", image, "30"})
			id := <-started
			if id == "" {
				t.Fatalf("%s did not start fixture container: %v", check.name, err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = runtime.Run(cleanup, []string{"rm", "--force", id}) // The regression may leave this owned fixture behind.
			})
			if !errors.Is(err, context.Canceled) {
				t.Errorf("%s cancellation error = %v, want context.Canceled", check.name, err)
			}
			if _, err := runtime.Output(control, "container", "inspect", id); err == nil {
				t.Errorf("%s left its canceled container %s present", check.name, id)
			}
		})
	}
}
