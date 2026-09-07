// START_MODULE_CONTRACT
// PURPOSE: Verify cancellation removes the running container.
// SCOPE: Measure cancellation after readiness, including a delayed cold start.
// DEPENDS: internal/container/runtime.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-container-runtime
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestAcceptanceCancellation - Check all runtime entrypoints and container cleanup.
// END_MODULE_MAP

package container_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagolubev/secscan/internal/container"
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
		{"RunDelayed", func(ctx context.Context, args []string) error {
			// A cold daemon may start later than the former five-second readiness limit.
			timer := time.NewTimer(6 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
				return runtime.Run(ctx, args)
			case <-ctx.Done():
				return ctx.Err()
			}
		}},
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
			// Startup has its own budget; cancellation is measured only after readiness.
			control, stop := context.WithTimeout(context.Background(), time.Minute)
			defer stop()
			ctx, cancel := context.WithCancel(control)
			defer cancel()
			label := fmt.Sprintf("secscan.cancel-test=%d", time.Now().UnixNano())
			type ready struct {
				id string
				at time.Time
			}
			started := make(chan ready, 1)
			go func() {
				defer cancel()
				for control.Err() == nil {
					data, err := runtime.Output(control, "ps", "--filter", "label="+label, "--format", "{{.ID}}")
					if err == nil && strings.TrimSpace(string(data)) != "" {
						started <- ready{id: strings.TrimSpace(string(data)), at: time.Now()}
						return
					}
					time.Sleep(30 * time.Millisecond)
				}
				started <- ready{}
			}()
			err := check.run(ctx, []string{"run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--label", label, "--entrypoint", "/bin/sleep", image, "30"})
			observed := <-started
			id := observed.id
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
			if elapsed := time.Since(observed.at); elapsed > 15*time.Second {
				t.Errorf("%s cancellation took %v, want at most 15s including cleanup", check.name, elapsed)
			}
			remaining, err := runtime.Output(control, "ps", "--all", "--filter", "label="+label, "--format", "{{.ID}}")
			if err != nil || strings.TrimSpace(string(remaining)) != "" {
				t.Errorf("%s canceled container removal: remaining=%q error=%v, want empty successful listing", check.name, remaining, err)
			}
		})
	}
}
