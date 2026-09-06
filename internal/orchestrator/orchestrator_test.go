package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
)

func TestRunPreservesSuccessOnPartialFailure(t *testing.T) {
	jobs := []Job{
		{
			Name: "gitleaks",
			Run: func(context.Context) (report.Scanner, []report.Finding, error) {
				return report.Scanner{Name: "gitleaks", Status: "success"}, []report.Finding{{RuleID: "secret"}}, nil
			},
		},
		{
			Name: "python-sast",
			Run: func(context.Context) (report.Scanner, []report.Finding, error) {
				return report.Scanner{}, nil, errors.New("scanner exploded")
			},
		},
	}

	got, err := Run(context.Background(), jobs, 2, func(progress.Event) {})
	if err != nil {
		t.Fatalf("Run() error = %v, want partial success", err)
	}
	if got.Successes != 1 || len(got.Scanners) != 2 || len(got.Findings) != 2 {
		t.Errorf("Run() = %#v", got)
	}
}

func TestRunProvidesPerJobTimeout(t *testing.T) {
	jobs := []Job{{
		Name:    "python-sast",
		Timeout: time.Minute,
		Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("job context has no deadline")
			}
			return report.Scanner{Name: "python-sast", Status: "success"}, nil, nil
		},
	}}

	if _, err := Run(context.Background(), jobs, 1, func(progress.Event) {}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunCancelsTimedOutJob(t *testing.T) {
	jobs := []Job{{
		Name:    "python-sast",
		Timeout: time.Nanosecond,
		Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
			<-ctx.Done()
			return report.Scanner{}, nil, ctx.Err()
		},
	}}

	got, err := Run(context.Background(), jobs, 1, func(progress.Event) {})
	if !errors.Is(err, ErrAllScannersFailed) || len(got.Scanners) != 1 ||
		got.Scanners[0].Status != "failed" {
		t.Fatalf("Run() = %#v, %v; want timed-out failed scanner", got, err)
	}
}

func TestRunLimitsConcurrency(t *testing.T) {
	var mu sync.Mutex
	active := 0
	maxActive := 0
	release := make(chan struct{})
	started := make(chan struct{}, 3)
	jobs := make([]Job, 3)
	for i := range jobs {
		jobs[i] = Job{
			Name: string(rune('a' + i)),
			Run: func(context.Context) (report.Scanner, []report.Finding, error) {
				mu.Lock()
				active++
				maxActive = max(maxActive, active)
				mu.Unlock()
				started <- struct{}{}
				<-release
				mu.Lock()
				active--
				mu.Unlock()
				return report.Scanner{Status: "success"}, nil, nil
			},
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Run(context.Background(), jobs, 2, func(progress.Event) {})
	}()
	<-started
	<-started
	select {
	case <-started:
		t.Fatal("Run() started a third job before capacity was released")
	default:
	}
	close(release)
	<-done

	if maxActive != 2 {
		t.Errorf("Run() max concurrency = %d, want 2", maxActive)
	}
}

func TestRunPreservesEvidenceReturnedWithFailure(t *testing.T) {
	for _, failure := range []error{errors.New("SYNTHETIC_RAW_DIAGNOSTIC"), context.Canceled} {
		evidence := report.Scanner{Name: "oci-images", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "images"}, Capabilities: []string{"host-runtime-registry-access"}, Images: []report.Image{{Reference: "synthetic:first", Digest: "sha256:completed", Status: "success"}, {Reference: "synthetic:second", Digest: "sha256:second", Status: "cleanup_failed"}}}
		jobs := []Job{{Name: "oci-images", Run: func(context.Context) (report.Scanner, []report.Finding, error) {
			return evidence, []report.Finding{{Kind: "dependency", RuleID: "completed-advisory", ImageDigest: "sha256:completed"}}, failure
		}}}
		got, err := Run(context.Background(), jobs, 1, func(progress.Event) {})
		if !errors.Is(err, ErrAllScannersFailed) || got.Successes != 0 || len(got.Scanners) != 1 || len(got.Findings) != 2 {
			t.Fatalf("Run failed evidence=%#v err=%v", got, err)
		}
		scanner := got.Scanners[0]
		if scanner.Status != "failed" || scanner.Coverage.Read != 1 || scanner.Coverage.Failed == 0 || len(scanner.Images) != 2 || scanner.Images[1].Status != "cleanup_failed" || len(scanner.Capabilities) != 1 {
			t.Errorf("failure evidence lost: %#v", scanner)
		}
		if got.Findings[0].ImageDigest != "sha256:completed" || got.Findings[1].Message != "scanner failed" {
			t.Errorf("completed finding/static error lost: %#v", got.Findings)
		}
	}
}

func TestRunCanceledJobCannotClaimPartialSuccess(t *testing.T) {
	jobs := []Job{{Name: "oci-images", Timeout: time.Millisecond, Run: func(ctx context.Context) (report.Scanner, []report.Finding, error) {
		<-ctx.Done()
		return report.Scanner{Name: "oci-images", Status: "success", Coverage: report.Coverage{Read: 1, Unit: "images"}}, []report.Finding{{RuleID: "completed"}}, nil
	}}}
	got, err := Run(context.Background(), jobs, 1, func(progress.Event) {})
	if !errors.Is(err, ErrAllScannersFailed) || got.Successes != 0 || got.Scanners[0].Status != "failed" || got.Scanners[0].Coverage.Read != 1 || len(got.Findings) != 2 {
		t.Fatalf("canceled partial result=%#v err=%v", got, err)
	}
}
