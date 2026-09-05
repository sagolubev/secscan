package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/sigiuscom/secscan/internal/progress"
	"github.com/sigiuscom/secscan/internal/report"
)

var ErrAllScannersFailed = errors.New("all selected scanners failed")

type Job struct {
	Name    string
	Timeout time.Duration
	Run     func(context.Context) (report.Scanner, []report.Finding, error)
}

type Result struct {
	Scanners  []report.Scanner
	Findings  []report.Finding
	Successes int
}

func Run(
	ctx context.Context,
	jobs []Job,
	concurrency int,
	emit func(progress.Event),
) (Result, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	type jobResult struct {
		scanner  report.Scanner
		findings []report.Finding
		err      error
		name     string
	}
	results := make(chan jobResult, len(jobs))
	limit := make(chan struct{}, concurrency)
	var group sync.WaitGroup
	for _, job := range jobs {
		group.Add(1)
		go func(job Job) {
			defer group.Done()
			select {
			case limit <- struct{}{}:
				defer func() { <-limit }()
			case <-ctx.Done():
				results <- jobResult{name: job.Name, err: ctx.Err()}
				return
			}
			jobContext := ctx
			cancel := func() {}
			if job.Timeout > 0 {
				jobContext, cancel = context.WithTimeout(ctx, job.Timeout)
			} else {
				jobContext, cancel = context.WithCancel(ctx)
			}
			scanner, findings, err := job.Run(jobContext)
			cancel()
			results <- jobResult{
				scanner:  scanner,
				findings: findings,
				err:      err,
				name:     job.Name,
			}
		}(job)
	}
	go func() {
		group.Wait()
		close(results)
	}()

	var output Result
	for result := range results {
		if result.err == nil {
			output.Scanners = append(output.Scanners, result.scanner)
			output.Findings = append(output.Findings, result.findings...)
			if result.scanner.Status == "success" {
				output.Successes++
			}
			continue
		}
		emit(progress.Event{
			Scanner: result.name,
			Stage:   progress.StageFailed,
			Status:  progress.StatusFailed,
			Message: "scanner failed",
		})
		output.Scanners = append(output.Scanners, report.Scanner{
			Name:   result.name,
			Status: "failed",
			Coverage: report.Coverage{
				Failed: 1,
				Unit:   "scanner",
			},
		})
		sum := sha256.Sum256([]byte(result.name + "\x00scanner failed"))
		output.Findings = append(output.Findings, report.Finding{
			Kind:        "error",
			RuleID:      "scanner-error",
			Message:     "scanner failed",
			Fingerprint: hex.EncodeToString(sum[:]),
			Sources:     []string{result.name},
		})
	}
	if len(jobs) > 0 && output.Successes == 0 {
		return output, ErrAllScannersFailed
	}
	return output, nil
}
