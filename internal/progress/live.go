package progress

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	hideCursor = "\x1b[?25l"
	showCursor = "\x1b[?25h"
)

type liveReporter struct {
	mu        sync.Mutex
	writer    io.Writer
	color     bool
	now       func() time.Time
	width     func() int
	dashboard Dashboard
	lines     int
	ticks     <-chan time.Time
	stop      func()
	done      chan struct{}
	closed    bool
}

func NewLive(writer io.Writer, color bool, now func() time.Time, width func() int) Reporter {
	ticker := time.NewTicker(100 * time.Millisecond)
	return newLive(writer, color, now, width, ticker.C, ticker.Stop)
}

func newLive(
	writer io.Writer,
	color bool,
	now func() time.Time,
	width func() int,
	ticks <-chan time.Time,
	stop func(),
) *liveReporter {
	reporter := &liveReporter{
		writer: writer,
		color:  color,
		now:    now,
		width:  width,
		ticks:  ticks,
		stop:   stop,
		done:   make(chan struct{}),
	}
	io.WriteString(writer, hideCursor)
	if ticks != nil {
		go reporter.refresh()
	}
	return reporter
}

func (reporter *liveReporter) Emit(event Event) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if reporter.closed {
		return
	}
	reporter.dashboard.Apply(event, reporter.now())
	if reporter.ticks == nil {
		reporter.redraw()
	}
}

func (reporter *liveReporter) Close() error {
	reporter.mu.Lock()
	if reporter.closed {
		reporter.mu.Unlock()
		return nil
	}
	reporter.closed = true
	if reporter.stop != nil {
		reporter.stop()
	}
	reporter.redraw()
	_, err := io.WriteString(reporter.writer, showCursor)
	close(reporter.done)
	reporter.mu.Unlock()
	return err
}

func (reporter *liveReporter) refresh() {
	for {
		select {
		case <-reporter.ticks:
			reporter.mu.Lock()
			if !reporter.closed {
				reporter.redraw()
			}
			reporter.mu.Unlock()
		case <-reporter.done:
			return
		}
	}
}

func (reporter *liveReporter) redraw() {
	rendered := RenderDashboard(reporter.dashboard, reporter.now(), reporter.width(), reporter.color)
	if reporter.lines > 0 {
		fmt.Fprintf(reporter.writer, "\x1b[%dA", reporter.lines)
	}
	lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
	for _, line := range lines {
		fmt.Fprintf(reporter.writer, "\r\x1b[2K%s\n", line)
	}
	reporter.lines = len(lines)
}

func RenderDashboard(state Dashboard, now time.Time, width int, color bool) string {
	if width < 24 {
		width = 24
	}
	names := make([]string, 0, len(state.Jobs))
	maxElapsed := time.Duration(0)
	for name, job := range state.Jobs {
		names = append(names, name)
		elapsed := jobElapsed(job, now)
		if elapsed > maxElapsed {
			maxElapsed = elapsed
		}
	}
	sort.Strings(names)
	if maxElapsed <= 0 {
		maxElapsed = time.Millisecond
	}

	var output strings.Builder
	fmt.Fprintf(&output, "secscan · %d jobs · %.1fs\n\n", len(names), now.Sub(state.Started).Seconds())
	nameWidth := min(18, max(8, width/4))
	barWidth := min(24, max(3, width-nameWidth-30))
	for _, name := range names {
		job := state.Jobs[name]
		elapsed := jobElapsed(job, now)
		filled := max(1, int(math.Ceil(float64(elapsed)*float64(barWidth)/float64(maxElapsed))))
		bar := strings.Repeat("█", min(filled, barWidth)) + strings.Repeat("░", max(0, barWidth-filled))
		status := jobStatus(job, elapsed)
		line := fmt.Sprintf("%-*s %s  %s", nameWidth, truncate(name, nameWidth), bar, status)
		line = truncate(line, width)
		output.WriteString(colorize(line, job.Status, color))
		output.WriteByte('\n')
	}
	if len(state.Events) > 0 {
		output.WriteByte('\n')
		for _, event := range state.Events {
			fmt.Fprintf(&output, "· %s\n", truncate(event, width-2))
		}
	}
	return output.String()
}

func jobElapsed(job JobState, now time.Time) time.Duration {
	if job.Started.IsZero() {
		return 0
	}
	end := now
	if job.Status == StatusSuccess || job.Status == StatusFailed || job.Status == StatusSkipped {
		end = job.Updated
	}
	return max(0, end.Sub(job.Started))
}

func jobStatus(job JobState, elapsed time.Duration) string {
	switch job.Status {
	case StatusSuccess:
		return fmt.Sprintf("✓ %s · %.1fs", findingLabel(job.Findings), elapsed.Seconds())
	case StatusSkipped:
		return fmt.Sprintf("– skipped · %s", findingLabel(job.Findings))
	case StatusFailed:
		return fmt.Sprintf("✗ failed · %s · %.1fs", findingLabel(job.Findings), elapsed.Seconds())
	default:
		return fmt.Sprintf("◌ %s · %s · %.1fs", job.Stage, findingLabel(job.Findings), elapsed.Seconds())
	}
}

func findingLabel(count int) string {
	if count == 1 {
		return "1 finding"
	}
	return fmt.Sprintf("%d findings", count)
}

func truncate(value string, width int) string {
	if width <= 0 || utf8.RuneCountInString(value) <= width {
		return value
	}
	runes := []rune(value)
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}

func colorize(value string, status Status, enabled bool) string {
	if !enabled {
		return value
	}
	code := "36"
	switch status {
	case StatusSuccess:
		code = "32"
	case StatusSkipped:
		code = "90"
	case StatusFailed:
		code = "31"
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}
