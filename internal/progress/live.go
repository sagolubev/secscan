package progress

import (
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
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
	height    func() int
	dashboard Dashboard
	lines     int
	ticks     <-chan time.Time
	stop      func()
	done      chan struct{}
	closed    bool
	fallback  *plainReporter
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
		height: func() int { return terminalHeight(writer) },
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
	if reporter.fallback != nil {
		reporter.fallback.Emit(event)
		return
	}
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
		reporter.stop = nil
	}
	reporter.redraw()
	var err error
	if reporter.fallback == nil {
		_, err = io.WriteString(reporter.writer, showCursor)
	}
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
	if reporter.fallback != nil {
		return
	}
	height := reporter.height()
	if height <= 0 {
		height = 24
	}
	width := reporter.width()
	reporter.clear(height)
	if width < 24 || len(reporter.dashboard.Jobs)+3 > height {
		io.WriteString(reporter.writer, showCursor)
		fmt.Fprintln(reporter.writer, "secscan: terminal too small; using plain progress")
		reporter.fallback = NewPlain(reporter.writer, reporter.now)
		names := make([]string, 0, len(reporter.dashboard.Jobs))
		for name := range reporter.dashboard.Jobs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			job := reporter.dashboard.Jobs[name]
			reporter.fallback.started[name] = job.Started
			at := reporter.now()
			if job.Status == StatusSuccess || job.Status == StatusFailed || job.Status == StatusSkipped {
				at = job.Updated
			}
			reporter.fallback.Emit(Event{Scanner: name, Stage: job.Stage, Status: job.Status, Files: job.Files, Findings: job.Findings, At: at})
		}
		if reporter.stop != nil {
			reporter.stop()
			reporter.stop = nil
		}
		return
	}
	rendered := RenderDashboard(reporter.dashboard, reporter.now(), width, reporter.color, height)
	lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
	for _, line := range lines {
		fmt.Fprintf(reporter.writer, "\r\x1b[2K%s\n", line)
	}
	reporter.lines = len(lines)
}

func (reporter *liveReporter) clear(height int) {
	if reporter.lines > 0 {
		if visible := min(reporter.lines, max(0, height-1)); visible > 0 {
			fmt.Fprintf(reporter.writer, "\x1b[%dA", visible)
		}
		// Progress owns the trailing region; resizing can hide part of the old frame.
		io.WriteString(reporter.writer, "\r\x1b[J")
	}
	reporter.lines = 0
}

// RenderDashboard defaults to 24 rows when terminal height is unavailable.
// The visible event tail shrinks before any scanner row is removed.
func RenderDashboard(state Dashboard, now time.Time, width int, color bool, heights ...int) string {
	if width < 24 {
		width = 24
	}
	height := 24
	if len(heights) > 0 && heights[0] > 0 {
		height = heights[0]
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
	elapsed := 0.0
	if !state.Started.IsZero() {
		elapsed = max(0, now.Sub(state.Started).Seconds())
	}
	fmt.Fprintf(&output, "%s\n\n", truncate(fmt.Sprintf("secscan · %d jobs · %.1fs", len(names), elapsed), width))
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
	eventCount := min(len(state.Events), max(0, height-len(names)-4))
	if eventCount > 0 {
		output.WriteByte('\n')
		for _, event := range state.Events[len(state.Events)-eventCount:] {
			fmt.Fprintf(&output, "· %s\n", truncate(event, width-2))
		}
	}
	return output.String()
}

func terminalHeight(writer io.Writer) int {
	if file, ok := writer.(*os.File); ok {
		if _, height, err := term.GetSize(int(file.Fd())); err == nil && height > 0 {
			return height
		}
	}
	return 24
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
