package progress

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestParseMode(t *testing.T) {
	for _, value := range []string{"auto", "tty", "plain", "off"} {
		if _, err := ParseMode(value); err != nil {
			t.Errorf("ParseMode(%q) error = %v", value, err)
		}
	}
	if _, err := ParseMode("spinner"); err == nil {
		t.Fatal("ParseMode(spinner) error = nil, want usage error")
	}
}

func TestPlainReporterWritesStableEvent(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	reporter := NewPlain(&output, func() time.Time { return now })

	reporter.Emit(Event{Scanner: "python-sast", Stage: StageScanning, Status: StatusRunning, Files: 12})

	want := "seq=1 scanner=python-sast stage=scanning status=running elapsed_ms=0 files=12 findings=0\n"
	if output.String() != want {
		t.Errorf("plain output = %q, want %q", output.String(), want)
	}
}

func TestRenderDashboardShowsElapsedBarsAndStates(t *testing.T) {
	start := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	state := Dashboard{
		Started: start,
		Jobs: map[string]JobState{
			"gitleaks": {
				Scanner:  "gitleaks",
				Stage:    StageDone,
				Status:   StatusSuccess,
				Findings: 1,
				Started:  start,
				Updated:  start.Add(2 * time.Second),
			},
			"python-sast": {
				Scanner: "python-sast",
				Stage:   StageScanning,
				Status:  StatusRunning,
				Files:   24,
				Started: start,
				Updated: start.Add(3 * time.Second),
			},
			"typescript-sast": {
				Scanner: "typescript-sast",
				Stage:   StageSkipped,
				Status:  StatusSkipped,
				Started: start,
				Updated: start.Add(time.Second),
			},
		},
		Events: []string{"python-sast: scanning 24 files"},
	}

	got := RenderDashboard(state, start.Add(4*time.Second), 90, false)
	for _, want := range []string{
		"secscan · 3 jobs · 4.0s",
		"gitleaks",
		"1 finding",
		"python-sast",
		"scanning · 0 findings · 4.0s",
		"typescript-sast",
		"skipped",
		"python-sast: scanning 24 files",
		"████",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderDashboard() missing %q:\n%s", want, got)
		}
	}
}

func TestRenderDashboardFitsNarrowTerminal(t *testing.T) {
	start := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	state := Dashboard{
		Started: start,
		Jobs: map[string]JobState{
			"typescript-sast-with-a-long-name": {
				Scanner: "typescript-sast-with-a-long-name",
				Stage:   StageScanning,
				Status:  StatusRunning,
				Started: start,
			},
		},
		Events: []string{"typescript-sast: scanning a deliberately long file name"},
	}
	got := RenderDashboard(state, start.Add(time.Second), 40, false)
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if width := utf8.RuneCountInString(line); width > 40 {
			t.Errorf("line width = %d, want <= 40: %q", width, line)
		}
	}
}

func TestLiveReporterRestoresCursor(t *testing.T) {
	var output bytes.Buffer
	start := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	reporter := newLive(&output, false, func() time.Time { return start }, func() int { return 80 }, nil, nil)

	reporter.Emit(Event{Scanner: "gitleaks", Stage: StageScanning, Status: StatusRunning})
	if err := reporter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	got := output.String()
	if !strings.Contains(got, "\x1b[?25l") {
		t.Fatal("live output does not hide cursor")
	}
	if !strings.HasSuffix(got, "\x1b[?25h") {
		t.Fatalf("live output does not restore cursor: %q", got)
	}
}

func TestNoColorKeepsDashboardWithoutColorSequences(t *testing.T) {
	start := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	state := Dashboard{
		Started: start,
		Jobs: map[string]JobState{
			"gitleaks": {
				Scanner: "gitleaks",
				Stage:   StageScanning,
				Status:  StatusRunning,
				Started: start,
				Updated: start,
			},
		},
	}
	got := RenderDashboard(state, start.Add(time.Second), 80, false)
	if strings.Contains(got, "\x1b[3") {
		t.Fatalf("RenderDashboard(color=false) contains color sequence: %q", got)
	}
	if !strings.Contains(got, "gitleaks") {
		t.Fatal("RenderDashboard(color=false) removed dashboard content")
	}
}

func TestFullRosterFitsStandardTerminal(t *testing.T) {
	now := time.Unix(1, 0)
	var state Dashboard
	for i := 0; i < 18; i++ {
		state.Apply(Event{Scanner: fmt.Sprintf("scanner-%02d", i), Stage: StageQueued, Status: StatusQueued}, now)
	}
	got := RenderDashboard(state, now, 80, false)
	if lines := strings.Count(got, "\n"); lines > 23 {
		t.Errorf("18-job dashboard has %d lines, want <=23 plus cursor row", lines)
	}
	for i := 0; i < 18; i++ {
		if !strings.Contains(got, fmt.Sprintf("scanner-%02d", i)) {
			t.Errorf("dashboard omitted scanner-%02d", i)
		}
	}
	if !strings.Contains(got, "scanner-17: queued") {
		t.Error("dashboard omitted newest event")
	}
}

func TestEmptyDashboardHasZeroElapsed(t *testing.T) {
	got := RenderDashboard(Dashboard{}, time.Now(), 80, false)
	if !strings.Contains(got, "0 jobs · 0.0s") {
		t.Errorf("empty dashboard = %q, want zero elapsed", got)
	}
}

func TestResizeFallsBackToPlainWithoutLosingScanners(t *testing.T) {
	var output bytes.Buffer
	now := time.Unix(1, 0)
	height := 40
	reporter := newLive(&output, false, func() time.Time { return now }, func() int { return 80 }, nil, nil)
	reporter.height = func() int { return height }
	defer reporter.Close()
	for i := 0; i < 18; i++ {
		reporter.Emit(Event{Scanner: fmt.Sprintf("scanner-%02d", i), Stage: StageQueued, Status: StatusQueued})
	}
	output.Reset()
	height = 8
	now = now.Add(2 * time.Second)
	reporter.Emit(Event{Scanner: "scanner-00", Stage: StageDone, Status: StatusSuccess})
	got := output.String()
	if !strings.Contains(got, showCursor) {
		t.Error("small-terminal fallback did not restore cursor")
	}
	for i := 0; i < 18; i++ {
		if !strings.Contains(got, fmt.Sprintf("scanner=scanner-%02d", i)) {
			t.Errorf("plain fallback omitted scanner-%02d", i)
		}
	}
	if !strings.Contains(got, "elapsed_ms=2000") {
		t.Error("fallback lost elapsed duration")
	}
	output.Reset()
	reporter.Emit(Event{Scanner: "scanner-17", Stage: StageDone, Status: StatusSuccess})
	if strings.Contains(output.String(), "\x1b[") || !strings.Contains(output.String(), "scanner=scanner-17 stage=done") {
		t.Errorf("progress after fallback is not plain: %q", output.String())
	}
}
