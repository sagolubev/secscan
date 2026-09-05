package progress

import (
	"fmt"
	"io"
	"strings"
	"time"
)

type Mode string

const (
	ModeAuto  Mode = "auto"
	ModeTTY   Mode = "tty"
	ModePlain Mode = "plain"
	ModeOff   Mode = "off"
)

type Stage string

const (
	StageQueued      Stage = "queued"
	StageDiscovering Stage = "discovering"
	StagePreparing   Stage = "preparing"
	StageScanning    Stage = "scanning"
	StageReading     Stage = "reading"
	StageNormalizing Stage = "normalizing"
	StageDone        Stage = "done"
	StageSkipped     Stage = "skipped"
	StageFailed      Stage = "failed"
)

type Status string

const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
	StatusSuccess Status = "success"
	StatusSkipped Status = "skipped"
	StatusFailed  Status = "failed"
)

type Event struct {
	Scanner  string
	Stage    Stage
	Status   Status
	Files    int
	Findings int
	Message  string
	At       time.Time
}

type Reporter interface {
	Emit(Event)
	Close() error
}

type JobState struct {
	Scanner  string
	Stage    Stage
	Status   Status
	Files    int
	Findings int
	Started  time.Time
	Updated  time.Time
}

type Dashboard struct {
	Started time.Time
	Jobs    map[string]JobState
	Events  []string
}

func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModeAuto, ModeTTY, ModePlain, ModeOff:
		return Mode(value), nil
	default:
		return "", fmt.Errorf("unknown progress mode %q", value)
	}
}

func (dashboard *Dashboard) Apply(event Event, now time.Time) {
	if dashboard.Started.IsZero() {
		dashboard.Started = now
	}
	if dashboard.Jobs == nil {
		dashboard.Jobs = make(map[string]JobState)
	}
	if event.At.IsZero() {
		event.At = now
	}
	state, exists := dashboard.Jobs[event.Scanner]
	if !exists {
		state = JobState{Scanner: event.Scanner, Started: event.At}
	}
	state.Stage = event.Stage
	state.Status = event.Status
	state.Files = event.Files
	state.Findings = event.Findings
	state.Updated = event.At
	dashboard.Jobs[event.Scanner] = state

	message := event.Message
	if message == "" {
		message = strings.ReplaceAll(string(event.Stage), "_", " ")
	}
	dashboard.Events = append(dashboard.Events, event.Scanner+": "+message)
	if len(dashboard.Events) > 6 {
		dashboard.Events = dashboard.Events[len(dashboard.Events)-6:]
	}
}

type offReporter struct{}

func (offReporter) Emit(Event)   {}
func (offReporter) Close() error { return nil }

func New(
	writer io.Writer,
	mode Mode,
	interactive bool,
	color bool,
	now func() time.Time,
	width func() int,
) Reporter {
	switch mode {
	case ModeOff:
		return offReporter{}
	case ModePlain:
		return NewPlain(writer, now)
	case ModeTTY:
		if interactive {
			return NewLive(writer, color, now, width)
		}
		return NewPlain(writer, now)
	case ModeAuto:
		if interactive {
			return NewLive(writer, color, now, width)
		}
		return NewPlain(writer, now)
	default:
		return offReporter{}
	}
}
