package progress

import (
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

type plainReporter struct {
	mu      sync.Mutex
	writer  io.Writer
	now     func() time.Time
	started map[string]time.Time
	seq     uint64
}

func NewPlain(writer io.Writer, now func() time.Time) Reporter {
	return &plainReporter{
		writer:  writer,
		now:     now,
		started: make(map[string]time.Time),
	}
}

func (reporter *plainReporter) Emit(event Event) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()

	at := event.At
	if at.IsZero() {
		at = reporter.now()
	}
	started, ok := reporter.started[event.Scanner]
	if !ok {
		started = at
		reporter.started[event.Scanner] = started
	}
	reporter.seq++
	fmt.Fprintf(
		reporter.writer,
		"seq=%d scanner=%s stage=%s status=%s elapsed_ms=%d files=%d findings=%d",
		reporter.seq,
		event.Scanner,
		event.Stage,
		event.Status,
		at.Sub(started).Milliseconds(),
		event.Files,
		event.Findings,
	)
	if event.Message != "" {
		fmt.Fprintf(reporter.writer, " message=%s", strconv.Quote(event.Message))
	}
	fmt.Fprintln(reporter.writer)
}

func (*plainReporter) Close() error { return nil }
