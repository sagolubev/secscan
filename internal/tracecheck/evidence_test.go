// START_MODULE_CONTRACT
// PURPOSE: Verify durable phase chains and bounded check summaries.
// SCOPE: Synthetic commands and isolated Beads databases; no real scanner output.
// DEPENDS: internal/tracecheck/evidence.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-development-traceability
// ROLE: TEST
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// TestDecodeEvidenceRejectsMalformedRecords - Reject ambiguous and incomplete record JSON.
// TestEvidenceChain - Reject incomplete, edited, failed and stale phase records.
// TestRunChecksSummarizesGoJSON - Count tests without inflating package results.
// TestEvidenceBeadsRoundTrip - Preserve records through real JSONL export and import.
// END_MODULE_MAP

package tracecheck

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func evidenceFixture(t *testing.T) (Manifest, []Evidence) {
	t.Helper()
	digest := fmt.Sprintf("%x", sha256.Sum256(nil))
	m := Manifest{SourcePath: "trace.json", Digest: digest, TargetOutcome: "test.1", BaselineCommit: strings.Repeat("a", 40), Checks: map[string][]Check{}}
	var records []Evidence
	for i, phase := range []string{"baseline", "target", "final"} {
		check := Check{Name: "pass", Argv: []string{"true"}}
		m.Checks[phase] = []Check{check}
		at := time.Date(2026, 9, 1, 0, i, 0, 0, time.UTC)
		e := Evidence{SchemaVersion: "2", StateAlgorithm: StateAlgorithm, ManifestPath: m.SourcePath, ManifestDigest: m.Digest, Phase: phase, Baseline: m.BaselineCommit, Outcome: m.TargetOutcome, StateIdentity: digest, AuthorityHash: digest, StartedAt: at, FinishedAt: at.Add(time.Second), OK: true,
			Checks: []CheckResult{{Name: check.Name, Argv: check.Argv, Cwd: "/original/checkout", Status: "passed", StdoutEmpty: true, Stdout: &OutputSummary{SHA256: digest}, Stderr: &OutputSummary{SHA256: digest}}},
		}
		if i > 0 {
			e.Previous = records[i-1].ID
		}
		if err := e.Seal(); err != nil {
			t.Fatal(err)
		}
		records = append(records, e)
	}
	return m, records
}

func TestEvidenceChain(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Manifest, *[]Evidence)
		next string
		want bool
	}{
		{name: "complete", next: "verify", want: true},
		{name: "target preflight", next: "target", want: true, edit: func(m *Manifest, e *[]Evidence) { *e = (*e)[:1] }},
		{name: "final preflight", next: "final", want: true, edit: func(m *Manifest, e *[]Evidence) { *e = (*e)[:2] }},
		{name: "missing", next: "verify", edit: func(m *Manifest, e *[]Evidence) { *e = nil }},
		{name: "legacy", next: "verify", edit: func(m *Manifest, e *[]Evidence) { (*e)[0].SchemaVersion = "1" }},
		{name: "tampered", next: "verify", edit: func(m *Manifest, e *[]Evidence) { (*e)[1].Checks[0].Name = "altered" }},
		{name: "broken link", next: "verify", edit: func(m *Manifest, e *[]Evidence) { (*e)[2].Previous = (*e)[0].ID; (*e)[2].Seal() }},
		{name: "authority", next: "verify", edit: func(m *Manifest, e *[]Evidence) { (*e)[0].AuthorityHash = strings.Repeat("b", 64); (*e)[0].Seal() }},
		{name: "manifest", next: "verify", edit: func(m *Manifest, e *[]Evidence) { m.Digest = strings.Repeat("b", 64) }},
		{name: "wrong checks", next: "verify", edit: func(m *Manifest, e *[]Evidence) { m.Checks["final"][0].Argv = []string{"false"} }},
		{name: "time reversal", next: "verify", edit: func(m *Manifest, e *[]Evidence) { (*e)[2].StartedAt = (*e)[0].StartedAt; (*e)[2].Seal() }},
		{name: "non UTC", next: "verify", edit: func(m *Manifest, e *[]Evidence) {
			(*e)[2].StartedAt = (*e)[2].StartedAt.In(time.FixedZone("offset", 3600))
			(*e)[2].Seal()
		}},
		{name: "future", next: "verify", edit: func(m *Manifest, e *[]Evidence) { (*e)[2].FinishedAt = time.Now().Add(time.Hour).UTC(); (*e)[2].Seal() }},
		{name: "stale final", next: "verify", edit: func(m *Manifest, e *[]Evidence) { (*e)[2].StateIdentity = strings.Repeat("b", 64); (*e)[2].Seal() }},
		{name: "stale target", next: "final", edit: func(m *Manifest, e *[]Evidence) {
			*e = (*e)[:2]
			(*e)[1].StateIdentity = strings.Repeat("b", 64)
			(*e)[1].Seal()
		}},
		{name: "latest target failure", next: "verify", edit: func(m *Manifest, e *[]Evidence) {
			bad := (*e)[1]
			bad.OK = false
			bad.StartedAt = (*e)[2].FinishedAt.Add(time.Second)
			bad.FinishedAt = bad.StartedAt
			bad.Seal()
			*e = append(*e, bad)
		}},
		{name: "latest final failure", next: "verify", edit: func(m *Manifest, e *[]Evidence) {
			bad := (*e)[2]
			bad.OK = false
			bad.StartedAt = bad.FinishedAt.Add(time.Second)
			bad.FinishedAt = bad.StartedAt
			bad.Seal()
			*e = append(*e, bad)
		}},
		{name: "absent output", next: "verify", edit: func(m *Manifest, e *[]Evidence) { (*e)[2].Checks[0].Stdout = nil; (*e)[2].Seal() }},
		{name: "bootstrap baseline", next: "verify", want: true, edit: func(m *Manifest, e *[]Evidence) {
			(*e)[0].Checks[0].Stdout = nil
			(*e)[0].Checks[0].Stderr = nil
			(*e)[0].Seal()
			(*e)[1].Previous = (*e)[0].ID
			(*e)[1].Seal()
			(*e)[2].Previous = (*e)[1].ID
			(*e)[2].Seal()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, records := evidenceFixture(t)
			current := records[2].StateIdentity
			authority := records[2].AuthorityHash
			if tc.edit != nil {
				tc.edit(&m, &records)
			}
			_, err := ValidateEvidenceChain(m, records, tc.next, authority, current, time.Now().UTC())
			if (err == nil) != tc.want {
				t.Errorf("ValidateEvidenceChain(%s) error=%v, want success=%t", tc.name, err, tc.want)
			}
		})
	}
}

func TestRunChecksSummarizesGoJSON(t *testing.T) {
	for _, tc := range []struct {
		name, events            string
		passed, failed, skipped int
		want                    bool
	}{
		{"pass", `{"Action":"pass","Test":"TestOne"}` + "\n" + `{"Action":"pass"}`, 1, 0, 0, true},
		{"skips", `{"Action":"skip","Test":"TestOne"}` + "\n" + `{"Action":"pass"}`, 0, 0, 1, false},
		{"no tests", `{"Action":"pass"}`, 0, 0, 0, false},
		{"failed", `{"Action":"fail","Test":"TestOne"}`, 0, 1, 0, false},
		{"malformed", `{"Action":"pass","Test":"TestOne"}` + "\ninvalid", 1, 0, 0, false},
		{"oversize", strings.Repeat("x", 1024*1024+1), 0, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			path := filepath.Join(bin, "go")
			if err := os.WriteFile(path, []byte("#!/bin/sh\ncat \"$TRACE_EVENTS\"\nprintf '%s' synthetic-canary >&2\n"), 0700); err != nil {
				t.Fatal(err)
			}
			eventPath := filepath.Join(bin, "events.json")
			if err := os.WriteFile(eventPath, []byte(tc.events), 0600); err != nil {
				t.Fatal(err)
			}
			results, ok := RunChecks(context.Background(), bin, []Check{{Name: "events", Argv: []string{path, "test", "-json"}, Env: []string{"TRACE_EVENTS=" + eventPath}}})
			if len(results) != 1 {
				t.Fatalf("RunChecks got %d results", len(results))
			}
			r := results[0]
			if ok != tc.want || r.Tests == nil || r.Tests.Passed != tc.passed || r.Tests.Failed != tc.failed || r.Tests.Skipped != tc.skipped {
				t.Errorf("RunChecks(%s) = %+v, %t; want %d/%d/%d, %t", tc.name, r, ok, tc.passed, tc.failed, tc.skipped, tc.want)
			}
			encoded, _ := json.Marshal(r)
			if strings.Contains(string(encoded), "synthetic-canary") {
				t.Error("raw stderr leaked")
			}
			if r.Stdout == nil || r.Stderr == nil || r.Stderr.Bytes != 16 || r.Stderr.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("synthetic-canary"))) {
				t.Errorf("missing output summaries: %+v", r)
			}
		})
	}
}

func TestEvidenceBeadsRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("br"); err != nil {
		t.Skip("br not installed")
	}
	runBR := func(root string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("br", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("br %q: %v: %s", args, err, out)
		}
		return out
	}
	first := t.TempDir()
	runBR(first, "init", "--prefix", "test")
	out := runBR(first, "create", "--title", "Evidence roundtrip", "--silent")
	id := strings.TrimSpace(string(out))
	m, records := evidenceFixture(t)
	m.TargetOutcome = id
	for i := range records {
		records[i].Outcome = id
		if i > 0 {
			records[i].Previous = records[i-1].ID
		}
		records[i].Seal()
		if err := AppendEvidence(first, records[i]); err != nil {
			t.Fatal(err)
		}
	}
	runBR(first, "sync", "--flush-only")
	data, err := os.ReadFile(filepath.Join(first, ".beads/issues.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	second := t.TempDir()
	runBR(second, "init", "--prefix", "test")
	if err := os.WriteFile(filepath.Join(second, ".beads/issues.jsonl"), data, 0600); err != nil {
		t.Fatal(err)
	}
	runBR(second, "sync", "--import-only")
	got, err := LoadEvidence(second, id)
	if err != nil {
		t.Fatal(err)
	}
	last, err := ValidateEvidenceChain(m, got, "verify", records[2].AuthorityHash, records[2].StateIdentity, time.Now().UTC())
	if err != nil || last.ID != records[2].ID {
		t.Fatalf("roundtrip chain=%+v err=%v", last, err)
	}
}

func TestDecodeEvidenceRejectsMalformedRecords(t *testing.T) {
	_, records := evidenceFixture(t)
	data, err := json.Marshal(records[2])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"missing status code", []byte(strings.Replace(string(data), `"exitCode":0,`, "", 1))},
		{"null status code", []byte(strings.Replace(string(data), `"exitCode":0`, `"exitCode":null`, 1))},
		{"missing output count", []byte(strings.Replace(string(data), `"bytes":0,`, "", 1))},
		{"duplicate", []byte(strings.Replace(string(data), `"phase":"final"`, `"phase":"final","phase":"final"`, 1))},
		{"case alias", []byte(strings.Replace(string(data), `"phase"`, `"Phase"`, 1))},
		{"unknown", []byte(strings.Replace(string(data), `"phase"`, `"surprise"`, 1))},
		{"trailing", append(append([]byte(nil), data...), []byte(` {}`)...)},
		{"tampered", []byte(strings.Replace(string(data), `"ok":true`, `"ok":false`, 1))},
		{"legacy", []byte(strings.Replace(string(data), `"schemaVersion":"2"`, `"schemaVersion":"1"`, 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeEvidence(tc.data); err == nil {
				t.Errorf("decodeEvidence(%s) succeeded", tc.name)
			}
		})
	}
	got, err := decodeEvidence(data)
	if err != nil || got.ID != records[2].ID {
		t.Fatalf("valid record error=%v id=%s", err, got.ID)
	}
}

func TestBeadsResponseLimit(t *testing.T) {
	output := limitedBuffer{limit: 16}
	_, err := io.Copy(&output, struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 32))})
	if err == nil || output.buffer.Len() > 16 {
		t.Errorf("bounded Beads response bytes=%d err=%v", output.buffer.Len(), err)
	}
}
