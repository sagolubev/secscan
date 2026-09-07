// START_MODULE_CONTRACT
// PURPOSE: Encode a complete JSON view under a conservative byte budget.
// SCOPE: Remove whole severity groups; preserve protected findings and all evidence without mutating input.
// DEPENDS: internal/report/report.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-report-rendering, internal/report/budget_test.go#TestBudgetExactBoundary, internal/report/budget_test.go#TestBudgetProtectsEvidence
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// BudgetSummary - Disclose byte counting, final severity floor and removed fragments.
// MarshalBudget - Encode a separate budgeted JSON view and its accounting.
// END_MODULE_MAP

package report

import (
	"encoding/json"
	"fmt"
)

// BudgetSummary accounts for the JSON-only stage after ordinary filtering.
// Measured includes the final LF, which MarshalBudget leaves to the caller.
type BudgetSummary struct {
	Counter           string `json:"counter"`
	Limit             int    `json:"limit"`
	Measured          int    `json:"measured"`
	Floor             string `json:"floor"`
	RemovedFragments  int    `json:"removedFragments"`
	RetainedFragments int    `json:"retainedFragments"`
	Exceeded          bool   `json:"exceeded,omitempty"`
}

// MarshalBudget encodes compact JSON without a trailing LF. Each encoded UTF-8
// byte plus that LF costs one conservative unit, including budget metadata.
// It removes complete severity groups until the report fits a positive limit.
// Secrets, errors, unranked findings and other evidence are never removed; when
// those exceed the limit, it returns complete JSON with Exceeded set to true.
// Neither the input report nor its nested collections are mutated.
func MarshalBudget(input Report, limit int) ([]byte, BudgetSummary, error) {
	if limit <= 0 {
		return nil, BudgetSummary{}, fmt.Errorf("JSON budget must be positive")
	}
	view := canonicalReport(input)
	fragments := view.Findings
	summary := BudgetSummary{Counter: "utf8-bytes-v1", Limit: limit}
	view.Budget = &summary
	for i, floor := range []string{"all", "low", "medium", "high", "critical", "protected-only"} {
		view.Findings = make([]Finding, 0, len(fragments))
		for _, finding := range fragments {
			rank := severityRank(finding.Severity)
			if finding.Kind == "secret" || finding.Kind == "error" || rank < 2 || rank >= i+2 {
				view.Findings = append(view.Findings, finding)
			}
		}
		summary.Floor = floor
		summary.RetainedFragments = len(view.Findings)
		summary.RemovedFragments = len(fragments) - len(view.Findings)
		data, err := marshalMeasured(view)
		if err != nil {
			return nil, BudgetSummary{}, err
		}
		if summary.Measured <= limit {
			return data, summary, nil
		}
	}
	// Omit false from fitting candidates: adding true can only increase an
	// overflowing protected view, avoiding a self-referential boolean boundary.
	summary.Exceeded = true
	data, err := marshalMeasured(view)
	return data, summary, err
}

func marshalMeasured(view Report) ([]byte, error) {
	view.Budget.Measured = 0
	// Only the decimal width of measured can change the next serialized size.
	// Twenty iterations cover every representable Go int width, including 64-bit.
	for range 20 {
		data, err := json.Marshal(view)
		if err != nil {
			return nil, err
		}
		measured := len(data) + 1
		if view.Budget.Measured == measured {
			return data, nil
		}
		view.Budget.Measured = measured
	}
	return nil, fmt.Errorf("JSON budget count did not converge")
}
