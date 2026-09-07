// START_MODULE_CONTRACT
// PURPOSE: Prepare requested report files and render visible HTML with full SARIF.
// SCOPE: JSON stdout is independent; render all payloads before publishing complete files.
// DEPENDS: cmd/secscan/output.go, internal/report/render.go
// LINKS: cmd/secscan/render_test.go#TestRunExportsVisibleHTMLAndFullSARIF, cmd/secscan/render_test.go#TestRunExportsFailedScanEvidence
// ROLE: SCRIPT
// MAP_MODE: LOCALS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// renderedOutput - A format paired with its pinned destination.
// prepareRenderedOutputs - Reserve output paths without creating files.
// writeRenderedOutputs - Render both report views and publish complete files.
// END_MODULE_MAP

package main

import (
	"context"
	"fmt"

	"github.com/sagolubev/secscan/internal/report"
)

type renderedOutput struct {
	format      string
	destination *fileDestination
}

func prepareRenderedOutputs(root, html, sarif string) ([]renderedOutput, error) {
	var outputs []renderedOutput
	for _, item := range []struct{ format, path string }{{"html", html}, {"sarif", sarif}} {
		if item.path == "" {
			continue
		}
		destination, err := prepareOutputFile(root, item.path)
		if err != nil {
			for _, output := range outputs {
				output.destination.close()
			}
			return nil, fmt.Errorf("prepare %s report: %w", item.format, err)
		}
		outputs = append(outputs, renderedOutput{format: item.format, destination: destination})
	}
	return outputs, nil
}

func writeRenderedOutputs(ctx context.Context, outputs []renderedOutput, visible, full report.Report) error {
	data := make([][]byte, len(outputs))
	for i, output := range outputs {
		var err error
		if output.format == "html" {
			data[i], err = report.HTML(visible)
		} else {
			data[i], err = report.SARIF(full)
		}
		if err != nil {
			return fmt.Errorf("render %s report: %w", output.format, err)
		}
	}
	for i, output := range outputs {
		if err := output.destination.write(ctx, data[i]); err != nil {
			return fmt.Errorf("write %s report: %w", output.format, err)
		}
	}
	return nil
}
