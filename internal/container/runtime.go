package container

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type Runtime struct {
	Binary string
}

func Detect(
	ctx context.Context,
	lookPath func(string) (string, error),
	probe func(context.Context, string) error,
) (Runtime, error) {
	var failures []error
	for _, name := range []string{"docker", "podman"} {
		path, err := lookPath(name)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s not found", name))
			continue
		}
		if err := probe(ctx, path); err != nil {
			failures = append(failures, fmt.Errorf("%s unavailable: %w", name, err))
			continue
		}
		return Runtime{Binary: path}, nil
	}
	return Runtime{}, fmt.Errorf("container runtime unavailable: %w", errors.Join(failures...))
}

func DetectDefault(ctx context.Context) (Runtime, error) {
	return Detect(ctx, exec.LookPath, func(ctx context.Context, binary string) error {
		output, err := exec.CommandContext(ctx, binary, "info").CombinedOutput()
		if err == nil {
			return nil
		}
		detail := strings.TrimSpace(string(output))
		if len(detail) > 512 {
			detail = detail[:512]
		}
		if detail == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, detail)
	})
}

func (runtime Runtime) Run(ctx context.Context, args []string) error {
	command := exec.CommandContext(ctx, runtime.Binary, args...)
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s run failed: %w", runtime.Binary, err)
	}
	return nil
}
