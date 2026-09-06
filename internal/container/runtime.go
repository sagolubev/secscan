package container

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

func (runtime Runtime) RunDiagnostic(ctx context.Context, args []string) error {
	command := exec.CommandContext(ctx, runtime.Binary, args...)
	if output, err := command.CombinedOutput(); err != nil {
		detail := strings.TrimSpace(string(output))
		if len(detail) > 2048 {
			detail = detail[len(detail)-2048:]
		}
		return fmt.Errorf("%s command failed: %w: %s", runtime.Binary, err, detail)
	}
	return nil
}

func (runtime Runtime) Output(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, runtime.Binary, args...)
	var output limitedBuffer
	command.Stdout = &output
	command.Stderr = io.Discard
	err := command.Run()
	if err != nil {
		return nil, fmt.Errorf("%s output failed: %w", runtime.Binary, err)
	}
	if output.exceeded {
		return nil, fmt.Errorf("scanner output exceeds 64 MiB limit")
	}
	return output.Bytes(), nil
}

// IsolatedArgs returns the common offline boundary with the invoking user identity.
func IsolatedArgs(target, destination string) []string {
	return isolatedArgs(target, destination, os.Getuid(), os.Getgid())
}

func isolatedArgs(target, destination string, uid, gid int) []string {
	return []string{"run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--user", fmt.Sprintf("%d:%d", uid, gid), "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--env", "HOME=/tmp", "--mount", "type=bind,src=" + target + ",dst=" + destination + ",readonly"}
}

type limitedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	const limit = 64 << 20
	n := len(p)
	remaining := limit - b.Len()
	if len(p) > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

// OutputRejecting also rejects known operational diagnostics without exposing their contents.
func (runtime Runtime) OutputRejecting(ctx context.Context, args []string, markers []string) ([]byte, error) {
	command := exec.CommandContext(ctx, runtime.Binary, args...)
	var output, diagnostics limitedBuffer
	command.Stdout = &output
	command.Stderr = &diagnostics
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("scanner execution failed: %w", err)
	}
	if output.exceeded || diagnostics.exceeded {
		return nil, fmt.Errorf("scanner output exceeds 64 MiB limit")
	}
	lower := bytes.ToLower(diagnostics.Bytes())
	for _, marker := range markers {
		if bytes.Contains(lower, []byte(marker)) {
			return nil, fmt.Errorf("scanner reported an input parsing failure")
		}
	}
	return output.Bytes(), nil
}
