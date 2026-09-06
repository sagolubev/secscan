package container

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
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
	if err := runtime.execute(ctx, args, io.Discard, io.Discard); err != nil {
		return fmt.Errorf("%s run failed: %w", runtime.Binary, err)
	}
	return nil
}

func (runtime Runtime) RunDiagnostic(ctx context.Context, args []string) error {
	var output limitedBuffer
	if err := runtime.execute(ctx, args, &output, &output); err != nil {
		detail := strings.TrimSpace(output.String())
		if len(detail) > 2048 {
			detail = detail[len(detail)-2048:]
		}
		return fmt.Errorf("%s command failed: %w: %s", runtime.Binary, err, detail)
	}
	if output.exceeded {
		return fmt.Errorf("command output exceeds 64 MiB limit")
	}
	return nil
}

func (runtime Runtime) Output(ctx context.Context, args ...string) ([]byte, error) {
	var output limitedBuffer
	err := runtime.execute(ctx, args, &output, io.Discard)
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
	var output, diagnostics limitedBuffer
	if err := runtime.execute(ctx, args, &output, &diagnostics); err != nil {
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

// OutputStatus returns bounded stdout and the process exit code. Launch errors,
// cancellation, oversized output and known failure diagnostics remain errors;
// stderr content never leaves this boundary.
func (runtime Runtime) OutputStatus(ctx context.Context, args []string, markers []string, required ...string) ([]byte, int, error) {
	var output, diagnostics limitedBuffer
	err := runtime.execute(ctx, args, &output, &diagnostics)
	if ctx.Err() != nil {
		return nil, 0, err
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return nil, 0, fmt.Errorf("scanner could not start")
		}
		code = exit.ExitCode()
	}
	if output.exceeded || diagnostics.exceeded {
		return nil, code, fmt.Errorf("scanner output exceeds 64 MiB limit")
	}
	lower := bytes.ToLower(diagnostics.Bytes())
	for _, marker := range markers {
		if bytes.Contains(lower, []byte(marker)) {
			return nil, code, fmt.Errorf("scanner reported an input analysis failure")
		}
	}
	for _, marker := range required {
		if !bytes.Contains(lower, []byte(marker)) {
			return nil, code, fmt.Errorf("scanner did not confirm analysis")
		}
	}
	return output.Bytes(), code, nil
}

// execute owns scanner container names so cancellation cannot leave a daemon-side
// process running after the CLI is killed. Callers must not set container names.
func (runtime Runtime) execute(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := ""
	if len(args) > 0 && args[0] == "run" {
		for _, arg := range args[1:] {
			if arg == "--name" || strings.HasPrefix(arg, "--name=") {
				return fmt.Errorf("container names are reserved for secscan cleanup")
			}
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("create container identity: %w", err)
		}
		name = "secscan-run-" + hex.EncodeToString(nonce[:])
		args = append([]string{"run", "--name", name}, args[1:]...)
	}
	command := exec.CommandContext(ctx, runtime.Binary, args...)
	command.Stdout, command.Stderr = stdout, stderr
	command.WaitDelay = time.Second
	err := command.Run()
	if ctx.Err() == nil {
		return err
	}
	var cleanupErr error
	if name != "" {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if removeErr := exec.CommandContext(cleanup, runtime.Binary, "rm", "--force", name).Run(); removeErr != nil {
			cleanupErr = fmt.Errorf("owned container cleanup could not be confirmed: %w", removeErr)
		}
	}
	return errors.Join(ctx.Err(), err, cleanupErr)
}
