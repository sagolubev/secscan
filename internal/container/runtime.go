// START_MODULE_CONTRACT
// PURPOSE: Run container clients with bounded output and owned cancellation cleanup.
// SCOPE: Preserve scanner exit status only after namespace transfers and cleanup succeed.
// DEPENDS: internal/container/namespace.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-container-runtime, internal/container/namespace_test.go#TestNamespaceSelectionRejectsUnknownBackend
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Runtime - Hold the selected client and validated namespace mode.
// Detect - Discover an available runtime through supplied lookup and probe functions.
// Runtime.Run - Run without exposing scanner output.
// Runtime.RunDiagnostic - Capture bounded maintenance diagnostics.
// Runtime.Output - Read bounded stdout.
// IsolatedArgs - Build the standard offline scanner boundary.
// Runtime.OutputRejecting - Reject known operational diagnostic markers.
// Runtime.OutputStatus - Preserve expected scanner exit codes after safe execution.
// limitedBuffer.Write - Retain at most the scanner output limit.
// END_MODULE_MAP

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
	Binary    string
	namespace string
	backend   string
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
		return Runtime{Binary: path, backend: name}, nil
	}
	return Runtime{}, fmt.Errorf("container runtime unavailable: %w", errors.Join(failures...))
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
	return runtime.imageInspectOutput(args, output.Bytes())
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
	args = runtime.buildArgs(args)
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
		if runtime.namespace != "" {
			return runtime.executeNamespace(ctx, args, name, stdout, stderr)
		}
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
		if removeErr := runtime.removeOwned(cleanup, name); removeErr != nil {
			cleanupErr = fmt.Errorf("owned container cleanup could not be confirmed: %w", removeErr)
		}
	}
	return errors.Join(ctx.Err(), err, cleanupErr)
}

// removeOwned skips Podman's default ten-second stop grace. These are our
// disposable scanner/helper containers; cancellation must terminate them now.
func (runtime Runtime) removeOwned(ctx context.Context, name string) error {
	args := []string{"rm", "--force"}
	if runtime.backend == "podman" {
		args = append(args, "--time", "0")
	}
	return runtime.command(ctx, append(args, name), nil, io.Discard, io.Discard)
}

// imageInspectOutput canonicalizes the one generated image-inspection format;
// scanner output and other formats never pass through image-ID normalization.
func (runtime Runtime) imageInspectOutput(args []string, data []byte) ([]byte, error) {
	if runtime.backend != "podman" || len(args) != 5 || args[0] != "image" || args[1] != "inspect" || args[2] != "--format" || (args[3] != "{{.Id}}" && !strings.HasPrefix(args[3], "{{.Id}} ")) {
		return data, nil
	}
	fields := bytes.Fields(data)
	if len(fields) == 0 {
		return nil, fmt.Errorf("invalid immutable container image ID")
	}
	id := string(fields[0])
	digest := strings.TrimPrefix(id, "sha256:")
	if len(digest) != 64 {
		return nil, fmt.Errorf("invalid immutable container image ID")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return nil, fmt.Errorf("invalid immutable container image ID")
	}
	if strings.HasPrefix(id, "sha256:") {
		return data, nil
	}
	offset := bytes.Index(data, fields[0])
	return []byte(string(data[:offset]) + "sha256:" + string(data[offset:])), nil
}

// buildArgs preserves Docker's existing explicit-update build policy in Podman:
// pull missing bases, omit disabled BuildKit provenance, keep all other argv.
func (runtime Runtime) buildArgs(args []string) []string {
	if runtime.backend != "podman" || len(args) == 0 || args[0] != "build" {
		return args
	}
	result := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--provenance=false":
			continue
		case "--pull=false":
			result = append(result, "--pull=missing")
		case "--build-arg", "--build-context", "--tag", "--file":
			result = append(result, args[i])
			if i+1 < len(args) {
				i++
				result = append(result, args[i])
			}
		default:
			result = append(result, args[i])
		}
	}
	return result
}
