// START_MODULE_CONTRACT
// PURPOSE: Preserve private payload ownership across container user namespaces.
// SCOPE: Immutable daemon mode; isolated owned volumes; bounded regular-file transfer and cleanup.
// DEPENDS: internal/container/runtime.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-container-runtime, internal/container/namespace_test.go#TestNamespaceSelectionRejectsUnknownBackend
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// DetectDefault - Select Docker or Podman and validate namespace metadata once.
// Runtime.NamespaceMode - Expose the validated namespace mode for acceptance evidence.
// metadataBuffer.Write - Reject daemon metadata above the fixed byte limit.
// contextReader.Read - Interrupt payload streaming when the context ends.
// END_MODULE_MAP

package container

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// NamespaceMode returns rootful, docker-userns, docker-rootless or podman-rootless.
func (runtime Runtime) NamespaceMode() string {
	if runtime.namespace == "" {
		return "rootful"
	}
	return runtime.namespace
}

// DetectDefault honors SECSCAN_RUNTIME or tries Docker, then Podman. Metadata and
// daemon diagnostics never become report text. Selection remains fixed per Runtime.
func DetectDefault(ctx context.Context) (Runtime, error) {
	names := []string{"docker", "podman"}
	if selected := os.Getenv("SECSCAN_RUNTIME"); selected != "" {
		if selected != "docker" && selected != "podman" {
			return Runtime{}, fmt.Errorf("SECSCAN_RUNTIME must be docker or podman")
		}
		names = []string{selected}
	}
	var failures []string
	for _, name := range names {
		binary, err := exec.LookPath(name)
		if err != nil {
			failures = append(failures, name+": executable not found")
			continue
		}
		args := []string{"info", "--format", "{{json .SecurityOptions}}"}
		if name == "podman" {
			args = []string{"info", "--format", "{{.Host.Security.Rootless}}"}
		}
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		data, err := clientMetadata(probe, binary, args)
		probeErr := probe.Err()
		cancel()
		if ctx.Err() != nil {
			return Runtime{}, ctx.Err()
		}
		if err != nil {
			if errors.Is(err, errMetadataLimit) {
				return Runtime{}, fmt.Errorf("%s: invalid container namespace metadata", name)
			}
			reason := "probe failed"
			if probeErr == context.DeadlineExceeded {
				reason = "probe timed out"
			}
			failures = append(failures, name+": "+reason)
			continue
		}
		mode, err := parseNamespace(name, data)
		if err != nil {
			return Runtime{}, fmt.Errorf("%s: invalid container namespace metadata", name)
		}
		return Runtime{Binary: binary, namespace: mode, backend: name}, nil
	}
	return Runtime{}, fmt.Errorf("container runtime unavailable: %s", strings.Join(failures, "; "))
}

func parseNamespace(backend string, data []byte) (string, error) {
	invalid := fmt.Errorf("invalid container namespace metadata")
	if len(data) > 64<<10 {
		return "", invalid
	}
	if backend == "podman" {
		switch strings.TrimSpace(string(data)) {
		case "true":
			return "podman-rootless", nil
		case "false":
			return "", nil
		}
		return "", invalid
	}
	var options []string
	if json.Unmarshal(data, &options) != nil || options == nil || len(options) > 128 {
		return "", invalid
	}
	mode := ""
	for _, option := range options {
		if len(option) > 1024 || strings.ContainsAny(option, "\x00\r\n") {
			return "", invalid
		}
		switch option {
		case "name=rootless":
			mode = "docker-rootless"
		case "name=userns":
			if mode == "" {
				mode = "docker-userns"
			}
		}
	}
	return mode, nil
}

var errMetadataLimit = errors.New("container metadata exceeds limit")

type metadataBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *metadataBuffer) Write(p []byte) (int, error) {
	if len(p) > (64<<10)-b.Len() {
		b.exceeded = true
		return 0, errMetadataLimit
	}
	return b.Buffer.Write(p)
}
func clientMetadata(ctx context.Context, binary string, args []string) ([]byte, error) {
	var out metadataBuffer
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if out.exceeded {
		return nil, errMetadataLimit
	}
	if err != nil {
		return nil, fmt.Errorf("container metadata unavailable")
	}
	return out.Bytes(), nil
}

const (
	maxPayloadBytes   int64 = 8 << 30
	maxPayloadEntries       = 100000
)

type payload struct {
	source, destination, volume string
	root                        *os.Root
	name                        string
	directory, readonly         bool
}

// validatePayload pins the source before any transfer. Writable sources are
// fresh, private staging directories owned by this process's user.
func validatePayload(ctx context.Context, source string, writable bool) (*payload, error) {
	info, err := os.Lstat(source)
	if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
		return nil, fmt.Errorf("namespace payload must be a regular file or directory")
	}
	if writable && (!info.IsDir() || info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid())) {
		return nil, fmt.Errorf("writable namespace payload must be a private owned directory")
	}
	parent, name := filepath.Dir(source), filepath.Base(source)
	if info.IsDir() {
		parent, name = source, "."
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open namespace payload failed")
	}
	p := &payload{source: source, root: root, name: name, directory: info.IsDir(), readonly: !writable}
	pinned, err := root.Lstat(name)
	if err != nil || !os.SameFile(info, pinned) {
		root.Close()
		return nil, fmt.Errorf("namespace payload changed before transfer")
	}
	if writable {
		entries, err := fs.ReadDir(root.FS(), ".")
		if err != nil || len(entries) != 0 {
			root.Close()
			return nil, fmt.Errorf("writable namespace payload must be empty")
		}
	}
	var size int64
	count := 0
	err = fs.WalkDir(root.FS(), name, func(path string, entry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			return fmt.Errorf("read namespace payload failed")
		}
		info, err := entry.Info()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode().IsRegular() && info.Sys().(*syscall.Stat_t).Nlink > 1 {
			return fmt.Errorf("namespace payload contains a link or special file")
		}
		count++
		if info.Mode().IsRegular() {
			size += info.Size()
		}
		if len(path) > 4096 || count > maxPayloadEntries || size > maxPayloadBytes {
			return fmt.Errorf("namespace payload exceeds transfer limits")
		}
		return nil
	})
	if err != nil {
		root.Close()
		return nil, err
	}
	return p, nil
}

// writePayload creates a local archive through the pinned root instead of
// allowing the container client to traverse a source tree again after validation.
func writePayload(ctx context.Context, p *payload, w io.Writer) error {
	tw := tar.NewWriter(w)
	var total int64
	count := 0
	err := fs.WalkDir(p.root.FS(), p.name, func(name string, entry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			return fmt.Errorf("read namespace payload failed")
		}
		info, err := p.root.Lstat(name)
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode().IsRegular() && info.Sys().(*syscall.Stat_t).Nlink > 1 {
			return fmt.Errorf("namespace payload changed during transfer")
		}
		relative := "payload"
		if p.directory && name != "." {
			relative += "/" + name
		}
		count++
		if !info.IsDir() {
			total += info.Size()
		}
		if len(relative) > 4096 || count > maxPayloadEntries || total > maxPayloadBytes {
			return fmt.Errorf("namespace payload exceeds transfer limits")
		}
		header := &tar.Header{Name: relative, Mode: int64(info.Mode().Perm()), Uid: os.Getuid(), Gid: os.Getgid(), Typeflag: tar.TypeDir}
		if info.IsDir() {
			return tw.WriteHeader(header)
		}
		file, err := p.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("open namespace input failed")
		}
		defer file.Close()
		current, err := file.Stat()
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || current.Size() != info.Size() {
			return fmt.Errorf("namespace input changed during transfer")
		}
		header.Typeflag, header.Size = tar.TypeReg, info.Size()
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := io.CopyN(tw, contextReader{ctx, file}, header.Size); err != nil {
			return fmt.Errorf("read namespace input failed")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func extractPayload(ctx context.Context, root *os.Root, input io.Reader) error {
	// Include bounded tar headers/padding in addition to declared file bytes.
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: maxPayloadBytes + maxPayloadEntries*8192 + 1024}
	tr := tar.NewReader(limited)
	seen := make(map[string]bool)
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid namespace output archive")
		}
		count++
		if count > maxPayloadEntries || h.Size < 0 || h.Size > maxPayloadBytes-total || len(h.Name) > 4096 {
			return fmt.Errorf("namespace output exceeds transfer limits")
		}
		total += h.Size
		name := strings.TrimSuffix(h.Name, "/")
		name = strings.TrimPrefix(name, "./")
		if strings.Contains(name, "\\") || !filepath.IsLocal(name) || path.Clean(name) != name || seen[name] {
			return fmt.Errorf("invalid or duplicate namespace output path")
		}
		seen[name] = true
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return fmt.Errorf("namespace output contains a link or special file")
		}
		if name == "." {
			if h.Typeflag != tar.TypeDir {
				return fmt.Errorf("invalid namespace output root")
			}
			continue
		}
		if h.Typeflag == tar.TypeDir {
			if err := root.Mkdir(name, 0700); err != nil {
				return fmt.Errorf("create namespace output directory failed")
			}
			continue
		}
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return fmt.Errorf("create namespace output file failed")
		}
		_, copyErr := io.CopyN(file, tr, h.Size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("write namespace output failed")
		}
	}
	// Consume the transport to detect truncated/overlong tails and let cp finish.
	if _, err := io.Copy(io.Discard, limited); err != nil || limited.N == 0 {
		return fmt.Errorf("namespace output archive exceeds limit or is incomplete")
	}
	return nil
}

type namespaceRun struct {
	args        []string
	image, user string
	mounts      []*payload
	labels      []string
}

func parseNamespaceRun(ctx context.Context, args []string) (*namespaceRun, error) {
	run := &namespaceRun{args: []string{"run"}}
	fail := func() (*namespaceRun, error) {
		for _, p := range run.mounts {
			p.root.Close()
		}
		return nil, fmt.Errorf("invalid namespace container invocation")
	}
	destinations := make(map[string]bool)
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			run.image = arg
			run.args = append(run.args, args[i:]...)
			break
		}
		switch arg {
		case "--rm":
			continue
		case "--read-only":
			run.args = append(run.args, arg)
			continue
		case "--pull", "--network", "--user", "--cap-drop", "--security-opt", "--env", "--tmpfs", "--workdir", "--entrypoint", "--label", "--ulimit", "--mount":
		default:
			return fail()
		}
		i++
		if i >= len(args) {
			return fail()
		}
		value := args[i]
		if arg == "--user" {
			if run.user != "" || !numericUser(value) {
				return fail()
			}
			run.user = value
		}
		if arg == "--label" {
			run.labels = append(run.labels, value)
		}
		if arg != "--mount" {
			run.args = append(run.args, arg, value)
			continue
		}
		source, destination, readonly, err := parseBind(value)
		if err != nil || destinations[destination] {
			return fail()
		}
		destinations[destination] = true
		p, err := validatePayload(ctx, source, !readonly)
		if err != nil {
			for _, previous := range run.mounts {
				previous.root.Close()
			}
			return nil, err
		}
		p.destination = destination
		run.mounts = append(run.mounts, p)
		run.args = append(run.args, "--mount", value)
	}
	if run.image == "" || (len(run.mounts) > 0 && run.user == "") {
		return fail()
	}
	return run, nil
}
func numericUser(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}
func parseBind(value string) (string, string, bool, error) {
	fields := strings.Split(value, ",")
	if len(fields) < 3 || len(fields) > 4 || fields[0] != "type=bind" || !strings.HasPrefix(fields[1], "src=") || !strings.HasPrefix(fields[2], "dst=") {
		return "", "", false, fmt.Errorf("invalid bind")
	}
	src, dst := strings.TrimPrefix(fields[1], "src="), strings.TrimPrefix(fields[2], "dst=")
	readonly := len(fields) == 4 && fields[3] == "readonly"
	if len(fields) == 4 && !readonly || !filepath.IsAbs(src) || !path.IsAbs(dst) || path.Clean(dst) != dst || dst == "/" || strings.ContainsAny(src+dst, "\x00\r\n:") {
		return "", "", false, fmt.Errorf("invalid bind path")
	}
	return src, dst, readonly, nil
}

func (runtime Runtime) executeNamespace(ctx context.Context, args []string, name string, stdout, stderr io.Writer) (result error) {
	run, err := parseNamespaceRun(ctx, args)
	if err != nil {
		return err
	}
	defer func() {
		for _, p := range run.mounts {
			p.root.Close()
		}
	}()
	if len(run.mounts) == 0 {
		runtime.namespace = ""
		return runtime.execute(ctx, args, stdout, stderr)
	}
	helper := strings.Replace(name, "secscan-run-", "secscan-helper-", 1)
	var volumes []string
	helperCreated, scannerStarted := false, false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		failed := false
		for _, owned := range []struct {
			name    string
			created bool
		}{{name, scannerStarted}, {helper, helperCreated}} {
			if owned.created && runtime.removeOwned(cleanup, owned.name) != nil {
				failed = true
			}
		}
		for _, volume := range volumes {
			if runtime.command(cleanup, []string{"volume", "rm", volume}, nil, io.Discard, io.Discard) != nil {
				failed = true
			}
		}
		if failed {
			result = fmt.Errorf("owned namespace resource cleanup failed")
		}
		if ctx.Err() != nil {
			result = errors.Join(ctx.Err(), result)
		}
	}()
	helperArgs := []string{"create", "--name", helper, "--pull", "never", "--network", "none", "--read-only", "--user", run.user, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "/secscan-helper-never-started"}
	for _, label := range run.labels {
		helperArgs = append(helperArgs, "--label", label)
	}
	for i, p := range run.mounts {
		p.volume = fmt.Sprintf("%s-%d", strings.Replace(name, "secscan-run-", "secscan-volume-", 1), i)
		volumes = append(volumes, p.volume)
		volumeArgs := []string{"volume", "create"}
		for _, label := range run.labels {
			volumeArgs = append(volumeArgs, "--label", label)
		}
		volumeArgs = append(volumeArgs, p.volume)
		if err := runtime.command(ctx, volumeArgs, nil, io.Discard, io.Discard); err != nil {
			return fmt.Errorf("create namespace volume failed")
		}
		helperArgs = append(helperArgs, "--mount", fmt.Sprintf("type=volume,src=%s,dst=/m%d", p.volume, i))
	}
	helperArgs = append(helperArgs, run.image)
	// Register resources before creating them so cancellation still attempts cleanup.
	helperCreated = true
	if err := runtime.command(ctx, helperArgs, nil, io.Discard, io.Discard); err != nil {
		return fmt.Errorf("create namespace helper failed")
	}
	for i, p := range run.mounts {
		archive := "false"
		if runtime.namespace == "podman-rootless" {
			archive = "true"
		}
		reader, writer := io.Pipe()
		done := make(chan error, 1)
		go func() { err := writePayload(ctx, p, writer); writer.CloseWithError(err); done <- err }()
		copyErr := runtime.command(ctx, []string{"cp", "--archive=" + archive, "-", fmt.Sprintf("%s:/m%d", helper, i)}, reader, io.Discard, io.Discard)
		reader.Close()
		writeErr := <-done
		if copyErr != nil || writeErr != nil {
			return fmt.Errorf("copy namespace input failed")
		}
		mountpoint, err := clientMetadata(ctx, runtime.Binary, []string{"volume", "inspect", "--format", "{{.Mountpoint}}", p.volume})
		daemonPath := strings.TrimSpace(string(mountpoint))
		if err != nil || !path.IsAbs(daemonPath) || path.Clean(daemonPath) != daemonPath || strings.ContainsAny(daemonPath, ",\x00\r\n:") {
			return fmt.Errorf("invalid namespace volume mountpoint")
		}
		for j := 1; j < len(run.args)-1; j++ {
			if run.args[j] == "--mount" {
				_, dst, _, err := parseBind(run.args[j+1])
				if err == nil && dst == p.destination {
					value := "type=bind,src=" + daemonPath + "/payload,dst=" + dst
					if p.readonly {
						value += ",readonly"
					}
					run.args[j+1] = value
					break
				}
			}
		}
	}
	scannerStarted = true
	runErr := runtime.command(ctx, append([]string{"run", "--name", name}, run.args[1:]...), nil, stdout, stderr)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Expected finding exit codes are preserved only after safe output transport.
	for _, p := range run.mounts {
		if !p.readonly {
			if err := runtime.copyNamespaceOutput(ctx, name, p); err != nil {
				return err
			}
		}
	}
	return runErr
}

func (runtime Runtime) copyNamespaceOutput(ctx context.Context, name string, p *payload) error {
	transfer, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(transfer, runtime.Binary, "cp", "--archive=false", name+":"+p.destination+"/.", "-")
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open namespace output failed")
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("copy namespace output failed")
	}
	extractErr := extractPayload(ctx, p.root, stdout)
	if extractErr != nil {
		cancel()
	}
	stdout.Close()
	waitErr := cmd.Wait()
	if extractErr != nil {
		return fmt.Errorf("copy namespace output: %w", extractErr)
	}
	if waitErr != nil {
		return fmt.Errorf("container output copy failed")
	}
	return nil
}

func (runtime Runtime) command(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, runtime.Binary, args...)
	cmd.Stdin = stdin
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	return cmd.Run()
}
