// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	terminalXSupervisorRelayMaximumBytes              int64 = 16 * 1024 * 1024
	terminalXNodeMaximumBytes                         int64 = 256 * 1024 * 1024
	terminalXSupervisorRelayMaximumInputBytes               = 1024*1024 + 4
	terminalXSupervisorRelayMaximumInternalInputBytes       = 4 + terminalXEffectiveIsolationMaximumBytes + terminalXSupervisorRelayMaximumInputBytes
	terminalXSupervisorRelayMaximumStderrBytes        int64 = 4 * 1024
)

const terminalXUnsafeFileMode = os.ModeSetuid | os.ModeSetgid | os.ModeSticky | os.ModeSymlink | os.ModeDevice | os.ModeNamedPipe | os.ModeSocket

// OpenTerminalXSupervisorRelay opens only the fixed root protocol relay from
// the exact hardened image. The caller controls framed stdin, never the exec
// path, uid, arguments, environment, working directory, privileges, or TTY.
func (d *DockerClient) OpenTerminalXSupervisorRelay(
	ctx context.Context,
	containerID string,
	input []byte,
) (io.ReadCloser, error) {
	if !d.terminalXHardened || len(input) < 6 || len(input) > terminalXSupervisorRelayMaximumInputBytes {
		return nil, fmt.Errorf("terminalx supervisor relay is unavailable")
	}
	ownedInput := bytes.Clone(input)
	inputOwnedByWorker := false
	defer func() {
		if !inputOwnedByWorker {
			wipeTerminalXRootExecInput(ownedInput)
		}
	}()
	// Streaming follows and hosted PTYs live for the caller's bounded
	// connection lifetime. Each fixed preflight operation has its own short
	// deadline; imposing a second relay-wide deadline would truncate healthy
	// long-running sessions.
	relayCtx, cancel := context.WithCancel(ctx)
	inspected, err := d.ContainerInspect(relayCtx, containerID)
	if err != nil {
		cancel()
		return nil, err
	}
	if inspected.State == nil || !inspected.State.Running {
		cancel()
		return nil, fmt.Errorf("terminalx supervisor relay requires a running sandbox")
	}
	releaseAdmission, admitted := d.terminalXSupervisorRelayAdmission.acquire(
		inspected.ID,
		terminalXSupervisorRelayMaximumPerSandbox,
		terminalXSupervisorRelayMaximumGlobal,
	)
	if !admitted {
		cancel()
		return nil, fmt.Errorf("terminalx supervisor relay capacity is exhausted")
	}
	releaseOnError := true
	defer func() {
		if releaseOnError {
			releaseAdmission()
			cancel()
		}
	}()
	if err := d.enforceTerminalXRootExecNetworkPolicy(relayCtx, inspected); err != nil {
		return nil, err
	}
	if err := d.verifyTerminalXSupervisorRelay(relayCtx, inspected.ID); err != nil {
		return nil, err
	}
	preparedInput, err := d.prepareTerminalXSupervisorRelay(relayCtx, ownedInput, inspected)
	if err != nil || len(preparedInput) < 6 || len(preparedInput) > terminalXSupervisorRelayMaximumInternalInputBytes {
		wipeTerminalXRootExecInput(preparedInput)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("terminalx supervisor relay evidence is invalid")
	}
	workerInput := bytes.Clone(preparedInput)
	wipeTerminalXRootExecInput(preparedInput)
	wipeTerminalXRootExecInput(ownedInput)
	ownedInput = workerInput

	execResponse, err := d.apiClient.ContainerExecCreate(relayCtx, inspected.ID, terminalXSupervisorExecOptions())
	if err != nil {
		return nil, fmt.Errorf("terminalx supervisor relay could not be created: %w", err)
	}
	attached, err := d.apiClient.ContainerExecAttach(relayCtx, execResponse.ID, container.ExecStartOptions{
		Detach: false,
		Tty:    false,
	})
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("terminalx supervisor relay could not attach: %w", err),
			d.ensureTerminalXExecTerminated(inspected.ID, execResponse.ID),
		)
	}

	var closeAttachedOnce sync.Once
	closeAttached := func() { closeAttachedOnce.Do(func() { attached.Close() }) }
	reader, writer := io.Pipe()
	done := make(chan struct{})
	stream := &terminalXSupervisorRelayStream{
		PipeReader:    reader,
		cancel:        cancel,
		closeAttached: closeAttached,
		done:          done,
	}
	requestDone := make(chan error, 1)
	inputOwnedByWorker = true
	go func(request []byte) {
		_, copyErr := io.Copy(attached.Conn, bytes.NewReader(request))
		requestErr := errors.Join(copyErr, attached.CloseWrite())
		wipeTerminalXRootExecInput(request)
		requestDone <- requestErr
	}(ownedInput)
	go func() {
		defer cancel()
		defer close(done)
		defer releaseAdmission()
		defer closeAttached()
		stderr := &terminalXBoundedBuffer{maximumBytes: terminalXSupervisorRelayMaximumStderrBytes}
		defer stderr.Zero()
		_, outputErr := stdcopy.StdCopy(writer, stderr, attached.Reader)
		if outputErr != nil || relayCtx.Err() != nil {
			closeAttached()
		}
		requestErr := <-requestDone
		inspect, inspectErr := d.apiClient.ContainerExecInspect(relayCtx, execResponse.ID)
		execTerminated := inspectErr == nil && !inspect.Running
		if !execTerminated {
			inspectErr = errors.Join(
				inspectErr,
				d.ensureTerminalXExecTerminated(inspected.ID, execResponse.ID),
			)
		} else if inspect.ExitCode != 0 {
			inspectErr = fmt.Errorf("terminalx supervisor relay exited unsuccessfully")
		}
		if stderr.Len() != 0 {
			inspectErr = errors.Join(inspectErr, fmt.Errorf("terminalx supervisor relay wrote stderr"))
		}
		terminalErr := errors.Join(requestErr, outputErr, inspectErr, relayCtx.Err())
		stream.setWorkerTerminalError(terminalErr)
		if terminalErr != nil {
			_ = writer.CloseWithError(terminalErr)
			return
		}
		_ = writer.Close()
	}()
	go func() {
		select {
		case <-relayCtx.Done():
			_ = stream.Close()
		case <-done:
		}
	}()
	releaseOnError = false
	return stream, nil
}

func terminalXSupervisorExecOptions() container.ExecOptions {
	return container.ExecOptions{
		User:         "0:0",
		Privileged:   false,
		Tty:          false,
		AttachStdin:  true,
		AttachStderr: true,
		AttachStdout: true,
		WorkingDir:   "/",
		Cmd:          []string{terminalXSupervisorRelayPath},
	}
}

func (d *DockerClient) verifyTerminalXSupervisorRelay(ctx context.Context, containerID string) error {
	return d.verifyTerminalXRootExecutionBoundary(
		ctx,
		containerID,
		terminalXSupervisorRelayPath,
		terminalXSupervisorRelayMaximumBytes,
		d.terminalXSupervisorRelaySHA256,
	)
}

func verifyTerminalXSupervisorRelayArchive(
	archive io.Reader,
	stat container.PathStat,
	expectedSHA256 string,
) error {
	return verifyTerminalXRootExecutableArchive(
		archive,
		stat,
		terminalXSupervisorRelayPath,
		terminalXSupervisorRelayMaximumBytes,
		expectedSHA256,
	)
}

func verifyTerminalXRootExecutableArchive(
	archive io.Reader,
	stat container.PathStat,
	executablePath string,
	maximumBytes int64,
	expectedSHA256 string,
) error {
	name := path.Base(executablePath)
	if stat.Name != name || stat.Size < 1 || stat.Size > maximumBytes ||
		!stat.Mode.IsRegular() || stat.Mode.Perm() != 0o555 || stat.LinkTarget != "" {
		return fmt.Errorf("terminalx fixed executable metadata does not match")
	}
	if stat.Mode&terminalXUnsafeFileMode != 0 {
		return fmt.Errorf("terminalx fixed executable has unsafe mode bits")
	}

	tarReader := tar.NewReader(archive)
	header, err := tarReader.Next()
	if err != nil || header == nil || header.Name != name || header.Linkname != "" ||
		header.Typeflag != tar.TypeReg || header.Size != stat.Size || header.Uid != 0 ||
		header.Gid != 0 || header.FileInfo().Mode().Perm() != 0o555 ||
		header.FileInfo().Mode()&terminalXUnsafeFileMode != 0 {
		return fmt.Errorf("terminalx fixed executable archive does not match")
	}
	hash := sha256.New()
	written, err := io.CopyN(hash, tarReader, header.Size)
	if err != nil || written != header.Size {
		return fmt.Errorf("terminalx fixed executable could not be measured")
	}
	if _, err := tarReader.Next(); err != io.EOF {
		return fmt.Errorf("terminalx fixed executable archive contains additional entries")
	}
	actualDigest := hash.Sum(nil)
	expectedDigest, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expectedDigest) != sha256.Size ||
		subtle.ConstantTimeCompare(actualDigest, expectedDigest) != 1 {
		return fmt.Errorf("terminalx fixed executable digest does not match")
	}
	return nil
}

func (d *DockerClient) verifyTerminalXRootExecutionBoundary(
	ctx context.Context,
	containerID string,
	executablePath string,
	maximumBytes int64,
	expectedSHA256 string,
) error {
	paths := terminalXProtectedExecutableParents(terminalXNodePath)
	seen := make(map[string]struct{}, len(paths))
	for _, directory := range paths {
		seen[directory] = struct{}{}
	}
	for _, directory := range terminalXProtectedExecutableParents(executablePath) {
		if _, exists := seen[directory]; exists {
			continue
		}
		seen[directory] = struct{}{}
		paths = append(paths, directory)
	}
	if err := d.verifyTerminalXProtectedDirectories(ctx, containerID, paths); err != nil {
		return err
	}
	if executablePath != terminalXNodePath {
		if err := d.verifyTerminalXRootExecutable(
			ctx,
			containerID,
			terminalXNodePath,
			terminalXNodeMaximumBytes,
			d.terminalXNodeSHA256,
		); err != nil {
			return err
		}
	}
	if err := d.verifyTerminalXRootExecutable(
		ctx,
		containerID,
		executablePath,
		maximumBytes,
		expectedSHA256,
	); err != nil {
		return err
	}
	return d.verifyTerminalXProtectedDirectories(ctx, containerID, paths)
}

func (d *DockerClient) verifyTerminalXRootExecutable(
	ctx context.Context,
	containerID string,
	executablePath string,
	maximumBytes int64,
	expectedSHA256 string,
) error {
	archive, stat, err := d.apiClient.CopyFromContainer(ctx, containerID, executablePath)
	if err != nil {
		return fmt.Errorf("terminalx fixed executable is unavailable: %w", err)
	}
	defer archive.Close()
	return verifyTerminalXRootExecutableArchive(
		archive,
		stat,
		executablePath,
		maximumBytes,
		expectedSHA256,
	)
}

func terminalXProtectedExecutableParents(executablePath string) []string {
	directory := path.Dir(executablePath)
	parents := []string{"/", "/usr", "/usr/local"}
	if strings.HasPrefix(directory, "/usr/local/") {
		current := "/usr/local"
		for _, component := range strings.Split(strings.TrimPrefix(directory, "/usr/local/"), "/") {
			if component == "" {
				continue
			}
			current = path.Join(current, component)
			parents = append(parents, current)
		}
	}
	return parents
}

func (d *DockerClient) verifyTerminalXProtectedDirectories(
	ctx context.Context,
	containerID string,
	directories []string,
) error {
	for _, directory := range directories {
		archive, stat, err := d.apiClient.CopyFromContainer(ctx, containerID, directory)
		if err != nil {
			return fmt.Errorf("terminalx protected executable path is unavailable: %w", err)
		}
		verifyErr := verifyTerminalXRootDirectoryArchive(archive, stat, directory)
		closeErr := archive.Close()
		if err := errors.Join(verifyErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func verifyTerminalXRootDirectoryArchive(
	archive io.Reader,
	stat container.PathStat,
	expectedPath string,
) error {
	name := path.Base(expectedPath)
	if stat.Name != name || !stat.Mode.IsDir() || stat.Mode.Perm() != 0o755 ||
		stat.Mode&terminalXUnsafeFileMode != 0 || stat.LinkTarget != "" {
		return fmt.Errorf("terminalx protected executable directory metadata does not match")
	}
	header, err := tar.NewReader(archive).Next()
	archiveName := ""
	if header != nil {
		archiveName = header.Name
		if archiveName != "/" {
			archiveName = strings.TrimSuffix(archiveName, "/")
		}
	}
	if err != nil || header == nil || archiveName != name ||
		header.Linkname != "" || header.Typeflag != tar.TypeDir || header.Uid != 0 ||
		header.Gid != 0 || header.FileInfo().Mode().Perm() != 0o755 ||
		header.FileInfo().Mode()&terminalXUnsafeFileMode != 0 {
		return fmt.Errorf("terminalx protected executable directory archive does not match")
	}
	return nil
}

type terminalXSupervisorRelayStream struct {
	*io.PipeReader
	cancel        context.CancelFunc
	closeAttached func()
	done          <-chan struct{}
	once          sync.Once
	closeErr      error
	workerErrMu   sync.Mutex
	workerErr     error
}

func (stream *terminalXSupervisorRelayStream) setWorkerTerminalError(err error) {
	stream.workerErrMu.Lock()
	stream.workerErr = err
	stream.workerErrMu.Unlock()
}

func (stream *terminalXSupervisorRelayStream) Close() error {
	stream.once.Do(func() {
		stream.cancel()
		stream.closeAttached()
		stream.closeErr = stream.PipeReader.Close()
	})
	<-stream.done
	stream.workerErrMu.Lock()
	workerErr := stream.workerErr
	stream.workerErrMu.Unlock()
	return errors.Join(stream.closeErr, workerErr)
}
