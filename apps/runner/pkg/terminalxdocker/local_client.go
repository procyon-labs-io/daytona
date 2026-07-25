// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

// Package terminalxdocker constructs the only Docker client permitted by the
// TerminalX hardened runner profile.
package terminalxdocker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/docker/docker/client"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

const (
	// The dedicated runner deployment mounts the host Docker control socket at
	// this exact path. Environment-selected, rootless, TCP, SSH, and proxy
	// endpoints are never accepted by the hardened profile.
	SocketPath = "/run/docker.sock"
	DockerHost = "unix:///run/docker.sock"
)

type socketIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
}

// NewPinnedClient validates the deployment socket before any Docker API use
// and revalidates the same inode, root peer, and host namespaces on every new
// connection. Existing connections remain bound to the already-validated
// Unix socket even if its pathname changes later.
func NewPinnedClient(ctx context.Context) (*client.Client, func() error, error) {
	return newPinnedClient(ctx, SocketPath, 0, true)
}

func newPinnedClient(
	ctx context.Context,
	socketPath string,
	expectedUID uint32,
	requireProtectedParents bool,
) (*client.Client, func() error, error) {
	pinnedFD, approved, err := pinSocket(socketPath, expectedUID, requireProtectedParents)
	if err != nil {
		return nil, nil, err
	}
	keepPin := false
	defer func() {
		if !keepPin {
			_ = unix.Close(pinnedFD)
		}
	}()

	dial := pinnedDialContext(socketPath, expectedUID, requireProtectedParents, approved)
	preflight, err := dial(ctx, "unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("TerminalX Docker socket preflight failed: %w", err)
	}
	if err := preflight.Close(); err != nil {
		return nil, nil, errors.New("TerminalX Docker socket preflight close failed")
	}

	dockerHost := "unix://" + socketPath
	result, err := client.NewClientWithOpts(
		client.WithHost(dockerHost),
		client.WithDialContext(dial),
		client.WithAPIVersionNegotiation(),
		client.WithTraceProvider(trace.NewNoopTracerProvider()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("construct TerminalX Docker client: %w", err)
	}
	if result.DaemonHost() != dockerHost {
		_ = result.Close()
		return nil, nil, errors.New("TerminalX Docker client host is not pinned")
	}
	keepPin = true
	var closeOnce sync.Once
	var closeError error
	closeClient := func() error {
		closeOnce.Do(func() {
			closeError = errors.Join(result.Close(), unix.Close(pinnedFD))
		})
		return closeError
	}
	return result, closeClient, nil
}

func pinSocket(
	socketPath string,
	expectedUID uint32,
	requireProtectedParents bool,
) (int, socketIdentity, error) {
	before, err := inspectSocket(socketPath, expectedUID, requireProtectedParents)
	if err != nil {
		return -1, socketIdentity{}, err
	}
	fd, err := unix.Open(socketPath, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, socketIdentity{}, errors.New("TerminalX Docker socket cannot be pinned")
	}
	valid := false
	defer func() {
		if !valid {
			_ = unix.Close(fd)
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return -1, socketIdentity{}, errors.New("TerminalX Docker socket pin cannot be inspected")
	}
	pinned := socketIdentity{device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid}
	after, err := inspectSocket(socketPath, expectedUID, requireProtectedParents)
	if err != nil || before != pinned || after != pinned {
		return -1, socketIdentity{}, errors.New("TerminalX Docker socket changed while it was pinned")
	}
	valid = true
	return fd, pinned, nil
}

func pinnedDialContext(
	socketPath string,
	expectedUID uint32,
	requireProtectedParents bool,
	approved socketIdentity,
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		if network != "unix" || address != socketPath {
			return nil, errors.New("TerminalX Docker dial target is not the pinned Unix socket")
		}
		before, err := inspectSocket(socketPath, expectedUID, requireProtectedParents)
		if err != nil || before != approved {
			return nil, errors.New("TerminalX Docker socket identity changed")
		}

		connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		if err != nil {
			return nil, err
		}
		valid := false
		defer func() {
			if !valid {
				_ = connection.Close()
			}
		}()

		after, err := inspectSocket(socketPath, expectedUID, requireProtectedParents)
		if err != nil || after != approved {
			return nil, errors.New("TerminalX Docker socket identity changed during connect")
		}
		if err := validatePeer(connection, socketPath, expectedUID); err != nil {
			return nil, err
		}
		valid = true
		return connection, nil
	}
}

func inspectSocket(
	socketPath string,
	expectedUID uint32,
	requireProtectedParents bool,
) (socketIdentity, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return socketIdentity{}, errors.New("TerminalX Docker socket path is invalid")
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		return socketIdentity{}, errors.New("TerminalX Docker socket is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 ||
		info.Mode().Perm()&0o007 != 0 {
		return socketIdentity{}, errors.New("TerminalX Docker socket metadata is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Nlink != 1 {
		return socketIdentity{}, errors.New("TerminalX Docker socket ownership is unsafe")
	}
	if requireProtectedParents {
		if err := validateProtectedParents(filepath.Dir(socketPath), expectedUID); err != nil {
			return socketIdentity{}, err
		}
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid}, nil
}

func validateProtectedParents(directory string, expectedUID uint32) error {
	for {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("TerminalX Docker socket parent is unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != expectedUID {
			return errors.New("TerminalX Docker socket parent ownership is unsafe")
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}
		directory = parent
	}
}

func validatePeer(connection net.Conn, socketPath string, expectedUID uint32) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || unixConnection.RemoteAddr().Network() != "unix" ||
		unixConnection.RemoteAddr().String() != socketPath {
		return errors.New("TerminalX Docker peer is not the approved Unix listener")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return errors.New("TerminalX Docker peer credentials are unavailable")
	}
	var credentials *unix.Ucred
	var controlError error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlError = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || controlError != nil || credentials == nil {
		return errors.New("TerminalX Docker peer credentials are unavailable")
	}
	if credentials.Uid != expectedUID || credentials.Pid <= 0 {
		return errors.New("TerminalX Docker peer identity is not approved")
	}
	for _, namespace := range []string{"mnt", "net", "pid", "user"} {
		self, selfErr := os.Stat(filepath.Join("/proc/self/ns", namespace))
		peer, peerErr := os.Stat(filepath.Join("/proc", fmt.Sprint(credentials.Pid), "ns", namespace))
		if selfErr != nil || peerErr != nil || !os.SameFile(self, peer) {
			return errors.New("TerminalX Docker peer is outside the runner deployment namespaces")
		}
	}
	return nil
}
