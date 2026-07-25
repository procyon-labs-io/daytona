// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package terminalxdocker

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPinnedClientUsesOnlyValidatedUnixSocket(t *testing.T) {
	socketPath, listener := testUnixListener(t, 0o660)
	uid := uint32(os.Geteuid())
	release := acceptOne(t, listener)
	defer release()

	client, closeClient, err := newPinnedClient(t.Context(), socketPath, uid, false)
	if err != nil {
		t.Fatalf("construct pinned client: %v", err)
	}
	t.Cleanup(func() { _ = closeClient() })
	wantHost := "unix://" + socketPath
	if client.DaemonHost() != wantHost {
		t.Fatalf("daemon host = %q, want %q", client.DaemonHost(), wantHost)
	}
}

func TestPinnedClientRejectsUnsafeSocketMetadataAndOwner(t *testing.T) {
	t.Run("ordinary file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "docker.sock")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectSocket(path, uint32(os.Geteuid()), false); err == nil {
			t.Fatal("ordinary file accepted as Docker socket")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		socketPath, listener := testUnixListener(t, 0o660)
		link := filepath.Join(t.TempDir(), "docker.sock")
		if err := os.Symlink(socketPath, link); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectSocket(link, uint32(os.Geteuid()), false); err == nil {
			t.Fatal("symlink accepted as Docker socket")
		}
		_ = listener.Close()
	})

	t.Run("world accessible", func(t *testing.T) {
		socketPath, listener := testUnixListener(t, 0o666)
		if _, err := inspectSocket(socketPath, uint32(os.Geteuid()), false); err == nil {
			t.Fatal("world-accessible Docker socket accepted")
		}
		_ = listener.Close()
	})

	t.Run("wrong owner", func(t *testing.T) {
		socketPath, listener := testUnixListener(t, 0o660)
		if _, err := inspectSocket(socketPath, uint32(os.Geteuid()+1), false); err == nil {
			t.Fatal("unexpected Docker socket owner accepted")
		}
		_ = listener.Close()
	})
}

func TestPinnedDialRejectsAnyOtherNetworkOrAddress(t *testing.T) {
	socketPath, listener := testUnixListener(t, 0o660)
	identity, err := inspectSocket(socketPath, uint32(os.Geteuid()), false)
	if err != nil {
		t.Fatal(err)
	}
	dial := pinnedDialContext(socketPath, uint32(os.Geteuid()), false, identity)
	for _, test := range []struct{ network, address string }{
		{"tcp", "127.0.0.1:2375"},
		{"unix", filepath.Join(t.TempDir(), "other.sock")},
		{"ssh", "docker@example.invalid"},
	} {
		if connection, err := dial(context.Background(), test.network, test.address); err == nil {
			_ = connection.Close()
			t.Fatalf("accepted Docker dial target %s %s", test.network, test.address)
		}
	}
	_ = listener.Close()
}

func TestPinnedDialRejectsSocketReplacementBeforeConnect(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "docker.sock")
	first, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}
	pinnedFD, approved, err := pinSocket(socketPath, uint32(os.Geteuid()), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(pinnedFD) })
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	second, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}

	dial := pinnedDialContext(socketPath, uint32(os.Geteuid()), false, approved)
	if connection, err := dial(t.Context(), "unix", socketPath); err == nil {
		_ = connection.Close()
		t.Fatal("replacement Docker socket inode accepted")
	}
}

func testUnixListener(t *testing.T, mode os.FileMode) (string, *net.UnixListener) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	return path, listener
}

func acceptOne(t *testing.T, listener *net.UnixListener) func() {
	t.Helper()
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		<-release
		done <- connection.Close()
	}()
	return func() {
		close(release)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("accept/close Unix connection: %v", err)
			}
		case <-t.Context().Done():
			t.Error("timed out closing accepted Unix connection")
		}
	}
}

func TestProtectedParentValidationRejectsWritableOrForeignDirectories(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateProtectedParents(directory, uint32(os.Geteuid())); err == nil {
		t.Fatal("writable parent accepted")
	}

	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if err := validateProtectedParents(directory, stat.Uid+1); err == nil {
		t.Fatal("foreign parent owner accepted")
	}
}
