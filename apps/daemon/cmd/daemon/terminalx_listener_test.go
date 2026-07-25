// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestTerminalXListenerArgumentIsExactExclusiveAndOptIn(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"entrypoint", "logs"}, {"/bin/true"}} {
		requested, err := terminalXListenerRequested(args)
		if err != nil || requested {
			t.Fatalf("ordinary daemon arguments selected hardened listener: args=%q requested=%v err=%v", args, requested, err)
		}
	}

	requested, err := terminalXListenerRequested([]string{terminalXToolboxListenerArgument})
	if err != nil || !requested {
		t.Fatalf("exact hardened listener argument rejected: requested=%v err=%v", requested, err)
	}

	for _, args := range [][]string{
		{"--terminalx-toolbox-listener-fd=4"},
		{"--terminalx-toolbox-listener-fd="},
		{terminalXToolboxListenerArgument, "extra"},
		{"extra", terminalXToolboxListenerArgument},
	} {
		if requested, err := terminalXListenerRequested(args); err == nil || requested {
			t.Fatalf("unsafe hardened listener argument accepted: %q", args)
		}
	}
}

func TestTerminalXListenerAdoptionFailsClosed(t *testing.T) {
	disable := func() error { return nil }
	if listener, err := adoptTerminalXToolboxListener(-1, terminalXToolboxSocketPath, disable); err == nil || listener != nil {
		t.Fatal("negative listener descriptor accepted")
	}
	if listener, err := adoptTerminalXToolboxListener(999_999, terminalXToolboxSocketPath, disable); err == nil || listener != nil {
		t.Fatal("missing listener descriptor accepted")
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer readPipe.Close()
	defer writePipe.Close()
	if listener, err := adoptTerminalXToolboxListener(int(readPipe.Fd()), terminalXToolboxSocketPath, disable); err == nil || listener != nil {
		t.Fatal("non-listening descriptor accepted")
	}

	unixListener, file := unixListenerFile(t)
	defer unixListener.Close()
	defer file.Close()
	if listener, err := adoptTerminalXToolboxListener(int(file.Fd()), filepath.Join(t.TempDir(), "wrong.sock"), disable); err == nil || listener != nil {
		t.Fatal("wrong Unix listener path accepted")
	}

	unixListener, file = unixListenerFile(t)
	defer unixListener.Close()
	defer file.Close()
	if listener, err := adoptTerminalXToolboxListener(int(file.Fd()), unixListener.Addr().String(), func() error {
		return errors.New("prctl unavailable")
	}); err == nil || listener != nil {
		t.Fatal("dumpability failure was ignored")
	}
}

func TestTerminalXListenerAdoptsExactListeningUnixDescriptor(t *testing.T) {
	unixListener, file := unixListenerFile(t)
	defer unixListener.Close()
	path := unixListener.Addr().String()

	adopted, err := adoptTerminalXToolboxListener(int(file.Fd()), path, func() error { return nil })
	if err != nil {
		t.Fatalf("adopt exact Unix listener: %v", err)
	}
	defer adopted.Close()
	if adopted.Addr().Network() != "unix" || adopted.Addr().String() != path {
		t.Fatalf("adopted listener identity = %s %s", adopted.Addr().Network(), adopted.Addr().String())
	}
}

func unixListenerFile(t *testing.T) (*net.UnixListener, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "daemon.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen Unix: %v", err)
	}
	file, err := listener.File()
	if err != nil {
		listener.Close()
		t.Fatalf("duplicate Unix listener descriptor: %v", err)
	}
	return listener, file
}
