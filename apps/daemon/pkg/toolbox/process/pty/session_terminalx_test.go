// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"context"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"
)

func TestTerminalXPTYCommandUsesFixedShellAndFreshPublicEnvironment(t *testing.T) {
	const providerID = "123e4567-e89b-42d3-a456-426614174000"
	const snapshot = "registry.example.invalid/private/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	t.Setenv("DAYTONA_SANDBOX_ID", providerID)
	t.Setenv("DAYTONA_SANDBOX_SNAPSHOT", snapshot)
	t.Setenv("TERMINALX_FUTURE_PRIVATE_VALUE", "must-not-be-inherited")

	cmd, err := ptyCommand(context.Background(), PTYSessionInfo{
		Cwd:  terminalXPTYWorkingDirectory,
		Envs: map[string]string{"TERM": "xterm-256color"},
	}, true)
	if err != nil {
		t.Fatalf("construct sanitized PTY command: %v", err)
	}

	if cmd.Path != "/bin/sh" || !slices.Equal(cmd.Args, []string{"/bin/sh", "-i"}) {
		t.Fatalf("sanitized PTY did not pin /bin/sh -i: path=%q args=%q", cmd.Path, cmd.Args)
	}
	if cmd.Dir != terminalXPTYWorkingDirectory {
		t.Fatalf("sanitized PTY working directory = %q", cmd.Dir)
	}
	wantEnv := []string{
		"HOME=/home/terminalx",
		"USER=terminalx",
		"LOGNAME=terminalx",
		"SHELL=/bin/sh",
		"TERM=xterm-256color",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"PWD=/home/terminalx",
	}
	if !slices.Equal(cmd.Env, wantEnv) {
		t.Fatalf("sanitized PTY environment = %q", cmd.Env)
	}
	joined := strings.Join(cmd.Env, "\x00")
	for _, privateValue := range []string{providerID, snapshot, "must-not-be-inherited", "DAYTONA_SANDBOX_ID", "DAYTONA_SANDBOX_SNAPSHOT"} {
		if strings.Contains(joined, privateValue) {
			t.Fatalf("sanitized PTY environment contains private value %q", privateValue)
		}
	}
}

func TestTerminalXPTYCommandRejectsCallerSelectedEnvironmentOrDirectory(t *testing.T) {
	tests := []PTYSessionInfo{
		{Cwd: "/tmp", Envs: map[string]string{"TERM": "xterm-256color"}},
		{Cwd: terminalXPTYWorkingDirectory, Envs: map[string]string{"TERM": "vt100"}},
		{Cwd: terminalXPTYWorkingDirectory, Envs: map[string]string{"TERM": "xterm-256color", "TOKEN": "private"}},
	}
	for _, info := range tests {
		if _, err := ptyCommand(context.Background(), info, true); err == nil {
			t.Fatalf("accepted unsafe sanitized PTY configuration: %#v", info)
		}
	}
}

func TestPTYKillDoesNotRaceReadOrInputLoops(t *testing.T) {
	readFile, writeFile, err := os.Pipe()
	if err != nil {
		t.Fatalf("create test pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = readFile.Close()
		_ = writeFile.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	session := &PTYSession{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		info:    PTYSessionInfo{ID: "race", Active: true},
		ptmx:    readFile,
		ctx:     ctx,
		cancel:  cancel,
		inCh:    make(chan []byte, 1024),
		clients: cmap.New[*wsClient](),
	}

	original := ptyManager
	ptyManager = NewPTYManager()
	t.Cleanup(func() { ptyManager = original })
	if !ptyManager.Add(session) {
		t.Fatal("register test session")
	}

	readDone := make(chan struct{})
	writeDone := make(chan struct{})
	go func() {
		defer close(readDone)
		session.ptyReadLoop(readFile)
	}()
	go func() {
		defer close(writeDone)
		session.inputWriteLoop(ctx, writeFile)
	}()

	const senders = 32
	start := make(chan struct{})
	var sendWG sync.WaitGroup
	for range senders {
		sendWG.Add(1)
		go func() {
			defer sendWG.Done()
			<-start
			_ = session.sendToPTY([]byte("x"))
		}()
	}
	close(start)
	session.kill()
	sendWG.Wait()

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("PTY reader did not stop after kill")
	}
	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("PTY input writer did not stop after kill")
	}
	if _, ok := ptyManager.Get("race"); ok {
		t.Fatal("killed session remained registered")
	}
}
