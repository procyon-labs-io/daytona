// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
	"github.com/daytonaio/daemon/pkg/childreap"
	"github.com/daytonaio/daemon/pkg/common"
	"github.com/shirou/gopsutil/v4/process"
)

// Info returns the current session information
func (s *PTYSession) Info() PTYSessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// start initializes and starts the PTY session
func (s *PTYSession) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return errors.New("PTY session is closing")
	}

	// already running?
	if s.info.Active && s.cmd != nil && s.ptmx != nil {
		return nil
	}

	// Prevent restarting - once a session exits, it should be removed from manager
	if s.cmd != nil {
		return errors.New("PTY session has already been used and cannot be restarted")
	}

	if s.inCh == nil {
		s.inCh = make(chan []byte, 1024)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	cmd, err := ptyCommand(ctx, s.info, s.sanitizeEnv)
	if err != nil {
		cancel()
		return err
	}

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: s.info.Rows, Cols: s.info.Cols})
	if err != nil {
		cancel()
		return fmt.Errorf("pty.StartWithSize: %w", err)
	}

	s.cmd = cmd
	s.ptmx = ptmx
	s.info.Active = true

	s.logger.Debug("Started PTY session", "sessionId", s.info.ID, "pid", s.cmd.Process.Pid)

	// 1) PTY -> clients broadcaster
	go s.ptyReadLoop(ptmx)

	// 2) clients -> PTY writer
	go s.inputWriteLoop(ctx, ptmx)

	// Reap the process; mark inactive on exit and send exit event.
	// Uses Reap (not Wait) because pty.StartWithSize wires std{in,out,err}
	// to *os.File slaves — no Go-level I/O goroutines to drain.
	go func(cmd *exec.Cmd) {
		exitCode, err := childreap.Reap(cmd)
		var exitReason string

		switch {
		case err != nil:
			exitCode = 1
			exitReason = " (process error)"
		case exitCode == 0:
			exitReason = " (clean exit)"
		case exitCode == 137:
			exitReason = " (SIGKILL)"
		case exitCode == 130:
			exitReason = " (SIGINT - Ctrl+C)"
		case exitCode == 143:
			exitReason = " (SIGTERM)"
		case exitCode > 128:
			exitReason = fmt.Sprintf(" (signal %d)", exitCode-128)
		default:
			exitReason = " (non-zero exit)"
		}

		s.mu.Lock()
		s.closing = true
		s.info.Active = false
		sessionID := s.info.ID
		s.mu.Unlock()

		// Close WebSocket connections with exit code and reason
		s.closeClientsWithExitCode(exitCode, exitReason)

		// Remove session from manager - process has exited and won't be reused
		ptyManager.DeleteExact(sessionID, s)

		s.logger.Debug("PTY session process exited and cleaned up", "sessionId", sessionID, "exitCode", exitCode, "exitReason", exitReason)
	}(cmd)

	return nil
}

// ptyCommand constructs the only user-visible process launched by the native
// PTY path. sanitizeEnv is selected only by TerminalX's root supervisor. It
// deliberately builds a new environment instead of filtering the daemon's
// environment, so provider identifiers and future daemon-only variables
// cannot be inherited accidentally.
func ptyCommand(ctx context.Context, info PTYSessionInfo, sanitizeEnv bool) (*exec.Cmd, error) {
	if sanitizeEnv {
		if info.Cwd != terminalXPTYWorkingDirectory ||
			len(info.Envs) != 1 || info.Envs["TERM"] != "xterm-256color" {
			return nil, errors.New("sanitized PTY configuration is invalid")
		}
		cmd := exec.CommandContext(ctx, "/bin/sh", "-i")
		cmd.Dir = terminalXPTYWorkingDirectory
		cmd.Env = []string{
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
		return cmd, nil
	}

	shell := common.GetShell()
	if shell == "" {
		return nil, errors.New("no shell resolved")
	}
	cmd := exec.CommandContext(ctx, shell, "-i", "-l")
	cmd.Dir = info.Cwd
	cmd.Env = os.Environ()
	for k, v := range info.Envs {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	return cmd, nil
}

// kill terminates the PTY session
func (s *PTYSession) kill() {
	// kill process and PTY
	s.mu.Lock()
	// Fence lazy start and client registration before sweeping clients. This is
	// required even for an inactive lazy session: a connector may already hold
	// the session pointer after the manager entry has been removed.
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true

	sessionID := s.info.ID
	var pid int
	if s.cmd != nil && s.cmd.Process != nil {
		pid = s.cmd.Process.Pid
	}

	// SIGKILL descendants BEFORE we cancel the ctx or close the PTY
	// master. Both of those have side effects that quickly kill the
	// shell — ctx cancel triggers an async SIGKILL via exec.CommandContext's
	// watchdog, and closing ptmx makes the shell's tty disappear — and
	// once the shell exits, the kernel reparents its children to PID 1.
	// At that point gopsutil.Children(shell_pid) returns nothing (the
	// children's PPID is no longer shell_pid), so descendants like a
	// `sleep & disown` that escaped job-control pgid would slip through
	// and survive teardown. Walking while the shell is still alive
	// guarantees we see and kill them.
	if pid > 0 {
		killProcessTree(pid)
	}

	if s.cancel != nil {
		s.cancel()
	}
	if s.ptmx != nil {
		_ = s.ptmx.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	s.info.Active = false
	s.mu.Unlock()

	// Close WebSocket connections with kill exit code - 137 = 128 + 9 (SIGKILL)
	s.closeClientsWithExitCode(137, " (SIGKILL)")

	// Remove session from manager - manually killed
	ptyManager.DeleteExact(sessionID, s)
}

// killProcessTree sends SIGKILL to every descendant of pid, depth-first so
// leaves die before their parents and don't get a chance to be reparented to
// PID 1 mid-teardown.
func killProcessTree(pid int) {
	parent, err := process.NewProcess(int32(pid))
	if err != nil {
		return
	}
	descendants, err := parent.Children()
	if err != nil {
		return
	}
	for _, child := range descendants {
		killProcessTree(int(child.Pid))
	}
	for _, child := range descendants {
		if p, err := os.FindProcess(int(child.Pid)); err == nil {
			_ = p.Signal(syscall.SIGKILL)
		}
	}
}

// ptyReadLoop reads from PTY and broadcasts to all clients
func (s *PTYSession) ptyReadLoop(ptmx *os.File) {
	buf := make([]byte, 32*1024)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			b := make([]byte, n)
			copy(b, buf[:n])
			s.broadcast(b)
		}
		if err != nil {
			return
		}
	}
}

// inputWriteLoop writes client input to PTY
func (s *PTYSession) inputWriteLoop(ctx context.Context, ptmx *os.File) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.inCh:
			if _, err := ptmx.Write(data); err != nil {
				return
			}
		}
	}
}

// sendToPTY sends data from a client to the PTY
func (s *PTYSession) sendToPTY(data []byte) error {
	s.mu.Lock()
	inCh := s.inCh
	ctx := s.ctx
	active := s.info.Active
	s.mu.Unlock()

	// Snapshot the immutable per-start input state under the session lock so a
	// concurrent lazy start cannot race this path.
	if !active || inCh == nil || ctx == nil {
		return fmt.Errorf("PTY session input channel not available")
	}

	select {
	case inCh <- data:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("PTY session input channel closed")
	}
}

// resize changes the PTY window size
func (s *PTYSession) resize(cols, rows uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if session is still active
	if !s.info.Active {
		return errors.New("cannot resize inactive PTY session")
	}

	if cols > 1000 {
		return fmt.Errorf("cols must be less than 1000")
	}
	if rows > 1000 {
		return fmt.Errorf("rows must be less than 1000")
	}

	s.info.Cols = cols
	s.info.Rows = rows

	if s.ptmx != nil {
		if err := pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
			s.logger.Debug("PTY resize error", "error", err)
			return err
		}
	} else {
		return errors.New("PTY file descriptor is not available")
	}
	return nil
}
