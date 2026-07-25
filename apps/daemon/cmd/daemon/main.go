// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	golog "log"

	"github.com/daytonaio/common-go/pkg/log"
	"github.com/daytonaio/daemon/cmd/daemon/config"
	"github.com/daytonaio/daemon/internal/util"
	"github.com/daytonaio/daemon/pkg/childreap"
	"github.com/daytonaio/daemon/pkg/recording"
	"github.com/daytonaio/daemon/pkg/recordingdashboard"
	"github.com/daytonaio/daemon/pkg/session"
	"github.com/daytonaio/daemon/pkg/ssh"
	"github.com/daytonaio/daemon/pkg/terminal"
	"github.com/daytonaio/daemon/pkg/toolbox"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"golang.org/x/sys/unix"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	terminalXToolboxListenerArgument = "--terminalx-toolbox-listener-fd=3"
	terminalXToolboxListenerFD       = 3
	terminalXToolboxSocketPath       = "/run/terminalx-private/daytona-daemon.sock"
)

func main() {
	os.Exit(run())
}

func run() int {
	logLevel := log.ParseLogLevel(os.Getenv("LOG_LEVEL"))

	// Create the console handler with tint for colored output
	consoleHandler := tint.NewHandler(os.Stdout, &tint.Options{
		NoColor:    !isatty.IsTerminal(os.Stdout.Fd()),
		TimeFormat: time.RFC3339,
		Level:      logLevel,
	})

	logger := slog.New(consoleHandler)
	slog.SetDefault(logger)

	// Redirect standard library log to slog
	golog.SetOutput(&log.DebugLogWriter{})

	args := os.Args[1:]
	terminalXListener, terminalXHardened, err := inheritedTerminalXToolboxListener(args)
	if err != nil {
		logger.Error("Invalid TerminalX daemon listener", "error", err)
		return 2
	}
	if terminalXListener != nil {
		defer terminalXListener.Close()
		args = nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Error("Failed to get user home directory", "error", err)
		return 2
	}

	configDir := filepath.Join(homeDir, ".daytona")
	err = os.MkdirAll(configDir, 0755)
	if err != nil {
		logger.Error("Failed to create config directory", "path", configDir, "error", err)
		return 2
	}

	entrypointLogFilePath := filepath.Join(configDir, "sessions", util.EntrypointSessionID, util.EntrypointCommandID, "output.log")

	// Check if user wants to read entrypoint logs
	if len(args) == 2 && args[0] == "entrypoint" && args[1] == "logs" {
		err := util.ReadEntrypointLogs(entrypointLogFilePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				logger.Warn("Logs not found, please check if correct entrypoint was provided for sandbox.")
			} else {
				logger.Error("Failed to read entrypoint log file", "error", err)
			}

			return 1
		}

		return 0
	}

	c, err := config.GetConfig()
	if err != nil {
		logger.Error("Failed to get config", "error", err)
		return 2
	}

	// If workdir in image is not set, use user home as workdir
	if c.UserHomeAsWorkDir {
		err = os.Chdir(homeDir)
		if err != nil {
			logger.Warn("Failed to change working directory to home directory", "error", err)
		}
	}

	if c.DaemonLogFilePath != "" {
		_ = os.MkdirAll(filepath.Dir(c.DaemonLogFilePath), 0755)
		logFile, err := os.OpenFile(c.DaemonLogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logger.Error("Failed to open daemon log file", "path", c.DaemonLogFilePath, "error", err)
		} else {
			_ = logFile.Close()

			logWriter := &lumberjack.Logger{
				Filename:   c.DaemonLogFilePath,
				MaxSize:    c.DaemonLogMaxSizeMB,
				MaxAge:     c.DaemonLogMaxAgeDays,
				MaxBackups: c.DaemonLogMaxBackups,
				LocalTime:  true,
				Compress:   c.DaemonLogCompress,
			}
			defer logWriter.Close()

			fileHandler := slog.NewTextHandler(logWriter, &slog.HandlerOptions{
				Level: logLevel,
			})
			handler := log.NewMultiHandler([]slog.Handler{consoleHandler, fileHandler}...)

			logger = slog.New(handler)
			slog.SetDefault(logger)
		}
	}

	sessionService := session.NewSessionService(logger, configDir, c.TerminationGracePeriod, c.TerminationCheckInterval)

	// Execute passed arguments as command in entrypoint session
	if len(args) > 0 {
		// Create entrypoint session
		err = sessionService.Create(util.EntrypointSessionID, false)
		if err != nil {
			logger.Error("Failed to create entrypoint session", "error", err)
			return 2
		}

		// Defer entrypoint session deletion concurrently with toolbox shutdown
		defer func() {
			delErr := sessionService.Delete(context.Background(), util.EntrypointSessionID)
			if delErr != nil {
				logger.Error("Failed to delete entrypoint session", "error", delErr)
			} else {
				logger.Debug("Deleted entrypoint session", "session_id", util.EntrypointSessionID)
			}
		}()

		logger.Debug("Created entrypoint session", "session_id", util.EntrypointSessionID)

		// Execute command asynchronously via session
		command := util.ShellQuoteJoin(args)
		_, err := sessionService.Execute(
			util.EntrypointSessionID,
			util.EntrypointCommandID,
			command,
			true,  // async=true for non-blocking
			false, // isCombinedOutput=false
			false, // skipServerDemux=false (internal, async so demux irrelevant)
			true,  // suppressInputEcho=true
		)
		if err != nil {
			logger.Error("Failed to execute entrypoint command", "error", err)
			return 2
		}
	}

	errChan := make(chan error)

	workDir, err := os.Getwd()
	if err != nil {
		logger.Error("Failed to get current working directory", "error", err)
		return 2
	}

	recordingsDir := c.RecordingsDir
	if recordingsDir == "" {
		recordingsDir = filepath.Join(configDir, "recordings")
	}
	recordingService := recording.NewRecordingService(logger, recordingsDir)

	toolBoxServer := toolbox.NewServer(toolbox.ServerConfig{
		Logger:                logger,
		WorkDir:               workDir,
		ConfigDir:             configDir,
		OtelEndpoint:          c.OtelEndpoint,
		SandboxId:             c.SandboxId,
		SessionService:        sessionService,
		RecordingService:      recordingService,
		OrganizationId:        c.OrganizationId,
		RegionId:              c.RegionId,
		Snapshot:              c.Snapshot,
		EntrypointLogFilePath: entrypointLogFilePath,
		Listener:              terminalXListener,
	})

	// Start the toolbox server in a go routine
	go func() {
		err := toolBoxServer.Start()
		if err != nil {
			errChan <- err
		}
	}()

	if !terminalXHardened {
		// Legacy listeners remain available only outside the hardened image. The
		// inherited Unix toolbox listener is the sole TerminalX ingress.
		go func() {
			if err := terminal.StartTerminalServer(22222); err != nil {
				errChan <- err
			}
		}()

		go func() {
			if err := recordingdashboard.NewDashboardServer(logger, recordingService).Start(); err != nil {
				errChan <- err
			}
		}()

		sshServer := ssh.NewServer(logger, workDir, workDir)
		go func() {
			if err := sshServer.Start(); err != nil {
				errChan <- err
			}
		}()
	}

	// Reap zombie children. The daemon runs as PID 1 inside containers, so
	// orphaned processes (e.g. from process.exec) get reparented here.
	// childreap installs the SIGCHLD reaper AND wires up cooperative status
	// recovery so cmd.Wait callers still get the right exit code when the
	// reaper claims a child before they do (see pkg/childreap).
	childreap.Start()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for either an error or shutdown signal
	select {
	case err := <-errChan:
		logger.Error("Error occurred", "error", err)
	case sig := <-sigChan:
		logger.Info("Received signal, shutting down gracefully...", "signal", sig)
	}

	// Toolbox server graceful shutdown
	toolBoxServer.Shutdown()

	slog.Info("Shutdown complete")
	return 0
}

func inheritedTerminalXToolboxListener(args []string) (net.Listener, bool, error) {
	requested, err := terminalXListenerRequested(args)
	if err != nil || !requested {
		return nil, false, err
	}
	listener, err := adoptTerminalXToolboxListener(
		terminalXToolboxListenerFD,
		terminalXToolboxSocketPath,
		disableProcessDumpability,
	)
	if err != nil {
		return nil, false, err
	}
	return listener, true, nil
}

func terminalXListenerRequested(args []string) (bool, error) {
	hasTerminalXArgument := slices.ContainsFunc(args, func(value string) bool {
		return strings.HasPrefix(value, "--terminalx-toolbox-listener-fd=")
	})
	if !hasTerminalXArgument {
		return false, nil
	}
	if len(args) != 1 || args[0] != terminalXToolboxListenerArgument {
		return false, errors.New("TerminalX toolbox listener argument must be exact and exclusive")
	}
	return true, nil
}

func disableProcessDumpability() error {
	// The listener pathname lives below a root:root 0700 directory, so uid
	// terminalx cannot connect by name. PR_SET_DUMPABLE=0 additionally denies a
	// same-uid shell access to /proc/<daemon-pid>/{fd,environ}, preventing it
	// from reopening the inherited listening descriptor through procfs.
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func adoptTerminalXToolboxListener(
	fd int,
	expectedPath string,
	disableDumpability func() error,
) (net.Listener, error) {
	if fd < 0 || expectedPath == "" || disableDumpability == nil {
		return nil, errors.New("TerminalX toolbox listener contract is invalid")
	}
	if err := disableDumpability(); err != nil {
		return nil, fmt.Errorf("disable process dumpability: %w", err)
	}
	if accepting, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || accepting != 1 {
		return nil, errors.New("TerminalX toolbox descriptor is not a listening socket")
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, fmt.Errorf("inspect TerminalX toolbox listener: %w", err)
	}
	unixAddress, ok := address.(*unix.SockaddrUnix)
	if !ok || unixAddress.Name != expectedPath {
		return nil, errors.New("TerminalX toolbox listener address does not match")
	}

	file := os.NewFile(uintptr(fd), "terminalx-toolbox-listener")
	if file == nil {
		return nil, errors.New("TerminalX toolbox listener descriptor is unavailable")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("adopt TerminalX toolbox listener: %w", err)
	}
	if listener.Addr().Network() != "unix" || listener.Addr().String() != expectedPath {
		_ = listener.Close()
		return nil, errors.New("adopted TerminalX toolbox listener address does not match")
	}
	return listener, nil
}
