// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
)

type terminalXMonitorAPIFake struct {
	containers   []container.Summary
	inspections  map[string]container.InspectResponse
	inspectError map[string]error
	listCalls    int
}

func (fake *terminalXMonitorAPIFake) Events(context.Context, events.ListOptions) (<-chan events.Message, <-chan error) {
	return make(chan events.Message), make(chan error)
}

func (fake *terminalXMonitorAPIFake) ContainerInspect(_ context.Context, id string) (container.InspectResponse, error) {
	if err := fake.inspectError[id]; err != nil {
		return container.InspectResponse{}, err
	}
	return fake.inspections[id], nil
}

func (fake *terminalXMonitorAPIFake) ContainerList(context.Context, container.ListOptions) ([]container.Summary, error) {
	fake.listCalls++
	return append([]container.Summary(nil), fake.containers...), nil
}

func newTerminalXMonitorForTest(fake dockerMonitorAPI) *DockerMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &DockerMonitor{
		apiClient: fake,
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		ctx:       ctx,
		cancel:    cancel,
		opts: MonitorOptions{
			TerminalXHardened: true,
		},
		fatalErr: make(chan error, 1),
	}
}

func TestMonitorReconnectListsAndValidatesEveryContainer(t *testing.T) {
	t.Parallel()
	validator, inspected := terminalXContainerForTest(t)
	inspected.State = &container.State{Running: true}
	fake := &terminalXMonitorAPIFake{
		containers:  []container.Summary{{ID: inspected.ID}}, // deliberately no profile label
		inspections: map[string]container.InspectResponse{inspected.ID: *inspected},
	}
	monitor := newTerminalXMonitorForTest(fake)
	validated := 0
	monitor.terminalXEnforce = func(_ context.Context, candidate *container.InspectResponse) error {
		validated++
		return validator.requireTerminalXContainer(candidate)
	}
	if err := monitor.reconcileTerminalXBlockedContainers(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if fake.listCalls != 1 || validated != 1 {
		t.Fatalf("list calls = %d, validations = %d", fake.listCalls, validated)
	}
}

func TestMonitorRejectsFullRuntimeBoundaryDrift(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*container.InspectResponse){
		"entrypoint": func(v *container.InspectResponse) { v.Config.Entrypoint = []string{"/bin/sh"} },
		"privileged": func(v *container.InspectResponse) { v.HostConfig.Privileged = true },
		"shared ipc": func(v *container.InspectResponse) { v.HostConfig.IpcMode = "container:peer" },
		"second network": func(v *container.InspectResponse) {
			v.NetworkSettings.Networks["external"] = v.NetworkSettings.Networks[RUNNER_BRIDGE_NETWORK_NAME]
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validator, inspected := terminalXContainerForTest(t)
			mutate(inspected)
			monitor := newTerminalXMonitorForTest(&terminalXMonitorAPIFake{})
			monitor.terminalXEnforce = func(_ context.Context, candidate *container.InspectResponse) error {
				return validator.requireTerminalXContainer(candidate)
			}
			if err := monitor.enforceTerminalXBlockedContainer(inspected); err == nil {
				t.Fatal("runtime drift passed live monitor")
			}
		})
	}
}

func TestHardenedStopAndKillRetainRulesUntilDestroy(t *testing.T) {
	t.Parallel()
	monitor := newTerminalXMonitorForTest(&terminalXMonitorAPIFake{})
	for _, action := range []events.Action{events.ActionStop, events.ActionKill} {
		event := events.Message{
			Type:   events.ContainerEventType,
			Action: action,
			Actor:  events.Actor{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		}
		if err := monitor.handleContainerEvent(event); err != nil {
			t.Fatalf("%s removed hardened rules: %v", action, err)
		}
	}
}

func TestNormalDestroyDisconnectDoesNotQuarantineRunningPeer(t *testing.T) {
	t.Parallel()
	removedID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fake := &terminalXMonitorAPIFake{inspectError: map[string]error{removedID: errdefs.ErrNotFound}}
	monitor := newTerminalXMonitorForTest(fake)
	quarantines := 0
	monitor.terminalXQuarantine = func(_ context.Context, cause error) error {
		quarantines++
		return cause
	}
	event := events.Message{
		Type:   events.NetworkEventType,
		Action: events.ActionDisconnect,
		Actor:  events.Actor{Attributes: map[string]string{"container": removedID}},
	}
	if err := monitor.handleContainerEvent(event); err != nil {
		t.Fatalf("normal destroy disconnect failed: %v", err)
	}
	if quarantines != 0 {
		t.Fatalf("normal destroy quarantined %d running peers", quarantines)
	}
}

func TestPeriodicEnforcementFailureQuarantinesAndStopsMonitor(t *testing.T) {
	t.Parallel()
	_, inspected := terminalXContainerForTest(t)
	fake := &terminalXMonitorAPIFake{
		containers:  []container.Summary{{ID: inspected.ID}},
		inspections: map[string]container.InspectResponse{inspected.ID: *inspected},
	}
	monitor := newTerminalXMonitorForTest(fake)
	boundaryFailure := errors.New("iptables unavailable")
	monitor.terminalXEnforce = func(context.Context, *container.InspectResponse) error {
		return boundaryFailure
	}
	quarantines := 0
	monitor.terminalXQuarantine = func(_ context.Context, cause error) error {
		quarantines++
		return cause
	}
	go monitor.reconcilerLoopAt(time.Millisecond)
	select {
	case err := <-monitor.fatalErr:
		if !errors.Is(err, boundaryFailure) {
			t.Fatalf("fatal error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("periodic boundary failure did not stop the monitor")
	}
	monitor.Stop()
	if quarantines != 1 {
		t.Fatalf("quarantine count = %d", quarantines)
	}
}
