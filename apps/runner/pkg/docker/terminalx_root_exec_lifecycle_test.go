// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

const terminalXTestInstalledDescriptor = `{"assignmentPlanDigest":"2222222222222222222222222222222222222222222222222222222222222222","bindingDigest":"3333333333333333333333333333333333333333333333333333333333333333","effectEnforcerKeyId":"runtime-enforcer-key-1","effectEnforcerPolicyDigest":"8888888888888888888888888888888888888888888888888888888888888888","effectEnforcerPublicKeyDigest":"6666666666666666666666666666666666666666666666666666666666666666","effectEnforcerSetDigest":"3333333333333333333333333333333333333333333333333333333333333333","effectManifestBindingDigest":"6666666666666666666666666666666666666666666666666666666666666666","envelopeDigest":"0000000000000000000000000000000000000000000000000000000000000000","installedMarker":"/run/terminalx-root/assignment.installed.json","kind":"terminalx.daytona-assignment-bootstrap-installed","observationIssuerKeyId":"observation-key-1","observationPublicKeyDigest":"4444444444444444444444444444444444444444444444444444444444444444","planDigest":"2222222222222222222222222222222222222222222222222222222222222222","providerIdentityCommitment":"1111111111111111111111111111111111111111111111111111111111111111","providerRevision":1,"stateVerificationPublicKeyDigest":"f156757c29b06e139f85f758a95e6819536ac887631d395782ce5797516e159b","stateVerificationPublicKeySpkiPem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2gR9n1Vv6T6g9gxucZyyi2dKXr0/TYBVlC6V6dH3v8A=\n-----END PUBLIC KEY-----\n","supervisorArtifactDigest":"5555555555555555555555555555555555555555555555555555555555555555","supervisorReady":false,"version":1}`

type terminalXExecAPIClient struct {
	client.APIClient

	boundary *terminalXRootBoundaryAPIClient
	inspect  container.InspectResponse

	blockFirstInspect bool
	inspectEntered    chan struct{}
	inspectRelease    chan struct{}
	inspectOnce       sync.Once
	inspectCalls      atomic.Int64

	attach func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error)

	execInspect   func(context.Context, string) (container.ExecInspect, error)
	containerKill func(context.Context, string, string) error
	containerList func(context.Context, container.ListOptions) ([]container.Summary, error)

	mu                     sync.Mutex
	inspectRequestedIDs    []string
	execCreateContainerIDs []string
	execCreateOptions      []container.ExecOptions
	execAttachIDs          []string
	killedContainerIDs     []string
}

func (fake *terminalXExecAPIClient) ContainerInspect(
	ctx context.Context,
	containerID string,
) (container.InspectResponse, error) {
	call := fake.inspectCalls.Add(1)
	fake.mu.Lock()
	fake.inspectRequestedIDs = append(fake.inspectRequestedIDs, containerID)
	fake.mu.Unlock()
	if fake.blockFirstInspect && call == 1 {
		fake.inspectOnce.Do(func() { close(fake.inspectEntered) })
		select {
		case <-fake.inspectRelease:
		case <-ctx.Done():
			return container.InspectResponse{}, ctx.Err()
		}
	}
	return fake.inspect, nil
}

func (fake *terminalXExecAPIClient) CopyFromContainer(
	ctx context.Context,
	containerID string,
	sourcePath string,
) (io.ReadCloser, container.PathStat, error) {
	return fake.boundary.CopyFromContainer(ctx, containerID, sourcePath)
}

func (fake *terminalXExecAPIClient) ContainerExecCreate(
	_ context.Context,
	containerID string,
	options container.ExecOptions,
) (container.ExecCreateResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.execCreateContainerIDs = append(fake.execCreateContainerIDs, containerID)
	fake.execCreateOptions = append(fake.execCreateOptions, options)
	return container.ExecCreateResponse{ID: fmt.Sprintf("exec-%d", len(fake.execCreateContainerIDs))}, nil
}

func (fake *terminalXExecAPIClient) ContainerExecAttach(
	ctx context.Context,
	execID string,
	options container.ExecAttachOptions,
) (types.HijackedResponse, error) {
	fake.mu.Lock()
	fake.execAttachIDs = append(fake.execAttachIDs, execID)
	fake.mu.Unlock()
	if fake.attach == nil {
		return types.HijackedResponse{}, errors.New("unexpected terminalx test attachment")
	}
	return fake.attach(ctx, execID, options)
}

func (fake *terminalXExecAPIClient) ContainerExecInspect(
	ctx context.Context,
	execID string,
) (container.ExecInspect, error) {
	if fake.execInspect != nil {
		return fake.execInspect(ctx, execID)
	}
	return container.ExecInspect{Running: false, ExitCode: 0}, nil
}

func (fake *terminalXExecAPIClient) ContainerKill(
	ctx context.Context,
	containerID string,
	signal string,
) error {
	fake.mu.Lock()
	fake.killedContainerIDs = append(fake.killedContainerIDs, containerID)
	fake.mu.Unlock()
	if fake.containerKill != nil {
		return fake.containerKill(ctx, containerID, signal)
	}
	return nil
}

func (fake *terminalXExecAPIClient) ContainerList(
	ctx context.Context,
	options container.ListOptions,
) ([]container.Summary, error) {
	if fake.containerList != nil {
		return fake.containerList(ctx, options)
	}
	return nil, nil
}

type terminalXObservingConn struct {
	net.Conn

	mu       sync.Mutex
	retained []byte
}

func (conn *terminalXObservingConn) Write(value []byte) (int, error) {
	written, err := conn.Conn.Write(value)
	conn.mu.Lock()
	conn.retained = value
	conn.mu.Unlock()
	return written, err
}

func (conn *terminalXObservingConn) retainedBytes() []byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return bytes.Clone(conn.retained)
}

func terminalXRootExecHarness(t *testing.T) (*DockerClient, *terminalXExecAPIClient, string) {
	t.Helper()
	dockerClient, inspected := terminalXContainerForTest(t)
	inspected.State = &container.State{Running: true}
	nodePayload := []byte("terminalx-test-node")
	relayPayload := []byte("terminalx-test-supervisor-relay")
	bootstrapPayload := []byte("terminalx-test-assignment-bootstrap")
	dockerClient.terminalXNodeSHA256 = terminalXTestSHA256(nodePayload)
	dockerClient.terminalXSupervisorRelaySHA256 = terminalXTestSHA256(relayPayload)
	dockerClient.terminalXAssignmentBootstrapSHA256 = terminalXTestSHA256(bootstrapPayload)
	inspected.Config.Labels[terminalXNodeDigestLabel] = dockerClient.terminalXNodeSHA256
	inspected.Config.Labels[terminalXSupervisorRelayDigestLabel] = dockerClient.terminalXSupervisorRelaySHA256
	inspected.Config.Labels[terminalXAssignmentBootstrapDigestLabel] = dockerClient.terminalXAssignmentBootstrapSHA256
	fake := &terminalXExecAPIClient{
		boundary: &terminalXRootBoundaryAPIClient{payloads: map[string][]byte{
			terminalXNodePath:                nodePayload,
			terminalXSupervisorRelayPath:     relayPayload,
			terminalXAssignmentBootstrapPath: bootstrapPayload,
		}},
		inspect: *inspected,
	}
	dockerClient.apiClient = fake
	dockerClient.terminalXNetworkPolicyEnforcer = func(_ context.Context, candidate *container.InspectResponse) error {
		if candidate == nil || candidate.ID != inspected.ID {
			return fmt.Errorf("network policy received a non-canonical sandbox")
		}
		return nil
	}
	dockerClient.terminalXAssignmentBootstrapPreflight = func(
		context.Context,
		[]byte,
		*container.InspectResponse,
	) (*terminalXAssignmentEvidenceConfiguration, error) {
		return nil, nil
	}
	dockerClient.terminalXSupervisorRelayPreflight = func(
		_ context.Context,
		input []byte,
		_ *container.InspectResponse,
	) ([]byte, error) {
		return bytes.Clone(input), nil
	}
	return dockerClient, fake, inspected.ID
}

func terminalXWaitForSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func terminalXRequireAllZero(t *testing.T, value []byte) {
	t.Helper()
	if len(value) == 0 {
		t.Fatal("test connection did not retain the root-exec input")
	}
	for index, element := range value {
		if element != 0 {
			t.Fatalf("owned root-exec input was not zeroed at byte %d: %x", index, value)
		}
	}
}

func terminalXRequireLimiterEmpty(t *testing.T, limiter *terminalXOperationLimiter) {
	t.Helper()
	limiter.mu.Lock()
	global := limiter.global
	sandboxes := len(limiter.bySandbox)
	limiter.mu.Unlock()
	if global != 0 || sandboxes != 0 {
		t.Fatalf("root-exec admission leaked: global=%d sandboxes=%d", global, sandboxes)
	}
}

func TestTerminalXRootExecNetworkPolicySeamDefaultsToProductionEnforcement(t *testing.T) {
	t.Parallel()
	dockerClient := &DockerClient{}
	if err := dockerClient.enforceTerminalXRootExecNetworkPolicy(t.Context(), &container.InspectResponse{}); err == nil ||
		!strings.Contains(err.Error(), "inspection is unavailable") {
		t.Fatalf("nil seam did not use production enforcement: %v", err)
	}
	want := errors.New("injected network policy")
	dockerClient.terminalXNetworkPolicyEnforcer = func(context.Context, *container.InspectResponse) error {
		return want
	}
	if err := dockerClient.enforceTerminalXRootExecNetworkPolicy(t.Context(), nil); !errors.Is(err, want) {
		t.Fatalf("injected network policy error = %v, want %v", err, want)
	}
}

func TestTerminalXRootExecAdmissionUsesCanonicalIDAndRejectsBeforeExecCreate(t *testing.T) {
	t.Run("assignment bootstrap", func(t *testing.T) {
		dockerClient, fake, canonicalID := terminalXRootExecHarness(t)
		release, ok := dockerClient.terminalXAssignmentBootstrapAdmission.acquire(
			canonicalID,
			terminalXAssignmentBootstrapMaximumPerSandbox,
			terminalXAssignmentBootstrapMaximumGlobal,
		)
		if !ok {
			t.Fatal("could not occupy bootstrap admission slot")
		}
		defer release()
		if _, err := dockerClient.RunTerminalXAssignmentBootstrap(t.Context(), "caller-alias", []byte("envelope")); !errors.Is(err, ErrTerminalXAssignmentBootstrapUnavailable) {
			t.Fatalf("bootstrap admission error = %v", err)
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if len(fake.execCreateContainerIDs) != 0 || len(fake.boundary.paths) != 0 {
			t.Fatalf("bootstrap passed admission before exec: exec=%v paths=%v", fake.execCreateContainerIDs, fake.boundary.paths)
		}
	})

	t.Run("supervisor relay", func(t *testing.T) {
		dockerClient, fake, canonicalID := terminalXRootExecHarness(t)
		releases := make([]func(), 0, terminalXSupervisorRelayMaximumPerSandbox)
		for index := 0; index < terminalXSupervisorRelayMaximumPerSandbox; index++ {
			release, ok := dockerClient.terminalXSupervisorRelayAdmission.acquire(
				canonicalID,
				terminalXSupervisorRelayMaximumPerSandbox,
				terminalXSupervisorRelayMaximumGlobal,
			)
			if !ok {
				t.Fatalf("could not occupy relay admission slot %d", index)
			}
			releases = append(releases, release)
		}
		defer func() {
			for _, release := range releases {
				release()
			}
		}()
		if stream, err := dockerClient.OpenTerminalXSupervisorRelay(t.Context(), "caller-alias", []byte("framed")); err == nil {
			_ = stream.Close()
			t.Fatal("relay bypassed canonical admission cap")
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if len(fake.execCreateContainerIDs) != 0 || len(fake.boundary.paths) != 0 {
			t.Fatalf("relay passed admission before exec: exec=%v paths=%v", fake.execCreateContainerIDs, fake.boundary.paths)
		}
	})
}

func TestOpenTerminalXSupervisorRelayClonesBeforeInspectionAndZerosOwnedInput(t *testing.T) {
	dockerClient, fake, canonicalID := terminalXRootExecHarness(t)
	fake.blockFirstInspect = true
	fake.inspectEntered = make(chan struct{})
	fake.inspectRelease = make(chan struct{})
	clientSide, serverSide := net.Pipe()
	observed := &terminalXObservingConn{Conn: clientSide}
	fake.attach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
		return types.NewHijackedResponse(observed, "application/vnd.docker.raw-stream"), nil
	}

	original := []byte("framed-original")
	callerInput := bytes.Clone(original)
	captured := make(chan []byte, 1)
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		defer serverSide.Close()
		request := make([]byte, len(original))
		if _, err := io.ReadFull(serverSide, request); err != nil {
			captured <- nil
			return
		}
		captured <- request
		_, _ = stdcopy.NewStdWriter(serverSide, stdcopy.Stdout).Write([]byte("relay-ok"))
	}()

	type result struct {
		stream io.ReadCloser
		err    error
	}
	opened := make(chan result, 1)
	go func() {
		stream, err := dockerClient.OpenTerminalXSupervisorRelay(t.Context(), "caller-alias", callerInput)
		opened <- result{stream: stream, err: err}
	}()
	terminalXWaitForSignal(t, fake.inspectEntered, "relay inspection")
	for index := range callerInput {
		callerInput[index] = 'x'
	}
	close(fake.inspectRelease)
	openResult := <-opened
	if openResult.err != nil {
		t.Fatalf("open relay: %v", openResult.err)
	}
	output, err := io.ReadAll(openResult.stream)
	if err != nil || string(output) != "relay-ok" {
		t.Fatalf("relay output = %q, err = %v", output, err)
	}
	if err := openResult.stream.Close(); err != nil {
		t.Fatalf("close relay: %v", err)
	}
	terminalXWaitForSignal(t, remoteDone, "relay peer completion")
	if got := <-captured; !bytes.Equal(got, original) {
		t.Fatalf("relay wrote caller-mutated input: got %q want %q", got, original)
	}
	if !bytes.Equal(callerInput, bytes.Repeat([]byte{'x'}, len(callerInput))) {
		t.Fatalf("relay modified caller-owned input: %q", callerInput)
	}
	terminalXRequireAllZero(t, observed.retainedBytes())
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.execCreateContainerIDs) != 1 || fake.execCreateContainerIDs[0] != canonicalID {
		t.Fatalf("relay exec used %v, want canonical %s", fake.execCreateContainerIDs, canonicalID)
	}
}

func TestRunTerminalXAssignmentBootstrapClonesBeforeInspectionAndZerosOwnedInput(t *testing.T) {
	dockerClient, fake, canonicalID := terminalXRootExecHarness(t)
	fake.blockFirstInspect = true
	fake.inspectEntered = make(chan struct{})
	fake.inspectRelease = make(chan struct{})
	clientSide, serverSide := net.Pipe()
	observed := &terminalXObservingConn{Conn: clientSide}
	fake.attach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
		return types.NewHijackedResponse(observed, "application/vnd.docker.raw-stream"), nil
	}

	original := []byte("bootstrap-original")
	callerInput := bytes.Clone(original)
	captured := make(chan []byte, 1)
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		defer serverSide.Close()
		request := make([]byte, len(original))
		if _, err := io.ReadFull(serverSide, request); err != nil {
			captured <- nil
			return
		}
		captured <- request
		_, _ = stdcopy.NewStdWriter(serverSide, stdcopy.Stdout).Write([]byte(terminalXTestInstalledDescriptor))
	}()

	type result struct {
		response []byte
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		response, err := dockerClient.RunTerminalXAssignmentBootstrap(t.Context(), "caller-alias", callerInput)
		completed <- result{response: response, err: err}
	}()
	terminalXWaitForSignal(t, fake.inspectEntered, "bootstrap inspection")
	for index := range callerInput {
		callerInput[index] = 'y'
	}
	close(fake.inspectRelease)
	bootstrapResult := <-completed
	if bootstrapResult.err != nil || string(bootstrapResult.response) != terminalXTestInstalledDescriptor {
		t.Fatalf("bootstrap response = %q, err = %v", bootstrapResult.response, bootstrapResult.err)
	}
	terminalXWaitForSignal(t, remoteDone, "bootstrap peer completion")
	if got := <-captured; !bytes.Equal(got, original) {
		t.Fatalf("bootstrap wrote caller-mutated input: got %q want %q", got, original)
	}
	if !bytes.Equal(callerInput, bytes.Repeat([]byte{'y'}, len(callerInput))) {
		t.Fatalf("bootstrap modified caller-owned input: %q", callerInput)
	}
	terminalXRequireAllZero(t, observed.retainedBytes())
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.execCreateContainerIDs) != 1 || fake.execCreateContainerIDs[0] != canonicalID {
		t.Fatalf("bootstrap exec used %v, want canonical %s", fake.execCreateContainerIDs, canonicalID)
	}
}

func TestOpenTerminalXSupervisorRelayCloseUnblocksPipesAndWaitsForWorkers(t *testing.T) {
	dockerClient, fake, _ := terminalXRootExecHarness(t)
	clientSide, serverSide := net.Pipe()
	observed := &terminalXObservingConn{Conn: clientSide}
	fake.attach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
		return types.NewHijackedResponse(observed, "application/vnd.docker.raw-stream"), nil
	}
	outputSent := make(chan struct{})
	releasePeer := make(chan struct{})
	peerDone := make(chan struct{})
	var releasePeerOnce sync.Once
	release := func() { releasePeerOnce.Do(func() { close(releasePeer) }) }
	t.Cleanup(release)
	go func() {
		defer close(peerDone)
		defer serverSide.Close()
		_, _ = stdcopy.NewStdWriter(serverSide, stdcopy.Stdout).Write([]byte("blocked-output"))
		close(outputSent)
		<-releasePeer
	}()
	inspectEntered := make(chan struct{})
	inspectRelease := make(chan struct{})
	var inspectOnce sync.Once
	fake.execInspect = func(context.Context, string) (container.ExecInspect, error) {
		inspectOnce.Do(func() { close(inspectEntered) })
		<-inspectRelease
		return container.ExecInspect{Running: false, ExitCode: 0}, nil
	}

	stream, err := dockerClient.OpenTerminalXSupervisorRelay(t.Context(), "sandbox-alias", []byte("blocked-frame"))
	if err != nil {
		t.Fatalf("open blocked relay: %v", err)
	}
	terminalXWaitForSignal(t, outputSent, "relay output pipe blockage")
	closed := make(chan error, 1)
	go func() { closed <- stream.Close() }()
	terminalXWaitForSignal(t, inspectEntered, "relay worker exit inspection")
	select {
	case err := <-closed:
		t.Fatalf("relay Close returned before output worker: %v", err)
	default:
	}
	close(inspectRelease)
	select {
	case err := <-closed:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("relay close did not return its worker cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay Close did not unblock blocked input/output pipes")
	}
	release()
	terminalXWaitForSignal(t, peerDone, "blocked relay peer completion")
	terminalXRequireAllZero(t, observed.retainedBytes())
	terminalXRequireLimiterEmpty(t, &dockerClient.terminalXSupervisorRelayAdmission)
}

func TestOpenTerminalXSupervisorRelayCloseReturnsWorkerCleanupAndQuarantineErrors(t *testing.T) {
	dockerClient, fake, _ := terminalXRootExecHarness(t)
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	fake.attach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
		return types.NewHijackedResponse(clientSide, "application/vnd.docker.raw-stream"), nil
	}
	fake.execInspect = func(context.Context, string) (container.ExecInspect, error) {
		return container.ExecInspect{Running: true}, nil
	}
	fake.containerKill = func(context.Context, string, string) error {
		return errors.New("forced sandbox kill failure")
	}
	fake.containerList = func(context.Context, container.ListOptions) ([]container.Summary, error) {
		return nil, errors.New("forced quarantine list failure")
	}

	stream, err := dockerClient.OpenTerminalXSupervisorRelay(t.Context(), "sandbox-alias", []byte("blocked-frame"))
	if err != nil {
		t.Fatalf("open relay: %v", err)
	}
	closeErr := stream.Close()
	for _, expected := range []string{
		"fixed root exec termination was not observed",
		"forced sandbox kill failure",
		"forced quarantine list failure",
	} {
		if closeErr == nil || !strings.Contains(closeErr.Error(), expected) {
			t.Fatalf("relay Close error %q does not contain %q", closeErr, expected)
		}
	}
	terminalXRequireLimiterEmpty(t, &dockerClient.terminalXSupervisorRelayAdmission)
}

func TestRunTerminalXAssignmentBootstrapCancellationUnblocksPipesAndWorkers(t *testing.T) {
	dockerClient, fake, _ := terminalXRootExecHarness(t)
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	observed := &terminalXObservingConn{Conn: clientSide}
	fake.attach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
		return types.NewHijackedResponse(observed, "application/vnd.docker.raw-stream"), nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	completed := make(chan error, 1)
	callerInput := []byte("blocked-bootstrap")
	go func() {
		_, err := dockerClient.RunTerminalXAssignmentBootstrap(ctx, "sandbox-alias", callerInput)
		completed <- err
	}()
	deadline := time.After(2 * time.Second)
	for {
		fake.mu.Lock()
		attached := len(fake.execAttachIDs) == 1
		fake.mu.Unlock()
		if attached {
			break
		}
		select {
		case <-deadline:
			t.Fatal("bootstrap did not attach")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-completed:
		if !errors.Is(err, ErrTerminalXAssignmentBootstrapUnavailable) {
			t.Fatalf("bootstrap cancellation error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bootstrap cancellation did not unblock input/output workers")
	}
	if string(callerInput) != "blocked-bootstrap" {
		t.Fatalf("bootstrap cancellation modified caller input: %q", callerInput)
	}
	terminalXRequireAllZero(t, observed.retainedBytes())
	terminalXRequireLimiterEmpty(t, &dockerClient.terminalXAssignmentBootstrapAdmission)
}

func TestTerminalXAssignmentBootstrapMapsOnlyFixedNonzeroExits(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		want     error
	}{
		{name: "usage", exitCode: 64, want: ErrTerminalXAssignmentBootstrapInvalid},
		{name: "conflict", exitCode: 73, want: ErrTerminalXAssignmentBootstrapConflict},
		{name: "unexpected", exitCode: 1, want: ErrTerminalXAssignmentBootstrapUnavailable},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			dockerClient, fake, _ := terminalXRootExecHarness(t)
			clientSide, serverSide := net.Pipe()
			fake.attach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
				return types.NewHijackedResponse(clientSide, "application/vnd.docker.raw-stream"), nil
			}
			fake.execInspect = func(context.Context, string) (container.ExecInspect, error) {
				return container.ExecInspect{Running: false, ExitCode: test.exitCode}, nil
			}
			remoteDone := make(chan struct{})
			go func() {
				defer close(remoteDone)
				defer serverSide.Close()
				request := make([]byte, len("envelope"))
				_, _ = io.ReadFull(serverSide, request)
			}()
			response, err := dockerClient.RunTerminalXAssignmentBootstrap(t.Context(), "sandbox-alias", []byte("envelope"))
			terminalXWaitForSignal(t, remoteDone, "bootstrap error peer completion")
			if len(response) != 0 || !errors.Is(err, test.want) {
				t.Fatalf("exit %d response=%q err=%v, want %v", test.exitCode, response, err, test.want)
			}
		})
	}
}

func TestTerminalXAssignmentBootstrapMapsReplayStateFailureToUnavailable(t *testing.T) {
	dockerClient, fake, _ := terminalXRootExecHarness(t)
	dockerClient.terminalXAssignmentBootstrapPreflight = func(
		context.Context,
		[]byte,
		*container.InspectResponse,
	) (*terminalXAssignmentEvidenceConfiguration, error) {
		return nil, errTerminalXBootstrapReplayStateUnavailable
	}
	callerInput := []byte("expired-envelope")
	response, err := dockerClient.RunTerminalXAssignmentBootstrap(
		t.Context(),
		"sandbox-alias",
		callerInput,
	)
	if len(response) != 0 || !errors.Is(err, ErrTerminalXAssignmentBootstrapUnavailable) ||
		errors.Is(err, ErrTerminalXAssignmentBootstrapInvalid) ||
		!errors.Is(err, errTerminalXBootstrapReplayStateUnavailable) {
		t.Fatalf("replay-state response=%q err=%v", response, err)
	}
	if string(callerInput) != "expired-envelope" {
		t.Fatal("replay-state failure modified caller input")
	}
	fake.mu.Lock()
	attachments := len(fake.execAttachIDs)
	fake.mu.Unlock()
	if attachments != 0 {
		t.Fatal("replay-state failure reached the root bootstrap executable")
	}
	terminalXRequireLimiterEmpty(t, &dockerClient.terminalXAssignmentBootstrapAdmission)
}

func TestOpenTerminalXSupervisorRelayRejectsNonzeroExitThroughStream(t *testing.T) {
	dockerClient, fake, _ := terminalXRootExecHarness(t)
	clientSide, serverSide := net.Pipe()
	fake.attach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
		return types.NewHijackedResponse(clientSide, "application/vnd.docker.raw-stream"), nil
	}
	fake.execInspect = func(context.Context, string) (container.ExecInspect, error) {
		return container.ExecInspect{Running: false, ExitCode: 9}, nil
	}
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		defer serverSide.Close()
		request := make([]byte, len("framed"))
		_, _ = io.ReadFull(serverSide, request)
	}()
	stream, err := dockerClient.OpenTerminalXSupervisorRelay(t.Context(), "sandbox-alias", []byte("framed"))
	if err != nil {
		t.Fatalf("open relay: %v", err)
	}
	_, readErr := io.ReadAll(stream)
	if readErr == nil || !strings.Contains(readErr.Error(), "exited unsuccessfully") {
		t.Fatalf("relay nonzero read error = %v", readErr)
	}
	_ = stream.Close()
	terminalXWaitForSignal(t, remoteDone, "relay error peer completion")
}

func TestTerminalXRootExecAttachmentFailureCleansCanonicalExecAndAdmission(t *testing.T) {
	for _, operation := range []string{"bootstrap", "relay"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			dockerClient, fake, canonicalID := terminalXRootExecHarness(t)
			fake.attach = func(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
				return types.HijackedResponse{}, errors.New("attach failed")
			}
			var killed atomic.Bool
			fake.execInspect = func(context.Context, string) (container.ExecInspect, error) {
				return container.ExecInspect{Running: !killed.Load()}, nil
			}
			fake.containerKill = func(_ context.Context, gotContainerID string, signal string) error {
				if gotContainerID != canonicalID || signal != "KILL" {
					return fmt.Errorf("cleanup kill = %s %s", gotContainerID, signal)
				}
				killed.Store(true)
				return nil
			}

			if operation == "bootstrap" {
				_, _ = dockerClient.RunTerminalXAssignmentBootstrap(t.Context(), "caller-alias", []byte("envelope"))
				terminalXRequireLimiterEmpty(t, &dockerClient.terminalXAssignmentBootstrapAdmission)
			} else {
				_, _ = dockerClient.OpenTerminalXSupervisorRelay(t.Context(), "caller-alias", []byte("framed"))
				terminalXRequireLimiterEmpty(t, &dockerClient.terminalXSupervisorRelayAdmission)
			}
			if !killed.Load() {
				t.Fatal("attachment failure did not terminate orphaned root exec")
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if len(fake.killedContainerIDs) != 1 || fake.killedContainerIDs[0] != canonicalID {
				t.Fatalf("attachment cleanup used %v, want canonical %s", fake.killedContainerIDs, canonicalID)
			}
		})
	}
}
