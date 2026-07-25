// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	terminalXAssignmentBootstrapMaximumArtifactBytes int64  = 16 * 1024 * 1024
	terminalXAssignmentBootstrapMaximumRequestBytes  int64  = 3 * 1024 * 1024
	terminalXAssignmentBootstrapMaximumResponseBytes int64  = 64 * 1024
	terminalXAssignmentBootstrapMaximumStderrBytes   int64  = 4 * 1024
	terminalXAssignmentBootstrapTimeout                     = 30 * time.Second
	terminalXJavaScriptMaximumSafeInteger            uint64 = 9_007_199_254_740_991
)

var terminalXPublicReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

var (
	// ErrTerminalXAssignmentBootstrapInvalid maps only the provisioner's
	// deliberately fixed EX_USAGE exit to a generic HTTP 400 response.
	ErrTerminalXAssignmentBootstrapInvalid = errors.New("terminalx assignment bootstrap is invalid")
	// ErrTerminalXAssignmentBootstrapConflict maps only the provisioner's
	// deliberately fixed EX_CANTCREAT exit to a generic HTTP 409 response.
	ErrTerminalXAssignmentBootstrapConflict = errors.New("terminalx assignment bootstrap conflicts")
	// ErrTerminalXAssignmentBootstrapUnavailable covers every runner, Docker,
	// artifact, timeout, output, and unexpected-exit failure.
	ErrTerminalXAssignmentBootstrapUnavailable = errors.New("terminalx assignment bootstrap is unavailable")
)

// RunTerminalXAssignmentBootstrap invokes only the digest-pinned, root-owned
// assignment provisioner. The caller controls the bounded binary envelope and
// no exec metadata. It returns only the provisioner's bounded public descriptor.
func (d *DockerClient) RunTerminalXAssignmentBootstrap(
	ctx context.Context,
	containerID string,
	input []byte,
) (response []byte, returnErr error) {
	if !d.terminalXHardened {
		return nil, ErrTerminalXAssignmentBootstrapUnavailable
	}
	if len(input) == 0 || int64(len(input)) > terminalXAssignmentBootstrapMaximumRequestBytes {
		return nil, ErrTerminalXAssignmentBootstrapInvalid
	}
	ownedInput := bytes.Clone(input)
	inputOwnedByWorker := false
	defer func() {
		if !inputOwnedByWorker {
			wipeTerminalXRootExecInput(ownedInput)
		}
	}()

	execCtx, cancel := context.WithTimeout(ctx, terminalXAssignmentBootstrapTimeout)
	defer cancel()
	inspected, err := d.ContainerInspect(execCtx, containerID)
	if err != nil || inspected.State == nil || !inspected.State.Running {
		return nil, fmt.Errorf("%w: sandbox validation failed", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	releaseAdmission, admitted := d.terminalXAssignmentBootstrapAdmission.acquire(
		inspected.ID,
		terminalXAssignmentBootstrapMaximumPerSandbox,
		terminalXAssignmentBootstrapMaximumGlobal,
	)
	if !admitted {
		return nil, fmt.Errorf("%w: operation capacity exhausted", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	defer releaseAdmission()
	if err := d.enforceTerminalXRootExecNetworkPolicy(execCtx, inspected); err != nil {
		return nil, fmt.Errorf("%w: network validation failed", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	if err := d.verifyTerminalXAssignmentBootstrap(execCtx, inspected.ID); err != nil {
		return nil, fmt.Errorf("%w: artifact validation failed", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	configuration, err := d.prepareTerminalXAssignmentBootstrap(execCtx, ownedInput, inspected)
	if err != nil {
		if errors.Is(err, errTerminalXDeploymentBindingConflict) {
			return nil, ErrTerminalXAssignmentBootstrapConflict
		}
		if errors.Is(err, ErrTerminalXAssignmentBootstrapInvalid) {
			return nil, ErrTerminalXAssignmentBootstrapInvalid
		}
		if errors.Is(err, errTerminalXBootstrapReplayStateUnavailable) {
			return nil, errors.Join(
				ErrTerminalXAssignmentBootstrapUnavailable,
				errTerminalXBootstrapReplayStateUnavailable,
			)
		}
		return nil, fmt.Errorf("%w: deployment validation failed", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	if configuration != nil {
		defer configuration.Close()
	}

	execResponse, err := d.apiClient.ContainerExecCreate(execCtx, inspected.ID, terminalXAssignmentBootstrapExecOptions())
	if err != nil {
		return nil, fmt.Errorf("%w: exec creation failed", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	attached, err := d.apiClient.ContainerExecAttach(execCtx, execResponse.ID, container.ExecStartOptions{
		Detach: false,
		Tty:    false,
	})
	if err != nil {
		cleanupErr := d.ensureTerminalXExecTerminated(inspected.ID, execResponse.ID)
		return nil, errors.Join(
			fmt.Errorf("%w: exec attachment failed", ErrTerminalXAssignmentBootstrapUnavailable),
			cleanupErr,
		)
	}

	var closeOnce sync.Once
	closeAttached := func() { closeOnce.Do(func() { attached.Close() }) }
	stopCancellationClose := context.AfterFunc(execCtx, closeAttached)
	execTerminated := false
	defer func() {
		stopCancellationClose()
		closeAttached()
		if !execTerminated {
			returnErr = errors.Join(
				returnErr,
				d.ensureTerminalXExecTerminated(inspected.ID, execResponse.ID),
			)
		}
	}()

	requestDone := make(chan error, 1)
	inputOwnedByWorker = true
	go func(request []byte) {
		_, copyErr := io.Copy(attached.Conn, bytes.NewReader(request))
		requestErr := errors.Join(copyErr, attached.CloseWrite())
		wipeTerminalXRootExecInput(request)
		requestDone <- requestErr
	}(ownedInput)

	stdout := &terminalXBoundedBuffer{maximumBytes: terminalXAssignmentBootstrapMaximumResponseBytes}
	stderr := &terminalXBoundedBuffer{maximumBytes: terminalXAssignmentBootstrapMaximumStderrBytes}
	defer stdout.Zero()
	defer stderr.Zero()
	_, outputErr := stdcopy.StdCopy(stdout, stderr, attached.Reader)
	if outputErr != nil || execCtx.Err() != nil {
		closeAttached()
	}
	requestErr := <-requestDone
	if execCtx.Err() != nil {
		return nil, fmt.Errorf("%w: provisioner transport failed", ErrTerminalXAssignmentBootstrapUnavailable)
	}

	inspect, err := d.apiClient.ContainerExecInspect(execCtx, execResponse.ID)
	if err != nil || inspect.Running {
		return nil, fmt.Errorf("%w: exit status unavailable", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	execTerminated = true
	if inspect.ExitCode != 0 {
		if outputErr != nil || stdout.Len() != 0 {
			return nil, fmt.Errorf("%w: invalid error output", ErrTerminalXAssignmentBootstrapUnavailable)
		}
		switch inspect.ExitCode {
		case 64:
			return nil, ErrTerminalXAssignmentBootstrapInvalid
		case 73:
			return nil, ErrTerminalXAssignmentBootstrapConflict
		default:
			return nil, fmt.Errorf("%w: provisioner exited unsuccessfully", ErrTerminalXAssignmentBootstrapUnavailable)
		}
	}
	if errors.Join(requestErr, outputErr) != nil {
		return nil, fmt.Errorf("%w: provisioner transport failed", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	if stderr.Len() != 0 || !validTerminalXAssignmentBootstrapResponse(stdout.Bytes()) ||
		configuration != nil && !terminalXAssignmentBootstrapResponseMatches(stdout.Bytes(), configuration) {
		return nil, fmt.Errorf("%w: public descriptor is invalid", ErrTerminalXAssignmentBootstrapUnavailable)
	}
	return bytes.Clone(stdout.Bytes()), nil
}

type terminalXAssignmentBootstrapPreflight func(
	context.Context,
	[]byte,
	*container.InspectResponse,
) (*terminalXAssignmentEvidenceConfiguration, error)

func (d *DockerClient) prepareTerminalXAssignmentBootstrap(
	ctx context.Context,
	input []byte,
	inspected *container.InspectResponse,
) (*terminalXAssignmentEvidenceConfiguration, error) {
	if d.terminalXAssignmentBootstrapPreflight != nil {
		return d.terminalXAssignmentBootstrapPreflight(ctx, input, inspected)
	}
	configuration, err := d.verifyAndCaptureTerminalXBootstrapEnvelope(ctx, input, inspected)
	if err != nil {
		if errors.Is(err, errTerminalXBootstrapReplayStateUnavailable) {
			return nil, errors.Join(ErrTerminalXAssignmentBootstrapUnavailable, err)
		}
		return nil, errors.Join(ErrTerminalXAssignmentBootstrapInvalid, err)
	}
	clock := d.terminalXClock
	if clock == nil {
		clock = time.Now
	}
	deploymentBinding, err := createTerminalXDeploymentBinding(
		d.terminalXDeploymentBindingSigner,
		terminalXDeploymentBindingClaims{
			ExpectedSandboxImageID:     inspected.Image,
			ExpectedSandboxSnapshotRef: d.terminalXSandboxSnapshotRef,
			Kind:                       terminalXDeploymentBindingKind,
			ProviderRevision:           configuration.Assignment.ExpectedRevision,
			ProviderSandboxID:          configuration.Assignment.ProviderSandboxID,
			SandboxArtifactDigest:      d.terminalXSandboxArtifactDigest,
			Version:                    1,
		},
		clock(),
		d.terminalXEvidenceTTL,
	)
	if err != nil {
		configuration.Close()
		return nil, errors.Join(ErrTerminalXAssignmentBootstrapUnavailable, err)
	}
	if err := d.installTerminalXDeploymentBinding(ctx, inspected.ID, deploymentBinding); err != nil {
		configuration.Close()
		if errors.Is(err, errTerminalXDeploymentBindingConflict) {
			return nil, err
		}
		return nil, errors.Join(ErrTerminalXAssignmentBootstrapUnavailable, err)
	}
	return configuration, nil
}

func terminalXAssignmentBootstrapResponseMatches(
	response []byte,
	configuration *terminalXAssignmentEvidenceConfiguration,
) bool {
	if configuration == nil {
		return false
	}
	var descriptor terminalXAssignmentBootstrapInstalledDescriptor
	if json.Unmarshal(response, &descriptor) != nil {
		return false
	}
	providerDigest := sha256.Sum256([]byte(
		"terminalx/daytona-provider-identity/v1\x00" + configuration.Assignment.ProviderSandboxID,
	))
	observationDigest := sha256.Sum256([]byte(configuration.Plan.Observation.PublicKeySPKIPEM))
	bindingHash := sha256.New()
	_, _ = bindingHash.Write([]byte("terminalx/daytona-bootstrap-binding/v1\x00"))
	_, _ = bindingHash.Write(configuration.Plan.Binding)
	return descriptor.ProviderRevision == configuration.Assignment.ExpectedRevision &&
		descriptor.PlanDigest == configuration.PlanDigest &&
		descriptor.AssignmentPlanDigest == configuration.PlanDigest &&
		descriptor.EffectEnforcerPolicyDigest == configuration.Plan.EffectEnforcerPolicyDigest &&
		descriptor.EffectManifestBindingDigest == configuration.Effect.Manifest.EffectManifestBindingDigest &&
		descriptor.EffectEnforcerSetDigest == configuration.Assignment.EffectEnforcerSetDigest &&
		descriptor.ProviderIdentityCommitment == hex.EncodeToString(providerDigest[:]) &&
		descriptor.ObservationIssuerKeyID == configuration.Plan.Observation.IssuerKeyID &&
		descriptor.ObservationPublicKeyDigest == hex.EncodeToString(observationDigest[:]) &&
		descriptor.BindingDigest == hex.EncodeToString(bindingHash.Sum(nil)) &&
		descriptor.EnvelopeDigest == configuration.EnvelopeDigest &&
		descriptor.SupervisorArtifactDigest == configuration.Assignment.SupervisorArtifactDigest
}

func terminalXAssignmentBootstrapExecOptions() container.ExecOptions {
	return container.ExecOptions{
		User:         "0:0",
		Privileged:   false,
		Tty:          false,
		AttachStdin:  true,
		AttachStderr: true,
		AttachStdout: true,
		WorkingDir:   "/",
		Cmd:          []string{terminalXAssignmentBootstrapPath},
	}
}

func (d *DockerClient) verifyTerminalXAssignmentBootstrap(ctx context.Context, containerID string) error {
	return d.verifyTerminalXRootExecutionBoundary(
		ctx,
		containerID,
		terminalXAssignmentBootstrapPath,
		terminalXAssignmentBootstrapMaximumArtifactBytes,
		d.terminalXAssignmentBootstrapSHA256,
	)
}

func verifyTerminalXAssignmentBootstrapArchive(
	archive io.Reader,
	stat container.PathStat,
	expectedSHA256 string,
) error {
	return verifyTerminalXRootExecutableArchive(
		archive,
		stat,
		terminalXAssignmentBootstrapPath,
		terminalXAssignmentBootstrapMaximumArtifactBytes,
		expectedSHA256,
	)
}

func validTerminalXAssignmentBootstrapResponse(value []byte) bool {
	if len(value) < 2 || int64(len(value)) > terminalXAssignmentBootstrapMaximumResponseBytes ||
		value[0] != '{' || value[len(value)-1] != '}' || !json.Valid(value) {
		return false
	}
	var descriptor terminalXAssignmentBootstrapInstalledDescriptor
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return false
	}
	canonical, err := json.Marshal(descriptor)
	if err != nil || !bytes.Equal(canonical, value) {
		return false
	}
	if descriptor.Version != 1 ||
		descriptor.Kind != "terminalx.daytona-assignment-bootstrap-installed" ||
		descriptor.InstalledMarker != "/run/terminalx-root/assignment.installed.json" ||
		descriptor.SupervisorReady || descriptor.ProviderRevision < 1 ||
		descriptor.ProviderRevision > terminalXJavaScriptMaximumSafeInteger ||
		!terminalXSha256Raw.MatchString(descriptor.BindingDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.AssignmentPlanDigest) ||
		!safeTerminalXPublicReference(descriptor.EffectEnforcerKeyID) ||
		!terminalXSha256Raw.MatchString(descriptor.EffectEnforcerPolicyDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.EffectEnforcerPublicKeyDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.EffectEnforcerSetDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.EffectManifestBindingDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.EnvelopeDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.ObservationPublicKeyDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.PlanDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.ProviderIdentityCommitment) ||
		!terminalXSha256Raw.MatchString(descriptor.StateVerificationPublicKeyDigest) ||
		!terminalXSha256Raw.MatchString(descriptor.SupervisorArtifactDigest) ||
		!safeTerminalXPublicReference(descriptor.ObservationIssuerKeyID) ||
		descriptor.PlanDigest != descriptor.AssignmentPlanDigest {
		return false
	}
	block, rest := pem.Decode([]byte(descriptor.StateVerificationPublicKeySPKIPem))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return false
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	if _, ok := publicKey.(ed25519.PublicKey); !ok {
		return false
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(canonicalDER, block.Bytes) ||
		!bytes.Equal(pem.EncodeToMemory(block), []byte(descriptor.StateVerificationPublicKeySPKIPem)) {
		return false
	}
	actualDigest := sha256.Sum256([]byte(descriptor.StateVerificationPublicKeySPKIPem))
	expectedDigest, err := hex.DecodeString(descriptor.StateVerificationPublicKeyDigest)
	return err == nil && len(expectedDigest) == sha256.Size &&
		subtle.ConstantTimeCompare(actualDigest[:], expectedDigest) == 1
}

type terminalXAssignmentBootstrapInstalledDescriptor struct {
	AssignmentPlanDigest              string `json:"assignmentPlanDigest"`
	BindingDigest                     string `json:"bindingDigest"`
	EffectEnforcerKeyID               string `json:"effectEnforcerKeyId"`
	EffectEnforcerPolicyDigest        string `json:"effectEnforcerPolicyDigest"`
	EffectEnforcerPublicKeyDigest     string `json:"effectEnforcerPublicKeyDigest"`
	EffectEnforcerSetDigest           string `json:"effectEnforcerSetDigest"`
	EffectManifestBindingDigest       string `json:"effectManifestBindingDigest"`
	EnvelopeDigest                    string `json:"envelopeDigest"`
	InstalledMarker                   string `json:"installedMarker"`
	Kind                              string `json:"kind"`
	ObservationIssuerKeyID            string `json:"observationIssuerKeyId"`
	ObservationPublicKeyDigest        string `json:"observationPublicKeyDigest"`
	PlanDigest                        string `json:"planDigest"`
	ProviderIdentityCommitment        string `json:"providerIdentityCommitment"`
	ProviderRevision                  uint64 `json:"providerRevision"`
	StateVerificationPublicKeyDigest  string `json:"stateVerificationPublicKeyDigest"`
	StateVerificationPublicKeySPKIPem string `json:"stateVerificationPublicKeySpkiPem"`
	SupervisorArtifactDigest          string `json:"supervisorArtifactDigest"`
	SupervisorReady                   bool   `json:"supervisorReady"`
	Version                           int    `json:"version"`
}

func safeTerminalXPublicReference(value string) bool {
	return terminalXPublicReference.MatchString(value)
}

type terminalXBoundedBuffer struct {
	bytes.Buffer
	maximumBytes int64
}

func (buffer *terminalXBoundedBuffer) Write(value []byte) (int, error) {
	if int64(buffer.Len())+int64(len(value)) > buffer.maximumBytes {
		return 0, fmt.Errorf("terminalx fixed executable output exceeds limit")
	}
	return buffer.Buffer.Write(value)
}

func (buffer *terminalXBoundedBuffer) Zero() {
	value := buffer.Bytes()
	for index := range value {
		value[index] = 0
	}
	buffer.Reset()
}
