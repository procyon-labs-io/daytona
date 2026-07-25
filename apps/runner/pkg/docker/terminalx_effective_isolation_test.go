// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	dockerclient "github.com/docker/docker/client"
)

type terminalXEffectiveIsolationAPI struct {
	dockerclient.APIClient
	network network.Inspect
}

func (fake *terminalXEffectiveIsolationAPI) NetworkInspect(
	context.Context,
	string,
	network.InspectOptions,
) (network.Inspect, error) {
	return fake.network, nil
}

func terminalXEffectiveIsolationNetwork() network.Inspect {
	return network.Inspect{
		Name:       RUNNER_BRIDGE_NETWORK_NAME,
		Scope:      "local",
		Driver:     "bridge",
		EnableIPv4: true,
		Internal:   true,
		Options: map[string]string{
			"com.docker.network.bridge.enable_icc": "false",
		},
		Labels: map[string]string{
			terminalXNetworkProfileLabel: terminalXHardenedProfileVersion,
		},
		IPAM: network.IPAM{
			Driver: "default",
			Config: []network.IPAMConfig{{Subnet: "172.20.0.0/16"}},
		},
	}
}

func terminalXProbeProcess(id int64, pid int64, root bool) terminalXIsolationProbeProcess {
	active := "0000000000000000"
	if root {
		active = "00000000000000e1"
	}
	return terminalXIsolationProbeProcess{
		CapAmbient: "0000000000000000", CapBounding: "00000000000000e1",
		CapEffective: active, CapInheritable: "0000000000000000", CapPermitted: active,
		EffectiveGID: id, EffectiveUID: id, FilesystemGID: id, FilesystemUID: id,
		NoNewPrivileges: true, PID: pid, RealGID: id, RealUID: id, SavedGID: id, SavedUID: id,
	}
}

func terminalXValidIsolationProbeReport() *terminalXIsolationProbeReport {
	agent := terminalXIsolationProbeAgent{
		CapAmbient: "0000000000000000", CapBounding: "00000000000000e1",
		CapEffective: "0000000000000000", CapInheritable: "0000000000000000",
		CapPermitted: "0000000000000000", EffectiveGID: terminalXSandboxUserUID,
		EffectiveUID: terminalXSandboxUserUID, FilesystemGID: terminalXSandboxUserUID,
		FilesystemUID: terminalXSandboxUserUID, NoNewPrivileges: true, ProcessCount: 1,
		RealGID: terminalXSandboxUserUID, RealUID: terminalXSandboxUserUID,
		SavedGID: terminalXSandboxUserUID, SavedUID: terminalXSandboxUserUID,
	}
	executables := []terminalXIsolationProbeExecutable{
		{GID: 0, Mode: 0o555, NLink: 1, Path: "/usr/local/bin/daytona", Regular: true, UID: 0},
		{GID: 0, Mode: 0o555, NLink: 1, Path: "/usr/local/bin/node", Regular: true, UID: 0},
		{GID: 0, Mode: 0o555, NLink: 1, Path: "/usr/local/bin/terminalx-sandbox-init", Regular: true, UID: 0},
		{GID: 0, Mode: 0o555, NLink: 1, Path: "/usr/local/libexec/terminalx/terminalx-assignment-bootstrap", Regular: true, UID: 0},
		{GID: 0, Mode: 0o555, NLink: 1, Path: "/usr/local/libexec/terminalx/terminalx-daytona-supervisor", Regular: true, UID: 0},
		{GID: 0, Mode: 0o555, NLink: 1, Path: "/usr/local/libexec/terminalx/terminalx-deployment-binding-install", Regular: true, UID: 0},
		{GID: 0, Mode: 0o500, NLink: 1, Path: "/usr/local/libexec/terminalx/terminalx-effect-enforcer", Regular: true, UID: 0},
		{GID: 0, Mode: 0o555, NLink: 1, Path: "/usr/local/libexec/terminalx/terminalx-isolation-probe", Regular: true, UID: 0},
		{GID: 0, Mode: 0o500, NLink: 1, Path: "/usr/local/libexec/terminalx/terminalx-peercred", Regular: true, UID: 0},
		{GID: 0, Mode: 0o555, NLink: 1, Path: "/usr/local/libexec/terminalx/terminalx-supervisor-relay", Regular: true, UID: 0},
	}
	privatePaths := []terminalXIsolationProbePrivatePath{
		{GID: 0, Mode: 0o500, NLink: 2, Path: "/etc/terminalx", Type: "directory", UID: 0},
		{GID: 0, Mode: 0o700, NLink: 2, Path: "/run/terminalx-private", Type: "directory", UID: 0},
		{GID: 0, Mode: 0o600, NLink: 1, Path: "/run/terminalx-private/daytona-daemon.sock", Type: "socket", UID: 0},
		{GID: 0, Mode: 0o700, NLink: 4, Path: "/run/terminalx-root", Type: "directory", UID: 0},
		{GID: 0, Mode: 0o700, NLink: 2, Path: "/run/terminalx-root/assignment", Type: "directory", UID: 0},
		{GID: 0, Mode: 0o600, NLink: 1, Path: "/run/terminalx-root/assignment/effect-enforcer-key.pk8", Type: "file", UID: 0},
		{GID: 0, Mode: 0o600, NLink: 1, Path: "/run/terminalx-root/assignment/observation-key.pk8", Type: "file", UID: 0},
		{GID: 0, Mode: 0o600, NLink: 1, Path: "/run/terminalx-root/assignment/state-signing.pk8", Type: "file", UID: 0},
		{GID: 0, Mode: 0o600, NLink: 1, Path: "/run/terminalx-root/deployment-binding.json", Type: "file", UID: 0},
		{GID: 0, Mode: 0o700, NLink: 2, Path: "/var/lib/terminalx-supervisor", Type: "directory", UID: 0},
	}
	return &terminalXIsolationProbeReport{
		Agent:  agent,
		Daemon: terminalXProbeProcess(terminalXSandboxUserUID, 2, false),
		Denials: terminalXIsolationProbeDenials{
			AgentPrivateKeyReadDenied: true, AgentPrivateKeyWriteDenied: true,
			AgentRootRuntimeWriteDenied: true, AgentRootStateWriteDenied: true,
			AgentSignalInitDenied: true, AgentSignalSupervisorDenied: true,
		},
		Executables: executables,
		Init:        terminalXProbeProcess(0, 1, true), Kind: terminalXIsolationProbeKind,
		RootPrivatePaths: privatePaths,
		Supervisor:       terminalXProbeProcess(0, 3, true), Version: 1,
	}
}

func TestTerminalXIsolationProbeParserRequiresExactCanonicalProof(t *testing.T) {
	valid := terminalXValidIsolationProbeReport()
	encoded, err := marshalTerminalXCanonicalJSON(*valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseTerminalXIsolationProbeReport(encoded); err != nil {
		t.Fatalf("valid isolation probe rejected: %v", err)
	}

	tests := map[string]func(*terminalXIsolationProbeReport){
		"agent capability": func(value *terminalXIsolationProbeReport) {
			value.Agent.CapEffective = "0000000000000001"
		},
		"root capability": func(value *terminalXIsolationProbeReport) {
			value.Supervisor.CapPermitted = "0000000000000000"
		},
		"wrong uid": func(value *terminalXIsolationProbeReport) {
			value.Daemon.FilesystemUID++
		},
		"duplicate pid": func(value *terminalXIsolationProbeReport) {
			value.Supervisor.PID = value.Daemon.PID
		},
		"denial missing": func(value *terminalXIsolationProbeReport) {
			value.Denials.AgentSignalSupervisorDenied = false
		},
		"executable order": func(value *terminalXIsolationProbeReport) {
			value.Executables[0], value.Executables[1] = value.Executables[1], value.Executables[0]
		},
		"executable link": func(value *terminalXIsolationProbeReport) {
			value.Executables[0].NLink = 2
		},
		"private path mode": func(value *terminalXIsolationProbeReport) {
			value.RootPrivatePaths[0].Mode = 0o700
		},
		"private file link": func(value *terminalXIsolationProbeReport) {
			value.RootPrivatePaths[5].NLink = 2
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := terminalXValidIsolationProbeReport()
			mutate(candidate)
			candidateBytes, err := marshalTerminalXCanonicalJSON(*candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseTerminalXIsolationProbeReport(candidateBytes); err == nil {
				t.Fatal("invalid isolation probe proof was accepted")
			}
		})
	}
	if _, err := parseTerminalXIsolationProbeReport(append(bytes.Clone(encoded), '\n')); err == nil {
		t.Fatal("noncanonical isolation probe JSON was accepted")
	}
}

func terminalXEffectiveIsolationFixture(
	t *testing.T,
) (*DockerClient, *terminalXAssignmentEvidenceConfiguration, *terminalXIsolationProbeReport, ed25519.PublicKey) {
	t.Helper()
	client, inspected := terminalXContainerForTest(t)
	inspected.State = &container.State{Running: true}
	observationSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	observationPrivate := ed25519.NewKeyFromSeed(observationSeed)
	zeroTerminalXBytes(observationSeed)
	observationPublic := observationPrivate.Public().(ed25519.PublicKey)
	defer zeroTerminalXBytes(observationPrivate)
	observationPEM := terminalXTestPublicKeyPEM(t, observationPublic)
	plan := terminalXHostedPlan{
		AdapterConfigurationRef: "daytona-production-v1",
		Binding: json.RawMessage(
			`{"projectId":"project-1","runtimeAssignmentGeneration":1,"runtimeAssignmentId":"assignment-1","runtimePrincipalId":"principal-1","sandboxGeneration":1,"sandboxId":"sandbox-1","sessionId":"session-1","teamId":"team-1"}`,
		),
		Capabilities: terminalXHostedPlanCapabilities{
			IsolatedExecution: true,
		},
		EffectEnforcerPolicyDigest: strings.Repeat("e", 64),
		Incarnation:                strings.Repeat("a", 64),
		Isolation: terminalXHostedPlanIsolation{
			IsolationPolicyDigest: strings.Repeat("c", 64),
			Network: terminalXHostedPlanNetwork{
				AllowedDestinations: []string{}, Mode: "blocked", PolicyDigest: strings.Repeat("d", 64),
			},
			Resources: terminalXHostedPlanResources{CPU: 2, DiskGiB: 20, MemoryGiB: 4, Pids: terminalXSandboxPidsLimit},
		},
		Observation: terminalXHostedPlanObservation{
			IssuerKeyID: "observation-key-1", KeyProvisioningRef: "observation-provisioning-1",
			PublicKeySPKIPEM: observationPEM,
		},
		RuntimeAuthorizationGeneration: 7,
		SpecificationDigest:            strings.Repeat("b", 64),
	}
	planBytes, err := marshalTerminalXCanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	planDigest := terminalXDomainDigest(terminalXHostedPlanDigestDomain, planBytes)
	configuration := &terminalXAssignmentEvidenceConfiguration{
		Assignment: terminalXBootstrapAssignment{
			ArtifactDigest: testTerminalXArtifactDigest, ExpectedRevision: 7,
			Plan: bytes.Clone(planBytes), ProviderSandboxID: testTerminalXSandboxUUID,
			SandboxUser: terminalXSandboxUser, SupervisorArtifactDigest: testTerminalXSupervisorDigest,
		},
		Isolation: terminalXBootstrapIsolation{
			ExpectedAgentUID: terminalXSandboxUserUID, ExpectedContainerdVersion: "2.2.1",
			ExpectedDaytonaDaemonUID: terminalXSandboxUserUID, ExpectedDockerVersion: "29.1.3",
			ExpectedProviderRevision: 7, ExpectedRunnerBinaryDigest: strings.Repeat("9", 64),
			ExpectedSandboxImageID:     testTerminalXImageID,
			ExpectedSandboxSnapshotRef: testTerminalXSnapshotRef, ExpectedSandboxUser: terminalXSandboxUser,
			ExpectedSeccompProfileDigest: testTerminalXSeccompDigest, ExpectedSupervisorUID: 0,
			HardenedDaytonaSourceCommit: testTerminalXHardenedCommit, IssuerKeyID: "isolation-key-1",
			MaximumAttestationTTLMS: 60_000,
		},
		Plan: plan, PlanBytes: bytes.Clone(planBytes), PlanDigest: planDigest,
	}
	t.Cleanup(configuration.Close)
	keyPath, publicDigest, isolationPublic := writeTerminalXTestSigner(t)
	signer, err := loadTerminalXEd25519Signer(
		keyPath,
		"isolation-key-1",
		publicDigest,
		uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)
	configuration.Isolation.IssuerPublicKeySPKIPEM = signer.publicKeySPKIPEM
	client.apiClient = &terminalXEffectiveIsolationAPI{network: terminalXEffectiveIsolationNetwork()}
	client.useSnapshotEntrypoint = true
	client.terminalXSandboxArtifactDigest = testTerminalXArtifactDigest
	client.terminalXRunnerSourceCommit = testTerminalXHardenedCommit
	client.terminalXRunnerBinaryDigest = strings.Repeat("9", 64)
	client.terminalXSeccompProfileSHA256 = testTerminalXSeccompDigest
	client.terminalXIsolationAttestorSigner = signer
	client.terminalXEvidenceTTL = time.Minute
	client.terminalXDaytonaDaemonUID = terminalXSandboxUserUID
	client.terminalXAgentUID = terminalXSandboxUserUID
	client.terminalXDockerVersion = "29.1.3"
	client.terminalXContainerdVersion = "2.2.1"
	client.terminalXClock = func() time.Time { return time.UnixMilli(testTerminalXContractNowMS) }
	inspected.Config.Labels["terminalx.artifact"] = testTerminalXArtifactDigest
	inspected.Config.Labels["terminalx.revision"] = "7"
	inspected.Config.Labels["terminalx.plan"] = planDigest
	providerSandboxID, ok := terminalXProviderSandboxIDFromEnvironment(
		inspected.Config.Env,
		client.terminalXSandboxSnapshotRef,
	)
	if !ok {
		t.Fatal("test container provider identity is invalid")
	}
	configuration.Assignment.ProviderSandboxID = providerSandboxID
	return client, configuration, terminalXValidIsolationProbeReport(), isolationPublic
}

func TestTerminalXEffectiveIsolationEvidenceIsCanonicalFreshAndVerifiable(t *testing.T) {
	client, configuration, report, publicKey := terminalXEffectiveIsolationFixture(t)
	_, inspected := terminalXContainerForTest(t)
	inspected.State = &container.State{Running: true}
	inspected.Config.Labels["terminalx.artifact"] = testTerminalXArtifactDigest
	inspected.Config.Labels["terminalx.revision"] = "7"
	inspected.Config.Labels["terminalx.plan"] = configuration.PlanDigest

	evidence, err := client.createTerminalXEffectiveIsolationAttestation(
		t.Context(), inspected, configuration, report,
	)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Plan.EffectEnforcerPolicyDigest != strings.Repeat("e", 64) ||
		configuration.Isolation.ExpectedRunnerBinaryDigest != strings.Repeat("9", 64) ||
		configuration.PlanDigest != "bfee8033134be117f8ddc3540ef3ba4171f59e7264fddccc2df535be3f75f90c" ||
		configuration.Isolation.IssuerPublicKeySPKIPEM != "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=\n-----END PUBLIC KEY-----\n" ||
		terminalXRawDigest(evidence) != "a633b632712678828611a04c227a2b9fce06e53f5e224733a0e8e67ae770d637" {
		t.Fatalf(
			"cross-language effective isolation fixture changed: plan=%s evidence=%s",
			configuration.PlanDigest,
			terminalXRawDigest(evidence),
		)
	}
	defer zeroTerminalXBytes(evidence)
	canonical, _, err := canonicalizeTerminalXJSON(evidence, terminalXEffectiveIsolationMaximumBytes)
	if err != nil || !bytes.Equal(canonical, evidence) {
		t.Fatalf("evidence is not canonical: %v", err)
	}
	var attestation terminalXEffectiveIsolationAttestation
	if err := json.Unmarshal(evidence, &attestation); err != nil {
		t.Fatal(err)
	}
	if attestation.Kind != terminalXEffectiveIsolationKind || attestation.Version != 1 ||
		attestation.Authority.IssuedAtMS != testTerminalXContractNowMS ||
		attestation.Authority.ExpiresAtMS != testTerminalXContractNowMS+60_000 ||
		attestation.Claims.ProviderRevision != 7 ||
		attestation.Claims.ProviderIdentityCommitment != terminalXDomainDigest(
			terminalXProviderIdentityDigestDomain, []byte(testTerminalXSandboxUUID),
		) ||
		attestation.Claims.ObservationKeyProvisioningRefDigest != terminalXDomainDigest(
			terminalXObservationProvisioningDigestDomain, []byte("observation-provisioning-1"),
		) || attestation.Claims.RunnerBinaryDigest != strings.Repeat("9", 64) {
		t.Fatal("effective isolation claims changed")
	}
	claimsBytes, err := marshalTerminalXCanonicalJSON(attestation.Claims)
	if err != nil {
		t.Fatal(err)
	}
	expectedClaimsDigest := terminalXDomainDigest(terminalXEffectiveIsolationClaimsDigestDomain, claimsBytes)
	if expectedClaimsDigest != "fee3f256d0025e190d605474fff25b1bb006caf37acd4b4cd11edab6c19c6cd9" ||
		attestation.Authority.ClaimsDigest != expectedClaimsDigest {
		t.Fatal("effective isolation claims digest did not verify")
	}
	statement := terminalXEffectiveIsolationStatement{
		Audience: attestation.Authority.Audience, Capability: attestation.Authority.Capability,
		ClaimsDigest: attestation.Authority.ClaimsDigest, ExpiresAtMS: attestation.Authority.ExpiresAtMS,
		IssuedAtMS: attestation.Authority.IssuedAtMS, Issuer: attestation.Authority.Issuer,
		IssuerKeyID: attestation.Authority.IssuerKeyID, Version: 1,
	}
	statementBytes, err := marshalTerminalXCanonicalJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(attestation.Authority.Signature)
	if attestation.Authority.Signature != "zD-ad24I4385MdeSi4jHx8EVwq8220UazGTqsocNIlY6sFR9Cjv_FrvuoWg9AIJOcWSV6BfTUWJ23lD6-iG1Cg" ||
		err != nil || !ed25519.Verify(
		publicKey,
		append([]byte(terminalXEffectiveIsolationSignatureDomain), statementBytes...),
		signature,
	) {
		t.Fatal("effective isolation signature did not verify")
	}
	var generic map[string]any
	if err := json.Unmarshal(evidence, &generic); err != nil {
		t.Fatal(err)
	}
	authority := generic["authority"].(map[string]any)
	if len(authority) != 8 || authority["version"] != nil {
		t.Fatal("serialized authority contains a non-contract field")
	}
}

func TestTerminalXEffectiveIsolationRejectsNetworkAndProbeDrift(t *testing.T) {
	client, configuration, report, _ := terminalXEffectiveIsolationFixture(t)
	_, inspected := terminalXContainerForTest(t)
	inspected.State = &container.State{Running: true}
	inspected.Config.Labels["terminalx.artifact"] = testTerminalXArtifactDigest
	inspected.Config.Labels["terminalx.revision"] = "7"
	inspected.Config.Labels["terminalx.plan"] = configuration.PlanDigest

	client.apiClient.(*terminalXEffectiveIsolationAPI).network.Internal = false
	if evidence, err := client.createTerminalXEffectiveIsolationAttestation(t.Context(), inspected, configuration, report); err == nil {
		zeroTerminalXBytes(evidence)
		t.Fatal("drifted runner network was attested")
	}
	client.apiClient.(*terminalXEffectiveIsolationAPI).network = terminalXEffectiveIsolationNetwork()
	configuration.Isolation.ExpectedRunnerBinaryDigest = strings.Repeat("8", 64)
	if evidence, err := client.createTerminalXEffectiveIsolationAttestation(t.Context(), inspected, configuration, report); err == nil {
		zeroTerminalXBytes(evidence)
		t.Fatal("mismatched bootstrap runner identity was attested")
	}
	configuration.Isolation.ExpectedRunnerBinaryDigest = strings.Repeat("9", 64)
	client.terminalXRunnerBinaryDigest = strings.Repeat("A", 64)
	if evidence, err := client.createTerminalXEffectiveIsolationAttestation(t.Context(), inspected, configuration, report); err == nil {
		zeroTerminalXBytes(evidence)
		t.Fatal("invalid runner executable identity was attested")
	}
	client.terminalXRunnerBinaryDigest = strings.Repeat("9", 64)
	report.Agent.CapEffective = "0000000000000001"
	if evidence, err := client.createTerminalXEffectiveIsolationAttestation(t.Context(), inspected, configuration, report); err == nil {
		zeroTerminalXBytes(evidence)
		t.Fatal("drifted process boundary was attested")
	}
}

func TestTerminalXEffectiveIsolationRejectsNonPortableLifetimes(t *testing.T) {
	for name, mutate := range map[string]func(*DockerClient){
		"sub-millisecond ttl": func(client *DockerClient) {
			client.terminalXEvidenceTTL = time.Nanosecond
		},
		"timestamp overflow": func(client *DockerClient) {
			client.terminalXClock = func() time.Time {
				return time.UnixMilli(int64(terminalXJavaScriptMaximumSafeInteger))
			}
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			client, configuration, report, _ := terminalXEffectiveIsolationFixture(t)
			_, inspected := terminalXContainerForTest(t)
			inspected.State = &container.State{Running: true}
			inspected.Config.Labels["terminalx.artifact"] = testTerminalXArtifactDigest
			inspected.Config.Labels["terminalx.revision"] = "7"
			inspected.Config.Labels["terminalx.plan"] = configuration.PlanDigest
			mutate(client)
			if evidence, err := client.createTerminalXEffectiveIsolationAttestation(
				t.Context(), inspected, configuration, report,
			); err == nil {
				zeroTerminalXBytes(evidence)
				t.Fatal("non-portable evidence lifetime was accepted")
			}
		})
	}
}

func TestTerminalXIsolationProbeExecOptionsExposeNoCallerSurface(t *testing.T) {
	options := terminalXIsolationProbeExecOptions()
	if options.User != "0:0" || options.Privileged || options.Tty || options.AttachStdin ||
		!options.AttachStdout || !options.AttachStderr || options.WorkingDir != "/" ||
		len(options.Cmd) != 1 || options.Cmd[0] != terminalXIsolationProbePath ||
		len(options.Env) != 0 {
		t.Fatalf("unsafe isolation probe exec options: %#v", options)
	}
}

func TestTerminalXEffectiveIsolationDigestDomainsStayDistinct(t *testing.T) {
	value := []byte("same-input")
	digests := map[string]bool{
		terminalXDomainDigest(terminalXEffectiveIsolationClaimsDigestDomain, value): true,
		terminalXDomainDigest(terminalXProviderIdentityDigestDomain, value):         true,
		terminalXDomainDigest(terminalXObservationProvisioningDigestDomain, value):  true,
		terminalXRawDigest(value): true,
	}
	if len(digests) != 4 {
		t.Fatal("effective isolation digest domains collapsed")
	}
}
