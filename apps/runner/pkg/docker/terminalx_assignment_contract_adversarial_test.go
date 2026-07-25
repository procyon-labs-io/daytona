// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
)

const (
	testTerminalXContractProviderID = "123e4567-e89b-42d3-a456-426614174000"
	testTerminalXContractNowMS      = int64(1_800_000_000_000)
	testTerminalXArtifactDigest     = "1111111111111111111111111111111111111111111111111111111111111111"
	testTerminalXSupervisorDigest   = "2222222222222222222222222222222222222222222222222222222222222222"
	testTerminalXSeccompDigest      = "7777777777777777777777777777777777777777777777777777777777777777"
	testTerminalXHardenedCommit     = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

type terminalXContractFixture struct {
	authorityPrivate ed25519.PrivateKey
	client           *DockerClient
	inspected        *container.InspectResponse
	observationDER   []byte
	effectDER        []byte
	isolationPEM     string
	observationPEM   string
}

type terminalXContractReplayAPI struct {
	dockerclient.APIClient
	marker     []byte
	statMode   os.FileMode
	headerMode int64
	headerUID  int
	headerGID  int
	headerName string
	extraEntry bool
}

func (fake *terminalXContractReplayAPI) CopyFromContainer(
	_ context.Context,
	_ string,
	sourcePath string,
) (io.ReadCloser, container.PathStat, error) {
	if sourcePath != terminalXAssignmentInstalledMarkerPath || fake.marker == nil {
		return nil, container.PathStat{}, errdefs.ErrNotFound
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	headerName := fake.headerName
	if headerName == "" {
		headerName = filepath.Base(terminalXAssignmentInstalledMarkerPath)
	}
	header := &tar.Header{
		Name:     headerName,
		Mode:     fake.headerMode,
		Uid:      fake.headerUID,
		Gid:      fake.headerGID,
		Size:     int64(len(fake.marker)),
		Typeflag: tar.TypeReg,
	}
	if err := writer.WriteHeader(header); err != nil {
		return nil, container.PathStat{}, err
	}
	if _, err := writer.Write(fake.marker); err != nil {
		return nil, container.PathStat{}, err
	}
	if fake.extraEntry {
		if err := writer.WriteHeader(&tar.Header{Name: "extra", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}); err != nil {
			return nil, container.PathStat{}, err
		}
		if _, err := writer.Write([]byte("x")); err != nil {
			return nil, container.PathStat{}, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, container.PathStat{}, err
	}
	return io.NopCloser(bytes.NewReader(archive.Bytes())), container.PathStat{
		Name: filepath.Base(terminalXAssignmentInstalledMarkerPath),
		Size: int64(len(fake.marker)),
		Mode: fake.statMode,
	}, nil
}

type terminalXContractEnvelopeOptions struct {
	issuedAtMS      int64
	expiresAtMS     int64
	mutateBootstrap func(map[string]any)
	mutateSections  func([]any)
	mutateAuthority func(map[string]any)
	trailingSecret  []byte
}

func newTerminalXContractFixture(t *testing.T) *terminalXContractFixture {
	t.Helper()
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	observationPublic, observationPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, effectPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	isolationPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	observationDER, err := x509.MarshalPKCS8PrivateKey(observationPrivate)
	if err != nil {
		t.Fatal(err)
	}
	effectDER, err := x509.MarshalPKCS8PrivateKey(effectPrivate)
	if err != nil {
		t.Fatal(err)
	}
	observationPEM := terminalXTestPublicKeyPEM(t, observationPublic)
	isolationPEM := terminalXTestPublicKeyPEM(t, isolationPublic)
	pids := int64(terminalXSandboxPidsLimit)
	host := &container.HostConfig{}
	host.PidsLimit = &pids
	host.CPUPeriod = 100000
	host.CPUQuota = 2 * 100000
	host.Memory = commonGBToBytes(4)
	host.StorageOpt = map[string]string{"size": "20G"}
	inspected := &container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			ID:         strings.Repeat("a", 64),
			Image:      testTerminalXImageID,
			HostConfig: host,
		},
		Config: &container.Config{
			Hostname: terminalXHardenedHostname,
			Env: []string{
				"DAYTONA_SANDBOX_ID=" + testTerminalXContractProviderID,
				"DAYTONA_SANDBOX_SNAPSHOT=" + testTerminalXSnapshotRef,
				"DAYTONA_SANDBOX_USER=" + terminalXSandboxUser,
			},
			Labels: map[string]string{
				"terminalx.artifact": testTerminalXArtifactDigest,
				"terminalx.revision": "7",
			},
		},
	}
	client := &DockerClient{
		apiClient: &terminalXContractReplayAPI{
			statMode:   0o600,
			headerMode: 0o600,
		},
		terminalXSandboxImageID:              testTerminalXImageID,
		terminalXSandboxSnapshotRef:          testTerminalXSnapshotRef,
		terminalXSandboxArtifactDigest:       testTerminalXArtifactDigest,
		terminalXRunnerSourceCommit:          testTerminalXHardenedCommit,
		terminalXRunnerBinaryDigest:          strings.Repeat("9", 64),
		terminalXSeccompProfileSHA256:        testTerminalXSeccompDigest,
		terminalXBootstrapAuthorityKeyID:     "platform-bootstrap-1",
		terminalXBootstrapAuthorityPublicKey: bytes.Clone(authorityPublic),
		terminalXIsolationAttestorSigner: &terminalXEd25519Signer{
			keyID:            "isolation-key-1",
			publicKeySPKIPEM: isolationPEM,
		},
		terminalXEvidenceTTL:       time.Minute,
		terminalXDaytonaDaemonUID:  1000,
		terminalXAgentUID:          1000,
		terminalXDockerVersion:     "29.1.3",
		terminalXContainerdVersion: "2.2.1",
		terminalXClock: func() time.Time {
			return time.UnixMilli(testTerminalXContractNowMS)
		},
	}
	fixture := &terminalXContractFixture{
		authorityPrivate: authorityPrivate,
		client:           client,
		inspected:        inspected,
		observationDER:   observationDER,
		effectDER:        effectDER,
		isolationPEM:     isolationPEM,
		observationPEM:   observationPEM,
	}
	t.Cleanup(func() {
		zeroTerminalXBytes(authorityPrivate)
		zeroTerminalXBytes(observationPrivate)
		zeroTerminalXBytes(effectPrivate)
		zeroTerminalXBytes(observationDER)
		zeroTerminalXBytes(effectDER)
	})
	return fixture
}

func terminalXTestPublicKeyPEM(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func (fixture *terminalXContractFixture) bootstrap() map[string]any {
	plan := map[string]any{
		"adapterConfigurationRef": "daytona-production-v1",
		"binding": map[string]any{
			"projectId":                   "project-1",
			"runtimeAssignmentGeneration": 1,
			"runtimeAssignmentId":         "assignment-1",
			"runtimePrincipalId":          "principal-1",
			"sandboxGeneration":           1,
			"sandboxId":                   "sandbox-1",
			"sessionId":                   "session-1",
			"teamId":                      "team-1",
		},
		"capabilities": map[string]any{
			"brokeredCredentials": false,
			"checkpoints":         false,
			"isolatedExecution":   true,
			"proxyOnlyEgress":     false,
			"yoloEligible":        false,
		},
		"effectEnforcerPolicyDigest": strings.Repeat("8", 64),
		"incarnation":                strings.Repeat("a", 64),
		"isolation": map[string]any{
			"hostMounts":            false,
			"isolationPolicyDigest": strings.Repeat("c", 64),
			"linkedSandbox":         false,
			"network": map[string]any{
				"allowedDestinations": []any{},
				"mode":                "blocked",
				"policyDigest":        strings.Repeat("d", 64),
			},
			"publicAccess": false,
			"resources": map[string]any{
				"cpu":       2,
				"diskGiB":   20,
				"memoryGiB": 4,
				"pids":      terminalXSandboxPidsLimit,
			},
			"rootIdentity": false,
		},
		"observation": map[string]any{
			"issuerKeyId":        "observation-key-1",
			"keyProvisioningRef": "observation-provisioning-1",
			"publicKeySpkiPem":   fixture.observationPEM,
		},
		"runtimeAuthorizationGeneration": 7,
		"specificationDigest":            strings.Repeat("b", 64),
	}
	planBytes, err := marshalTerminalXCanonicalJSON(plan)
	if err != nil {
		panic(err)
	}
	planHash := sha256.New()
	_, _ = planHash.Write([]byte(terminalXHostedPlanDigestDomain))
	_, _ = planHash.Write(planBytes)
	assignmentPlanDigest := hex.EncodeToString(planHash.Sum(nil))
	providerDigest := sha256.Sum256([]byte(
		"terminalx/daytona-provider-identity/v1\x00" + testTerminalXContractProviderID,
	))
	return map[string]any{
		"assignment": map[string]any{
			"artifactDigest":           testTerminalXArtifactDigest,
			"effectEnforcerSetDigest":  strings.Repeat("3", 64),
			"expectedRevision":         7,
			"maxOperations":            100,
			"plan":                     plan,
			"providerSandboxId":        testTerminalXContractProviderID,
			"sandboxUser":              terminalXSandboxUser,
			"supervisorArtifactDigest": testTerminalXSupervisorDigest,
		},
		"commandAuthority": map[string]any{
			"maximumAuthorityTtlMs": 60000,
			"pinnedPublicKeys":      []any{},
		},
		"effect": map[string]any{
			"executableFile":   "/usr/local/libexec/terminalx/terminalx-effect-enforcer",
			"executableRoot":   "/usr/local/libexec/terminalx",
			"executableSha256": strings.Repeat("4", 64),
			"manifest": map[string]any{
				"assignmentPlanDigest": assignmentPlanDigest,
				"authority": map[string]any{
					"audience": "terminalx-control-plane", "capability": "runtime.effect-enforcer-manifest.trust",
					"claimsDigest": strings.Repeat("3", 64), "expiresAtMs": testTerminalXContractNowMS + 60_000,
					"issuedAtMs": testTerminalXContractNowMS, "issuer": "platform-security",
					"issuerKeyId": "effect-manifest-authority-1", "signature": strings.Repeat("A", 86),
				},
				"effectEnforcerPolicyDigest":  strings.Repeat("8", 64),
				"effectManifestBindingDigest": strings.Repeat("6", 64),
				"enforcers": []any{map[string]any{
					"allowedPurposes": []any{"runtime-lifecycle", "stale-lifecycle-effect-containment"},
					"enforcerKeyId":   "runtime-enforcer-key-1", "enforcerKind": "runtime",
					"enforcerRef": "runtime-enforcer-1", "publicKeySpkiDigest": strings.Repeat("7", 64),
					"publicKeySpkiPem": fixture.observationPEM,
				}},
				"expiresAtMs": testTerminalXContractNowMS + 60_000,
				"kind":        "runtime.effect-enforcer-manifest", "manifestId": "daytona-effect-manifest:v1:test",
				"providerIdentityCommitment": hex.EncodeToString(providerDigest[:]),
				"providerRevision":           7, "validFromMs": testTerminalXContractNowMS, "version": 1,
			},
			"maximumInputBytes":                 1048576,
			"maximumOutputBytes":                1048576,
			"pinnedManifestAuthorityPublicKeys": []any{},
			"timeoutMs":                         5000,
		},
		"isolation": map[string]any{
			"attestationFile":              "/run/terminalx-root/live/isolation-attestation.json",
			"expectedAgentUid":             1000,
			"expectedContainerdVersion":    "2.2.1",
			"expectedDaytonaDaemonUid":     1000,
			"expectedDockerVersion":        "29.1.3",
			"expectedProviderRevision":     7,
			"expectedRunnerBinaryDigest":   strings.Repeat("9", 64),
			"expectedSandboxImageId":       testTerminalXImageID,
			"expectedSandboxSnapshotRef":   testTerminalXSnapshotRef,
			"expectedSandboxUser":          terminalXSandboxUser,
			"expectedSeccompProfileDigest": testTerminalXSeccompDigest,
			"expectedSupervisorUid":        0,
			"hardenedDaytonaSourceCommit":  testTerminalXHardenedCommit,
			"issuerKeyId":                  "isolation-key-1",
			"issuerPublicKeySpkiPem":       fixture.isolationPEM,
			"maximumAttestationTtlMs":      60000,
		},
		"kind": "terminalx.daytona-supervisor-bootstrap",
		"observation": map[string]any{
			"observationTtlMs":       60000,
			"provisioningRecordFile": "/run/terminalx-root/assignment/observation-provisioning.json",
		},
		"state": map[string]any{
			"maxStateBytes":             1048576,
			"signingPrivateKeyFile":     "/run/terminalx-root/assignment/state-signing.pk8",
			"stateDirectory":            "/var/lib/terminalx-root/state",
			"stateFileName":             "supervisor-state.json",
			"verificationPublicKeyFile": "/run/terminalx-root/assignment/state-verification.pem",
		},
		"terminal": map[string]any{
			"maximumLifetimeMs":            604800000,
			"maximumOutputFrameBytes":      65536,
			"maximumPendingOutputBytes":    16777216,
			"maximumPendingWebSocketBytes": 1048576,
			"maximumTerminals":             64,
			"maximumTerminalsPerSandbox":   8,
			"requestTimeoutMs":             5000,
		},
		"transport": map[string]any{
			"authenticationTimeoutMs":        1000,
			"maximumFrameBytes":              1048576,
			"maximumInflightRequests":        32,
			"peerCredentialExecutableFile":   "/usr/local/libexec/terminalx/terminalx-peercred",
			"peerCredentialExecutableRoot":   "/usr/local/libexec/terminalx",
			"peerCredentialExecutableSha256": strings.Repeat("5", 64),
			"requestTimeoutMs":               5000,
			"socketDirectory":                "/run/terminalx-root",
			"socketPath":                     "/run/terminalx-root/supervisor.sock",
		},
		"version": 1,
	}
}

func (fixture *terminalXContractFixture) envelope(
	t *testing.T,
	options terminalXContractEnvelopeOptions,
) ([]byte, string) {
	t.Helper()
	bootstrap := fixture.bootstrap()
	if options.mutateBootstrap != nil {
		options.mutateBootstrap(bootstrap)
	}
	observation := bytes.Clone(fixture.observationDER)
	effect := bytes.Clone(fixture.effectDER)
	sections := []any{
		map[string]any{
			"bytes":  len(observation),
			"kind":   "observation-ed25519-pkcs8",
			"sha256": terminalXTestRawDigest(observation),
		},
		map[string]any{
			"bytes":  len(effect),
			"kind":   "effect-enforcer-ed25519-pkcs8",
			"sha256": terminalXTestRawDigest(effect),
		},
	}
	if options.mutateSections != nil {
		options.mutateSections(sections)
	}
	claims := map[string]any{
		"bootstrap": bootstrap,
		"kind":      terminalXAssignmentBootstrapKind,
		"sections":  sections,
		"version":   1,
	}
	claimsBytes, err := marshalTerminalXCanonicalJSON(claims)
	if err != nil {
		t.Fatal(err)
	}
	claimsHash := sha256.New()
	_, _ = claimsHash.Write([]byte(terminalXAssignmentBootstrapClaimsDigestDomain))
	_, _ = claimsHash.Write(claimsBytes)
	claimsDigest := hex.EncodeToString(claimsHash.Sum(nil))
	issuedAtMS := options.issuedAtMS
	if issuedAtMS == 0 {
		issuedAtMS = testTerminalXContractNowMS
	}
	expiresAtMS := options.expiresAtMS
	if expiresAtMS == 0 {
		expiresAtMS = issuedAtMS + 60_000
	}
	statement := map[string]any{
		"audience":     "terminalx-sandbox-init",
		"capability":   "runtime.assignment.bootstrap",
		"claimsDigest": claimsDigest,
		"expiresAtMs":  expiresAtMS,
		"issuedAtMs":   issuedAtMS,
		"issuer":       "platform-security",
		"issuerKeyId":  "platform-bootstrap-1",
		"version":      1,
	}
	statementBytes, err := marshalTerminalXCanonicalJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(terminalXAssignmentBootstrapSignatureDomain), statementBytes...)
	authority := map[string]any{
		"audience":     statement["audience"],
		"capability":   statement["capability"],
		"claimsDigest": claimsDigest,
		"expiresAtMs":  expiresAtMS,
		"issuedAtMs":   issuedAtMS,
		"issuer":       statement["issuer"],
		"issuerKeyId":  statement["issuerKeyId"],
		"signature": base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(fixture.authorityPrivate, message),
		),
	}
	if options.mutateAuthority != nil {
		options.mutateAuthority(authority)
	}
	header := map[string]any{
		"authority": authority,
		"bootstrap": bootstrap,
		"kind":      terminalXAssignmentBootstrapKind,
		"sections":  sections,
		"version":   1,
	}
	headerBytes, err := marshalTerminalXCanonicalJSON(header)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]byte, 4+len(headerBytes)+len(observation)+len(effect)+len(options.trailingSecret))
	binary.BigEndian.PutUint32(result[:4], uint32(len(headerBytes)))
	offset := 4
	offset += copy(result[offset:], headerBytes)
	offset += copy(result[offset:], observation)
	offset += copy(result[offset:], effect)
	copy(result[offset:], options.trailingSecret)
	plan := bootstrap["assignment"].(map[string]any)["plan"]
	planBytes, err := marshalTerminalXCanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	planHash := sha256.New()
	_, _ = planHash.Write([]byte(terminalXHostedPlanDigestDomain))
	_, _ = planHash.Write(planBytes)
	return result, hex.EncodeToString(planHash.Sum(nil))
}

func terminalXTestRawDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func terminalXContractInstalledMarker(t *testing.T, envelope []byte, statePublicKeyPEM string) []byte {
	t.Helper()
	envelopeHash := sha256.New()
	_, _ = envelopeHash.Write([]byte(terminalXAssignmentEnvelopeDigestDomain))
	_, _ = envelopeHash.Write(envelope)
	stateDigest := sha256.Sum256([]byte(statePublicKeyPEM))
	descriptor := terminalXAssignmentBootstrapInstalledDescriptor{
		AssignmentPlanDigest:              strings.Repeat("2", 64),
		BindingDigest:                     strings.Repeat("3", 64),
		EffectEnforcerKeyID:               "runtime-enforcer-key-1",
		EffectEnforcerPolicyDigest:        strings.Repeat("8", 64),
		EffectEnforcerPublicKeyDigest:     strings.Repeat("6", 64),
		EffectEnforcerSetDigest:           strings.Repeat("3", 64),
		EffectManifestBindingDigest:       strings.Repeat("6", 64),
		EnvelopeDigest:                    hex.EncodeToString(envelopeHash.Sum(nil)),
		InstalledMarker:                   terminalXAssignmentInstalledMarkerPath,
		Kind:                              "terminalx.daytona-assignment-bootstrap-installed",
		ObservationIssuerKeyID:            "observation-key-1",
		ObservationPublicKeyDigest:        strings.Repeat("4", 64),
		PlanDigest:                        strings.Repeat("2", 64),
		ProviderIdentityCommitment:        strings.Repeat("1", 64),
		ProviderRevision:                  7,
		StateVerificationPublicKeyDigest:  hex.EncodeToString(stateDigest[:]),
		StateVerificationPublicKeySPKIPem: statePublicKeyPEM,
		SupervisorArtifactDigest:          testTerminalXSupervisorDigest,
		SupervisorReady:                   false,
		Version:                           1,
	}
	value, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !validTerminalXAssignmentBootstrapResponse(value) {
		t.Fatal("test installed marker is invalid")
	}
	return value
}

func terminalXContractMatchingResponse(
	t *testing.T,
	configuration *terminalXAssignmentEvidenceConfiguration,
	statePublicKeyPEM string,
) terminalXAssignmentBootstrapInstalledDescriptor {
	t.Helper()
	providerDigest := sha256.Sum256([]byte(
		"terminalx/daytona-provider-identity/v1\x00" + configuration.Assignment.ProviderSandboxID,
	))
	observationDigest := sha256.Sum256([]byte(configuration.Plan.Observation.PublicKeySPKIPEM))
	bindingHash := sha256.New()
	_, _ = bindingHash.Write([]byte("terminalx/daytona-bootstrap-binding/v1\x00"))
	_, _ = bindingHash.Write(configuration.Plan.Binding)
	stateDigest := sha256.Sum256([]byte(statePublicKeyPEM))
	return terminalXAssignmentBootstrapInstalledDescriptor{
		AssignmentPlanDigest:              configuration.PlanDigest,
		BindingDigest:                     hex.EncodeToString(bindingHash.Sum(nil)),
		EffectEnforcerKeyID:               "runtime-enforcer-key-1",
		EffectEnforcerPolicyDigest:        configuration.Plan.EffectEnforcerPolicyDigest,
		EffectEnforcerPublicKeyDigest:     strings.Repeat("6", 64),
		EffectEnforcerSetDigest:           configuration.Assignment.EffectEnforcerSetDigest,
		EffectManifestBindingDigest:       configuration.Effect.Manifest.EffectManifestBindingDigest,
		EnvelopeDigest:                    configuration.EnvelopeDigest,
		InstalledMarker:                   terminalXAssignmentInstalledMarkerPath,
		Kind:                              "terminalx.daytona-assignment-bootstrap-installed",
		ObservationIssuerKeyID:            configuration.Plan.Observation.IssuerKeyID,
		ObservationPublicKeyDigest:        hex.EncodeToString(observationDigest[:]),
		PlanDigest:                        configuration.PlanDigest,
		ProviderIdentityCommitment:        hex.EncodeToString(providerDigest[:]),
		ProviderRevision:                  configuration.Assignment.ExpectedRevision,
		StateVerificationPublicKeyDigest:  hex.EncodeToString(stateDigest[:]),
		StateVerificationPublicKeySPKIPem: statePublicKeyPEM,
		SupervisorArtifactDigest:          configuration.Assignment.SupervisorArtifactDigest,
		SupervisorReady:                   false,
		Version:                           1,
	}
}

func TestTerminalXBootstrapEnvelopeMatchesSignedTypeScriptContract(t *testing.T) {
	fixture := newTerminalXContractFixture(t)
	envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{})
	fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
	captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(t.Context(), envelope, fixture.inspected)
	if err != nil {
		t.Fatalf("valid app-compatible envelope rejected: %v", err)
	}
	planBacking := captured.PlanBytes
	if captured.PlanDigest != planDigest || len(planBacking) == 0 {
		t.Fatal("captured plan contract changed")
	}
	captured.Close()
	if captured.PlanBytes != nil || !bytes.Equal(planBacking, make([]byte, len(planBacking))) {
		t.Fatal("captured public plan bytes were not zeroed on close")
	}
}

func TestTerminalXBootstrapEnvelopeRejectsActivationBindingDrift(t *testing.T) {
	tests := map[string]func(map[string]any){
		"missing terminal contract": func(bootstrap map[string]any) {
			delete(bootstrap, "terminal")
		},
		"legacy dual enforcer digests": func(bootstrap map[string]any) {
			assignment := bootstrap["assignment"].(map[string]any)
			delete(assignment, "effectEnforcerSetDigest")
			assignment["lifecycleEffectEnforcerSetDigest"] = strings.Repeat("3", 64)
			assignment["containmentEffectEnforcerSetDigest"] = strings.Repeat("3", 64)
		},
		"missing effect policy": func(bootstrap map[string]any) {
			plan := bootstrap["assignment"].(map[string]any)["plan"].(map[string]any)
			delete(plan, "effectEnforcerPolicyDigest")
		},
		"manifest assignment plan": func(bootstrap map[string]any) {
			manifest := bootstrap["effect"].(map[string]any)["manifest"].(map[string]any)
			manifest["assignmentPlanDigest"] = strings.Repeat("9", 64)
		},
		"manifest effect policy": func(bootstrap map[string]any) {
			manifest := bootstrap["effect"].(map[string]any)["manifest"].(map[string]any)
			manifest["effectEnforcerPolicyDigest"] = strings.Repeat("9", 64)
		},
		"manifest provider commitment": func(bootstrap map[string]any) {
			manifest := bootstrap["effect"].(map[string]any)["manifest"].(map[string]any)
			manifest["providerIdentityCommitment"] = strings.Repeat("9", 64)
		},
		"manifest provider revision": func(bootstrap map[string]any) {
			manifest := bootstrap["effect"].(map[string]any)["manifest"].(map[string]any)
			manifest["providerRevision"] = 8
		},
		"manifest binding digest": func(bootstrap map[string]any) {
			manifest := bootstrap["effect"].(map[string]any)["manifest"].(map[string]any)
			manifest["effectManifestBindingDigest"] = "not-a-digest"
		},
		"manifest set digest": func(bootstrap map[string]any) {
			manifest := bootstrap["effect"].(map[string]any)["manifest"].(map[string]any)
			manifest["authority"].(map[string]any)["claimsDigest"] = strings.Repeat("9", 64)
		},
		"runner binary digest": func(bootstrap map[string]any) {
			bootstrap["isolation"].(map[string]any)["expectedRunnerBinaryDigest"] = strings.Repeat("8", 64)
		},
		"terminal frame exceeds pending output": func(bootstrap map[string]any) {
			terminal := bootstrap["terminal"].(map[string]any)
			terminal["maximumOutputFrameBytes"] = 65536
			terminal["maximumPendingOutputBytes"] = 65535
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			fixture := newTerminalXContractFixture(t)
			envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{
				mutateBootstrap: mutate,
			})
			fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
			if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(
				t.Context(), envelope, fixture.inspected,
			); err == nil {
				captured.Close()
				t.Fatal("activation-binding drift was accepted")
			}
		})
	}
}

func TestTerminalXBootstrapResponseMustMatchCapturedSignedAssignment(t *testing.T) {
	fixture := newTerminalXContractFixture(t)
	envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{})
	fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
	captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(
		t.Context(), envelope, fixture.inspected,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer captured.Close()
	valid := terminalXContractMatchingResponse(t, captured, fixture.observationPEM)
	validBytes, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if !validTerminalXAssignmentBootstrapResponse(validBytes) ||
		!terminalXAssignmentBootstrapResponseMatches(validBytes, captured) {
		t.Fatal("matching root provisioner response rejected")
	}
	tests := map[string]func(*terminalXAssignmentBootstrapInstalledDescriptor){
		"binding digest": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.BindingDigest = strings.Repeat("9", 64)
		},
		"envelope digest": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.EnvelopeDigest = strings.Repeat("9", 64)
		},
		"effect policy digest": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.EffectEnforcerPolicyDigest = strings.Repeat("9", 64)
		},
		"effect manifest binding digest": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.EffectManifestBindingDigest = strings.Repeat("9", 64)
		},
		"effect set digest": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.EffectEnforcerSetDigest = strings.Repeat("9", 64)
		},
		"observation issuer": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.ObservationIssuerKeyID = "other-observation-key"
		},
		"observation public key digest": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.ObservationPublicKeyDigest = strings.Repeat("9", 64)
		},
		"plan binding digests": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.PlanDigest = strings.Repeat("9", 64)
			value.AssignmentPlanDigest = strings.Repeat("9", 64)
		},
		"provider commitment": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.ProviderIdentityCommitment = strings.Repeat("9", 64)
		},
		"provider revision": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.ProviderRevision++
		},
		"supervisor digest": func(value *terminalXAssignmentBootstrapInstalledDescriptor) {
			value.SupervisorArtifactDigest = strings.Repeat("9", 64)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			candidateBytes, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if !validTerminalXAssignmentBootstrapResponse(candidateBytes) {
				t.Fatal("test candidate is not a syntactically valid public descriptor")
			}
			if terminalXAssignmentBootstrapResponseMatches(candidateBytes, captured) {
				t.Fatal("root provisioner response escaped its signed assignment binding")
			}
		})
	}
}

func TestTerminalXBootstrapEnvelopeRejectsAuthorityAndFreshnessDrift(t *testing.T) {
	tests := map[string]terminalXContractEnvelopeOptions{
		"bad signature": {mutateAuthority: func(authority map[string]any) {
			authority["signature"] = strings.Repeat("A", 86)
		}},
		"wrong claims digest": {mutateAuthority: func(authority map[string]any) {
			authority["claimsDigest"] = strings.Repeat("0", 64)
		}},
		"future issued": {
			issuedAtMS:  testTerminalXContractNowMS + 1,
			expiresAtMS: testTerminalXContractNowMS + 60_001,
		},
		"expired at boundary": {
			issuedAtMS:  testTerminalXContractNowMS - 60_000,
			expiresAtMS: testTerminalXContractNowMS,
		},
		"ttl over five minutes": {
			issuedAtMS:  testTerminalXContractNowMS,
			expiresAtMS: testTerminalXContractNowMS + terminalXMaximumEvidenceTTL.Milliseconds() + 1,
		},
		"wrong audience": {mutateAuthority: func(authority map[string]any) {
			authority["audience"] = "other"
		}},
		"wrong key id": {mutateAuthority: func(authority map[string]any) {
			authority["issuerKeyId"] = "other-key"
		}},
	}
	for name, options := range tests {
		name, options := name, options
		t.Run(name, func(t *testing.T) {
			fixture := newTerminalXContractFixture(t)
			envelope, planDigest := fixture.envelope(t, options)
			fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
			if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(t.Context(), envelope, fixture.inspected); err == nil {
				captured.Close()
				t.Fatal("invalid bootstrap authority was accepted")
			}
		})
	}

	t.Run("exact maximum ttl remains valid", func(t *testing.T) {
		fixture := newTerminalXContractFixture(t)
		envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{
			issuedAtMS:  testTerminalXContractNowMS,
			expiresAtMS: testTerminalXContractNowMS + terminalXMaximumEvidenceTTL.Milliseconds(),
		})
		fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
		captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(t.Context(), envelope, fixture.inspected)
		if err != nil {
			t.Fatalf("maximum valid authority ttl rejected: %v", err)
		}
		captured.Close()
	})
}

func TestTerminalXExpiredBootstrapReplayRequiresExactProtectedInstalledMarker(t *testing.T) {
	fixture := newTerminalXContractFixture(t)
	envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{
		issuedAtMS:  testTerminalXContractNowMS - 120_000,
		expiresAtMS: testTerminalXContractNowMS - 60_000,
	})
	fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
	replayAPI := fixture.client.apiClient.(*terminalXContractReplayAPI)

	if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(
		t.Context(), envelope, fixture.inspected,
	); err == nil {
		captured.Close()
		t.Fatal("expired first installation was accepted without an installed marker")
	}

	replayAPI.marker = terminalXContractInstalledMarker(t, envelope, fixture.observationPEM)
	captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(
		t.Context(), envelope, fixture.inspected,
	)
	if err != nil {
		t.Fatalf("exact expired installed replay was rejected: %v", err)
	}
	captured.Close()

	different := bytes.Clone(envelope)
	different[len(different)-1] ^= 0x01
	if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(
		t.Context(), different, fixture.inspected,
	); err == nil {
		captured.Close()
		t.Fatal("expired envelope with a different digest reused installed replay authority")
	}

	replayAPI.marker = []byte(`{"not":"an installed descriptor"}`)
	if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(
		t.Context(), envelope, fixture.inspected,
	); err == nil {
		captured.Close()
		t.Fatal("expired replay was accepted from a malformed installed marker")
	}

	metadataDrift := map[string]func(*terminalXContractReplayAPI){
		"writable stat mode": func(api *terminalXContractReplayAPI) { api.statMode = 0o660 },
		"writable archive mode": func(api *terminalXContractReplayAPI) {
			api.headerMode = 0o660
		},
		"non-root archive uid": func(api *terminalXContractReplayAPI) { api.headerUID = 1000 },
		"non-root archive gid": func(api *terminalXContractReplayAPI) { api.headerGID = 1000 },
		"wrong archive path":   func(api *terminalXContractReplayAPI) { api.headerName = "other.json" },
		"additional archive entry": func(api *terminalXContractReplayAPI) {
			api.extraEntry = true
		},
	}
	for name, mutate := range metadataDrift {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := newTerminalXContractFixture(t)
			candidateEnvelope, candidatePlanDigest := candidate.envelope(t, terminalXContractEnvelopeOptions{
				issuedAtMS:  testTerminalXContractNowMS - 120_000,
				expiresAtMS: testTerminalXContractNowMS - 60_000,
			})
			candidate.inspected.Config.Labels["terminalx.plan"] = candidatePlanDigest
			api := candidate.client.apiClient.(*terminalXContractReplayAPI)
			api.marker = terminalXContractInstalledMarker(t, candidateEnvelope, candidate.observationPEM)
			mutate(api)
			if captured, err := candidate.client.verifyAndCaptureTerminalXBootstrapEnvelope(
				t.Context(), candidateEnvelope, candidate.inspected,
			); err == nil {
				captured.Close()
				t.Fatal("expired replay accepted an unprotected installed marker")
			}
		})
	}
}

func TestTerminalXBootstrapEnvelopeRejectsSecretSectionDrift(t *testing.T) {
	tests := map[string]terminalXContractEnvelopeOptions{
		"wrong first kind": {mutateSections: func(sections []any) {
			sections[0].(map[string]any)["kind"] = "effect-enforcer-ed25519-pkcs8"
		}},
		"zero bytes": {mutateSections: func(sections []any) {
			sections[0].(map[string]any)["bytes"] = 0
		}},
		"oversized section": {mutateSections: func(sections []any) {
			sections[0].(map[string]any)["bytes"] = 64*1024 + 1
		}},
		"wrong digest": {mutateSections: func(sections []any) {
			sections[1].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		}},
		"trailing secret bytes": {trailingSecret: []byte("not-declared")},
	}
	for name, options := range tests {
		name, options := name, options
		t.Run(name, func(t *testing.T) {
			fixture := newTerminalXContractFixture(t)
			envelope, planDigest := fixture.envelope(t, options)
			fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
			if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(t.Context(), envelope, fixture.inspected); err == nil {
				captured.Close()
				t.Fatal("invalid secret section layout was accepted")
			}
		})
	}
}

func TestTerminalXBootstrapEnvelopeRejectsContainerLabelAndResourceDrift(t *testing.T) {
	tests := map[string]func(*container.InspectResponse){
		"hostname": func(inspected *container.InspectResponse) {
			inspected.Config.Hostname = "provider-identity-leak"
		},
		"provider identity": func(inspected *container.InspectResponse) {
			inspected.Config.Env[0] = "DAYTONA_SANDBOX_ID=123e4567-e89b-42d3-a456-426614174001"
		},
		"artifact label": func(inspected *container.InspectResponse) {
			inspected.Config.Labels["terminalx.artifact"] = strings.Repeat("9", 64)
		},
		"revision label": func(inspected *container.InspectResponse) {
			inspected.Config.Labels["terminalx.revision"] = "8"
		},
		"plan label": func(inspected *container.InspectResponse) {
			inspected.Config.Labels["terminalx.plan"] = strings.Repeat("9", 64)
		},
		"cpu period": func(inspected *container.InspectResponse) {
			inspected.HostConfig.CPUPeriod++
		},
		"cpu quota": func(inspected *container.InspectResponse) {
			inspected.HostConfig.CPUQuota++
		},
		"memory": func(inspected *container.InspectResponse) {
			inspected.HostConfig.Memory++
		},
		"disk": func(inspected *container.InspectResponse) {
			inspected.HostConfig.StorageOpt["size"] = "21G"
		},
		"pids": func(inspected *container.InspectResponse) {
			value := int64(terminalXSandboxPidsLimit + 1)
			inspected.HostConfig.PidsLimit = &value
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			fixture := newTerminalXContractFixture(t)
			envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{})
			fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
			mutate(fixture.inspected)
			if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(t.Context(), envelope, fixture.inspected); err == nil {
				captured.Close()
				t.Fatal("container state drift was accepted")
			}
		})
	}
}

func TestTerminalXBootstrapEnvelopeRequiresAppCompatibleProviderUUID(t *testing.T) {
	fixture := newTerminalXContractFixture(t)
	fixture.inspected.Config.Env[0] = "DAYTONA_SANDBOX_ID=sandbox-1"
	envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{
		mutateBootstrap: func(bootstrap map[string]any) {
			bootstrap["assignment"].(map[string]any)["providerSandboxId"] = "sandbox-1"
		},
	})
	fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
	if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(
		t.Context(), envelope, fixture.inspected,
	); err == nil {
		captured.Close()
		t.Fatal("bootstrap accepted a provider identity rejected by the sandbox provisioner")
	}
}

func TestTerminalXBootstrapEnvelopeRequiresObservationAuthoritySeparation(t *testing.T) {
	tests := map[string]func(*testing.T, *terminalXContractFixture, map[string]any){
		"bootstrap key id": func(_ *testing.T, _ *terminalXContractFixture, observation map[string]any) {
			observation["issuerKeyId"] = "platform-bootstrap-1"
		},
		"isolation key id": func(_ *testing.T, _ *terminalXContractFixture, observation map[string]any) {
			observation["issuerKeyId"] = "isolation-key-1"
		},
		"bootstrap public key": func(t *testing.T, fixture *terminalXContractFixture, observation map[string]any) {
			observation["publicKeySpkiPem"] = terminalXTestPublicKeyPEM(
				t,
				fixture.authorityPrivate.Public().(ed25519.PublicKey),
			)
		},
		"isolation public key": func(_ *testing.T, fixture *terminalXContractFixture, observation map[string]any) {
			observation["publicKeySpkiPem"] = fixture.isolationPEM
		},
		"deployment key id": func(t *testing.T, fixture *terminalXContractFixture, observation map[string]any) {
			public, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			fixture.client.terminalXDeploymentBindingSigner = &terminalXEd25519Signer{
				keyID: "deployment-binding-key-1", publicKeySPKIPEM: terminalXTestPublicKeyPEM(t, public),
			}
			observation["issuerKeyId"] = "deployment-binding-key-1"
		},
		"deployment public key": func(t *testing.T, fixture *terminalXContractFixture, observation map[string]any) {
			public, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			publicPEM := terminalXTestPublicKeyPEM(t, public)
			fixture.client.terminalXDeploymentBindingSigner = &terminalXEd25519Signer{
				keyID: "deployment-binding-key-1", publicKeySPKIPEM: publicPEM,
			}
			observation["publicKeySpkiPem"] = publicPEM
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			fixture := newTerminalXContractFixture(t)
			envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{
				mutateBootstrap: func(bootstrap map[string]any) {
					assignment := bootstrap["assignment"].(map[string]any)
					plan := assignment["plan"].(map[string]any)
					mutate(t, fixture, plan["observation"].(map[string]any))
				},
			})
			fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
			if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(
				t.Context(), envelope, fixture.inspected,
			); err == nil {
				captured.Close()
				t.Fatal("bootstrap accepted a reused observation authority")
			}
		})
	}
}

func TestTerminalXHostedPlanMemoryComparisonDoesNotWrap(t *testing.T) {
	fixture := newTerminalXContractFixture(t)
	// 2^34 GiB is exactly 2^64 bytes. Adding it to 4 GiB wraps the
	// unchecked int64 conversion back to the real container's four GiB.
	const wrappingMemoryGiB = int64(4 + (1 << 34))
	envelope, planDigest := fixture.envelope(t, terminalXContractEnvelopeOptions{
		mutateBootstrap: func(bootstrap map[string]any) {
			assignment := bootstrap["assignment"].(map[string]any)
			plan := assignment["plan"].(map[string]any)
			isolation := plan["isolation"].(map[string]any)
			isolation["resources"].(map[string]any)["memoryGiB"] = wrappingMemoryGiB
		},
	})
	fixture.inspected.Config.Labels["terminalx.plan"] = planDigest
	if captured, err := fixture.client.verifyAndCaptureTerminalXBootstrapEnvelope(t.Context(), envelope, fixture.inspected); err == nil {
		captured.Close()
		t.Fatal("overflowing plan memory was accepted as matching four GiB")
	}
}

func TestTerminalXDeploymentBindingHasExactAppAuthorityShape(t *testing.T) {
	keyPath, publicDigest, _ := writeTerminalXTestSigner(t)
	signer, err := loadTerminalXEd25519Signer(
		keyPath,
		"deployment-binding-key-1",
		publicDigest,
		uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	binding, err := createTerminalXDeploymentBinding(signer, terminalXDeploymentBindingClaims{
		ExpectedSandboxImageID:     testTerminalXImageID,
		ExpectedSandboxSnapshotRef: testTerminalXSnapshotRef,
		Kind:                       terminalXDeploymentBindingKind,
		ProviderRevision:           7,
		ProviderSandboxID:          testTerminalXContractProviderID,
		SandboxArtifactDigest:      testTerminalXArtifactDigest,
		Version:                    1,
	}, time.UnixMilli(testTerminalXContractNowMS), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(binding, &value); err != nil {
		t.Fatal(err)
	}
	authority, ok := value["authority"].(map[string]any)
	if !ok {
		t.Fatal("deployment authority is not an object")
	}
	want := []string{
		"audience", "capability", "claimsDigest", "expiresAtMs",
		"issuedAtMs", "issuer", "issuerKeyId", "signature",
	}
	if len(authority) != len(want) {
		t.Fatalf("deployment authority keys = %v; app contract requires exactly %v", terminalXTestSortedKeys(authority), want)
	}
	for _, key := range want {
		if _, exists := authority[key]; !exists {
			t.Fatalf("deployment authority omitted %q", key)
		}
	}
	if _, exists := authority["version"]; exists {
		t.Fatal("deployment authority serialized statement-only version field")
	}
	// Generated independently with Node's canonicalRuntimeJson profile and
	// node:crypto from the deterministic seed used by writeTerminalXTestSigner.
	const appGolden = `{"authority":{"audience":"terminalx-assignment-bootstrap","capability":"sandbox.deployment.bind","claimsDigest":"087c91049c91e24d4040d47f0a276b46e59b0480994447641e04e939ed74e96a","expiresAtMs":1800000060000,"issuedAtMs":1800000000000,"issuer":"daytona-runner","issuerKeyId":"deployment-binding-key-1","signature":"4DmqeND4VuLf0O5sm66ukRK_--D3eMSEWwGVK8hZHBRdZDzGOWwsfphxEKIQzJBZFG2tyHMRRrY2lbCKmsrRAQ"},"expectedSandboxImageId":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expectedSandboxSnapshotRef":"registry.example/terminalx/sandbox@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"terminalx.daytona-sandbox-deployment-binding","providerRevision":7,"providerSandboxId":"123e4567-e89b-42d3-a456-426614174000","sandboxArtifactDigest":"1111111111111111111111111111111111111111111111111111111111111111","version":1}`
	if !bytes.Equal(binding, []byte(appGolden)) {
		t.Fatalf("deployment binding differs from independent app golden:\n got %s\nwant %s", binding, appGolden)
	}
}

func TestTerminalXDeploymentBindingRejectsNonUUIDProviderIdentity(t *testing.T) {
	keyPath, publicDigest, _ := writeTerminalXTestSigner(t)
	signer, err := loadTerminalXEd25519Signer(
		keyPath,
		"deployment-binding-key-1",
		publicDigest,
		uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	if _, err := createTerminalXDeploymentBinding(signer, terminalXDeploymentBindingClaims{
		ExpectedSandboxImageID:     testTerminalXImageID,
		ExpectedSandboxSnapshotRef: testTerminalXSnapshotRef,
		Kind:                       terminalXDeploymentBindingKind,
		ProviderRevision:           7,
		ProviderSandboxID:          "sandbox-1",
		SandboxArtifactDigest:      testTerminalXArtifactDigest,
		Version:                    1,
	}, time.UnixMilli(testTerminalXContractNowMS), time.Minute); err == nil {
		t.Fatal("deployment binding accepted a provider identity rejected by the app and image installer")
	}
}

func terminalXTestSortedKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	// Avoid importing slices only for a test failure diagnostic.
	for left := 0; left < len(keys); left++ {
		for right := left + 1; right < len(keys); right++ {
			if keys[right] < keys[left] {
				keys[left], keys[right] = keys[right], keys[left]
			}
		}
	}
	return keys
}

func TestTerminalXCanonicalJSONMatchesRuntimeCanonicalProfile(t *testing.T) {
	t.Run("unicode line separators remain literal like JSON.stringify", func(t *testing.T) {
		value := map[string]any{"value": "left\u2028middle\u2029right"}
		actual, err := marshalTerminalXCanonicalJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		expected := []byte("{\"value\":\"left\u2028middle\u2029right\"}")
		if !bytes.Equal(actual, expected) {
			t.Fatalf("Go canonical JSON %q differs from TypeScript canonicalRuntimeJson %q", actual, expected)
		}
		canonical, _, err := canonicalizeTerminalXJSON(expected, 1024)
		if err != nil || !bytes.Equal(canonical, expected) {
			t.Fatalf("TypeScript canonical JSON was rejected: %v", err)
		}
	})

	t.Run("depth is bounded to 32", func(t *testing.T) {
		atLimit := terminalXTestNestedCanonicalValue(32)
		atLimitBytes, err := json.Marshal(atLimit)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonicalizeTerminalXJSON(atLimitBytes, len(atLimitBytes)); err != nil {
			t.Fatalf("canonical depth limit was rejected: %v", err)
		}
		tooDeep := terminalXTestNestedCanonicalValue(33)
		tooDeepBytes, err := json.Marshal(tooDeep)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonicalizeTerminalXJSON(tooDeepBytes, len(tooDeepBytes)); err == nil {
			t.Fatal("canonical value deeper than the app's depth limit was accepted")
		}
	})

	t.Run("record fields are bounded to 1000", func(t *testing.T) {
		value := make(map[string]any, 1001)
		for index := 0; index < 1001; index++ {
			value[fmt.Sprintf("field-%04d", index)] = true
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonicalizeTerminalXJSON(encoded, len(encoded)); err == nil {
			t.Fatal("record beyond the app's field limit was accepted")
		}
	})

	t.Run("string budget is bounded to one megabyte", func(t *testing.T) {
		value := map[string]any{"value": strings.Repeat("x", 1_000_001)}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonicalizeTerminalXJSON(encoded, len(encoded)); err == nil {
			t.Fatal("value beyond the app's canonical string budget was accepted")
		}
	})

	t.Run("unpaired UTF-16 surrogate is rejected at the portability boundary", func(t *testing.T) {
		if _, _, err := canonicalizeTerminalXJSON([]byte(`{"value":"\ud800"}`), 1024); err == nil {
			t.Fatal("non-portable unpaired surrogate was accepted")
		}
	})
}

func terminalXTestNestedCanonicalValue(depth int) any {
	var value any = true
	for index := 0; index < depth; index++ {
		value = map[string]any{"value": value}
	}
	return value
}

func TestTerminalXSignerCloseIsIdempotentAndRaceSafe(t *testing.T) {
	keyPath, publicDigest, publicKey := writeTerminalXTestSigner(t)
	signer, err := loadTerminalXEd25519Signer(
		keyPath,
		"deployment-binding-key-1",
		publicDigest,
		uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			signature, signErr := signer.sign("terminalx/test/v1\x00", map[string]any{"version": 1})
			if signErr != nil {
				return // Close won the mutex, which is an allowed result.
			}
			decoded, decodeErr := base64.RawURLEncoding.DecodeString(signature)
			message := []byte("terminalx/test/v1\x00{\"version\":1}")
			if decodeErr != nil || !ed25519.Verify(publicKey, message, decoded) {
				t.Errorf("concurrent signature was invalid")
			}
		}()
	}
	close(start)
	signer.Close()
	signer.Close()
	wait.Wait()
	if signer.privateKey != nil || !signer.closed {
		t.Fatal("closed signer retained private key state")
	}
}

func TestTerminalXSignerRejectsHardLinksAndNonCanonicalPEM(t *testing.T) {
	t.Run("hard link", func(t *testing.T) {
		keyPath, publicDigest, _ := writeTerminalXTestSigner(t)
		linked := filepath.Join(filepath.Dir(keyPath), "second-name.pem")
		if err := os.Link(keyPath, linked); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTerminalXEd25519Signer(
			keyPath, "deployment-binding-key-1", publicDigest, uint32(os.Getuid()),
		); err == nil {
			t.Fatal("multiply-linked private key was accepted")
		}
	})

	t.Run("extra pem bytes", func(t *testing.T) {
		keyPath, publicDigest, _ := writeTerminalXTestSigner(t)
		if err := os.Chmod(keyPath, 0o600); err != nil {
			t.Fatal(err)
		}
		value, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		value = append(value, '\n')
		if err := os.WriteFile(keyPath, value, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keyPath, 0o400); err != nil {
			t.Fatal(err)
		}
		zeroTerminalXBytes(value)
		if _, err := loadTerminalXEd25519Signer(
			keyPath, "deployment-binding-key-1", publicDigest, uint32(os.Getuid()),
		); err == nil {
			t.Fatal("non-canonical private PEM was accepted")
		}
	})
}

func TestTerminalXPublicKeyLoaderPinsCanonicalSPKIFile(t *testing.T) {
	keyPath, _, publicKey := writeTerminalXTestSigner(t)
	publicPEM := []byte(terminalXTestPublicKeyPEM(t, publicKey))
	publicDigest := terminalXTestRawDigest(publicPEM)
	publicPath := filepath.Join(filepath.Dir(keyPath), "bootstrap-authority.pem")
	if err := os.WriteFile(publicPath, publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicPath, 0o444); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadTerminalXEd25519PublicKey(
		publicPath,
		publicDigest,
		uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatalf("canonical pinned public key rejected: %v", err)
	}
	if !bytes.Equal(loaded, publicKey) {
		t.Fatal("loaded public key changed")
	}
	loaded[0] ^= 0xff
	if bytes.Equal(loaded, publicKey) {
		t.Fatal("public key loader returned aliased key storage")
	}
	if _, err := loadTerminalXEd25519PublicKey(
		publicPath,
		strings.Repeat("0", 64),
		uint32(os.Getuid()),
	); err == nil {
		t.Fatal("wrong public key digest was accepted")
	}
	if err := os.Chmod(publicPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTerminalXEd25519PublicKey(
		publicPath,
		publicDigest,
		uint32(os.Getuid()),
	); err == nil {
		t.Fatal("writable public trust key was accepted")
	}
	zeroTerminalXBytes(publicPEM)
}

func TestDockerClientClosesBothTerminalXSigningIdentities(t *testing.T) {
	firstPath, firstDigest, _ := writeTerminalXTestSigner(t)
	first, err := loadTerminalXEd25519Signer(
		firstPath, "deployment-binding-key-1", firstDigest, uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondPath, secondDigest, _ := writeTerminalXTestSigner(t)
	second, err := loadTerminalXEd25519Signer(
		secondPath, "isolation-key-1", secondDigest, uint32(os.Getuid()),
	)
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	client := &DockerClient{
		terminalXDeploymentBindingSigner: first,
		terminalXIsolationAttestorSigner: second,
	}
	client.CloseTerminalXSecrets()
	client.CloseTerminalXSecrets()
	if !first.closed || first.privateKey != nil || !second.closed || second.privateKey != nil {
		t.Fatal("Docker client shutdown retained a TerminalX signing identity")
	}
}

func TestTerminalXAttestationAuthoritiesRemainCryptographicallySeparated(t *testing.T) {
	valid := func() DockerClientConfig {
		return DockerClientConfig{
			TerminalXDeploymentBindingInstallerSHA256:  strings.Repeat("1", 64),
			TerminalXIsolationProbeSHA256:              strings.Repeat("2", 64),
			TerminalXSandboxArtifactDigest:             strings.Repeat("3", 64),
			TerminalXSeccompProfileSHA256:              strings.Repeat("4", 64),
			TerminalXRunnerSourceCommit:                testTerminalXHardenedCommit,
			TerminalXRunnerBinaryDigest:                strings.Repeat("8", 64),
			TerminalXDeploymentBindingKeyID:            "deployment-binding-key-1",
			TerminalXDeploymentBindingPrivateKeyFile:   "/run/terminalx-secrets/deployment-binding.pem",
			TerminalXDeploymentBindingPublicKeySHA256:  strings.Repeat("5", 64),
			TerminalXIsolationAttestorKeyID:            "isolation-attestor-key-1",
			TerminalXIsolationAttestorPrivateKeyFile:   "/run/terminalx-secrets/isolation-attestor.pem",
			TerminalXIsolationAttestorPublicKeySHA256:  strings.Repeat("6", 64),
			TerminalXBootstrapAuthorityKeyID:           "platform-bootstrap-key-1",
			TerminalXBootstrapAuthorityPublicKeySHA256: strings.Repeat("7", 64),
			TerminalXEvidenceTTL:                       time.Minute,
			TerminalXDaytonaDaemonUID:                  terminalXSandboxUserUID,
			TerminalXAgentUID:                          terminalXSandboxUserUID,
		}
	}
	if err := validateTerminalXAttestationRequirements(valid()); err != nil {
		t.Fatalf("valid separated attestation identities rejected: %v", err)
	}
	tests := map[string]func(*DockerClientConfig){
		"base source revision": func(value *DockerClientConfig) {
			value.TerminalXRunnerSourceCommit = terminalXDaytonaBaseCommit
		},
		"uppercase runner digest": func(value *DockerClientConfig) {
			value.TerminalXRunnerBinaryDigest = strings.Repeat("A", 64)
		},
		"bootstrap key id equals deployment": func(value *DockerClientConfig) {
			value.TerminalXBootstrapAuthorityKeyID = value.TerminalXDeploymentBindingKeyID
		},
		"bootstrap key id equals isolation": func(value *DockerClientConfig) {
			value.TerminalXBootstrapAuthorityKeyID = value.TerminalXIsolationAttestorKeyID
		},
		"bootstrap public key equals deployment": func(value *DockerClientConfig) {
			value.TerminalXBootstrapAuthorityPublicKeySHA256 = value.TerminalXDeploymentBindingPublicKeySHA256
		},
		"bootstrap public key equals isolation": func(value *DockerClientConfig) {
			value.TerminalXBootstrapAuthorityPublicKeySHA256 = value.TerminalXIsolationAttestorPublicKeySHA256
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			configuration := valid()
			mutate(&configuration)
			if err := validateTerminalXAttestationRequirements(configuration); err == nil {
				t.Fatal("collapsed attestation identity boundary was accepted")
			}
		})
	}
}
