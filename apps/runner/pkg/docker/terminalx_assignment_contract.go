// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
)

const (
	terminalXAssignmentBootstrapKind               = "terminalx.daytona-assignment-bootstrap"
	terminalXAssignmentBootstrapClaimsDigestDomain = "terminalx/daytona-assignment-bootstrap-claims/v1\x00"
	terminalXAssignmentBootstrapSignatureDomain    = "terminalx/daytona-assignment-bootstrap-authority/v1\x00"
	terminalXHostedPlanDigestDomain                = "terminalx/hosted-runtime-assignment-plan/v1\x00"
	terminalXAssignmentEnvelopeDigestDomain        = "terminalx/daytona-assignment-bootstrap-envelope/v1\x00"
	terminalXBootstrapHeaderMaxBytes               = 2 * 1024 * 1024
	terminalXAssignmentInstalledMarkerPath         = "/run/terminalx-root/assignment.installed.json"
	terminalXInstalledBootstrapPath                = "/run/terminalx-root/assignment/bootstrap.json"
)

var errTerminalXBootstrapReplayStateUnavailable = fmt.Errorf("terminalx bootstrap replay state is unavailable")

var terminalXSafeTextReference = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,300}$`)

type terminalXBootstrapEnvelopeHeader struct {
	Authority terminalXBootstrapEnvelopeAuthority       `json:"authority"`
	Bootstrap terminalXSupervisorBootstrapConfiguration `json:"bootstrap"`
	Kind      string                                    `json:"kind"`
	Sections  []terminalXBootstrapEnvelopeSection       `json:"sections"`
	Version   int                                       `json:"version"`
}

type terminalXBootstrapEnvelopeAuthority struct {
	Audience     string `json:"audience"`
	Capability   string `json:"capability"`
	ClaimsDigest string `json:"claimsDigest"`
	ExpiresAtMS  int64  `json:"expiresAtMs"`
	IssuedAtMS   int64  `json:"issuedAtMs"`
	Issuer       string `json:"issuer"`
	IssuerKeyID  string `json:"issuerKeyId"`
	Signature    string `json:"signature"`
}

type terminalXBootstrapEnvelopeStatement struct {
	Audience     string `json:"audience"`
	Capability   string `json:"capability"`
	ClaimsDigest string `json:"claimsDigest"`
	ExpiresAtMS  int64  `json:"expiresAtMs"`
	IssuedAtMS   int64  `json:"issuedAtMs"`
	Issuer       string `json:"issuer"`
	IssuerKeyID  string `json:"issuerKeyId"`
	Version      int    `json:"version"`
}

type terminalXBootstrapEnvelopeSection struct {
	Bytes  uint64 `json:"bytes"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

type terminalXSupervisorBootstrapConfiguration struct {
	Assignment       terminalXBootstrapAssignment `json:"assignment"`
	CommandAuthority json.RawMessage              `json:"commandAuthority"`
	Effect           terminalXBootstrapEffect     `json:"effect"`
	Isolation        terminalXBootstrapIsolation  `json:"isolation"`
	Kind             string                       `json:"kind"`
	Observation      json.RawMessage              `json:"observation"`
	State            json.RawMessage              `json:"state"`
	Terminal         terminalXBootstrapTerminal   `json:"terminal"`
	Transport        json.RawMessage              `json:"transport"`
	Version          int                          `json:"version"`
}

type terminalXBootstrapAssignment struct {
	ArtifactDigest           string          `json:"artifactDigest"`
	EffectEnforcerSetDigest  string          `json:"effectEnforcerSetDigest"`
	ExpectedRevision         uint64          `json:"expectedRevision"`
	MaxOperations            uint64          `json:"maxOperations"`
	Plan                     json.RawMessage `json:"plan"`
	ProviderSandboxID        string          `json:"providerSandboxId"`
	SandboxUser              string          `json:"sandboxUser"`
	SupervisorArtifactDigest string          `json:"supervisorArtifactDigest"`
}

type terminalXBootstrapEffect struct {
	ExecutableFile                    string                  `json:"executableFile"`
	ExecutableRoot                    string                  `json:"executableRoot"`
	ExecutableSHA256                  string                  `json:"executableSha256"`
	Manifest                          terminalXEffectManifest `json:"manifest"`
	MaximumInputBytes                 uint64                  `json:"maximumInputBytes"`
	MaximumOutputBytes                uint64                  `json:"maximumOutputBytes"`
	PinnedManifestAuthorityPublicKeys []json.RawMessage       `json:"pinnedManifestAuthorityPublicKeys"`
	TimeoutMS                         uint64                  `json:"timeoutMs"`
}

type terminalXEffectManifest struct {
	AssignmentPlanDigest        string                           `json:"assignmentPlanDigest"`
	Authority                   terminalXEffectManifestAuthority `json:"authority"`
	EffectEnforcerPolicyDigest  string                           `json:"effectEnforcerPolicyDigest"`
	EffectManifestBindingDigest string                           `json:"effectManifestBindingDigest"`
	Enforcers                   []json.RawMessage                `json:"enforcers"`
	ExpiresAtMS                 int64                            `json:"expiresAtMs"`
	Kind                        string                           `json:"kind"`
	ManifestID                  string                           `json:"manifestId"`
	ProviderIdentityCommitment  string                           `json:"providerIdentityCommitment"`
	ProviderRevision            uint64                           `json:"providerRevision"`
	ValidFromMS                 int64                            `json:"validFromMs"`
	Version                     int                              `json:"version"`
}

type terminalXEffectManifestAuthority struct {
	Audience     string `json:"audience"`
	Capability   string `json:"capability"`
	ClaimsDigest string `json:"claimsDigest"`
	ExpiresAtMS  int64  `json:"expiresAtMs"`
	IssuedAtMS   int64  `json:"issuedAtMs"`
	Issuer       string `json:"issuer"`
	IssuerKeyID  string `json:"issuerKeyId"`
	Signature    string `json:"signature"`
}

type terminalXBootstrapTerminal struct {
	MaximumLifetimeMS            uint64 `json:"maximumLifetimeMs"`
	MaximumOutputFrameBytes      uint64 `json:"maximumOutputFrameBytes"`
	MaximumPendingOutputBytes    uint64 `json:"maximumPendingOutputBytes"`
	MaximumPendingWebSocketBytes uint64 `json:"maximumPendingWebSocketBytes"`
	MaximumTerminals             uint64 `json:"maximumTerminals"`
	MaximumTerminalsPerSandbox   uint64 `json:"maximumTerminalsPerSandbox"`
	RequestTimeoutMS             uint64 `json:"requestTimeoutMs"`
}

type terminalXBootstrapIsolation struct {
	AttestationFile              string `json:"attestationFile"`
	ExpectedAgentUID             int    `json:"expectedAgentUid"`
	ExpectedContainerdVersion    string `json:"expectedContainerdVersion"`
	ExpectedDaytonaDaemonUID     int    `json:"expectedDaytonaDaemonUid"`
	ExpectedDockerVersion        string `json:"expectedDockerVersion"`
	ExpectedProviderRevision     uint64 `json:"expectedProviderRevision"`
	ExpectedRunnerBinaryDigest   string `json:"expectedRunnerBinaryDigest"`
	ExpectedSandboxImageID       string `json:"expectedSandboxImageId"`
	ExpectedSandboxSnapshotRef   string `json:"expectedSandboxSnapshotRef"`
	ExpectedSandboxUser          string `json:"expectedSandboxUser"`
	ExpectedSeccompProfileDigest string `json:"expectedSeccompProfileDigest"`
	ExpectedSupervisorUID        int    `json:"expectedSupervisorUid"`
	HardenedDaytonaSourceCommit  string `json:"hardenedDaytonaSourceCommit"`
	IssuerKeyID                  string `json:"issuerKeyId"`
	IssuerPublicKeySPKIPEM       string `json:"issuerPublicKeySpkiPem"`
	MaximumAttestationTTLMS      int64  `json:"maximumAttestationTtlMs"`
}

type terminalXHostedPlan struct {
	AdapterConfigurationRef        string                          `json:"adapterConfigurationRef"`
	Binding                        json.RawMessage                 `json:"binding"`
	Capabilities                   terminalXHostedPlanCapabilities `json:"capabilities"`
	EffectEnforcerPolicyDigest     string                          `json:"effectEnforcerPolicyDigest"`
	Incarnation                    string                          `json:"incarnation"`
	Isolation                      terminalXHostedPlanIsolation    `json:"isolation"`
	Observation                    terminalXHostedPlanObservation  `json:"observation"`
	RuntimeAuthorizationGeneration uint64                          `json:"runtimeAuthorizationGeneration"`
	SpecificationDigest            string                          `json:"specificationDigest"`
}

type terminalXHostedPlanCapabilities struct {
	BrokeredCredentials bool `json:"brokeredCredentials"`
	Checkpoints         bool `json:"checkpoints"`
	IsolatedExecution   bool `json:"isolatedExecution"`
	ProxyOnlyEgress     bool `json:"proxyOnlyEgress"`
	YoloEligible        bool `json:"yoloEligible"`
}

type terminalXHostedPlanIsolation struct {
	HostMounts            bool                         `json:"hostMounts"`
	IsolationPolicyDigest string                       `json:"isolationPolicyDigest"`
	LinkedSandbox         bool                         `json:"linkedSandbox"`
	Network               terminalXHostedPlanNetwork   `json:"network"`
	PublicAccess          bool                         `json:"publicAccess"`
	Resources             terminalXHostedPlanResources `json:"resources"`
	RootIdentity          bool                         `json:"rootIdentity"`
}

type terminalXHostedPlanNetwork struct {
	AllowedDestinations []string `json:"allowedDestinations"`
	Mode                string   `json:"mode"`
	PolicyDigest        string   `json:"policyDigest"`
}

type terminalXHostedPlanResources struct {
	CPU       int64 `json:"cpu"`
	DiskGiB   int64 `json:"diskGiB"`
	MemoryGiB int64 `json:"memoryGiB"`
	Pids      int64 `json:"pids"`
}

type terminalXHostedPlanObservation struct {
	IssuerKeyID        string `json:"issuerKeyId"`
	KeyProvisioningRef string `json:"keyProvisioningRef"`
	PublicKeySPKIPEM   string `json:"publicKeySpkiPem"`
}

type terminalXAssignmentEvidenceConfiguration struct {
	Assignment     terminalXBootstrapAssignment
	Effect         terminalXBootstrapEffect
	Isolation      terminalXBootstrapIsolation
	Plan           terminalXHostedPlan
	PlanBytes      []byte
	PlanDigest     string
	EnvelopeDigest string
}

func (configuration *terminalXAssignmentEvidenceConfiguration) Close() {
	if configuration == nil {
		return
	}
	zeroTerminalXBytes(configuration.PlanBytes)
	configuration.PlanBytes = nil
}

func (d *DockerClient) verifyAndCaptureTerminalXBootstrapEnvelope(
	ctx context.Context,
	input []byte,
	inspected *container.InspectResponse,
) (*terminalXAssignmentEvidenceConfiguration, error) {
	if len(input) < 6 || len(input) > int(terminalXAssignmentBootstrapMaximumRequestBytes) ||
		inspected == nil || inspected.Config == nil || inspected.HostConfig == nil {
		return nil, fmt.Errorf("terminalx assignment bootstrap contract is invalid")
	}
	headerLength := int(binary.BigEndian.Uint32(input[:4]))
	if headerLength < 2 || headerLength > terminalXBootstrapHeaderMaxBytes || 4+headerLength >= len(input) {
		return nil, fmt.Errorf("terminalx assignment bootstrap contract is invalid")
	}
	headerBytes := input[4 : 4+headerLength]
	envelopeDigestValue := sha256.New()
	_, _ = envelopeDigestValue.Write([]byte(terminalXAssignmentEnvelopeDigestDomain))
	_, _ = envelopeDigestValue.Write(input)
	envelopeDigest := hex.EncodeToString(envelopeDigestValue.Sum(nil))
	_, genericHeader, err := canonicalizeTerminalXJSON(headerBytes, terminalXBootstrapHeaderMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("terminalx assignment bootstrap contract is invalid")
	}
	headerObject, err := terminalXExactObject(genericHeader,
		"authority", "bootstrap", "kind", "sections", "version")
	if err != nil {
		return nil, err
	}
	if err := validateTerminalXBootstrapObjectShape(headerObject); err != nil {
		return nil, err
	}

	var header terminalXBootstrapEnvelopeHeader
	decoder := json.NewDecoder(bytes.NewReader(headerBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&header); err != nil || header.Version != 1 ||
		header.Kind != terminalXAssignmentBootstrapKind || len(header.Sections) != 2 {
		return nil, fmt.Errorf("terminalx assignment bootstrap contract is invalid")
	}
	clock := d.terminalXClock
	if clock == nil {
		clock = time.Now
	}
	now := clock().UnixMilli()
	authorityFresh := header.Authority.IssuedAtMS <= now && now < header.Authority.ExpiresAtMS
	installedReplay := false
	if !authorityFresh {
		installedReplay, err = d.isTerminalXInstalledEnvelopeReplay(ctx, inspected.ID, envelopeDigest)
		if err != nil {
			return nil, errTerminalXBootstrapReplayStateUnavailable
		}
	}
	if err := d.verifyTerminalXBootstrapAuthority(headerObject, header.Authority, now, installedReplay); err != nil {
		return nil, err
	}
	if err := verifyTerminalXBootstrapSections(input[4+headerLength:], header.Sections); err != nil {
		return nil, err
	}

	return d.captureTerminalXAssignmentEvidenceConfiguration(header.Bootstrap, inspected, envelopeDigest)
}

func (d *DockerClient) captureTerminalXAssignmentEvidenceConfiguration(
	bootstrap terminalXSupervisorBootstrapConfiguration,
	inspected *container.InspectResponse,
	envelopeDigest string,
) (*terminalXAssignmentEvidenceConfiguration, error) {
	if inspected == nil || inspected.Config == nil || inspected.HostConfig == nil ||
		d.terminalXIsolationAttestorSigner == nil {
		return nil, fmt.Errorf("terminalx assignment bootstrap contract is unavailable")
	}
	assignment := bootstrap.Assignment
	isolation := bootstrap.Isolation
	providerSandboxID, environmentMatches := terminalXProviderSandboxIDFromEnvironment(
		inspected.Config.Env,
		d.terminalXSandboxSnapshotRef,
	)
	if bootstrap.Version != 1 || bootstrap.Kind != "terminalx.daytona-supervisor-bootstrap" ||
		assignment.SandboxUser != terminalXSandboxUser || isolation.ExpectedSandboxUser != terminalXSandboxUser ||
		!terminalXProviderSandboxUUID.MatchString(assignment.ProviderSandboxID) ||
		inspected.Config.Hostname != terminalXHardenedHostname || !environmentMatches ||
		assignment.ProviderSandboxID != providerSandboxID ||
		isolation.ExpectedProviderRevision != assignment.ExpectedRevision ||
		assignment.ExpectedRevision < 1 || assignment.ExpectedRevision > terminalXJavaScriptMaximumSafeInteger ||
		isolation.ExpectedProviderRevision > terminalXJavaScriptMaximumSafeInteger ||
		isolation.ExpectedSupervisorUID != 0 || isolation.ExpectedDaytonaDaemonUID != d.terminalXDaytonaDaemonUID ||
		isolation.ExpectedAgentUID != d.terminalXAgentUID ||
		!terminalXSha256Raw.MatchString(isolation.ExpectedRunnerBinaryDigest) ||
		isolation.ExpectedRunnerBinaryDigest != d.terminalXRunnerBinaryDigest ||
		isolation.ExpectedSandboxImageID != d.terminalXSandboxImageID ||
		isolation.ExpectedSandboxSnapshotRef != d.terminalXSandboxSnapshotRef ||
		isolation.HardenedDaytonaSourceCommit != d.terminalXRunnerSourceCommit ||
		isolation.ExpectedSeccompProfileDigest != d.terminalXSeccompProfileSHA256 ||
		isolation.ExpectedDockerVersion != d.terminalXDockerVersion ||
		isolation.ExpectedContainerdVersion != d.terminalXContainerdVersion ||
		isolation.IssuerKeyID != d.terminalXIsolationAttestorSigner.keyID ||
		isolation.IssuerPublicKeySPKIPEM != d.terminalXIsolationAttestorSigner.publicKeySPKIPEM ||
		isolation.MaximumAttestationTTLMS < d.terminalXEvidenceTTL.Milliseconds() ||
		isolation.MaximumAttestationTTLMS > terminalXMaximumEvidenceTTL.Milliseconds() ||
		!terminalXSha256Raw.MatchString(assignment.ArtifactDigest) ||
		assignment.ArtifactDigest != d.terminalXSandboxArtifactDigest ||
		!terminalXSha256Raw.MatchString(assignment.SupervisorArtifactDigest) ||
		!terminalXSha256Raw.MatchString(assignment.EffectEnforcerSetDigest) ||
		assignment.MaxOperations < 1 || assignment.MaxOperations > terminalXJavaScriptMaximumSafeInteger ||
		!validTerminalXBootstrapTerminal(bootstrap.Terminal) {
		return nil, fmt.Errorf("terminalx assignment bootstrap contract does not match runner evidence")
	}
	if inspected.Config.Labels[terminalXSandboxArtifactDigestLabel] != assignment.ArtifactDigest ||
		inspected.Config.Labels[terminalXSandboxRevisionLabel] != strconv.FormatUint(assignment.ExpectedRevision, 10) {
		return nil, fmt.Errorf("terminalx assignment bootstrap does not match durable container identity")
	}

	var plan terminalXHostedPlan
	planDecoder := json.NewDecoder(bytes.NewReader(assignment.Plan))
	planDecoder.DisallowUnknownFields()
	if err := planDecoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("terminalx hosted plan is invalid")
	}
	planDigestValue := sha256.New()
	_, _ = planDigestValue.Write([]byte(terminalXHostedPlanDigestDomain))
	_, _ = planDigestValue.Write(assignment.Plan)
	planDigest := hex.EncodeToString(planDigestValue.Sum(nil))
	providerDigest := sha256.Sum256([]byte(
		"terminalx/daytona-provider-identity/v1\x00" + assignment.ProviderSandboxID,
	))
	manifest := bootstrap.Effect.Manifest
	if inspected.Config.Labels[terminalXSandboxPlanDigestLabel] != planDigest ||
		!validTerminalXHostedPlan(plan, inspected.HostConfig) ||
		manifest.Version != 1 || manifest.Kind != "runtime.effect-enforcer-manifest" ||
		!terminalXSafeTextReference.MatchString(manifest.ManifestID) ||
		manifest.AssignmentPlanDigest != planDigest ||
		manifest.EffectEnforcerPolicyDigest != plan.EffectEnforcerPolicyDigest ||
		manifest.ProviderIdentityCommitment != hex.EncodeToString(providerDigest[:]) ||
		manifest.ProviderRevision != assignment.ExpectedRevision ||
		!terminalXSha256Raw.MatchString(manifest.EffectManifestBindingDigest) ||
		manifest.Authority.ClaimsDigest != assignment.EffectEnforcerSetDigest {
		return nil, fmt.Errorf("terminalx hosted plan does not match enforced container state")
	}
	observationPublicKey, err := parseTerminalXCanonicalEd25519PublicKey(plan.Observation.PublicKeySPKIPEM)
	if err != nil {
		return nil, err
	}
	if plan.Observation.IssuerKeyID == d.terminalXBootstrapAuthorityKeyID ||
		plan.Observation.IssuerKeyID == d.terminalXIsolationAttestorSigner.keyID ||
		plan.Observation.PublicKeySPKIPEM == d.terminalXIsolationAttestorSigner.publicKeySPKIPEM ||
		bytes.Equal(observationPublicKey, d.terminalXBootstrapAuthorityPublicKey) ||
		d.terminalXDeploymentBindingSigner != nil &&
			(plan.Observation.IssuerKeyID == d.terminalXDeploymentBindingSigner.keyID ||
				plan.Observation.PublicKeySPKIPEM == d.terminalXDeploymentBindingSigner.publicKeySPKIPEM) {
		return nil, fmt.Errorf("terminalx assignment observation identity is not cryptographically separated")
	}
	return &terminalXAssignmentEvidenceConfiguration{
		Assignment:     assignment,
		Effect:         bootstrap.Effect,
		Isolation:      isolation,
		Plan:           plan,
		PlanBytes:      bytes.Clone(assignment.Plan),
		PlanDigest:     planDigest,
		EnvelopeDigest: envelopeDigest,
	}, nil
}

func (d *DockerClient) verifyTerminalXBootstrapAuthority(
	header map[string]any,
	authority terminalXBootstrapEnvelopeAuthority,
	now int64,
	allowExpiredReplay bool,
) error {
	if authority.Issuer != "platform-security" || authority.IssuerKeyID != d.terminalXBootstrapAuthorityKeyID ||
		authority.Audience != "terminalx-sandbox-init" ||
		authority.Capability != "runtime.assignment.bootstrap" ||
		!terminalXSha256Raw.MatchString(authority.ClaimsDigest) ||
		authority.IssuedAtMS < 0 || authority.ExpiresAtMS <= authority.IssuedAtMS ||
		(!allowExpiredReplay && (authority.IssuedAtMS > now || now >= authority.ExpiresAtMS)) ||
		authority.ExpiresAtMS-authority.IssuedAtMS > terminalXMaximumEvidenceTTL.Milliseconds() ||
		authority.ExpiresAtMS > int64(terminalXJavaScriptMaximumSafeInteger) {
		return fmt.Errorf("terminalx assignment bootstrap authority is invalid")
	}
	claims := map[string]any{
		"bootstrap": header["bootstrap"],
		"kind":      header["kind"],
		"sections":  header["sections"],
		"version":   header["version"],
	}
	claimsBytes, err := marshalTerminalXCanonicalJSON(claims)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(terminalXAssignmentBootstrapClaimsDigestDomain))
	_, _ = digest.Write(claimsBytes)
	expectedDigest := digest.Sum(nil)
	actualDigest, err := hex.DecodeString(authority.ClaimsDigest)
	if err != nil || len(actualDigest) != sha256.Size ||
		subtle.ConstantTimeCompare(expectedDigest, actualDigest) != 1 {
		return fmt.Errorf("terminalx assignment bootstrap claims are invalid")
	}
	statement := terminalXBootstrapEnvelopeStatement{
		Audience: authority.Audience, Capability: authority.Capability,
		ClaimsDigest: authority.ClaimsDigest, ExpiresAtMS: authority.ExpiresAtMS,
		IssuedAtMS: authority.IssuedAtMS, Issuer: authority.Issuer,
		IssuerKeyID: authority.IssuerKeyID, Version: 1,
	}
	statementBytes, err := marshalTerminalXCanonicalJSON(statement)
	if err != nil {
		return err
	}
	message := append([]byte(terminalXAssignmentBootstrapSignatureDomain), statementBytes...)
	signature, err := base64.RawURLEncoding.DecodeString(authority.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(d.terminalXBootstrapAuthorityPublicKey, message, signature) {
		return fmt.Errorf("terminalx assignment bootstrap signature is invalid")
	}
	return nil
}

func (d *DockerClient) isTerminalXInstalledEnvelopeReplay(
	ctx context.Context,
	containerID string,
	envelopeDigest string,
) (bool, error) {
	if d.apiClient == nil {
		return false, errTerminalXBootstrapReplayStateUnavailable
	}
	archive, stat, err := d.apiClient.CopyFromContainer(ctx, containerID, terminalXAssignmentInstalledMarkerPath)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	defer archive.Close()
	name := path.Base(terminalXAssignmentInstalledMarkerPath)
	if stat.Name != name || stat.Size < 2 || stat.Size > terminalXAssignmentBootstrapMaximumResponseBytes ||
		!stat.Mode.IsRegular() || stat.Mode.Perm() != 0o600 || stat.Mode&terminalXUnsafeFileMode != 0 ||
		stat.LinkTarget != "" {
		return false, fmt.Errorf("terminalx installed assignment marker metadata is invalid")
	}
	tarReader := tar.NewReader(archive)
	header, err := tarReader.Next()
	if err != nil || header == nil || header.Name != name || header.Linkname != "" ||
		header.Typeflag != tar.TypeReg || header.Size != stat.Size || header.Uid != 0 || header.Gid != 0 ||
		header.FileInfo().Mode().Perm() != 0o600 || header.FileInfo().Mode()&terminalXUnsafeFileMode != 0 {
		return false, fmt.Errorf("terminalx installed assignment marker archive is invalid")
	}
	value := make([]byte, header.Size)
	defer zeroTerminalXBytes(value)
	if _, err := io.ReadFull(tarReader, value); err != nil {
		return false, fmt.Errorf("terminalx installed assignment marker is incomplete")
	}
	if _, err := tarReader.Next(); err != io.EOF || !validTerminalXAssignmentBootstrapResponse(value) {
		return false, fmt.Errorf("terminalx installed assignment marker is invalid")
	}
	var descriptor terminalXAssignmentBootstrapInstalledDescriptor
	if json.Unmarshal(value, &descriptor) != nil {
		return false, fmt.Errorf("terminalx installed assignment marker is invalid")
	}
	return descriptor.EnvelopeDigest == envelopeDigest, nil
}

func (d *DockerClient) readTerminalXInstalledAssignmentConfiguration(
	ctx context.Context,
	inspected *container.InspectResponse,
) (*terminalXAssignmentEvidenceConfiguration, error) {
	value, err := d.readTerminalXRootPrivateRegularFile(
		ctx,
		inspected.ID,
		terminalXInstalledBootstrapPath,
		2*1024*1024,
	)
	if err != nil {
		return nil, err
	}
	defer zeroTerminalXBytes(value)
	_, generic, err := canonicalizeTerminalXJSON(value, 2*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("terminalx installed bootstrap is invalid")
	}
	bootstrapObject, ok := generic.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("terminalx installed bootstrap is invalid")
	}
	syntheticHeader := map[string]any{
		"authority": map[string]any{
			"audience": "", "capability": "", "claimsDigest": "", "expiresAtMs": float64(1),
			"issuedAtMs": float64(0), "issuer": "", "issuerKeyId": "", "signature": "",
		},
		"bootstrap": bootstrapObject,
		"kind":      terminalXAssignmentBootstrapKind,
		"sections": []any{
			map[string]any{"bytes": float64(1), "kind": "observation-ed25519-pkcs8", "sha256": strings.Repeat("0", 64)},
			map[string]any{"bytes": float64(1), "kind": "effect-enforcer-ed25519-pkcs8", "sha256": strings.Repeat("0", 64)},
		},
		"version": float64(1),
	}
	if err := validateTerminalXBootstrapObjectShape(syntheticHeader); err != nil {
		return nil, fmt.Errorf("terminalx installed bootstrap is invalid")
	}
	var bootstrap terminalXSupervisorBootstrapConfiguration
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bootstrap); err != nil {
		return nil, fmt.Errorf("terminalx installed bootstrap is invalid")
	}
	return d.captureTerminalXAssignmentEvidenceConfiguration(bootstrap, inspected, "")
}

func (d *DockerClient) readTerminalXRootPrivateRegularFile(
	ctx context.Context,
	containerID string,
	filePath string,
	maximumBytes int64,
) ([]byte, error) {
	archive, stat, err := d.apiClient.CopyFromContainer(ctx, containerID, filePath)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	name := path.Base(filePath)
	if stat.Name != name || stat.Size < 2 || stat.Size > maximumBytes || !stat.Mode.IsRegular() ||
		stat.Mode.Perm() != 0o600 || stat.Mode&terminalXUnsafeFileMode != 0 || stat.LinkTarget != "" {
		return nil, fmt.Errorf("terminalx root-private file metadata is invalid")
	}
	tarReader := tar.NewReader(archive)
	header, err := tarReader.Next()
	if err != nil || header == nil || header.Name != name || header.Linkname != "" ||
		header.Typeflag != tar.TypeReg || header.Size != stat.Size || header.Uid != 0 || header.Gid != 0 ||
		header.FileInfo().Mode().Perm() != 0o600 || header.FileInfo().Mode()&terminalXUnsafeFileMode != 0 {
		return nil, fmt.Errorf("terminalx root-private file archive is invalid")
	}
	value := make([]byte, header.Size)
	if _, err := io.ReadFull(tarReader, value); err != nil {
		zeroTerminalXBytes(value)
		return nil, fmt.Errorf("terminalx root-private file is incomplete")
	}
	if _, err := tarReader.Next(); err != io.EOF {
		zeroTerminalXBytes(value)
		return nil, fmt.Errorf("terminalx root-private file archive contains additional entries")
	}
	return value, nil
}

func verifyTerminalXBootstrapSections(secretBytes []byte, sections []terminalXBootstrapEnvelopeSection) error {
	if len(sections) != 2 || sections[0].Kind != "observation-ed25519-pkcs8" ||
		sections[1].Kind != "effect-enforcer-ed25519-pkcs8" || sections[0].Bytes < 1 ||
		sections[1].Bytes < 1 || sections[0].Bytes > 64*1024 || sections[1].Bytes > 64*1024 ||
		sections[0].Bytes+sections[1].Bytes != uint64(len(secretBytes)) {
		return fmt.Errorf("terminalx assignment bootstrap sections are invalid")
	}
	offset := uint64(0)
	for _, section := range sections {
		if !terminalXSha256Raw.MatchString(section.SHA256) {
			return fmt.Errorf("terminalx assignment bootstrap section digest is invalid")
		}
		digest := sha256.Sum256(secretBytes[offset : offset+section.Bytes])
		expected, _ := hex.DecodeString(section.SHA256)
		if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
			return fmt.Errorf("terminalx assignment bootstrap section digest does not match")
		}
		offset += section.Bytes
	}
	return nil
}

func validTerminalXHostedPlan(plan terminalXHostedPlan, host *container.HostConfig) bool {
	resources := plan.Isolation.Resources
	if host == nil || plan.RuntimeAuthorizationGeneration < 1 ||
		plan.RuntimeAuthorizationGeneration > terminalXJavaScriptMaximumSafeInteger ||
		!terminalXSha256Raw.MatchString(plan.Incarnation) ||
		!terminalXSha256Raw.MatchString(plan.SpecificationDigest) ||
		!terminalXSha256Raw.MatchString(plan.EffectEnforcerPolicyDigest) ||
		!terminalXSafeTextReference.MatchString(plan.AdapterConfigurationRef) ||
		!terminalXSha256Raw.MatchString(plan.Isolation.IsolationPolicyDigest) ||
		plan.Isolation.PublicAccess || plan.Isolation.HostMounts || plan.Isolation.LinkedSandbox ||
		plan.Isolation.RootIdentity || plan.Isolation.Network.Mode != "blocked" ||
		len(plan.Isolation.Network.AllowedDestinations) != 0 ||
		!terminalXSha256Raw.MatchString(plan.Isolation.Network.PolicyDigest) ||
		!plan.Capabilities.IsolatedExecution || plan.Capabilities.BrokeredCredentials ||
		plan.Capabilities.ProxyOnlyEgress || plan.Capabilities.Checkpoints || plan.Capabilities.YoloEligible ||
		!terminalXSafeTextReference.MatchString(plan.Observation.KeyProvisioningRef) ||
		!safeTerminalXPublicReference(plan.Observation.IssuerKeyID) ||
		resources.CPU < 1 || resources.CPU > terminalXSandboxMaxCPU ||
		resources.MemoryGiB < 1 || resources.MemoryGiB > terminalXSandboxMaxMemoryGiB ||
		resources.DiskGiB < 1 || resources.DiskGiB > terminalXSandboxMaxDiskGiB ||
		resources.Pids != terminalXSandboxPidsLimit || host.PidsLimit == nil ||
		*host.PidsLimit != resources.Pids || host.CPUPeriod != 100000 ||
		host.CPUQuota != resources.CPU*100000 || host.Memory != commonGBToBytes(resources.MemoryGiB) ||
		host.StorageOpt["size"] != strconv.FormatInt(resources.DiskGiB, 10)+"G" {
		return false
	}
	return true
}

func validTerminalXBootstrapTerminal(value terminalXBootstrapTerminal) bool {
	return value.RequestTimeoutMS >= 100 && value.RequestTimeoutMS <= 60_000 &&
		value.MaximumLifetimeMS >= 60_000 && value.MaximumLifetimeMS <= uint64((7*24*time.Hour)/time.Millisecond) &&
		value.MaximumTerminals >= 1 && value.MaximumTerminals <= 256 &&
		value.MaximumTerminalsPerSandbox >= 1 && value.MaximumTerminalsPerSandbox <= value.MaximumTerminals &&
		value.MaximumOutputFrameBytes >= 1024 && value.MaximumOutputFrameBytes <= 64*1024 &&
		value.MaximumPendingOutputBytes >= value.MaximumOutputFrameBytes &&
		value.MaximumPendingOutputBytes <= 16*1024*1024 &&
		value.MaximumPendingWebSocketBytes >= 64*1024 &&
		value.MaximumPendingWebSocketBytes <= 1024*1024
}

func validateTerminalXCanonicalEd25519PublicKey(value string) error {
	_, err := parseTerminalXCanonicalEd25519PublicKey(value)
	return err
}

func parseTerminalXCanonicalEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	if len(value) < 1 || len(value) > 16*1024 || !strings.HasPrefix(value, "-----BEGIN PUBLIC KEY-----\n") ||
		!strings.HasSuffix(value, "-----END PUBLIC KEY-----\n") {
		return nil, fmt.Errorf("terminalx assignment public key is invalid")
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 ||
		!bytes.Equal(pem.EncodeToMemory(block), []byte(value)) {
		return nil, fmt.Errorf("terminalx assignment public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("terminalx assignment public key is invalid")
	}
	return bytes.Clone(key), nil
}

func validateTerminalXBootstrapObjectShape(header map[string]any) error {
	authority, err := terminalXExactObject(header["authority"],
		"audience", "capability", "claimsDigest", "expiresAtMs", "issuedAtMs", "issuer", "issuerKeyId", "signature")
	if err != nil {
		return err
	}
	_ = authority
	bootstrap, err := terminalXExactObject(header["bootstrap"],
		"assignment", "commandAuthority", "effect", "isolation", "kind", "observation", "state", "terminal", "transport", "version")
	if err != nil {
		return err
	}
	assignment, err := terminalXExactObject(bootstrap["assignment"],
		"artifactDigest", "effectEnforcerSetDigest", "expectedRevision",
		"maxOperations", "plan", "providerSandboxId", "sandboxUser", "supervisorArtifactDigest")
	if err != nil {
		return err
	}
	plan, err := terminalXExactObject(assignment["plan"],
		"adapterConfigurationRef", "binding", "capabilities", "effectEnforcerPolicyDigest", "incarnation", "isolation", "observation",
		"runtimeAuthorizationGeneration", "specificationDigest")
	if err != nil {
		return err
	}
	if _, err = terminalXExactObject(plan["capabilities"],
		"brokeredCredentials", "checkpoints", "isolatedExecution", "proxyOnlyEgress", "yoloEligible"); err != nil {
		return err
	}
	planIsolation, err := terminalXExactObject(plan["isolation"],
		"hostMounts", "isolationPolicyDigest", "linkedSandbox", "network", "publicAccess", "resources", "rootIdentity")
	if err != nil {
		return err
	}
	if _, err = terminalXExactObject(planIsolation["network"], "allowedDestinations", "mode", "policyDigest"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(planIsolation["resources"], "cpu", "diskGiB", "memoryGiB", "pids"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(plan["observation"], "issuerKeyId", "keyProvisioningRef", "publicKeySpkiPem"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(bootstrap["isolation"],
		"attestationFile", "expectedAgentUid", "expectedContainerdVersion", "expectedDaytonaDaemonUid",
		"expectedDockerVersion", "expectedProviderRevision", "expectedRunnerBinaryDigest", "expectedSandboxImageId", "expectedSandboxSnapshotRef",
		"expectedSandboxUser", "expectedSeccompProfileDigest", "expectedSupervisorUid", "hardenedDaytonaSourceCommit",
		"issuerKeyId", "issuerPublicKeySpkiPem", "maximumAttestationTtlMs"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(bootstrap["commandAuthority"], "maximumAuthorityTtlMs", "pinnedPublicKeys"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(bootstrap["observation"], "observationTtlMs", "provisioningRecordFile"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(bootstrap["transport"],
		"authenticationTimeoutMs", "maximumFrameBytes", "maximumInflightRequests", "peerCredentialExecutableFile",
		"peerCredentialExecutableRoot", "peerCredentialExecutableSha256", "requestTimeoutMs", "socketDirectory", "socketPath"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(bootstrap["state"],
		"maxStateBytes", "signingPrivateKeyFile", "stateDirectory", "stateFileName", "verificationPublicKeyFile"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(bootstrap["terminal"],
		"maximumLifetimeMs", "maximumOutputFrameBytes", "maximumPendingOutputBytes",
		"maximumPendingWebSocketBytes", "maximumTerminals", "maximumTerminalsPerSandbox",
		"requestTimeoutMs"); err != nil {
		return err
	}
	if _, err = terminalXExactObject(bootstrap["effect"],
		"executableFile", "executableRoot", "executableSha256", "manifest", "maximumInputBytes", "maximumOutputBytes",
		"pinnedManifestAuthorityPublicKeys", "timeoutMs"); err != nil {
		return err
	}
	sections, ok := header["sections"].([]any)
	if !ok || len(sections) != 2 {
		return fmt.Errorf("terminalx assignment bootstrap sections are invalid")
	}
	for _, section := range sections {
		if _, err := terminalXExactObject(section, "bytes", "kind", "sha256"); err != nil {
			return err
		}
	}
	return nil
}

func terminalXExactObject(value any, expectedKeys ...string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(expectedKeys) {
		return nil, fmt.Errorf("terminalx assignment bootstrap object is invalid")
	}
	for _, key := range expectedKeys {
		if _, exists := object[key]; !exists {
			return nil, fmt.Errorf("terminalx assignment bootstrap object is invalid")
		}
	}
	return object, nil
}
