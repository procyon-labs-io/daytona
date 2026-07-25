// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
)

func TestTerminalXAssignmentBootstrapFailsClosedBeforeDocker(t *testing.T) {
	t.Parallel()
	if _, err := (&DockerClient{}).RunTerminalXAssignmentBootstrap(t.Context(), "sandbox-1", []byte("x")); !errors.Is(err, ErrTerminalXAssignmentBootstrapUnavailable) {
		t.Fatalf("non-hardened client error = %v", err)
	}
	if _, err := (&DockerClient{terminalXHardened: true}).RunTerminalXAssignmentBootstrap(t.Context(), "sandbox-1", nil); !errors.Is(err, ErrTerminalXAssignmentBootstrapInvalid) {
		t.Fatalf("empty envelope error = %v", err)
	}
}

func TestTerminalXAssignmentBootstrapExecOptionsHaveNoCallerControlledSurface(t *testing.T) {
	t.Parallel()
	options := terminalXAssignmentBootstrapExecOptions()
	if options.User != "0:0" || options.Privileged || options.Tty || !options.AttachStdin ||
		!options.AttachStdout || !options.AttachStderr || options.WorkingDir != "/" ||
		len(options.Cmd) != 1 || options.Cmd[0] != terminalXAssignmentBootstrapPath ||
		len(options.Env) != 0 || options.Detach || options.DetachKeys != "" || options.ConsoleSize != nil {
		t.Fatalf("unsafe assignment bootstrap exec options: %#v", options)
	}
}

func TestVerifyTerminalXAssignmentBootstrapArchivePinsRootRegularExecutable(t *testing.T) {
	t.Parallel()
	payload := []byte("terminalx-assignment-bootstrap-v1")
	digest := sha256.Sum256(payload)
	expected := hex.EncodeToString(digest[:])
	archive := func(headerMutator func(*tar.Header), extra bool) *bytes.Reader {
		var output bytes.Buffer
		writer := tar.NewWriter(&output)
		header := &tar.Header{
			Name:     "terminalx-assignment-bootstrap",
			Mode:     0o555,
			Uid:      0,
			Gid:      0,
			Size:     int64(len(payload)),
			Typeflag: tar.TypeReg,
		}
		if headerMutator != nil {
			headerMutator(header)
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			if _, err := writer.Write(payload[:header.Size]); err != nil {
				t.Fatalf("write payload: %v", err)
			}
		}
		if extra {
			if err := writer.WriteHeader(&tar.Header{Name: "extra", Mode: 0o444, Size: 1, Typeflag: tar.TypeReg}); err != nil {
				t.Fatalf("write extra header: %v", err)
			}
			if _, err := writer.Write([]byte("x")); err != nil {
				t.Fatalf("write extra payload: %v", err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close tar: %v", err)
		}
		return bytes.NewReader(output.Bytes())
	}
	stat := container.PathStat{
		Name: "terminalx-assignment-bootstrap",
		Size: int64(len(payload)),
		Mode: 0o555,
	}
	if err := verifyTerminalXAssignmentBootstrapArchive(archive(nil, false), stat, expected); err != nil {
		t.Fatalf("valid assignment bootstrap rejected: %v", err)
	}

	tests := map[string]struct {
		mutateHeader func(*tar.Header)
		mutateStat   func(*container.PathStat)
		digest       string
		extra        bool
	}{
		"wrong digest":   {digest: testTerminalXSupervisorRelaySHA256},
		"non-root owner": {mutateHeader: func(value *tar.Header) { value.Gid = 1000 }},
		"writable executable": {
			mutateHeader: func(value *tar.Header) { value.Mode = 0o755 },
			mutateStat:   func(value *container.PathStat) { value.Mode = 0o755 },
		},
		"setuid executable": {
			mutateHeader: func(value *tar.Header) { value.Mode = 0o4555 },
			mutateStat:   func(value *container.PathStat) { value.Mode = os.ModeSetuid | 0o555 },
		},
		"renamed archive entry": {mutateHeader: func(value *tar.Header) { value.Name = "nested/terminalx-assignment-bootstrap" }},
		"additional entry":      {extra: true},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidateStat := stat
			if test.mutateStat != nil {
				test.mutateStat(&candidateStat)
			}
			candidateDigest := test.digest
			if candidateDigest == "" {
				candidateDigest = expected
			}
			if err := verifyTerminalXAssignmentBootstrapArchive(
				archive(test.mutateHeader, test.extra), candidateStat, candidateDigest,
			); err == nil {
				t.Fatal("unsafe assignment bootstrap artifact was accepted")
			}
		})
	}
}

func TestTerminalXAssignmentBootstrapResponseIsBoundedJSONObject(t *testing.T) {
	t.Parallel()
	golden := []byte(`{"assignmentPlanDigest":"2222222222222222222222222222222222222222222222222222222222222222","bindingDigest":"3333333333333333333333333333333333333333333333333333333333333333","effectEnforcerKeyId":"runtime-enforcer-key-1","effectEnforcerPolicyDigest":"8888888888888888888888888888888888888888888888888888888888888888","effectEnforcerPublicKeyDigest":"6666666666666666666666666666666666666666666666666666666666666666","effectEnforcerSetDigest":"3333333333333333333333333333333333333333333333333333333333333333","effectManifestBindingDigest":"6666666666666666666666666666666666666666666666666666666666666666","envelopeDigest":"0000000000000000000000000000000000000000000000000000000000000000","installedMarker":"/run/terminalx-root/assignment.installed.json","kind":"terminalx.daytona-assignment-bootstrap-installed","observationIssuerKeyId":"observation-key-1","observationPublicKeyDigest":"4444444444444444444444444444444444444444444444444444444444444444","planDigest":"2222222222222222222222222222222222222222222222222222222222222222","providerIdentityCommitment":"1111111111111111111111111111111111111111111111111111111111111111","providerRevision":1,"stateVerificationPublicKeyDigest":"f156757c29b06e139f85f758a95e6819536ac887631d395782ce5797516e159b","stateVerificationPublicKeySpkiPem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2gR9n1Vv6T6g9gxucZyyi2dKXr0/TYBVlC6V6dH3v8A=\n-----END PUBLIC KEY-----\n","supervisorArtifactDigest":"5555555555555555555555555555555555555555555555555555555555555555","supervisorReady":false,"version":1}`)
	if !validTerminalXAssignmentBootstrapResponse(golden) {
		t.Fatal("cross-repository golden installed descriptor rejected")
	}
	invalid := [][]byte{
		nil,
		[]byte(`[]`),
		[]byte(`{"kind":"terminalx.daytona-assignment-bootstrap-installed"}`),
		append([]byte(" "), golden...),
		append(bytes.Clone(golden), '\n'),
		[]byte(`{"unterminated":`),
		bytes.Replace(bytes.Clone(golden), []byte(`{"assignmentPlanDigest"`), []byte(`{"unknown":true,"assignmentPlanDigest"`), 1),
		bytes.Replace(bytes.Clone(golden), []byte(`"assignmentPlanDigest":"`+strings.Repeat("2", 64)+`",`), nil, 1),
		bytes.Replace(bytes.Clone(golden), []byte(`"effectEnforcerPolicyDigest":"`+strings.Repeat("8", 64)+`",`), nil, 1),
		bytes.Replace(bytes.Clone(golden), []byte(`"effectEnforcerSetDigest":"`+strings.Repeat("3", 64)+`",`), nil, 1),
		bytes.Replace(bytes.Clone(golden), []byte(`"effectManifestBindingDigest":"`+strings.Repeat("6", 64)+`",`), nil, 1),
		bytes.Replace(bytes.Clone(golden), []byte(`"assignmentPlanDigest":"`+strings.Repeat("2", 64)+`"`), []byte(`"assignmentPlanDigest":"`+strings.Repeat("9", 64)+`"`), 1),
		bytes.Replace(bytes.Clone(golden), []byte(`"providerRevision":1`), []byte(`"providerRevision":0`), 1),
		bytes.Replace(bytes.Clone(golden), []byte(`"supervisorReady":false`), []byte(`"supervisorReady":true`), 1),
		bytes.Replace(bytes.Clone(golden), []byte(`"stateVerificationPublicKeyDigest":"f156757c29b06e139f85f758a95e6819536ac887631d395782ce5797516e159b"`), []byte(`"stateVerificationPublicKeyDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`), 1),
		bytes.Repeat([]byte("x"), int(terminalXAssignmentBootstrapMaximumResponseBytes)+1),
	}
	for _, candidate := range invalid {
		if validTerminalXAssignmentBootstrapResponse(candidate) {
			t.Fatalf("invalid public descriptor accepted: %q", candidate[:min(len(candidate), 80)])
		}
	}
}

func TestTerminalXBoundedBufferRejectsOverflowWithoutPartialWrite(t *testing.T) {
	t.Parallel()
	buffer := &terminalXBoundedBuffer{maximumBytes: 3}
	if written, err := buffer.Write([]byte("abc")); err != nil || written != 3 {
		t.Fatalf("bounded write rejected: written=%d err=%v", written, err)
	}
	if written, err := buffer.Write([]byte("d")); err == nil || written != 0 || buffer.String() != "abc" {
		t.Fatalf("overflow was not rejected atomically: written=%d err=%v value=%q", written, err, buffer.String())
	}
	backing := buffer.Bytes()
	buffer.Zero()
	if buffer.Len() != 0 || !bytes.Equal(backing, []byte{0, 0, 0}) {
		t.Fatalf("bounded buffer was not zeroed: len=%d backing=%v", buffer.Len(), backing)
	}
}
