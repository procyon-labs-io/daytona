// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTerminalXTestSigner(t *testing.T) (string, string, ed25519.PublicKey) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	for index := range seed {
		seed[index] = 0
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	keyPath := filepath.Join(directory, "runner-attestor.pem")
	if err := os.WriteFile(keyPath, privatePEM, 0o400); err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	digest := sha256.Sum256(publicPEM)
	for index := range privateKey {
		privateKey[index] = 0
	}
	for index := range privatePEM {
		privatePEM[index] = 0
	}
	return keyPath, hex.EncodeToString(digest[:]), bytes.Clone(publicKey)
}

func TestTerminalXSignerLoadsStrictKeyAndCreatesVerifiableDeploymentBinding(t *testing.T) {
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
	defer signer.Close()

	claims := terminalXDeploymentBindingClaims{
		ExpectedSandboxImageID:     testTerminalXImageID,
		ExpectedSandboxSnapshotRef: testTerminalXSnapshotRef,
		Kind:                       terminalXDeploymentBindingKind,
		ProviderRevision:           7,
		ProviderSandboxID:          "123e4567-e89b-42d3-a456-426614174000",
		SandboxArtifactDigest:      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Version:                    1,
	}
	bindingBytes, err := createTerminalXDeploymentBinding(
		signer,
		claims,
		time.UnixMilli(1_800_000_000_000),
		60*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := canonicalizeTerminalXJSON(bindingBytes, 256*1024)
	if err != nil || !bytes.Equal(canonical, bindingBytes) {
		t.Fatalf("binding is not canonical: %v", err)
	}

	var binding terminalXDeploymentBinding
	decoder := json.NewDecoder(bytes.NewReader(bindingBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := marshalTerminalXCanonicalJSON(claims)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(terminalXDeploymentBindingClaimsDigestDomain))
	_, _ = digest.Write(claimsBytes)
	if actual := hex.EncodeToString(digest.Sum(nil)); binding.Authority.ClaimsDigest != actual {
		t.Fatalf("claims digest mismatch: %s != %s", binding.Authority.ClaimsDigest, actual)
	}
	statement := terminalXDeploymentBindingStatement{
		Audience:     binding.Authority.Audience,
		Capability:   binding.Authority.Capability,
		ClaimsDigest: binding.Authority.ClaimsDigest,
		ExpiresAtMS:  binding.Authority.ExpiresAtMS,
		IssuedAtMS:   binding.Authority.IssuedAtMS,
		Issuer:       binding.Authority.Issuer,
		IssuerKeyID:  binding.Authority.IssuerKeyID,
		Version:      1,
	}
	statementBytes, err := marshalTerminalXCanonicalJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(terminalXDeploymentBindingSignatureDomain), statementBytes...)
	signature, err := base64.RawURLEncoding.DecodeString(binding.Authority.Signature)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("deployment binding signature did not verify")
	}
	if binding.Authority.IssuedAtMS != 1_800_000_000_000 ||
		binding.Authority.ExpiresAtMS != 1_800_000_060_000 {
		t.Fatal("deployment binding lifetime changed")
	}
}

func TestTerminalXDeploymentBindingRejectsNonPortableLifetimes(t *testing.T) {
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
	claims := terminalXDeploymentBindingClaims{
		ExpectedSandboxImageID: testTerminalXImageID, ExpectedSandboxSnapshotRef: testTerminalXSnapshotRef,
		Kind: terminalXDeploymentBindingKind, ProviderRevision: 7,
		ProviderSandboxID: testTerminalXSandboxUUID, SandboxArtifactDigest: strings.Repeat("c", 64), Version: 1,
	}
	for name, input := range map[string]struct {
		issuedAt time.Time
		ttl      time.Duration
	}{
		"sub-millisecond ttl": {issuedAt: time.UnixMilli(testTerminalXContractNowMS), ttl: time.Nanosecond},
		"timestamp overflow": {
			issuedAt: time.UnixMilli(int64(terminalXJavaScriptMaximumSafeInteger)), ttl: time.Minute,
		},
	} {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			if value, err := createTerminalXDeploymentBinding(signer, claims, input.issuedAt, input.ttl); err == nil {
				zeroTerminalXBytes(value)
				t.Fatal("non-portable deployment-binding lifetime was accepted")
			}
		})
	}
}

func TestTerminalXSignerFailsClosedForUnsafeKeyFilesAndAfterClose(t *testing.T) {
	keyPath, publicDigest, _ := writeTerminalXTestSigner(t)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTerminalXEd25519Signer(
		keyPath,
		"deployment-binding-key-1",
		publicDigest,
		uint32(os.Getuid()),
	); err == nil {
		t.Fatal("group/world-readable signer key was accepted")
	}
	if err := os.Chmod(keyPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTerminalXEd25519Signer(
		keyPath,
		"deployment-binding-key-1",
		publicDigest,
		uint32(os.Getuid()+1),
	); err == nil {
		t.Fatal("wrong signer owner was accepted")
	}
	linkPath := filepath.Join(filepath.Dir(keyPath), "linked.pem")
	if err := os.Symlink(keyPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTerminalXEd25519Signer(
		linkPath,
		"deployment-binding-key-1",
		publicDigest,
		uint32(os.Getuid()),
	); err == nil {
		t.Fatal("symlink signer key was accepted")
	}
	wrongDigest := "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := loadTerminalXEd25519Signer(
		keyPath,
		"deployment-binding-key-1",
		wrongDigest,
		uint32(os.Getuid()),
	); err == nil {
		t.Fatal("wrong signer public digest was accepted")
	}

	signer, err := loadTerminalXEd25519Signer(
		keyPath,
		"deployment-binding-key-1",
		publicDigest,
		uint32(os.Getuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	signer.Close()
	if _, err := signer.sign("domain\x00", struct {
		Version int `json:"version"`
	}{Version: 1}); err == nil {
		t.Fatal("closed signer accepted signing")
	}
	if signer.privateKey != nil {
		t.Fatal("closed signer retained private key storage")
	}
}

func TestTerminalXCanonicalJSONRejectsAlternativeEncodings(t *testing.T) {
	for name, value := range map[string][]byte{
		"reordered":    []byte(`{"version":1,"kind":"x"}`),
		"duplicate":    []byte(`{"kind":"x","kind":"x","version":1}`),
		"negativezero": []byte(`{"value":-0}`),
		"whitespace":   []byte("{\"kind\":\"x\",\"version\":1}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := canonicalizeTerminalXJSON(value, 1024); err == nil {
				t.Fatal("alternative JSON encoding was accepted")
			}
		})
	}
	canonical := []byte(`{"kind":"x","version":1}`)
	actual, _, err := canonicalizeTerminalXJSON(canonical, 1024)
	if err != nil || !bytes.Equal(actual, canonical) {
		t.Fatalf("canonical JSON was rejected: %v", err)
	}
}
