// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
)

const (
	terminalXDaytonaBaseCommit                   = "b5a5d9e78d76c8bcf351f2049620250e0f34eea4"
	terminalXDeploymentBindingKind               = "terminalx.daytona-sandbox-deployment-binding"
	terminalXDeploymentBindingClaimsDigestDomain = "terminalx/daytona-sandbox-deployment-binding-claims/v1\x00"
	terminalXDeploymentBindingSignatureDomain    = "terminalx/daytona-sandbox-deployment-binding-authority/v1\x00"
	terminalXMaximumSignerFileBytes              = 16 * 1024
	terminalXMaximumEvidenceTTL                  = 5 * time.Minute
	terminalXCanonicalMaximumDepth               = 32
	terminalXCanonicalMaximumNodes               = 20_000
	terminalXCanonicalMaximumFields              = 1_000
	terminalXCanonicalMaximumStringBytes         = 1_000_000
	terminalXCanonicalReservedBytesField         = "$terminalx.runtime.bytes.v1"
)

var (
	terminalXGitCommit           = regexp.MustCompile(`^[0-9a-f]{40}$`)
	terminalXProviderSandboxUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func validateTerminalXAttestationRequirements(config DockerClientConfig) error {
	if !terminalXSha256Raw.MatchString(config.TerminalXDeploymentBindingInstallerSHA256) ||
		!terminalXSha256Raw.MatchString(config.TerminalXIsolationProbeSHA256) {
		return fmt.Errorf("terminalx hardened runner requires pinned evidence helpers")
	}
	if !terminalXSha256Raw.MatchString(config.TerminalXSandboxArtifactDigest) ||
		!terminalXSha256Raw.MatchString(config.TerminalXSeccompProfileSHA256) {
		return fmt.Errorf("terminalx hardened runner evidence digests are invalid")
	}
	if !terminalXGitCommit.MatchString(config.TerminalXHardenedSourceCommit) ||
		config.TerminalXHardenedSourceCommit == terminalXDaytonaBaseCommit {
		return fmt.Errorf("terminalx hardened runner source commit is invalid")
	}
	if !safeTerminalXPublicReference(config.TerminalXDeploymentBindingKeyID) ||
		!safeTerminalXPublicReference(config.TerminalXIsolationAttestorKeyID) ||
		config.TerminalXDeploymentBindingKeyID == config.TerminalXIsolationAttestorKeyID ||
		!terminalXSha256Raw.MatchString(config.TerminalXDeploymentBindingPublicKeySHA256) ||
		!terminalXSha256Raw.MatchString(config.TerminalXIsolationAttestorPublicKeySHA256) ||
		config.TerminalXDeploymentBindingPublicKeySHA256 == config.TerminalXIsolationAttestorPublicKeySHA256 ||
		config.TerminalXDeploymentBindingPrivateKeyFile == config.TerminalXIsolationAttestorPrivateKeyFile {
		return fmt.Errorf("terminalx hardened runner requires distinct attestation identities")
	}
	if !safeTerminalXPublicReference(config.TerminalXBootstrapAuthorityKeyID) ||
		!terminalXSha256Raw.MatchString(config.TerminalXBootstrapAuthorityPublicKeySHA256) ||
		config.TerminalXBootstrapAuthorityKeyID == config.TerminalXDeploymentBindingKeyID ||
		config.TerminalXBootstrapAuthorityKeyID == config.TerminalXIsolationAttestorKeyID ||
		config.TerminalXBootstrapAuthorityPublicKeySHA256 == config.TerminalXDeploymentBindingPublicKeySHA256 ||
		config.TerminalXBootstrapAuthorityPublicKeySHA256 == config.TerminalXIsolationAttestorPublicKeySHA256 {
		return fmt.Errorf("terminalx hardened runner bootstrap authority is invalid")
	}
	if config.TerminalXEvidenceTTL <= 0 || config.TerminalXEvidenceTTL > terminalXMaximumEvidenceTTL {
		return fmt.Errorf("terminalx hardened runner evidence lifetime is invalid")
	}
	if config.TerminalXDaytonaDaemonUID != terminalXSandboxUserUID ||
		config.TerminalXAgentUID != terminalXSandboxUserUID {
		return fmt.Errorf("terminalx hardened runner process identity is invalid")
	}
	return nil
}

func loadTerminalXEd25519PublicKey(
	publicKeyFile string,
	expectedPublicKeySHA256 string,
	expectedOwnerUID uint32,
) (ed25519.PublicKey, error) {
	if !terminalXSha256Raw.MatchString(expectedPublicKeySHA256) {
		return nil, fmt.Errorf("terminalx runner public key digest is invalid")
	}
	keyBytes, err := readTerminalXKeyFile(
		publicKeyFile,
		expectedOwnerUID,
		map[os.FileMode]bool{0o400: true, 0o444: true, 0o600: true},
	)
	if err != nil {
		return nil, err
	}
	defer zeroTerminalXBytes(keyBytes)
	block, rest := pem.Decode(keyBytes)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 ||
		!bytes.Equal(pem.EncodeToMemory(block), keyBytes) {
		return nil, fmt.Errorf("terminalx runner public key is not canonical SPKI PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("terminalx runner public key is not Ed25519")
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(canonicalDER, block.Bytes) {
		return nil, fmt.Errorf("terminalx runner public key is not canonical SPKI")
	}
	digest := sha256.Sum256(keyBytes)
	expectedDigest, err := hex.DecodeString(expectedPublicKeySHA256)
	if err != nil || len(expectedDigest) != sha256.Size ||
		subtle.ConstantTimeCompare(digest[:], expectedDigest) != 1 {
		return nil, fmt.Errorf("terminalx runner public key digest does not match")
	}
	return bytes.Clone(publicKey), nil
}

// terminalXEd25519Signer owns a runner-host private key. The key is loaded
// only from a root-owned, non-linked PKCS#8 file and is never serialized after
// construction. Sign and Close are mutually exclusive so shutdown can zero
// the key without racing an in-flight attestation.
type terminalXEd25519Signer struct {
	mu               sync.Mutex
	keyID            string
	privateKey       ed25519.PrivateKey
	publicKeySPKIPEM string
	publicKeySHA256  string
	closed           bool
}

func loadTerminalXEd25519Signer(
	privateKeyFile string,
	keyID string,
	expectedPublicKeySHA256 string,
	expectedOwnerUID uint32,
) (*terminalXEd25519Signer, error) {
	if !safeTerminalXPublicReference(keyID) || !terminalXSha256Raw.MatchString(expectedPublicKeySHA256) {
		return nil, fmt.Errorf("terminalx runner signer identity is invalid")
	}
	keyBytes, err := readTerminalXPrivateKeyFile(privateKeyFile, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	defer zeroTerminalXBytes(keyBytes)

	block, rest := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 ||
		!bytes.Equal(pem.EncodeToMemory(block), keyBytes) {
		return nil, fmt.Errorf("terminalx runner signer key is not canonical PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("terminalx runner signer key is invalid")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("terminalx runner signer key is not Ed25519")
	}
	defer zeroTerminalXBytes(privateKey)
	canonicalDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil || !bytes.Equal(canonicalDER, block.Bytes) {
		return nil, fmt.Errorf("terminalx runner signer key is not canonical PKCS#8")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("terminalx runner signer public key is invalid")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("terminalx runner signer public key is invalid")
	}
	publicPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	publicDigest := sha256.Sum256(publicPEMBytes)
	expectedDigest, err := hex.DecodeString(expectedPublicKeySHA256)
	if err != nil || len(expectedDigest) != sha256.Size ||
		subtle.ConstantTimeCompare(publicDigest[:], expectedDigest) != 1 {
		return nil, fmt.Errorf("terminalx runner signer public key digest does not match")
	}

	return &terminalXEd25519Signer{
		keyID:            keyID,
		privateKey:       bytes.Clone(privateKey),
		publicKeySPKIPEM: string(publicPEMBytes),
		publicKeySHA256:  expectedPublicKeySHA256,
	}, nil
}

func readTerminalXPrivateKeyFile(path string, expectedOwnerUID uint32) ([]byte, error) {
	return readTerminalXKeyFile(
		path,
		expectedOwnerUID,
		map[os.FileMode]bool{0o400: true, 0o600: true},
	)
}

func readTerminalXKeyFile(
	path string,
	expectedOwnerUID uint32,
	allowedModes map[os.FileMode]bool,
) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("terminalx runner signer path is invalid")
	}
	if err := validateTerminalXPrivatePathParents(filepath.Dir(path), expectedOwnerUID); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("terminalx runner signer file is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("terminalx runner signer metadata is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || !allowedModes[info.Mode().Perm()] ||
		info.Mode()&os.ModeType != 0 || stat.Uid != expectedOwnerUID || stat.Nlink != 1 ||
		info.Size() < 1 || info.Size() > terminalXMaximumSignerFileBytes {
		return nil, fmt.Errorf("terminalx runner signer file permissions are invalid")
	}
	value, err := io.ReadAll(io.LimitReader(file, terminalXMaximumSignerFileBytes+1))
	if err != nil || len(value) < 1 || len(value) > terminalXMaximumSignerFileBytes {
		zeroTerminalXBytes(value)
		return nil, fmt.Errorf("terminalx runner signer file is invalid")
	}
	return value, nil
}

func validateTerminalXPrivatePathParents(path string, expectedOwnerUID uint32) error {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil || realPath != path {
		return fmt.Errorf("terminalx runner signer parent path is invalid")
	}
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("terminalx runner signer parent is unavailable")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("terminalx runner signer parent permissions are invalid")
		}
		ownedPrivate := stat.Uid == expectedOwnerUID && info.Mode().Perm()&0o022 == 0
		rootProtected := stat.Uid == 0 &&
			(info.Mode().Perm()&0o022 == 0 || info.Mode()&os.ModeSticky != 0)
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			(!ownedPrivate && !rootProtected) {
			return fmt.Errorf("terminalx runner signer parent permissions are invalid")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func (signer *terminalXEd25519Signer) sign(domain string, statement any) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("terminalx runner signer is unavailable")
	}
	statementBytes, err := marshalTerminalXCanonicalJSON(statement)
	if err != nil {
		return "", err
	}
	message := make([]byte, len(domain)+len(statementBytes))
	copy(message, domain)
	copy(message[len(domain):], statementBytes)
	defer zeroTerminalXBytes(message)

	signer.mu.Lock()
	defer signer.mu.Unlock()
	if signer.closed || len(signer.privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("terminalx runner signer is closed")
	}
	signature := ed25519.Sign(signer.privateKey, message)
	defer zeroTerminalXBytes(signature)
	encoded := base64.RawURLEncoding.EncodeToString(signature)
	if len(encoded) != 86 {
		return "", fmt.Errorf("terminalx runner signature is invalid")
	}
	return encoded, nil
}

func (signer *terminalXEd25519Signer) Close() {
	if signer == nil {
		return
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if signer.closed {
		return
	}
	zeroTerminalXBytes(signer.privateKey)
	signer.privateKey = nil
	signer.closed = true
}

type terminalXDeploymentBindingClaims struct {
	ExpectedSandboxImageID     string `json:"expectedSandboxImageId"`
	ExpectedSandboxSnapshotRef string `json:"expectedSandboxSnapshotRef"`
	Kind                       string `json:"kind"`
	ProviderRevision           uint64 `json:"providerRevision"`
	ProviderSandboxID          string `json:"providerSandboxId"`
	SandboxArtifactDigest      string `json:"sandboxArtifactDigest"`
	Version                    int    `json:"version"`
}

type terminalXDeploymentBindingStatement struct {
	Audience     string `json:"audience"`
	Capability   string `json:"capability"`
	ClaimsDigest string `json:"claimsDigest"`
	ExpiresAtMS  int64  `json:"expiresAtMs"`
	IssuedAtMS   int64  `json:"issuedAtMs"`
	Issuer       string `json:"issuer"`
	IssuerKeyID  string `json:"issuerKeyId"`
	Version      int    `json:"version"`
}

type terminalXDeploymentBindingAuthority struct {
	Audience     string `json:"audience"`
	Capability   string `json:"capability"`
	ClaimsDigest string `json:"claimsDigest"`
	ExpiresAtMS  int64  `json:"expiresAtMs"`
	IssuedAtMS   int64  `json:"issuedAtMs"`
	Issuer       string `json:"issuer"`
	IssuerKeyID  string `json:"issuerKeyId"`
	Signature    string `json:"signature"`
}

type terminalXDeploymentBinding struct {
	Authority                  terminalXDeploymentBindingAuthority `json:"authority"`
	ExpectedSandboxImageID     string                              `json:"expectedSandboxImageId"`
	ExpectedSandboxSnapshotRef string                              `json:"expectedSandboxSnapshotRef"`
	Kind                       string                              `json:"kind"`
	ProviderRevision           uint64                              `json:"providerRevision"`
	ProviderSandboxID          string                              `json:"providerSandboxId"`
	SandboxArtifactDigest      string                              `json:"sandboxArtifactDigest"`
	Version                    int                                 `json:"version"`
}

func createTerminalXDeploymentBinding(
	signer *terminalXEd25519Signer,
	claims terminalXDeploymentBindingClaims,
	issuedAt time.Time,
	ttl time.Duration,
) ([]byte, error) {
	if signer == nil || claims.Version != 1 || claims.Kind != terminalXDeploymentBindingKind ||
		!terminalXProviderSandboxUUID.MatchString(claims.ProviderSandboxID) || claims.ProviderRevision < 1 ||
		claims.ProviderRevision > terminalXJavaScriptMaximumSafeInteger ||
		!terminalXSha256Raw.MatchString(claims.SandboxArtifactDigest) ||
		!isSha256ImageID(claims.ExpectedSandboxImageID) ||
		!terminalXSnapshotRef.MatchString(claims.ExpectedSandboxSnapshotRef) || ttl <= 0 ||
		ttl > terminalXMaximumEvidenceTTL || issuedAt.UnixMilli() < 0 {
		return nil, fmt.Errorf("terminalx deployment binding claims are invalid")
	}
	claimsBytes, err := marshalTerminalXCanonicalJSON(claims)
	if err != nil {
		return nil, err
	}
	claimsDigestValue := sha256.New()
	_, _ = claimsDigestValue.Write([]byte(terminalXDeploymentBindingClaimsDigestDomain))
	_, _ = claimsDigestValue.Write(claimsBytes)
	claimsDigest := hex.EncodeToString(claimsDigestValue.Sum(nil))
	issuedAtMS := issuedAt.UnixMilli()
	ttlMS := ttl.Milliseconds()
	maximumTimestamp := int64(terminalXJavaScriptMaximumSafeInteger)
	if issuedAtMS < 0 || issuedAtMS > maximumTimestamp || ttlMS < 1 ||
		ttlMS > terminalXMaximumEvidenceTTL.Milliseconds() || issuedAtMS > maximumTimestamp-ttlMS {
		return nil, fmt.Errorf("terminalx deployment binding lifetime is invalid")
	}
	expiresAtMS := issuedAtMS + ttlMS
	statement := terminalXDeploymentBindingStatement{
		Audience:     "terminalx-assignment-bootstrap",
		Capability:   "sandbox.deployment.bind",
		ClaimsDigest: claimsDigest,
		ExpiresAtMS:  expiresAtMS,
		IssuedAtMS:   issuedAtMS,
		Issuer:       "daytona-runner",
		IssuerKeyID:  signer.keyID,
		Version:      1,
	}
	signature, err := signer.sign(terminalXDeploymentBindingSignatureDomain, statement)
	if err != nil {
		return nil, err
	}
	binding := terminalXDeploymentBinding{
		Authority: terminalXDeploymentBindingAuthority{
			Audience:     statement.Audience,
			Capability:   statement.Capability,
			ClaimsDigest: statement.ClaimsDigest,
			ExpiresAtMS:  statement.ExpiresAtMS,
			IssuedAtMS:   statement.IssuedAtMS,
			Issuer:       statement.Issuer,
			IssuerKeyID:  statement.IssuerKeyID,
			Signature:    signature,
		},
		ExpectedSandboxImageID:     claims.ExpectedSandboxImageID,
		ExpectedSandboxSnapshotRef: claims.ExpectedSandboxSnapshotRef,
		Kind:                       claims.Kind,
		ProviderRevision:           claims.ProviderRevision,
		ProviderSandboxID:          claims.ProviderSandboxID,
		SandboxArtifactDigest:      claims.SandboxArtifactDigest,
		Version:                    claims.Version,
	}
	return marshalTerminalXCanonicalJSON(binding)
}

func marshalTerminalXCanonicalJSON(value any) ([]byte, error) {
	var intermediate bytes.Buffer
	encoder := json.NewEncoder(&intermediate)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("terminalx canonical JSON is invalid")
	}
	encoded := intermediate.Bytes()
	if len(encoded) < 2 || encoded[len(encoded)-1] != '\n' ||
		json.Unmarshal(encoded[:len(encoded)-1], &value) != nil {
		return nil, fmt.Errorf("terminalx canonical JSON is invalid")
	}
	var output bytes.Buffer
	if err := writeTerminalXCanonicalJSON(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// encoding/json deliberately escapes U+2028/U+2029 even with EscapeHTML(false),
// while JSON.stringify (the authoritative TypeScript canonicalizer) emits the
// UTF-8 code points. Replace only JSON escapes with an even-length preceding
// backslash run; an odd run denotes a literal "\\u2028" string and must stay.
func terminalXUnescapeJavaScriptLineSeparators(encoded []byte) []byte {
	result := make([]byte, 0, len(encoded))
	for index := 0; index < len(encoded); {
		match := index+6 <= len(encoded) && encoded[index] == '\\' && encoded[index+1] == 'u' &&
			(bytes.Equal(encoded[index+2:index+6], []byte("2028")) ||
				bytes.Equal(encoded[index+2:index+6], []byte("2029")))
		if match {
			preceding := 0
			for cursor := len(result) - 1; cursor >= 0 && result[cursor] == '\\'; cursor-- {
				preceding++
			}
			if preceding%2 == 0 {
				if encoded[index+5] == '8' {
					result = append(result, 0xe2, 0x80, 0xa8)
				} else {
					result = append(result, 0xe2, 0x80, 0xa9)
				}
				index += 6
				continue
			}
		}
		result = append(result, encoded[index])
		index++
	}
	return result
}

func writeTerminalXCanonicalJSON(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		encoded, err := marshalTerminalXJSONPrimitive(typed)
		if err != nil {
			return err
		}
		output.Write(encoded)
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || typed == 0 && math.Signbit(typed) {
			return fmt.Errorf("terminalx canonical JSON is invalid")
		}
		encoded, err := marshalTerminalXJSONPrimitive(typed)
		if err != nil {
			return err
		}
		output.Write(encoded)
	case []any:
		output.WriteByte('[')
		for index, entry := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeTerminalXCanonicalJSON(output, entry); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left int, right int) bool {
			return compareTerminalXUTF16(keys[left], keys[right]) < 0
		})
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			encodedKey, err := marshalTerminalXJSONPrimitive(key)
			if err != nil {
				return err
			}
			output.Write(encodedKey)
			output.WriteByte(':')
			if err := writeTerminalXCanonicalJSON(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("terminalx canonical JSON is invalid")
	}
	return nil
}

func marshalTerminalXJSONPrimitive(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("terminalx canonical JSON is invalid")
	}
	encoded := output.Bytes()
	if len(encoded) < 2 || encoded[len(encoded)-1] != '\n' {
		return nil, fmt.Errorf("terminalx canonical JSON is invalid")
	}
	return terminalXUnescapeJavaScriptLineSeparators(encoded[:len(encoded)-1]), nil
}

func compareTerminalXUTF16(left string, right string) int {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for index := 0; index < limit; index++ {
		if leftUnits[index] < rightUnits[index] {
			return -1
		}
		if leftUnits[index] > rightUnits[index] {
			return 1
		}
	}
	if len(leftUnits) < len(rightUnits) {
		return -1
	}
	if len(leftUnits) > len(rightUnits) {
		return 1
	}
	return 0
}

func canonicalizeTerminalXJSON(input []byte, maximumBytes int) ([]byte, any, error) {
	if len(input) < 2 || len(input) > maximumBytes || !json.Valid(input) {
		return nil, nil, fmt.Errorf("terminalx canonical JSON is invalid")
	}
	if err := validateTerminalXJSONNesting(input); err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, fmt.Errorf("terminalx canonical JSON is invalid")
	}
	budget := terminalXCanonicalBudget{
		remainingNodes:       terminalXCanonicalMaximumNodes,
		remainingStringBytes: terminalXCanonicalMaximumStringBytes,
	}
	if decoder.Decode(new(any)) != io.EOF || containsTerminalXNegativeZero(reflect.ValueOf(value)) ||
		validateTerminalXCanonicalProfile(value, 0, &budget) != nil {
		return nil, nil, fmt.Errorf("terminalx canonical JSON is invalid")
	}
	var output bytes.Buffer
	err := writeTerminalXCanonicalJSON(&output, value)
	canonical := output.Bytes()
	if err != nil || !bytes.Equal(canonical, input) {
		return nil, nil, fmt.Errorf("terminalx canonical JSON is invalid")
	}
	return canonical, value, nil
}

type terminalXCanonicalBudget struct {
	remainingNodes       int
	remainingStringBytes int
}

func validateTerminalXCanonicalProfile(value any, depth int, budget *terminalXCanonicalBudget) error {
	if depth > terminalXCanonicalMaximumDepth || budget.remainingNodes < 1 {
		return fmt.Errorf("terminalx canonical JSON exceeds profile limits")
	}
	budget.remainingNodes--
	switch typed := value.(type) {
	case nil, bool, float64:
		return nil
	case string:
		budget.remainingStringBytes -= len([]byte(typed))
		if budget.remainingStringBytes < 0 {
			return fmt.Errorf("terminalx canonical JSON exceeds profile limits")
		}
		return nil
	case []any:
		for _, entry := range typed {
			if err := validateTerminalXCanonicalProfile(entry, depth+1, budget); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if len(typed) > terminalXCanonicalMaximumFields {
			return fmt.Errorf("terminalx canonical JSON exceeds profile limits")
		}
		for key, entry := range typed {
			if key == terminalXCanonicalReservedBytesField {
				return fmt.Errorf("terminalx canonical JSON is invalid")
			}
			budget.remainingStringBytes -= len([]byte(key))
			if budget.remainingStringBytes < 0 {
				return fmt.Errorf("terminalx canonical JSON exceeds profile limits")
			}
			if err := validateTerminalXCanonicalProfile(entry, depth+1, budget); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("terminalx canonical JSON is invalid")
	}
}

// Bound container nesting before encoding/json allocates a complete object.
// The first container occupies canonical depth zero, so depth+1 opens are
// permitted. Braces inside strings are ignored with exact escape tracking.
func validateTerminalXJSONNesting(value []byte) error {
	depth := 0
	inString := false
	escaped := false
	for _, character := range value {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
			} else if character == '"' {
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > terminalXCanonicalMaximumDepth+1 {
				return fmt.Errorf("terminalx canonical JSON exceeds profile limits")
			}
		case '}', ']':
			depth--
		}
	}
	if inString || depth != 0 {
		return fmt.Errorf("terminalx canonical JSON is invalid")
	}
	return nil
}

func containsTerminalXNegativeZero(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}
	switch value.Kind() {
	case reflect.Float64:
		return value.Float() == 0 && math.Signbit(value.Float())
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return false
		}
		return containsTerminalXNegativeZero(value.Elem())
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if containsTerminalXNegativeZero(iterator.Value()) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if containsTerminalXNegativeZero(value.Index(index)) {
				return true
			}
		}
	}
	return false
}

func zeroTerminalXBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
