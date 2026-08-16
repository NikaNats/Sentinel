// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// Unit test for the xk6-dpop signer: signs a proof from a P-256 private JWK
// (same shape minted by tests/scripts/mint-dpop-pool.mjs), then verifies the
// JWS structure and the ES256 signature with the public key.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

const testJWK = `{
  "kty": "EC",
  "crv": "P-256",
  "x": "V7oWkgL1cJ3fMNOHn2SN2KHq5Tlt3rOuT7CJEck_3b8",
  "y": "NHC_h7XZqVTziHRfuCRWX2I3zrKx7DqQK98SKmWuzLM",
  "d": "QYMOgm_TQDUa_gjnZWJjDTtL3s-YGZG7n-N1ZZntfHA"
}`

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func TestSignProofStructureAndSignature(t *testing.T) {
	proof, err := signES256("POST", "https://sentinel-api.sentinel-prod.svc.cluster.local/api/v1/finance/transfer",
		testJWK, map[string]interface{}{"nonce": "nonce-123", "iat": int64(1786190754), "jti": "t-1"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWS segments, got %d", len(parts))
	}

	headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	payloadRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sigRaw, _ := base64.RawURLEncoding.DecodeString(parts[2])

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Jwk struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
		} `json:"jwk"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		t.Fatalf("header JSON: %v", err)
	}
	if header.Alg != "ES256" || header.Typ != "dpop+jwt" || header.Jwk.Kty != "EC" || header.Jwk.Crv != "P-256" {
		t.Fatalf("unexpected header: %s", headerRaw)
	}

	var payload struct {
		Jti   string `json:"jti"`
		Htm   string `json:"htm"`
		Htu   string `json:"htu"`
		Iat   int64  `json:"iat"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	if payload.Jti != "t-1" || payload.Htm != "POST" || payload.Nonce != "nonce-123" || payload.Iat != 1786190754 {
		t.Fatalf("unexpected payload: %s", payloadRaw)
	}
	if !strings.HasPrefix(payload.Htu, "https://sentinel-api.sentinel-prod.svc.cluster.local") {
		t.Fatalf("unexpected htu: %s", payload.Htu)
	}
	if len(sigRaw) != 64 {
		t.Fatalf("expected 64-byte P1363 signature, got %d", len(sigRaw))
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(mustDecode(t, "V7oWkgL1cJ3fMNOHn2SN2KHq5Tlt3rOuT7CJEck_3b8")),
		Y:     new(big.Int).SetBytes(mustDecode(t, "NHC_h7XZqVTziHRfuCRWX2I3zrKx7DqQK98SKmWuzLM")),
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sigRaw[:32])
	s := new(big.Int).SetBytes(sigRaw[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("ES256 signature does not verify against the JWK public key")
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		jwk  string
		opts map[string]interface{}
	}{
		{"missing fields", `{"kty":"EC","crv":"P-256"}`, nil},
		{"wrong curve", strings.Replace(testJWK, `"crv": "P-256"`, `"crv": "P-384"`, 1), nil},
		{"non-EC", strings.Replace(testJWK, `"kty": "EC"`, `"kty": "RSA"`, 1), nil},
		{"bad base64", strings.Replace(testJWK, `"x": "V7oWkgL1cJ3fMNOHn2SN2KHq5Tlt3rOuT7CJEck_3b8"`, `"x": "!!!"`, 1), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := signES256("POST", "https://x.example/", c.jwk, c.opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFreshIatByDefault(t *testing.T) {
	proof, err := signES256("GET", "https://x.example/", testJWK, map[string]interface{}{"jti": "t-2"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	payloadRaw, _ := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[1])
	var payload struct {
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	if d := time.Now().Unix() - payload.Iat; d < -2 || d > 2 {
		t.Fatalf("iat must be current, got %d (%ds old)", payload.Iat, d)
	}
}