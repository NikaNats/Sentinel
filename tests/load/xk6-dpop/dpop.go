// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// xk6-dpop - Go-native DPoP proof signing for k6 (RFC 9449).
//
// Why: Sentinel's SRE load suite signs a fresh ES256 DPoP proof per request
// (a static proof pool is invalid - proofs carry a fresh `iat` and a
// server-issued `nonce`). k6's JS webcrypto path signs ~2-3k proofs/sec,
// which becomes the load generator bottleneck long before a 20k RPS target
// is reached. This extension moves signing into Go (crypto/ecdsa), sustaining
// orders of magnitude more proofs/sec per runner.
//
// JS API (registered as "k6/x/dpop"):
//
//	import dpop from 'k6/x/dpop';
//	const proof = dpop.sign(method, url, jwkJson, { nonce, iat, jti });
//
//	jwkJson  - JSON string of an EC P-256 private key JWK (kty/crv/x/y/d)
//	           exactly as minted by tests/scripts/mint-dpop-pool.mjs
//	nonce    - optional server-issued DPoP-Nonce (RFC 9449 §4.3)
//	iat      - seconds; default now. MUST be fresh (±60s) - Sentinel rejects
//	           stale proofs
//	jti      - unique per proof; default <method>.<url>.<epoch-ns>
//
// Returns the complete compact JWS proof string
// (<b64url(header)>.<b64url(payload)>.<b64url(ES256 sig)>).
// Throws a JS Error on malformed JWK or signing failure.
//
// Build with xk6 (see tests/load/Dockerfile.xk6 and
// docs/SRE_LOAD_TESTING_RUNBOOK.md):
//
//	xk6 build --with github.com/sentinel/xk6-dpop=./tests/load/xk6-dpop
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/dpop", &RootModule{})
}

// RootModule is the k6 module entry point (v0.52 module API).
type RootModule struct{}

var _ modules.Module = (*RootModule)(nil)

// NewModuleInstance returns a per-VU instance.
func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	return &ModuleInstance{vu: vu}
}

// ModuleInstance carries the VU handle (unused for pure signing).
type ModuleInstance struct {
	vu modules.VU
}

var _ modules.Instance = (*ModuleInstance)(nil)

// Exports exposes the signer as the module default.
func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{Default: &API{}}
}

// API is the JS-facing object.
type API struct{}

// Sign produces an ES256 DPoP proof (compact JWS) from a P-256 private JWK.
//
// opts (map[string]interface{}) may contain: nonce (string), iat (int),
// jti (string).
func (a *API) Sign(method string, url string, jwkJSON string, opts map[string]interface{}) string {
	proof, err := signES256(method, url, jwkJSON, opts)
	if err != nil {
		// The k6 v0.52 modules runtime surfaces panics as JS errors; a panic
		// also unwinds cleanly across the goja boundary.
		panic(fmt.Sprintf("xk6-dpop: %v", err))
	}
	return proof
}

type ecJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

func signES256(method, url, jwkJSON string, opts map[string]interface{}) (string, error) {
	if method == "" || url == "" {
		return "", errors.New("method and url are required")
	}
	var jwk ecJWK
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return "", fmt.Errorf("invalid JWK JSON: %w", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.X == "" || jwk.Y == "" || jwk.D == "" {
		return "", errors.New("JWK must be an EC P-256 private key (kty=EC, crv=P-256, x, y, d)")
	}
	x := b64urlDecode(jwk.X)
	y := b64urlDecode(jwk.Y)
	d := b64urlDecode(jwk.D)
	if len(x) != 32 || len(y) != 32 || len(d) != 32 {
		return "", errors.New("JWK x/y/d must be 32-byte base64url values")
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}

	iat := int64(time.Now().Unix())
	jti := method + "." + url + "." + strconv.FormatInt(time.Now().UnixNano(), 10)
	if v, ok := opts["iat"]; ok {
		switch n := v.(type) {
		case int64:
			iat = n
		case float64:
			iat = int64(n)
		}
	}
	if v, ok := opts["jti"]; ok {
		if s, ok := v.(string); ok && s != "" {
			jti = s
		}
	}
	var nonce string
	if v, ok := opts["nonce"]; ok {
		if s, ok := v.(string); ok {
			nonce = s
		}
	}

	header := fmt.Sprintf(
		`{"alg":"ES256","typ":"dpop+jwt","jwk":{"kty":"EC","crv":"P-256","x":%q,"y":%q}}`,
		jwk.X, jwk.Y)
	payload := fmt.Sprintf(`{"jti":%q,"htm":%q,"htu":%q,"iat":%d`, jti, method, url, iat)
	if nonce != "" {
		payload += `,"nonce":` + strconv.Quote(nonce)
	}
	payload += `}`

	signingInput := b64url([]byte(header)) + "." + b64url([]byte(payload))
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("ECDSA sign failed: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64url(sig), nil
}

func b64url(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func b64urlDecode(s string) []byte {
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// tolerate padded forms
		out, err = base64.URLEncoding.DecodeString(s)
	}
	if err != nil {
		return nil
	}
	return out
}