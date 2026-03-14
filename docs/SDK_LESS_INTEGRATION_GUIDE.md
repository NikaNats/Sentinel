# SDK-less Integration Guide for Sentinel API

This guide explains how to integrate with Sentinel without an SDK, using plain HTTP and DPoP proof generation with standard libraries.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Endpoints](#endpoints)
4. [DPoP Proof Generation](#dpop-proof-generation)
5. [Authentication Flows](#authentication-flows)
6. [Error Handling](#error-handling)
7. [Examples](#examples)

---

## Overview

Sentinel is a DPoP-protected API (RFC 9449 + FAPI 2.0 Baseline). All requests require:
- Valid JWT bearer token
- DPoP proof (cryptographic proof of possession tying token to HTTP method + URI)
- Rotating nonce (issued by server, included in each proof)

### Key Concepts

| Term | Definition |
|------|-----------|
| **DPoP Proof** | JWK-signed JWT asserting right to use a token for specific HTTP method + URI |
| **Nonce** | Server-issued per-JWK-thumbprint value preventing proof replay; rotates per-request |
| **JTI** | JWT ID claim; unique per proof; prevents same proof reuse |
| **cnf.jkt** | Confirmation claim; JWK thumbprint (S256) binding token to client's JWK |

---

## Prerequisites

### Libraries Required

- **JWT Library:** Any RFC 7519 JWT library (HS256/HS512, RS256/RS512, ES256)
  - JavaScript: `jose`, `jsonwebtoken`
  - Python: `PyJWT`, `cryptography`
  - Java: `java-jwt`, `jjwt`
  - C#: `System.IdentityModel.Tokens.Jwt`, `jose-jwt`
  - Go: `golang-jwt/jwt`, `lestrrat-go/jwx`

- **Cryptography Library:** For JWK generation and signing
  - JavaScript: `jose` (includes crypto operations)
  - Python: `cryptography`, `jwcrypto`
  - Java: `bouncycastle`
  - C#: `System.Security.Cryptography`

- **HTTP Client:** Any HTTP 1.1+ client with header support
  - JavaScript: `fetch`, `axios`
  - Python: `requests`, `httpx`
  - Java: `HttpClient`, `OkHttp`
  - C#: `HttpClient`

### Server Setup

1. Keycloak authorization server is running and configured
2. Sentinel API is running (typically `https://api.sentinel.local/v1`)
3. Redis cache is accessible to Sentinel (for replay & nonce state)

---

## Endpoints

### 1. Token Refresh

**POST** `/v1/auth/refresh`

Refresh an expired or expiring access token using a valid refresh token.

**Request Headers:**
```
Authorization: Bearer <refresh_token>
DPoP: <proof_jwt>
Content-Type: application/json
```

**Request Body:**
```json
{
  "refreshToken": "<refresh_token_from_auth_server>"
}
```

**Response (200 OK):**
```json
{
  "access_token": "<new_access_token>",
  "refresh_token": "<new_refresh_token>",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Response (400 Bad Request):**
Missing or invalid refresh token.

**Response (401 Unauthorized):**
Refresh token expired, revoked, or DPoP proof invalid.

**Response (429 Too Many Requests):**
Rate limit exceeded (per identity or IP).

---

### 2. Logout / Token Revocation

**POST** `/v1/auth/logout`

Revoke a refresh token and blacklist associated session.

**Request Headers:**
```
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
Idempotency-Key: <uuid_v4>
Content-Type: application/json
```

**Request Body:**
```json
{
  "refreshToken": "<refresh_token_to_revoke>"
}
```

**Response (204 No Content):**
Logout successful; session blacklisted.

**Response (400 Bad Request):**
Missing refresh token or invalid Idempotency-Key.

**Response (401 Unauthorized):**
Access token invalid or expired.

**Response (409 Conflict):**
Logout already in progress (Idempotency-Key retry); wait before retrying.

---

### 3. Protected Resource Endpoint

**GET** `/v1/profile`

Access protected user profile (requires valid access token + DPoP proof).

**Request Headers:**
```
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

**Response (200 OK):**
```json
{
  "sub": "user-123",
  "email": "user@example.com",
  "name": "John Doe"
}
```

**Response (401 Unauthorized):**
Access token invalid, expired, or DPoP proof missing/invalid.

**Response (503 Service Unavailable):**
Token reuse detected (JTI already used); request new token.

---

### 4. Finance Endpoint

**GET** `/v1/finance`

Access high-value financial operations (requires ACR=urn:mace:incommon:iap:silver minimum assurance).

**Request Headers:**
```
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

**Response (200 OK):**
```json
{
  "accounts": [
    { "id": "acct-1", "balance": 10000.00 }
  ]
}
```

**Response (403 Forbidden):**
ACR requirement not met (insufficient assurance level).

---

### 5. Documents Endpoint

**GET** `/v1/documents`

Access document store (scope: `documents:read` required).

**Request Headers:**
```
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

---

### 6. Backchannel Logout (RP-initiated)

**POST** `/v1/auth/backchannel-logout`

Sentinel receives logout token from authorized party (e.g., Keycloak); invalidates session server-side.

**Request Headers:**
```
Content-Type: application/x-www-form-urlencoded
```

**Request Body:**
```
logout_token=<jwt_signed_by_issuer>
```

**Response (200 OK):**
Session invalidated.

**Response (400 Bad Request):**
Invalid logout token.

---

## DPoP Proof Generation

### Step 1: Generate Ephemeral JWK

Every DPoP proof requires a unique ephemeral JWK (RSA, EC, or OKP). For highest compatibility with Keycloak and FAPI2, use **EC P-256 (ES256)**.

#### JavaScript Example

```javascript
import * as jose from 'jose';

// Generate EC P-256 JWK
const { public: publicJwk, private: privateJwk } = await jose.generateKeyPair('ES256');
const jwk = await jose.exportSPKI(publicJwk);
```

#### Python Example

```python
from jwcrypto import jwk
import json

# Generate EC P-256 JWK
key = jwk.JWK.generate(kty='EC', crv='P-256')
public_key = json.loads(key.export_public())
```

#### Java Example

```java
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

ECKey ecKey = new ECKeyGenerator(Curve.P_256)
    .keyID(UUID.randomUUID().toString())
    .generate();
```

#### C# Example

```csharp
using System.Security.Cryptography;
using System.Text.Json;

// Generate EC P-256 key
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
string keyId = Guid.NewGuid().ToString();
```

### Step 2: Compute JWK Thumbprint (S256)

The thumbprint identifies your JWK uniquely and is included in the access token's `cnf.jkt` claim.

**Formula (RFC 7638):**
```
thumbprint = Base64URL(SHA-256(UTF8(JWK)))
```

Where JWK is the **lexicographically sorted** JSON of: `{"crv":"...", "kty":"EC", "x":"...", "y":"..."}`

#### JavaScript Example

```javascript
const thumbprint = await jose.calculateJwkThumbprint(publicJwk);
// Returns base64url-encoded SHA-256 hash
```

#### Python Example

```python
from jwcrypto.jwk import JWK
import hashlib
import base64

key = JWK.generate(kty='EC', crv='P-256')
thumbprint = key.thumbprint()  # Returns base64url hash
```

#### Java Example

```java
String thumbprint = ecKey.computeThumbprint("SHA-256").toBase64URL().toString();
```

#### C# Example

```csharp
using System.Text.Json;
using System.Security.Cryptography;

string ComputeJwkThumbprint(JsonElement jwk)
{
    var hash = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(SortJsonByKeys(jwk)));
    return Base64UrlEncode(hash);
}
```

### Step 3: Generate Nonce

The nonce is issued by Sentinel server in response headers. On the first unauthenticated request, you'll receive:

**Response (400 Bad Request):**
```
HTTP/1.1 400 Bad Request
DPoP-Nonce: <server_issued_nonce>
Content-Type: application/problem+json

{
  "type": "/errors/missing-dpop-nonce",
  "title": "Valid DPoP-Nonce required"
}
```

Cache this nonce and include it in the next proof.

### Step 4: Create DPoP Proof JWT

The proof is a JWT signed with your private JWK, containing:
- `typ`: `"dpop+jwt"`
- `alg`: Message signing algorithm (`"ES256"` for EC P-256)
- `jwk`: Public JWK (unencrypted)
- `claims`:
  - `jti`: Unique identifier for this proof (use `uuid()` or timestamp + random)
  - `htm`: HTTP method (uppercase: `"GET"`, `"POST"`, etc.)
  - `htu`: Full HTTP URI without query string (e.g., `"https://api.sentinel.local/v1/profile"`)
  - `iat`: Issued-at (Unix timestamp, current second)
  - `exp`: Expiration (typically `iat + 60` seconds)
  - `nonce`: Server-issued nonce (from previous 400 response header)

#### JavaScript Example

```javascript
import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';

async function generateDpopProof(privateKey, nonce, method, url) {
  const now = Math.floor(Date.now() / 1000);
  
  const proof = await jose.SignJWT({
    jti: uuidv4(),
    htm: method.toUpperCase(),
    htu: url,
    iat: now,
    exp: now + 60,
    nonce: nonce
  })
    .setProtectedHeader({
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: await jose.exportSPKI(publicKey)
    })
    .sign(privateKey);
  
  return proof;
}
```

#### Python Example

```python
import jwt
import json
from datetime import datetime, timedelta
import uuid

def generate_dpop_proof(private_key, public_key, nonce, method, url):
    now = datetime.utcnow()
    payload = {
        'jti': str(uuid.uuid4()),
        'htm': method.upper(),
        'htu': url,
        'iat': int(now.timestamp()),
        'exp': int((now + timedelta(seconds=60)).timestamp()),
        'nonce': nonce
    }
    
    headers = {
        'typ': 'dpop+jwt',
        'alg': 'ES256',
        'jwk': json.loads(public_key.export(format='JSON', private_key=False))
    }
    
    return jwt.encode(payload, private_key, algorithm='ES256', headers=headers)
```

#### Java Example

```java
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.UUID;

String generateDpopProof(ECKey ecKey, String nonce, String method, String url) throws Exception {
    long now = Instant.now().getEpochSecond();
    
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .jwtID(UUID.randomUUID().toString())
        .claim("htm", method.toUpperCase())
        .claim("htu", url)
        .issueTime(new Date(now * 1000))
        .expirationTime(new Date((now + 60) * 1000))
        .claim("nonce", nonce)
        .build();
    
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(new JOSEObjectType("dpop+jwt"))
        .jwk(ecKey.toPublicJWK())
        .build();
    
    JWSObject jwsObject = new JWSObject(header, new Payload(claims.toJSONObject()));
    JWSSigner signer = new ECDSASigner(ecKey);
    jwsObject.sign(signer);
    
    return jwsObject.serialize();
}
```

#### C# Example

```csharp
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

string GenerateDpopProof(ECDsa privateKey, string nonce, string method, string url)
{
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var handler = new JwtSecurityTokenHandler();
    
    var token = handler.CreateJwtSecurityToken(
        issuer: null,
        audience: null,
        subject: null,
        notBefore: DateTime.UtcNow,
        expires: DateTime.UtcNow.AddSeconds(60),
        issuedAt: DateTime.UtcNow,
        signingCredentials: new SigningCredentials(new ECDsaSecurityKey(privateKey), "ES256")
    );
    
    // Add custom claims
    token.Payload["jti"] = Guid.NewGuid().ToString();
    token.Payload["htm"] = method.ToUpper();
    token.Payload["htu"] = url;
    token.Payload["nonce"] = nonce;
    
    // Set header
    token.Header["typ"] = "dpop+jwt";
    token.Header["jwk"] = ExportPublicJwk(privateKey);
    
    return handler.WriteToken(token);
}
```

### Step 5: Include Proof in Request

Add the proof JWT to every request:

```http
GET /v1/profile HTTP/1.1
Host: api.sentinel.local
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

---

## Authentication Flows

### Flow 1: Initial Challenge and Nonce Acquisition

**Step 1: Send unauthenticated request**

```http
GET /v1/profile HTTP/1.1
Host: api.sentinel.local
```

**Response (400 Bad Request):**
```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0...
Content-Type: application/problem+json

{
  "type": "/errors/missing-dpop-nonce",
  "title": "DPoP-Nonce required"
}
```

**Step 2: Cache nonce, generate proof including nonce**

```javascript
const nonce = responseHeaders['dpop-nonce'];
const proof = await generateDpopProof(privateKey, nonce, 'GET', 'https://api.sentinel.local/v1/profile');
```

**Step 3: Retry with proof + access token**

```http
GET /v1/profile HTTP/1.1
Host: api.sentinel.local
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

**Response (200 OK):**
```http
HTTP/1.1 200 OK
DPoP-Nonce: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0...

{
  "sub": "user-123",
  "email": "user@example.com"
}
```

**Step 4: Cache returned nonce for next request**

```javascript
nextNonce = responseHeaders['dpop-nonce'];
```

---

### Flow 2: Authenticated Request with Cached Nonce

Subsequent requests use the cached nonce:

```http
GET /v1/documents HTTP/1.1
Host: api.sentinel.local
Authorization: Bearer <access_token>
DPoP: <proof_jwt_with_cached_nonce>
```

---

### Flow 3: Token Refresh

**Step 1: Generate refresh proof (same as above)**

```javascript
const refreshProof = await generateDpopProof(privateKey, cachedNonce, 'POST', 'https://api.sentinel.local/v1/auth/refresh');
```

**Step 2: Send refresh request**

```http
POST /v1/auth/refresh HTTP/1.1
Host: api.sentinel.local
Authorization: Bearer <refresh_token>
DPoP: <refresh_proof>
Content-Type: application/json

{
  "refreshToken": "<refresh_token_value>"
}
```

**Response (200 OK):**
```http
HTTP/1.1 200 OK
DPoP-Nonce: <new_nonce>

{
  "access_token": "<new_access_token>",
  "refresh_token": "<new_refresh_token>",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

---

### Flow 4: Logout (Idempotent)

Logout is idempotent; retries with same `Idempotency-Key` return 204 (already done).

**Step 1: Generate logout proof**

```javascript
const logoutProof = await generateDpopProof(privateKey, cachedNonce, 'POST', 'https://api.sentinel.local/v1/auth/logout');
```

**Step 2: Send logout request**

```http
POST /v1/auth/logout HTTP/1.1
Host: api.sentinel.local
Authorization: Bearer <access_token>
DPoP: <logout_proof>
Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
Content-Type: application/json

{
  "refreshToken": "<refresh_token>"
}
```

**Response (204 No Content):**
```http
HTTP/1.1 204 No Content
DPoP-Nonce: <new_nonce>
```

**Step 3: Retry with same Idempotency-Key**

```http
POST /v1/auth/logout HTTP/1.1
...
Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
...
```

**Response (204 No Content):** ← Same response (idempotent)
```http
HTTP/1.1 204 No Content
```

---

## Error Handling

### 400: DPoP-Nonce Required

**Cause:** First request or nonce expired.

**Response:**
```json
{
  "type": "/errors/missing-dpop-nonce",
  "title": "DPoP-Nonce required",
  "status": 400
}
```

**Action:** Extract `DPoP-Nonce` header, generate new proof, retry.

### 400: Invalid DPoP Proof

**Cause:** Proof signature invalid, wrong method/URI, expired.

**Response:**
```json
{
  "type": "/errors/invalid-dpop-proof",
  "title": "DPoP proof validation failed",
  "detail": "Proof signature is invalid",
  "status": 400
}
```

**Action:** Verify proof generation; ensure `htm`, `htu` match request. Check system clock synchronization.

### 401: Unauthorized

**Cause:** Access token invalid, expired, or missing.

**Response:**
```json
{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401
}
```

**Action:** Refresh access token or re-authenticate.

### 403: Forbidden (ACR Insufficient)

**Cause:** Access token ACR less than required (e.g., requires `urn:mace:incommon:iap:silver`).

**Response:**
```json
{
  "type": "/errors/insufficient-acr",
  "title": "Insufficient authentication context",
  "status": 403
}
```

**Action:** Authenticate with higher assurance (MFA, etc.) via Keycloak.

### 429: Too Many Requests

**Cause:** Rate limit exceeded (identity or IP partition).

**Response:**
```json
{
  "type": "/errors/rate-limit-exceeded",
  "title": "Too many requests",
  "status": 429
}
```

**Headers:**
```
Retry-After: 60
```

**Action:** Wait `Retry-After` seconds; exponential backoff recommended.

### 409: Conflict (Idempotency Retry In Progress)

**Cause:** Same `Idempotency-Key` logout is still in progress.

**Response:**
```json
{
  "type": "/errors/idempotency-conflict",
  "title": "Request already in progress",
  "status": 409
}
```

**Action:** Wait and retry with same Idempotency-Key, or use new Idempotency-Key for new request.

### 503: Token Reuse Detected

**Cause:** Access token JTI or proof JTI already used (replay detected).

**Response:**
```json
{
  "type": "/errors/token-reuse-detected",
  "title": "Token already used",
  "status": 503
}
```

**Action:** Obtain new access token and retry.

---

## Examples

### Full JavaScript Example

```javascript
import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';

const API_URL = 'https://api.sentinel.local/v1';

class SentinelClient {
  constructor() {
    this.privateKey = null;
    this.publicKey = null;
    this.nonce = null;
    this.accessToken = null;
  }

  async initialize() {
    // Generate EC P-256 key pair
    const { public: pub, private: priv } = await jose.generateKeyPair('ES256');
    this.publicKey = pub;
    this.privateKey = priv;
  }

 async generateProof(method, url, nonce) {
    const now = Math.floor(Date.now() / 1000);
    const publicJwk = await jose.exportSPKI(this.publicKey);

    return await jose.SignJWT({
      jti: uuidv4(),
      htm: method.toUpperCase(),
      htu: url,
      iat: now,
      exp: now + 60,
      nonce
    })
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: 'ES256',
        jwk: JSON.parse(publicJwk)
      })
      .sign(this.privateKey);
  }

  async request(method, endpoint, data = null, options = {}) {
    if (!this.nonce) {
      // Initial challenge request
      try {
        await axios({
          method,
          url: `${API_URL}${endpoint}`,
          headers: { 'Authorization': `Bearer ${this.accessToken}` }
        });
      } catch (error) {
        if (error.response?.status === 400) {
          this.nonce = error.response.headers['dpop-nonce'];
        } else {
          throw error;
        }
      }
    }

    // Generate proof with nonce
    const proof = await this.generateProof(method, `${API_URL}${endpoint}`, this.nonce);

    // Make authenticated request
    const response = await axios({
      method,
      url: `${API_URL}${endpoint}`,
      data,
      headers: {
        'Authorization': `Bearer ${this.accessToken}`,
        'DPoP': proof,
        ...options.headers
      }
    });

    // Cache new nonce from response
    if (response.headers['dpop-nonce']) {
      this.nonce = response.headers['dpop-nonce'];
    }

    return response.data;
  }

  async refresh(refreshToken) {
    const proof = await this.generateProof('POST', `${API_URL}/auth/refresh`, this.nonce);

    const response = await axios.post(`${API_URL}/auth/refresh`, 
      { refreshToken },
      {
        headers: {
          'Authorization': `Bearer ${refreshToken}`,
          'DPoP': proof
        }
      }
    );

    this.accessToken = response.data.access_token;
    if (response.headers['dpop-nonce']) {
      this.nonce = response.headers['dpop-nonce'];
    }
    return response.data;
  }

  async logout(refreshToken) {
    const proof = await this.generateProof('POST', `${API_URL}/auth/logout`, this.nonce);

    return await axios.post(`${API_URL}/auth/logout`,
      { refreshToken },
      {
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'DPoP': proof,
          'Idempotency-Key': uuidv4()
        }
      }
    );
  }

  async getProfile() {
    return this.request('GET', '/profile');
  }
}

// Usage
const client = new SentinelClient();
await client.initialize();

// Assume access_token set from OAuth2 flow
client.accessToken = '<access_token_from_keycloak>';

// First request triggers nonce challenge
const profile = await client.getProfile();
console.log(profile);

// Refresh token
const { access_token, refresh_token } = await client.refresh('<refresh_token>');
client.accessToken = access_token;

// Logout
await client.logout(refresh_token);
```

### Full Python Example

```python
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
import uuid
import requests
import json

API_URL = 'https://api.sentinel.local/v1'

class SentinelClient:
    def __init__(self):
        self.key = jwk.JWK.generate(kty='EC', crv='P-256')
        self.nonce = None
        self.access_token = None

    def _generate_proof(self, method, url):
        now = datetime.utcnow()
        payload = {
            'jti': str(uuid.uuid4()),
            'htm': method.upper(),
            'htu': url,
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(seconds=60)).timestamp()),
            'nonce': self.nonce
        }

        token = jwt.JWT(
            header={
                'typ': 'dpop+jwt',
                'alg': 'ES256',
                'jwk': json.loads(self.key.export_public())
            },
            claims=payload
        )
        token.make_signed_token(self.key)
        return token.serialize()

    def _request(self, method, endpoint, json_data=None):
        url = f"{API_URL}{endpoint}"

        if not self.nonce:
            # Initial challenge
            response = requests.request(
                method,
                url,
                headers={'Authorization': f'Bearer {self.access_token}'}
            )
            if response.status_code == 400:
                self.nonce = response.headers.get('dpop-nonce')
            else:
                raise Exception(f"Unexpected response: {response.status_code}")

        # Generate proof and retry
        proof = self._generate_proof(method, url)
        response = requests.request(
            method,
            url,
            json=json_data,
            headers={
                'Authorization': f'Bearer {self.access_token}',
                'DPoP': proof
            }
        )

        # Cache new nonce
        if 'dpop-nonce' in response.headers:
            self.nonce = response.headers['dpop-nonce']

        if response.status_code >= 400:
            raise Exception(f"Request failed: {response.status_code} - {response.text}")

        return response.json() if response.text else None

    def refresh(self, refresh_token):
        proof = self._generate_proof('POST', f"{API_URL}/auth/refresh")
        response = requests.post(
            f"{API_URL}/auth/refresh",
            json={'refreshToken': refresh_token},
            headers={
                'Authorization': f'Bearer {refresh_token}',
                'DPoP': proof
            }
        )
        data = response.json()
        self.access_token = data['access_token']
        if 'dpop-nonce' in response.headers:
            self.nonce = response.headers['dpop-nonce']
        return data

    def get_profile(self):
        return self._request('GET', '/profile')

# Usage
client = SentinelClient()
client.access_token = '<access_token_from_keycloak>'
profile = client.get_profile()
print(profile)
```

