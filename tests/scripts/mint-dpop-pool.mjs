#!/usr/bin/env node
// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// mint-dpop-pool.mjs - 2026 SRE DPoP token pool provisioner.
import { createHash, createPrivateKey, createSign, generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

function parseArgs(argv) {
    const opts = {};
    for (let i = 2; i < argv.length; i++) {
        const k = argv[i];
        if (!k.startsWith('--')) throw new Error(`unexpected argument ${k}`);
        const name = k.slice(2).replaceAll('-', '_');
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith('--')) {
            opts[name] = next;
            i++;
        } else {
            opts[name] = 'true';
        }
    }
    return {
        count: Number(opts.count ?? 64),
        out: opts.out ?? 'tests/load/dpop-pool.json',
        selftest: opts.selftest === '1' || opts.selftest === 'true',
        keycloak_url: opts.keycloak_url ?? null,
        realm: opts.realm ?? 'sentinel',
        client: opts.client ?? 'sentinel-gate',
        client_secret: opts.client_secret ?? null,
        grant_type: opts.grant_type ?? null,
        username: opts.username ?? 'gate-user',
        password: opts.password ?? null,
        allow_unbound: ['1', 'true'].includes(opts.allow_unbound),
    };
}

function rfc7638(jwk) {
    const canonical = JSON.stringify({ crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y });
    return b64url(createHash('sha256').update(canonical).digest());
}

function toPrivateKey(jwk) {
    return createPrivateKey({ key: { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }, format: 'jwk' });
}

function signProof(jwk, { method, url, nonce }) {
    const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y } };
    const payload = {
        jti: randomUUID().replaceAll('-', ''),
        htm: method,
        htu: url,
        iat: Math.floor(Date.now() / 1000),
    };
    if (nonce) payload.nonce = nonce;
    const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;

    const signature = createSign('SHA256').update(input).end().sign({
        key: toPrivateKey(jwk),
        dsaEncoding: 'ieee-p1363',
    });

    return `${input}.${b64url(signature)}`;
}

async function generateKey() {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pub = publicKey.export({ format: 'jwk' });
    const priv = privateKey.export({ format: 'jwk' });
    return { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, d: priv.d };
}

async function mintViaKeycloak(cfg, jwk) {
    const tokenUrl = `${cfg.keycloak_url}/realms/${encodeURIComponent(cfg.realm)}/protocol/openid-connect/token`;
    const proof = signProof(jwk, { method: 'POST', url: tokenUrl });

    const grantType = cfg.grant_type ?? (cfg.client_secret ? 'client_credentials' : 'password');
    const bodyParams = {
        grant_type: grantType,
        client_id: cfg.client,
        scope: 'openid profile email',
    };

    if (grantType === 'client_credentials') {
        if (cfg.client_secret) {
            bodyParams.client_secret = cfg.client_secret;
        }
    } else {
        bodyParams.username = cfg.username;
        bodyParams.password = cfg.password ?? '';
        if (cfg.client_secret) {
            bodyParams.client_secret = cfg.client_secret;
        }
    }

    const body = new URLSearchParams(bodyParams);
    const res = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'DPoP': proof,
        },
        body,
    });
    if (res.status !== 200) {
        throw new Error(`Keycloak mint failed (HTTP ${res.status}): ${(await res.text()).slice(0, 240)}`);
    }
    const json = await res.json();
    if (!json.access_token) throw new Error('No access_token in Keycloak response');
    return json.access_token;
}

async function main() {
    const cfg = parseArgs(process.argv.slice(0));
    if (cfg.selftest) {
        const jwk = await generateKey();
        const proof = signProof(jwk, { method: 'POST', url: 'https://example.test/api' });
        const [, , sigB64] = proof.split('.');
        const sigLen = Buffer.from(sigB64, 'base64url').length;
        if (sigLen !== 64) {
            throw new Error(`SELFTEST FAIL: signature is ${sigLen} bytes (DER?), expected exactly 64 (IEEE P1363)`);
        }
        console.log('SELFTEST OK: ES256 proof signature is 64 bytes (IEEE P1363), as required by RFC 7515 §3.1 / RFC 9449.');
        return;
    }
    if (!cfg.out) throw new Error('--out is required');
    if (cfg.count < 1 || cfg.count > 4096) throw new Error('--count must be 1..4096');
    if (cfg.keycloak_url && !cfg.password && !cfg.client_secret) {
        throw new Error('--password or --client-secret is required with --keycloak-url');
    }

    const keys = [];
    let bound = 0;
    for (let i = 0; i < cfg.count; i++) {
        const jwk = await generateKey();
        const jkt = rfc7638(jwk);
        let token = null;
        let mintNote = 'self-signed pool (no Keycloak endpoint)';

        if (cfg.keycloak_url) {
            try {
                token = await mintViaKeycloak(cfg, jwk);
                const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
                if (payload.cnf && payload.cnf.jkt && payload.cnf.jkt !== jkt) {
                    throw new Error(`Token #${i} bound to DIFFERENT jkt (${payload.cnf.jkt.slice(0, 12)}...) vs ${jkt.slice(0, 12)}...`);
                }
                if (!payload.cnf || !payload.cnf.jkt) {
                    mintNote = 'UNBOUND: Keycloak returned no cnf.jkt (dpop feature/client config missing)';
                    if (!cfg.allow_unbound) {
                        throw new Error('Keycloak did not DPoP-bind the token (no cnf.jkt). Set KC_FEATURES=dpop,par + DPoP-enabled client.');
                    }
                } else {
                    bound += 1;
                    const activeGrant = cfg.grant_type ?? (cfg.client_secret ? 'client_credentials' : 'password');
                    mintNote = `keycloak(${activeGrant}, DPoP-bound): cnf.jkt verified`;
                }
            } catch (err) {
                console.error(`WARN: mint of key #${i} failed: ${err.message}`);
            }
            if (!token && !cfg.allow_unbound) {
                throw new Error(`Aborting: key #${i} could not be minted (fail-close, see warning above).`);
            }
        }

        keys.push({ jwk, jkt, token, mint_note: mintNote });
    }

    const outPath = resolve(cfg.out);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(
        outPath,
        JSON.stringify(
            {
                generated_at: Math.floor(Date.now() / 1000),
                issuer: cfg.keycloak_url ? 'keycloak' : 'self',
                token_url: cfg.keycloak_url ? `${cfg.keycloak_url}/realms/${encodeURIComponent(cfg.realm)}/protocol/openid-connect/token` : null,
                keys,
            },
            null,
            2,
        ),
    );
    console.log(`Wrote ${keys.length} keys to ${outPath} (${bound} DPoP-bound tokens).`);
    if (cfg.keycloak_url && bound === 0) {
        console.error('CRITICAL: 0/0 tokens bound via Keycloak. The suite will be rejected - fix KC_FEATURES=dpop,par.');
        if (!cfg.allow_unbound) process.exit(1);
    }
}

export { signProof, generateKey };

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
    main().catch((e) => {
        console.error(`mint-dpop-pool: ${e.message}`);
        process.exit(2);
    });
}