#!/usr/bin/env node
// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// sign-dpop-proof.mjs - sign an RFC 9449 DPoP proof for a pool entry minted by
// mint-dpop-pool.mjs. Used by the observability gate to present the SAME access
// token with FRESH proofs (per-request jti) - i.e. to exercise access-token jti
// single-use enforcement without replaying the proof itself.
//
// Usage:
//   node tests/scripts/sign-dpop-proof.mjs --pool <pool.json> --index 0 \
//     --method GET --url http://localhost:5260/v1/profile [--nonce <n>] \
//     [--token-only]
//
// Prints the signed proof on one line. With --token-only (or --print-token)
// the pool entry's access token is printed on a single line.
import { readFileSync } from 'node:fs';
import { signProof } from './mint-dpop-pool.mjs';

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
    return opts;
}

async function main() {
    const opts = parseArgs(process.argv.slice(0));
    if (!opts.pool) throw new Error('--pool is required');
    if (!opts.url) throw new Error('--url is required');

    const pool = JSON.parse(readFileSync(opts.pool, 'utf8'));
    const index = Number(opts.index ?? 0);
    const entry = pool.keys[index];
    if (!entry) throw new Error(`pool has no key at index ${index}`);
    if (!entry.token) {
        throw new Error(`pool entry ${index} has no DPoP-bound access token (mint with --keycloak-url)`);
    }

    if (opts.print_token || opts.token_only) {
        console.log(entry.token);
        return;
    }

    const proof = signProof(entry.jwk, {
        method: opts.method ?? 'GET',
        url: opts.url,
        nonce: opts.nonce ?? null,
    });

    console.log(proof);
}

main().catch((e) => {
    console.error(`sign-dpop-proof: ${e.message}`);
    process.exit(2);
});