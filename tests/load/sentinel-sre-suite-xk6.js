// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// sentinel-sre-suite-xk6.js - SRE suite entry point for the distributed k6
// runner built with the Go-native DPoP signer (tests/load/xk6-dpop).
//
// The stock-k6 entry (sentinel-sre-suite.js) signs every proof in JS
// webcrypto, which caps a runner around ~2-3k proofs/sec - far below the
// 2k RPS per-runner target of the distributed topology (10 runners x 2k RPS
// = 20k RPS aggregate). This entry replaces signing with the xk6 extension:
// Go crypto/ecdsa sustains orders of magnitude more proofs/sec per runner.
//
// MUST be run with a k6 binary built via tests/load/Dockerfile.xk6
// (see docs/SRE_LOAD_TESTING_RUNBOOK.md §6). The static import below fails
// on stock k6 by design - the CRDs (infra/k8s/sre/) select this entry.
import dpop from 'k6/x/dpop';
import coreRun, { options, setSigner } from './sentinel-sre-core.js';

setSigner((method, url, jwkJson, opts) => dpop.sign(method, url, jwkJson, opts));

export { options };
export default coreRun;