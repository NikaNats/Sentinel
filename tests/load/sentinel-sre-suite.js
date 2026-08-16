// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// sentinel-sre-suite.js - SRE Load / Soak / Capacity suite entry point for
// STOCK k6 (webcrypto ES256 signing). The xk6 entry is
// sentinel-sre-suite-xk6.js (Go-native DPoP signing via tests/load/xk6-dpop).
//
// Shared logic lives in sentinel-sre-core.js; see its header comment for
// the corrections vs the 2026 Enterprise guide and the full ENV surface.
import coreRun, { options } from './sentinel-sre-core.js';

export { options };
export default coreRun;