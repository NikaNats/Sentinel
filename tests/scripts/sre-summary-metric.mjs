#!/usr/bin/env node
// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// sre-summary-metric.mjs - jq-free single-value reader for k6 --summary-export
// JSON (which is written as ONE LINE; naive grep approaches break).
//
// Used by validate-sre-soak.sh (node is a repository prerequisite: the DPoP
// pool mint, structure-minting scripts, and RSR pipeline all already depend
// on it, so no new tooling is introduced by the fallback path).
//
// Usage:
//   node tests/scripts/sre-summary-metric.mjs <summary.json> <metric> <field>
//   # prints the numeric value, or 0 when the metric/field is absent.

import { readFileSync } from 'node:fs';

const [summaryPath, metric, field] = process.argv.slice(2);
if (!summaryPath || !metric || !field) {
  console.error('usage: sre-summary-metric.mjs <summary.json> <metric> <field>');
  process.exit(2);
}

let summary;
try {
  summary = JSON.parse(readFileSync(summaryPath, 'utf8'));
} catch (err) {
  console.error(`cannot read k6 summary '${summaryPath}': ${err.message}`);
  process.exit(2);
}

// k6 v0.52 exported metrics as { values: { count, ... } } while k6 v2.x
// exports them FLAT ({ count, rate, ... } at the metric level). Read both.
const metricObj = summary.metrics?.[metric] ?? {};
const bucket = metricObj.values ?? metricObj;
console.log(bucket[field] ?? 0);