# Compliance Evidence Index

> **Document ID**: CMP-0002
> **Status**: ACTIVE
> **Purpose**: Single index of release-blocking compliance evidence committed to
> this directory, with the SHA-256 chain-of-custody manifest convention
> (`PENTEST_PROGRAM.md` §11, `OIDF_FAPI_CONFORMANCE_RUNBOOK.md` §5).

## Layout

| Artifact | Naming convention | Producer | Retention |
|---|---|---|---|
| FAPI 2.0 conformance certificate | `fapi2-certificate-<YYYY-MM-DD>.pdf` | `fapi-conformance-gate.yml` | 7 years |
| FAPI evidence manifest | `fapi-evidence-manifest.txt` | `run-fapi-conformance.sh` | 7 years |
| Pen test report (anonymized) | `pentest-report-<YYYY-MM-DD>.pdf` | engagement close (§11) | 7 years |
| Pen test findings log | `pentest-findings-<YYYY-MM-DD>.json` | engagement close (§9.2 schema) | 7 years |
| Pen test retest results | `pentest-retest-<YYYY-MM-DD>.pdf` | post-remediation retest | 7 years |

## Chain of Custody

- Every artifact committed here is immutable (Git history) and its SHA-256 is
  recorded in the per-engagement manifest (`fapi-evidence-manifest.txt` for
  FAPI runs; the pen test manifest lives beside the findings JSON as
  `pentest-manifest-<YYYY-MM-DD>.sha256`).
- Pen test report + retest PDFs committed here are **anonymized** copies
  approved by the client; the encrypted originals (with PoCs and tester
  certifications) are retained in encrypted storage for 7 years
  (`PENTEST_PROGRAM.md` §11).
- Raw test data is destroyed within 30 days of final acceptance.

## Release Gates Consuming This Directory

| Gate | Consumes | Blocks on |
|---|---|---|
| `.github/workflows/fapi-conformance-gate.yml` | `fapi2-certificate-*.pdf` | missing certificate on `release/**` |
| `.github/workflows/pentest-gate.yml` | `pentest-report-*.pdf`, `pentest-findings-*.json`, `pentest-retest-*.pdf` | missing/stale evidence, open CRITICAL/HIGH findings |

## Current Evidence

| Artifact | Date | Status |
|---|---|---|
| *(pending first hosted FAPI run)* | — | — |
| *(pending first independent pen test)* | — | — |