# Kubernetes Secret Management Strategy

> **Document ID**: SEC-K8S-0001
> **Status**: APPROVED
> **Compliance Baseline**: FedRAMP High · NIST SP 800-53 SC-28 · FAPI 2.0
> **Last Updated**: 2026-06-16

Sentinel production clusters must not store source-controlled Kubernetes `Secret` manifests. Runtime secrets are fetched from a cloud KMS-backed secret manager and reconciled into the cluster by External Secrets Operator (ESO), with envelope encryption enabled for the Kubernetes API server and short secret refresh intervals.

Use Azure Key Vault for AKS or AWS Secrets Manager for EKS as the system of record for `redis-connection-string`, `keycloak-client-secret`, SIEM mTLS material, and API TLS material. ESO should authenticate with workload identity only: Azure Workload Identity on AKS or IRSA on EKS. Do not use static cloud access keys in Kubernetes.

The Kubernetes-facing secret names consumed by the manifests are:

- `sentinel-runtime-secrets`: `redis-connection-string`, `keycloak-client-secret`
- `sentinel-api-tls`: `tls.crt`, `tls.key`
- `sentinel-ca-bundle`: `ca.crt`
- `sentinel-siem-mtls`: `ca.crt`, `tls.crt`, `tls.key`

## ESO Policy Requirements

- **Least-Privilege RBAC & Scoping**: Scope each `SecretStore` or `ClusterSecretStore` to the minimum cloud identity permissions required to read only the named secrets.
- **Short Refresh Intervals**: Use refresh intervals no longer than 15 minutes for client credentials and connection strings to ensure timely credential propagation.
- **Service Account Isolation**: Deny secret reads to application service accounts through Kubernetes RBAC except where a pod mount or `secretKeyRef` requires it.
- **Automated Rotation & Alerts**: Enable cloud-side key/secret rotation and alert immediately on stale secret versions or failed ESO reconciliation loops.
- **Volume Mounted Secrets**: Prefer CSI Secret Store mounted volumes for TLS key material when supported by the platform baseline; use ESO-synced Kubernetes secrets only where workload compatibility requires standard `secretKeyRef` or `secret` volume semantics.


## Hardening Standards

### 1. KMS Envelope Encryption for etcd (NIST SP 800-53 SC-28)
To satisfy FedRAMP High and NIST SP 800-53 data-at-rest protection standards, the Kubernetes control plane's `etcd` database must be encrypted at rest using envelope encryption backed by a cloud HSM/KMS (Azure Key Vault KMS Plugin or AWS KMS KMS-Plugin).
- All secrets synchronized into the cluster by ESO must be encrypted immediately on the physical disk at the etcd database layer.
- Plaintext storage of secret values in etcd is a critical compliance violation.

### 2. Key Rollover Grace Periods (Zero-Downtime Rollout)
During automated rotation of signing keys, encryption keys, or client secrets, the cloud KMS must maintain a **24-hour overlap grace period**:
- The previous version of the rotated credential/key must remain in an active, decrypt-only phase.
- This ensures that intermediate transactions or active sessions validated during the ESO sync interval do not fail due to a sudden trust-anchor removal.
- Stale or fully retired key versions must be automatically deactivated and archived after the 24-hour rollover window has successfully concluded.
