# Kubernetes Secret Management Strategy

Sentinel production clusters must not store source-controlled Kubernetes `Secret` manifests. Runtime secrets are fetched from a cloud KMS-backed secret manager and reconciled into the cluster by External Secrets Operator (ESO), with envelope encryption enabled for the Kubernetes API server and short secret refresh intervals.

Use Azure Key Vault for AKS or AWS Secrets Manager for EKS as the system of record for `redis-connection-string`, `keycloak-client-secret`, SIEM mTLS material, and API TLS material. ESO should authenticate with workload identity only: Azure Workload Identity on AKS or IRSA on EKS. Do not use static cloud access keys in Kubernetes.

The Kubernetes-facing secret names consumed by the manifests are:

- `sentinel-runtime-secrets`: `redis-connection-string`, `keycloak-client-secret`
- `sentinel-api-tls`: `tls.crt`, `tls.key`
- `sentinel-ca-bundle`: `ca.crt`
- `sentinel-siem-mtls`: `ca.crt`, `tls.crt`, `tls.key`

ESO policy requirements:

- Scope each `SecretStore` or `ClusterSecretStore` to the minimum cloud identity permissions required to read only the named secrets.
- Use refresh intervals no longer than 15 minutes for client credentials and connection strings.
- Deny secret reads to application service accounts through Kubernetes RBAC except where a pod mount or `secretKeyRef` requires it.
- Enable cloud-side rotation and alert on stale secret versions.
- Prefer CSI Secret Store mounted volumes for TLS key material when supported by the platform baseline; use ESO-synced Kubernetes secrets only where workload compatibility requires standard `secretKeyRef` or `secret` volume semantics.
