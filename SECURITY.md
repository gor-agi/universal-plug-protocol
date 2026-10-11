# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately by email to **gor@agi-brain.com**, or through the repository's **Security → Report a vulnerability** form (GitHub private vulnerability reporting) where it is enabled. Do not open a public issue, pull request, or discussion.

Include the affected version or commit, the component (core, a signature suite, an adapter), a description of the impact, and a minimal reproduction. Maintainers aim to acknowledge reports within five business days and to agree a disclosure date with the reporter before any public advisory.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.4.x | Yes |
| 0.3.x | No: verification trusted any authentic issuer by default |
| 0.2.x | No: proofs signed only the subject hash, so type, issuer, times, and meta could be relabeled |
| < 0.2 | No: receipt hashing and canonical form changed |

## Scope

In scope: canonical serialization and hashing, signature suites and issuer binding, receipt and idempotency logic, bridge verification, and the adapters in this repository.

Out of scope: vulnerabilities in third-party networks or in optional dependencies themselves. Report those upstream; reports of how this project uses them are in scope.

## Known limitations

- **SM2 signing backend.** The `sm2-sm3` suite performs curve arithmetic through a pure-Python library that is not constant-time. Verification is unaffected. Signing on hosts exposed to timing measurement requires a constant-time backend; none is installable today on every target platform (see docs/threat-model.md, P4).
- **Ledger finality.** Verification reports finality; it does not wait for it. Relying parties choose their own threshold.
- **Signed time is a claim.** A proof signs the attestation's statement: subject hash, type, issuer, `issued_at`, `expires_at`, role, and meta. `issued_at` is the issuer's signed claim, not evidence of when; the anchored time comes from the ledger, and registry keys are judged at it.
- **Status lists.** The EUDI adapter reads Token Status Lists in JWT form only; a CWT status list, or any token it cannot verify, is rejected. Freshness is judged from the token's signed `iat`: a token older than its `ttl` plus `status_list_max_stale`, or older than `status_list_max_age` (one day by default), is refused, as is a token older than one already seen. When a fresh token cannot be fetched or verified, a cached one stands in only within those bounds and never past `exp`. Whoever can block the status host can therefore delay a revocation by at most that window.
- **Remote documents.** Registries, trusted lists, and status lists are fetched only from public addresses (IPv4-mapped and NAT64 addresses are judged by the IPv4 host they reach) unless the deployment calls `plug.adapters.base.allow_private_networks()`. Environment and system proxies are not used, so the address checked is the host fetched. Deployments that enable private addresses should allowlist registry URLs, since status list URIs come from credentials.
- **EUDI scope.** The EUDI adapter's trusted lists are JSON registries (`{"issuers", "keys"}`), not signed ETSI TS 119 612 trusted lists or OpenID Federation trust chains, and it gates SD-JWT VC and mdoc credentials by format name without verifying them. Deployments that need those verify credentials and trust lists upstream (see [docs/threat-model.md](docs/threat-model.md), P8 and P9).
- **Closed by default.** Verification, remote fetching, signing, and the MCP server are closed until the operator grants access (SPEC, Permissions). `ANY` opens a grant on purpose and is logged on `plug.policy`; review those log lines as you would firewall exceptions.
- **Key custody.** Attestation proofs can be signed inside an HSM through `Pkcs11Signer` (P-256, Ed25519). Ledger adapters still hold their transaction keys (secp256k1, SM2) in process memory.
- **Ledger reads.** A ledger adapter with one endpoint trusts it. Give the Ethereum adapter more read endpoints, such as a Helios light client, so that verification reads must agree.
- **ECDSA malleability.** High-S ECDSA signatures are accepted. Nothing keys on signature bytes, so a second valid signature over the same statement carries the same meaning.
- **Local DID aliases.** `did:plug` identifiers in local form are meaningful only inside one deployment (see [spec/did-plug.md](spec/did-plug.md)).
