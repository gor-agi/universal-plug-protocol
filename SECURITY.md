# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately by email to **gor@agi-brain.com**, or through the repository's **Security → Report a vulnerability** form (GitHub private vulnerability reporting) where it is enabled. Do not open a public issue, pull request, or discussion.

Include the affected version or commit, the component (core, a signature suite, an adapter), a description of the impact, and a minimal reproduction. Maintainers aim to acknowledge reports within five business days and to agree a disclosure date with the reporter before any public advisory.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| < 0.2 | No: receipt hashing and canonical form changed |

## Scope

In scope: canonical serialization and hashing, signature suites and issuer binding, receipt and idempotency logic, bridge verification, and the adapters in this repository.

Out of scope: vulnerabilities in third-party networks or in optional dependencies themselves. Report those upstream; reports of how this project uses them are in scope.

## Known limitations

- **SM2 signing backend.** The `sm2-sm3` suite performs curve arithmetic through a pure-Python library that is not constant-time. Verification is unaffected. Signing on hosts exposed to timing measurement requires a constant-time backend.
- **Ledger finality.** Verification reports finality; it does not wait for it. Relying parties choose their own threshold.
- **Signed scope.** A proof signs the 32-byte subject hash only. `fact_type`, `issued_at`, and `meta` are labels that travel with it, not signed claims. Anchored time comes from the ledger; relying parties that need a signed type or time must commit them inside the fact.
- **Local DID aliases.** `did:plug` identifiers in local form are meaningful only inside one deployment (see [spec/did-plug.md](spec/did-plug.md)).
