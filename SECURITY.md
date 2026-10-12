# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately by email to **gor@agi-brain.com**, or through the repository's **Security → Report a vulnerability** form (GitHub private vulnerability reporting) where it is enabled. Do not open a public issue, pull request, or discussion.

Include the affected version or commit, the component (core, a signature suite, an adapter), a description of the impact, and a minimal reproduction. Maintainers aim to acknowledge reports within five business days and to agree a disclosure date with the reporter before any public advisory.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.6.x | Yes |
| < 0.6 | No: the package was `plug`; 0.6 renamed it to `upp` and removed the bridge, settle, and other unsafe or unused surface |

## Scope

In scope: canonical serialization and hashing, signature suites and issuer binding, statements and batches, trust
registries and remote fetching, grants, the ledgers, the MCP server, and the `upp.ext` extensions.

Out of scope: vulnerabilities in third-party networks or in optional dependencies themselves. Report those upstream;
reports of how this project uses them are in scope.

## Known limitations

- **No external audit yet.** The code has had repeated internal reviews and third-party test vectors, not an
  independent audit.
- **Local ledger trust.** `LocalLedger`'s log is hash-chained, so inserting, editing, reordering, or backdating a
  record invalidates everything after it. Without `keeper=`, anyone who can write the file can append a record dated
  no earlier than the last one; with it, only the keeper's key can add records. The keeper can still rewrite the
  whole file and choose the clock: publish
  `head()` somewhere they cannot change (for example, prove it on a public ledger) to pin history, or use a public or
  permissioned ledger when a third party must not trust the keeper. On Windows, where file locks are not used, give
  each log file one writing process.
- **SM2 signing.** The `sm2-sm3` suite uses a pure-Python library that is not constant-time. Verification is
  unaffected; do not sign with SM2 on hosts exposed to timing measurement.
- **Ledger finality and reads.** Verification reports finality; it does not wait for it. A ledger with one read
  endpoint trusts it; give `EthereumLedger` several (`read_urls`) so reads must agree.
- **Signed time is a claim.** `issued_at` is the issuer's claim; registry keys are judged at the anchored time.
- **Status lists.** `upp.ext.eudi.status_lists` reads JWT Token Status Lists only. Freshness comes from the signed
  `iat` and `ttl`; a cached token stands in for at most `max_stale` seconds when a fresh one cannot be fetched, so
  whoever can block the status host can delay a revocation by at most that window.
- **Remote documents.** Registries and status lists are fetched only from hosts allowed with `allow_hosts` and from
  public addresses (IPv4-mapped and NAT64 addresses judged by the IPv4 host) unless `allow_private_networks()` is
  called. Proxies are not used, so the address checked is the host fetched.
- **EUDI scope.** Signer certificates for trusted lists must be pinned from a source you already trust. OpenID
  Federation trust chains are not supported.
- **`ANY`.** Every use is logged on the `upp.policy` logger; review those lines as you would firewall exceptions.
- **Key custody.** Proofs can be signed inside an HSM through `Pkcs11Signer` (P-256, Ed25519). Ethereum and
  ChainMaker transaction keys are held in process memory.
- **ECDSA malleability.** High-S signatures are accepted; nothing keys on signature bytes.
