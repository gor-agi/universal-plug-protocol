# Changelog

All notable changes to the specification and the reference implementation. Versions follow [SPEC.md](SPEC.md).

## 0.5.0

### Added

- **Grants profile** (SPEC, Grants profile; docs/threat-model.md, G8, P15, P16): consent, agent mandates, and human approvals as one primitive, a signed `grant` with grantee, scope, and expiry. `plug.grants.check_authority` follows an action's grant chain to a principal the trust policy accepts; delegation only narrows; revocation (`grant.revoke`) by the grantor or any ancestor, ordered by proven time, so withdrawn consent never undoes earlier actions. Agents need not be trusted themselves.
- **Signed references**: `meta.refs` names other attestations by statement hash; `check_sequence` detects skipped or forked records in an actor's `refs.prev` chain.
- MCP reserves the `grant` prefix: a model issues grants or revocations only if the operator allows those types by name.
- From review before release: a chain is judged on the verifier's network only (an unsigned anchor on a more open network no longer lends its trust), and revokers and grantees are compared by the key their DID names, so a withdrawal is never lost to a different spelling of the grantor's DID.

The design follows UCAN (attenuation, revocation by ancestors), OAuth RFC 9396 and GNAP (structured scope), Google AP2 (mandates bound to actions), ISO/IEC TS 27560 and Kantara (consent per purpose), and in-toto, SLSA, and SCITT (references by digest).

## 0.4.1

### Added

- `plug.trusted_lists.verify_trusted_list`: ETSI TS 119 612 trusted lists verified with `signxml` against pinned signer certificates, returning anchors of the service types you name. Tested against Luxembourg's live list with the signers the EU list of trusted lists pins.
- `plug.credentials.verify_sd_jwt_vc` (RFC 9901, SD-JWT VC) and `verify_mdoc` (ISO/IEC 18013-5, via `pymdoccbor`), each requiring an X.509 chain to anchors and returning the issuer as a did:key for trust policies. Tested with credentials issued by `sd-jwt-python` and `pymdoccbor`; `sd-jwt-python` also runs as a reference verifier in CI.
- The `eudi` extra.

## 0.4.0

### Breaking: closed by default

One permission layer: a grant is an explicit list, empty by default, and the single value `ANY` opens it on purpose and is logged on `plug.policy` (SPEC, Permissions; docs/threat-model.md, G7 and P14).

- **Verification needs a trust policy.** `Plug(trust={network: registry})` or `plug.trust(network, registry)` sets the operator's policy; a registry passed to `check` narrows it and never widens it. With no policy, `check` is rejected (`not_authorized: no trust policy for <network> (closed by default)`). `ANY` accepts any authentic issuer. A malformed policy raises.
- **Remote documents only from allowed hosts.** `plug.adapters.base.allow_hosts(...)`; redirects are held to the same list; private addresses still need `allow_private_networks()`.
- **Only the open session signs.** A ledger adapter signs only for the session open on its network: no anonymous signing with its configured key, and no signing for an issuer a caller merely names (a review found `attest` would sign with any loaded key whose address the issuer named).
- **MCP proves nothing until granted.** `build_server(fact_types=[...])` or `ANY`; registries only by operator-given name (inline registries from the model are refused); calls are rate-limited (`rate=(calls, seconds)`, 120 per minute by default). Config gains `trust` and `hosts`.

### Added

- `KeySigner`, `Pkcs11Signer` (keys inside an HSM or SoftHSM; P-256 and Ed25519), and `sign_attestation` in `plug.suites`; the `hsm` extra. CI signs inside a SoftHSM2 token.
- Extra read endpoints for the Ethereum adapter (`read_urls`, `readers`): verification reads must agree across all of them, and finality is the weakest reported.
- JWS `alg` `Ed25519` (RFC 9864) for status list tokens, alongside `EdDSA`.
- Oracles: Wycheproof secp256k1 through Ethereum recovery; `joserfc` signs status list tokens our verifier must accept.

### Changed

- Merkle batches build their tree once (`merkle_levels`), O(n) instead of O(n^2) for all inclusion proofs; output unchanged.

## 0.3.2

### Security

From an audit against the new threat model ([docs/threat-model.md](docs/threat-model.md)):

- **Ed25519 small-order keys.** The identity key "signed" every message, and OpenSSL accepts such forgeries. Keys that are not canonical points or lie in the small-order subgroup are rejected, here and in the Node verifier.
- **One key, one did:key.** P-256 keys were accepted uncompressed or as DER, so one key had several identifiers. Only the canonical form (32-byte Ed25519, 33-byte compressed point, re-encoding to the same string) is accepted.
- **Status list freshness is judged from the signed `iat`**, so an old pre-revocation token without `exp` is refused however recently it was fetched; future `iat` is refused.
- **Registry URLs reached the model** in MCP receipts. Receipts are now redacted of URLs, gRPC targets, and host addresses throughout.
- **Operator trusted lists are no longer replaced** by a caller's registry; a caller can only narrow them.
- **Unsigned batch labels.** A batch member carrying its own `batch_size` or `batch_fact_type` is rejected.
- **Scalar facts** (`true`, `null`, numbers) are hashed as RFC 8785, not Python `str()`; facts of other types are refused, and integers beyond 2^53 are refused instead of hashed.
- **Address guard** also refuses multicast, local-use NAT64, IPv4-compatible, SIIT, and SRv6 ranges. MCP calls are bounded in batch size and fact size.

### Changed

- Ed25519 and P-256 use **pyca/cryptography** (OpenSSL-backed) instead of pycryptodome; signatures are byte-identical (deterministic), and the `suites` extra now requires `cryptography>=43`.

### Added

- `docs/threat-model.md`: security goals, problem definitions P1–P13, and the decision on each after surveying existing solutions.
- Third-party vectors in `spec/vectors/` (see its README): Wycheproof P-256 and Ed25519, the RFC 8785 reference data, and the status list draft's Appendix C; Trail of Bits `rfc8785` as a test oracle (`dev` extra).

## 0.3.1

### Fixed

- **EUDI status lists never worked.** The status list was parsed as a trust registry: a real list (no `issuers`) was always rejected as unreachable, and a list that carried `issuers` lost its status bits, so revoked credentials verified. The adapter now implements IETF Token Status Lists (draft-ietf-oauth-status-list): a `statuslist+jwt` signed with ES256 or EdDSA by a key of the credential's issuer, `sub` equal to the referenced uri, `iat` required, `exp` and `ttl` honoured, 1/2/4/8-bit ZLIB-compressed lists, VALID only for status 0x00. Out-of-range indexes, malformed lists, and decompression beyond 16 MiB are rejected.
- The status reference moves to `meta.status.status_list {idx, uri}`, as in the draft. The old `status_list_url` / `status_list_index` keys are rejected rather than ignored.

### Security

Found by a security review of 0.3.0:

- **A ledger record used as a trust registry restricted nothing.** A StateRef registry whose record had no `issuers` list was treated as no registry, so any self-signed issuer verified. It is now rejected unless the record is ok and lists issuers.
- **SSRF through status list URIs.** A model could make the MCP server fetch any URL by proving with `meta.status`. The MCP server refuses operator-only meta; remote documents are fetched only from public addresses (checked on the connected socket, every redirect hop, with IPv4-mapped and NAT64 addresses judged by their IPv4 host, and without environment proxies) unless a deployment opts in; and the EUDI adapter verifies the credential's signature before it fetches a status list.
- **RPC URL disclosure.** Upstream errors could carry the RPC URL, and with it a provider API key, to the model. The Ethereum adapter no longer copies upstream text into errors; the MCP server removes URLs from errors and answers unexpected failures with a generic error, logging details server-side.
- **Revocation hidden by blocking the status host.** A cached status list stood in indefinitely when the host was unreachable and the token had no `exp`. Stale reuse is now bounded by `ttl` and `status_list_max_stale`, only verified tokens are cached, and older tokens are refused.

### Added

- `fetch_document` and `allow_private_networks` in `plug.adapters.base`: the registry fetch guards (http/https only, public addresses only, timeout, size cap, no redirect off http(s)) for any document. `plug.suites.verify_jws` for ES256 and EdDSA over did:key.
- Tests for trusted lists, status lists, caching, and the draft's worked examples. EUDI adapter coverage rises from 69% to 95%.

## 0.3.0

### Breaking

- **Proofs sign the statement, not the bare subject hash.** A proof signs, and a ledger anchors, H(JCS({"plug.statement": {subject_hash, hash_alg, fact_type, issuer, issued_at, expires_at, role, meta, disclosure}})). In 0.2 these labels travelled unsigned, so a signed attestation could be relabeled: a `control.halt` presented as `control.resume`, a document hash as an `agent.action`, a review under another `model_family`, or an EUDI credential with its `status_list_url` removed. Proofs and anchors made under 0.2 do not verify under 0.3.
- Batch verification rebuilds the signed `plug.batch` statement, so a batch member's fact type is signed through it.
- Meta keys beginning with `_` are implementation-internal and are not signed.
- The idempotency cache is keyed on the statement. An attestation that differs in any signed label is anchored anew; where the plug sets `issued_at` itself (prove, prove_batch), a retry returns the first receipt with its original time.

### Added

- `statement` and `statement_hash` in `plug.core`; `Attestation.from_receipt` rebuilds the exact signed attestation from an attest receipt. Attest receipts carry `meta`, `role`, and, when set, `expires_at` and `disclosure`.
- In-memory adapters record the statement hash and report `proof_invalid: statement does not match the anchor` for a relabeled attestation.
- `spec/vectors/protocol.json` with an independent Node verifier (`verify_protocol.mjs`): salted, bridge, and batch commitments, RFC 9162 inclusion proofs, statements, the reserved domain, and Ed25519 and P-256 proofs including relabeling cases.
- Git hooks in `.githooks/`: DCO sign-off on commit; tests and vector checks before a push to `main`.

### Changed

- The diversity signal and the prediction-market loop form one prediction-market profile in the specification. Behavior is unchanged.
- The bridge section states what a verifier trusts: its own view of each network.
- The EUDI adapter fails closed when a status list is unreachable and no cached copy exists.

### Fixed

- The InMemoryAdapter extraction shipped with missing imports, a wrong receipt field in the oracle adapter, and a list used as a dict for trusted-list keys.

## 0.2.0

First public specification and reference implementation.
