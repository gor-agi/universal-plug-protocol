# Changelog

All notable changes to the specification and the reference implementation. Versions follow [SPEC.md](SPEC.md).

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
