# Changelog

All notable changes to the specification and the reference implementation. Versions follow [SPEC.md](SPEC.md).

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
