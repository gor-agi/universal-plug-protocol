# Universal Plug Protocol

A network-agnostic Python core for attestations and identity. Callers use prove, check, and watch. Each backend is an adapter.

## What is in this package

- `plug.core` — protocol core. It does not import a network SDK. RFC 8785 canonical form; SHA-256, SHA3-256, or SM3 by deployment profile; optional salted commitments for personal data.
- `plug.suites` — signature suites: ecdsa-secp256k1, ed25519, ecdsa-p256, sm2-sm3. Issuer binding for `did:key`, `did:plug`, and `did:pkh`.
- `plug.adapters.StubAdapter` — in-memory adapter. The test suite uses it. It does not check signatures, and it rejects proofs it cannot check.
- `plug.adapters.OracleAdapter` — observation-to-attest backend with freshness, jump-bound, and issuer checks.
- `plug.adapters.EudiAdapter` — EU digital identity wallet profile: trusted lists that supply issuers and their keys, and IETF Token Status Lists. A credential that names a status list in `meta.status.status_list {idx, uri}` verifies only while its status is VALID; the Status List Token must be a `statuslist+jwt` signed (ES256 or EdDSA) by a key of the issuer. An unreachable list with no unexpired cached copy fails closed. Trusted lists here are JSON registries, not signed ETSI trusted lists, and SD-JWT VC and mdoc credentials are gated by format name, not verified (see [docs/threat-model.md](docs/threat-model.md)).
- `plug.adapters.ChainMakerAdapter` — permissioned ledger with certificate-based membership (ChainMaker v3). Anchors statement hashes through a one-opcode EVM contract; verification binds the issuer to the member's P-256 key and reports the member organization and finality.
- `plug.adapters.LiveAdapter` — Ethereum-family adapter (Sepolia by default). Install the `live` extra. Set `SEPOLIA_RPC_URL`; a session brings its key as raw auth material, and `SEPOLIA_PRIVATE_KEY` is the optional default. Attest signs the attestation's statement hash (subject hash, type, issuer, times, role, and meta), records it on-chain, and sets the attestation's `anchor`. Verify passes only when the signature, the issuer DID, and the on-chain anchor all name the same key and carry the same hash; it reports `anchored_at` and finality.
- `plug.mcp_server` — Model Context Protocol transport: prove, prove_batch, check, watch, networks. Keys stay server-side; the server, not the model, decides which fact types it proves and sets the model identity. Run `python -m plug.mcp_server --config plug-mcp.json` (install the `mcp` extra).

Watch returns a stream handle. The stub appends a matching `event` record to the adapter log. The Sepolia adapter polls that transaction's receipt once per subscribe and records the tx and logs selected by the filter. This package does not open a long-lived socket.

## Installation

From this repository:

```bash
pip install -e ".[dev]"      # tests
pip install -e ".[live]"     # Ethereum-family adapter
pip install -e ".[suites]"   # Ed25519, P-256, SM2 signature suites
# ChainMaker adapter: its SDK pins pysha3, which does not build on Python 3.11+.
pip install -e ".[suites]" safe-pysha3 protobuf grpcio pyyaml cryptography asn1 pyasn1 pyasn1-modules requests pymysql
pip install --no-deps "chainmaker==3.0.7"
```

`scripts/bridge_test.py` proves a fact on a ChainMaker ledger, references it on an Ethereum-family network through the relayer-free bridge, and verifies both sides.

`requirements.txt` lists the same live packages. Core install has no runtime dependencies.

## Quick start

```python
from plug import Attestation, Plug
from plug.adapters import StubAdapter

plug = Plug()
plug.register_adapter("testnet", StubAdapter())
plug.open("testnet", {"scheme": "raw", "material": "key", "subject": "alice"})

receipt = plug.prove({"temp": 21.5}, "sensor.reading")
print(receipt.status)

attestation = Attestation.from_receipt(receipt)   # every signed label, ready for check
print(plug.check(attestation)["valid"])           # False here: the stub holds no keys and checks no signatures
```

An explicit network is required when there is no open session. Prove hashes `bytes` as raw bytes. A trust registry is `{"issuers": ["did:..."]}`, passed inline or as a URL fetched by the adapter over http or https. The attestation issuer has to be in that list.

## Specification

- [SPEC.md](SPEC.md) — operations, payload schemas, canonical form, signature suites, the error model, session rules, the idempotency invariant, and bridge verification.
- [spec/did-plug.md](spec/did-plug.md) — the `did:plug` method.
- [spec/vectors/](spec/vectors/) — language-neutral conformance vectors, with an independent Node verifier for commitments, batch inclusion proofs, and Ed25519 and P-256 proofs, plus third-party vectors (Wycheproof, RFC 8785 reference data, the status list draft).
- [docs/threat-model.md](docs/threat-model.md) — security goals, per-component problem definitions, and the decisions taken on each.

## Project

[CHANGELOG.md](CHANGELOG.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [GOVERNANCE.md](GOVERNANCE.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [MAINTAINERS.md](MAINTAINERS.md)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
