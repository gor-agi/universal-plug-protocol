# Universal Plug Protocol (UPP)

**Checkable evidence for AI agents: what an agent did, and on whose authority. Closed by default.**

An agent acts for you: sends an email, moves money, changes a record. Later someone asks: *was it allowed to?* Logs
can be edited, and the agent's own word is worthless. UPP gives every action a signed, anchored statement, and every
"you may" a signed, scoped, revocable grant, so anyone can check, without trusting the agent, its operator, or you.

```python
from upp import Attestation, LocalLedger, Plug

plug = Plug()
plug.register("log", LocalLedger("evidence.jsonl"))
plug.open("log")                                            # a fresh Ed25519 identity
receipt = plug.prove({"tool": "email.send", "to": "bob"}, "agent.action")

auditor = Plug(trust={"log": {"issuers": [plug.active().subject]}})   # trusts nobody else
auditor.register("log", LocalLedger("evidence.jsonl"))
print(auditor.check(Attestation.from_receipt(receipt))["valid"])      # True; False if anything was altered
```

```
pip install universal-plug
```

## What you get

- **prove / check.** A fact's hash, its type, issuer, times and labels are signed together and anchored on a ledger.
  check accepts it only if the signature, the issuer, the anchor and the verifier's own trust policy all hold.
- **Grants: on whose behalf.** Consent, mandates and approvals are one primitive: a signed grant with a scope, an
  expiry and optional delegation that can only narrow. `check_authority` tells you whether an action was authorized,
  in scope, and not revoked. See [examples/agent_evidence.py](examples/agent_evidence.py).
- **Closed by default.** No issuer is trusted, no host fetched, no fact type provable by a model until the operator
  grants it. `ANY` opens a permission explicitly and is logged.
- **Personal data stays off the ledger.** Salted commitments: only an unlinkable hash is anchored; erase the salt
  and it is gone. See [examples/consent_record.py](examples/consent_record.py).
- **Any ledger.** A local JSONL log, any EVM chain (`EthereumLedger`), or ChainMaker; Ed25519, P-256, secp256k1 and
  SM2 keys, in software or in an HSM (PKCS#11).
- **MCP server.** Give a model `prove` and `check` tools while the server keeps every key:
  `upp-mcp --config upp-mcp.json` (see [upp/mcp_server.py](upp/mcp_server.py) for the config).

Run the examples:

```
python examples/agent_evidence.py
python examples/consent_record.py
```

```
reminder email                         AUTHORIZED
marketing email                        REFUSED  not_authorized: action is outside the grant's purpose
action relabeled after the fact        REFUSED  action: proof_invalid: statement does not match the anchor
reminder sent before the revocation    AUTHORIZED
reminder sent after the revocation     REFUSED  not_authorized: grant revoked
```

## Extras

| Extra | Adds |
| --- | --- |
| `universal-plug[ethereum]` | `upp.ledgers.EthereumLedger` (web3) |
| `universal-plug[mcp]` | `upp.mcp_server` |
| `universal-plug[hsm]` | `upp.suites.Pkcs11Signer` |
| `universal-plug[eudi]` | `upp.ext.eudi`: ETSI trusted lists, SD-JWT VC and mdoc credentials, Token Status Lists |
| `universal-plug[chainmaker]` | `upp.ext.chainmaker.ChainMakerLedger` |
| `universal-plug[sm2]` | the SM2/SM3 suite |

## Status

Pre-1.0. The protocol and API may still change. It has been through repeated internal security reviews and is
tested against third-party vectors (Wycheproof, RFC 8785, RFC 9162, IETF status lists) and an independent Node
verifier, but it has **not** had an external audit. Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Read more

- [SPEC.md](SPEC.md): the protocol (normative).
- [docs/threat-model.md](docs/threat-model.md): what it defends against, and what it does not.
- [spec/vectors/](spec/vectors/): conformance vectors for other implementations.
- [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md).

Apache-2.0.
