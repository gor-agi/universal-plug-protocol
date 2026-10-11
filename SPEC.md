# Universal Plug Protocol Specification

Version 0.6.0

UPP makes a fact checkable by anyone: an issuer **proves** it (signs a statement about its hash and anchors it on a
ledger), and anyone **checks** it later without trusting the issuer, the ledger operator, or the software that made
it. Its main use is evidence about AI agents: what an agent did, and on whose authority.

This document is normative. Where the reference implementation (`upp`, Python) differs, this document wins.

## Principles

- **Closed by default.** Nothing is trusted, fetched, or signed without an explicit grant by the operator. Any grant
  can be opened, but only by the explicit value `ANY`, whose use is logged. A malformed grant is an error, never an
  opening.
- **Small.** Two verbs (prove, check), one statement format, one registry format. Profiles add vocabulary and rules,
  never operations.
- **Any ledger.** A ledger anchors statements and reports when; the guarantee a verifier gets is the same on a local
  log, a public chain, or a permissioned one.
- **Only hashes leave.** Facts stay with whoever holds them; ledgers see hashes, salted when the fact is personal.

## Permissions

| Permission | Granted with | Default | `ANY` opens it to |
| --- | --- | --- | --- |
| Which issuers check as valid on a network | `Plug(trust={network: registry})`, `plug.trust(network, registry)` | none: check is rejected `not_authorized` | any authentic issuer |
| Narrowing at one check | `check(att, trust_registry=...)` | — | — (only narrows the operator's) |
| Hosts remote documents come from | `allow_hosts(host, ...)` | none; private addresses also need `allow_private_networks()` | any public host |
| Who signs | an open session on the network | nobody: a ledger signs only as the open session, never as an issuer a caller names | — |
| What a model may prove over MCP | `build_server(fact_types=[...])` | nothing | every type outside the reserved prefixes |
| Registries a model may name over MCP | `build_server(registries={name: registry})` | none | — |

## Data model

- **Attestation**: `subject_hash` (hex, 32 bytes), `hash_alg` (`sha-256` default, `sha3-256`, `sm3`), `fact_type`
  (open vocabulary, canonicalized to lowercase dotted), `issuer` (DID), `issued_at` and optional `expires_at`
  (ISO-8601), `meta` (signed labels; keys beginning with `_` are internal and never signed), `proof`
  (`{alg, sig, verification_method}`), `anchor` (StateRef, set by the ledger), and for a batch member `inclusion`.
- **StateRef**: `network`, `address`: where a statement was anchored.
- **Receipt**: `op`, `status` (`ok` or `rejected`), `network`, optional `state_ref`, `data`, optional `error`. A
  ledger reports `anchored_at` and, where it applies, `finality: {kind: final | probabilistic, confirmations}` in data.

## Canonical form and hashing

Structured facts are serialized with RFC 8785 (JCS) before hashing, so every implementation derives the same hash.
Integers beyond 2^53 are carried as strings (I-JSON). Bytes are hashed as-is, text as UTF-8, any other JSON value as
its RFC 8785 form; other types are refused. Every supported hash algorithm yields 32 bytes; the attestation names it.

**Salted commitments.** A plain hash of low-entropy data (a name, a phone number) can be reversed by guessing. With
`commitment = salted`, prove anchors `H(salt ‖ fact)` under a fresh 32-byte salt returned only to the caller.
Whoever holds fact and salt can open it; nobody else can link it. Deleting the salt and the fact leaves the anchor
unlinkable, which is how a ledger deployment honours erasure (GDPR Art. 17) without rewriting history.

## Statement

A proof signs, and a ledger anchors, the **statement**: the subject hash with every label a verifier acts on.

```
statement      = {"upp.statement": {"subject_hash", "hash_alg", "fact_type", "issuer", "issued_at", "expires_at", "meta"}}
statement_hash = H(JCS(statement))   under the attestation's hash_alg
```

`subject_hash` is lowercase hex; `expires_at` is `null` when absent; `meta` omits keys beginning with `_`. No label
can be changed without invalidating the proof: a halt cannot be shown as a resume, or one purpose as another.
`issued_at` is the issuer's claim and is never the time a key is judged at.

## Signature suites and DIDs

Every suite signs the 32-byte statement hash:

| alg | standard | verification_method |
| --- | --- | --- |
| `ed25519` | PureEdDSA, RFC 8032 | did:key |
| `ecdsa-p256` | ECDSA P-256 with SHA-256, deterministic (RFC 6979), r‖s | did:key |
| `ecdsa-secp256k1` | ECDSA with the hash as digest (Ethereum-compatible) | 0x address |
| `sm2-sm3` | SM2 with SM3, ID 1234567812345678 (GB/T 32918.2), r‖s | did:key |

A did:key is accepted only in canonical form (a 32-byte Ed25519 key or a 33-byte compressed point, re-encoding to the
same identifier). Ed25519 keys that are not canonical points or lie in the small-order subgroup are rejected:
common libraries, OpenSSL included, verify forgeries under them. A proof is valid only when its signature verifies
and the issuer DID names the same key: did:key names itself, `did:pkh:eip155:<chain>:<address>` names an account. An
issuer whose DID names no key is unverifiable unless a registry lists its keys.

## Check

check accepts an attestation only when all of these hold:

1. **A trust policy applies**: the operator's for the network, the caller's registry, or both (then both must pass).
   With none, check is rejected `not_authorized`. `ANY` accepts any authentic issuer.
2. **Authentic**: the proof verifies over the statement hash and the issuer DID names the signing key.
3. **Anchored**: the anchor is on this network, succeeded, carries exactly the statement hash, and (on a ledger whose
   transactions are signed) was sent by the signing key. A signature alone proves possession of a key, not that a
   fact was recorded or when.
4. **Not expired**: `expires_at`, if present, is in the future.
5. **Trusted**: the issuer is in every applicable registry, and when a registry lists keys for it, the signing key is
   listed and valid at the **proven time**: the anchoring time, never a time the issuer claims. A key revoked after an
   anchor still verifies it; a key revoked before it does not.

**Registry**: `{"issuers": ["did:...", ...], "keys": {"<did>": [{"verification_method", "valid_from"?, "valid_until"?}]}}`,
given inline or as an http(s) URL. URLs are fetched only from allowed hosts and public addresses (checked on the
address actually connected to, on every redirect), with a 5 s timeout, a 64 KiB cap, and no environment proxy.

## Batches

`prove_batch(facts, fact_type)` proves many facts under one anchor. The facts' subject hashes (salted individually)
are the leaves of an RFC 9162 Merkle tree; the anchored subject is `H(JCS({"upp.batch": {"root", "size"}}))`,
attested once as fact type `upp.batch` with meta `{...caller meta, batch_size, batch_fact_type}`. Each fact's
attestation carries `inclusion: {tree: "rfc9162", index, size, path, root}` and the batch's proof and anchor. check
verifies the inclusion proof, rebuilds the batch statement from the member (so the member's fact type is signed),
and checks it. A member whose meta carries `batch_size` or `batch_fact_type` is rejected.

**Reserved domain.** Statements and batch commitments are JSON objects keyed `upp.*`. prove refuses any fact whose
bytes begin with `{"upp.`, so no fact can pass as a statement or a batch root.

## Ledgers

A ledger implements `connect(network, auth) → {subject}`, `bind(subject)`, `attest(network, att)`, and
`verify(att, network, registry)`. It signs only as the session bound to the call and refuses any other issuer.

| Ledger | Issuer | Anchor | Anchoring time |
| --- | --- | --- | --- |
| `LocalLedger` | did:key of the session key (Ed25519 by default; any suite, or a PKCS#11 HSM) | append-only log, in memory or a JSONL file | the log keeper's clock |
| `EthereumLedger` | `did:pkh:eip155:<chain>:<address>` | 0-wei self-transaction carrying the statement hash | block timestamp |
| `ChainMakerLedger` | did:key of the member's P-256 certificate key | call to a STOP-only anchor contract | block timestamp |

A local log proves order and integrity to whoever trusts its keeper; a public or permissioned ledger removes that
trust. A verifier that needs more assurance reads a ledger from several independent endpoints and requires them to
agree (`EthereumLedger(read_urls=[...])`).

## Grants profile: on whose behalf

Consent, an agent's mandate, and a human's approval of one action are one primitive: a **grant**, an attestation of
fact type `grant` issued by the grantor, with required `expires_at` and signed meta:

| Field | Meaning |
| --- | --- |
| `grantee` | the DID the grant is to |
| `scope` | `{key: [allowed values]}`. An action is within it when, for every key, its value is listed: `fact_type`, `subject_hash`, `network` from the action, any other key (`tool`, `purpose`, `channel`, ...) from its signed meta. A missing value is outside. |
| `kind` | optional: `consent`, `mandate`, or `approval` |
| `refs.parent` | for a delegated grant, the statement hash of its parent grant |

An action claims authority by naming its grant in signed `meta.refs.grant`. It is authorized only if:

1. the action is authentic;
2. following `refs.parent`, each grant names as grantee the party that used it, every grant's scope contains the
   action, each delegated scope narrows its parent's, and no grant expires later than its parent or before the
   action's proven time;
3. the root grant passes the verifier's trust policy (authority starts only from a trusted principal; agents
   themselves need not be trusted);
4. no presented revocation applies: a `grant.revoke` naming a grant in `meta.refs.revokes`, issued by that grant's
   grantor or an ancestor's, proven no later than the action (or with either time unknown). Revocation is final and
   never invalidates actions proven before it (GDPR Art. 7(3)).

The whole chain is judged on the verifier's network. Parties are compared by the key their DID names, references
as lowercase statement hashes. Nothing is fetched by following a reference.

**References.** `meta.refs` is the one place an attestation names others: `{name: statement hash or [hashes]}`,
signed, so a link cannot be added, removed, or redirected. Names: `grant`, `parent`, `revokes`, `action`, `data`,
and `prev` (the same actor's previous action, which makes an omitted or forked record visible).

## Agent oversight profile

For systems where AI models act on someone's behalf. Every model is treated as a potentially compromised insider:
authority over it sits outside it, and the evidence of what it did does not depend on it.

| fact_type | issued by | records |
| --- | --- | --- |
| `agent.action` | the harness running the model, never the model | an action: tool, `model_family`, `model_id`, digests of inputs and outputs, `refs.grant`, `refs.prev` |
| `agent.review` | a person, or a model of a different family | a judgment on an action (`refs.action`) |
| `control.halt`, `control.resume` | an authorized controller | containment of an actor |
| `incident.report` | the operator | a failure and which controls did not hold (salted) |

The harness signs with a key the model cannot use; an automated review counts only from another model family; the
harness checks the latest halt/resume before each action; evidence is anchored on a ledger the model's operator does
not control alone.

## MCP transport

`upp.mcp_server` exposes `prove`, `prove_batch`, `check`, and `networks` as Model Context Protocol tools. The server
holds every key and accepts no credential from the model. The model proves only fact types the operator grants
(none by default; `ANY` excludes `agent.`, `control.`, `incident.`, and `grant`, which must be granted by name;
`upp.` is never granted), names trust registries only from a server-side list, and cannot set `model_family` or
`model_id`. Calls are rate-limited and bounded in size; nothing returned carries URLs or host addresses.

## Errors

`auth_failed`, `not_found`, `not_authorized`, `unsupported_op`, `proof_invalid`, and the retryable `timeout` and
`rate_limited`.

## Conformance

`spec/vectors/` holds language-neutral vectors. `jcs.json` is generated by an independent implementation (Node);
`rfc9162.json` comes from an independent RFC 9162 implementation; `protocol.json` (salted and batch commitments,
inclusion proofs, statements, Ed25519 and P-256 proofs with relabeling and key-validation cases, the reserved
domain) is produced by the reference and re-derived from this document alone by `verify_protocol.mjs`. Third-party
suites (Wycheproof, cyberphone JCS, IETF status-list examples) are run in the test suite. An implementation conforms
when it reproduces every value and verdict.

## Appendix: problems this answers (informative)

| Problem | Where it occurs | Answer |
| --- | --- | --- |
| An AI model attests to its own actions | agent frameworks with self-reported logs | The harness signs; reviews come from another model family |
| Agents act with no verifiable "on whose behalf"; consent cannot be proven or withdrawn | agent frameworks, messaging opt-in, consent banners | Grants: signed, scoped, expiring, revocable; delegation only narrows |
| A signature covers a hash but not its labels | detached signatures, hash anchoring | The statement signs subject, type, issuer, times, and meta together |
| Personal data on an immutable ledger cannot be erased | on-chain attestation schemas | Salted commitments |
| One transaction per attestation | per-attestation registries | Batches: one anchor per RFC 9162 root |
| Batching depends on an aggregation server | calendar timestamping | The issuer batches its own facts |
| Rotated or leaked keys break old signatures or backdate new ones | credentials, trust lists | Registry key windows judged at the proven time |
| Hashes differ between implementations | JSON-based formats | RFC 8785 with independent vectors |
| Everything is open to whoever asks | permissive defaults in agent tooling | Closed by default; `ANY` is explicit and logged |
