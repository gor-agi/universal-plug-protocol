# Universal Plug Protocol Specification

Version 0.5.0

UPP defines a universal interface for attestations and identity across heterogeneous networks. Eight core operations — connect, identify, attest, query, verify, settle, bridge, subscribe — plus five session operations. Three user-facing verbs: prove, check, watch.

This document is the canonical reference. The implementation must match it; where they diverge, the spec wins.

## Design principles

- **Rail-neutral.** The plug carries attestations and identity. It does not own markets, tokens, or governance. Currency is the current settlement reality; value-net direction is roadmap context only.
- **Op budget.** Thirteen operations total. Any new op must delete or demote an existing one.
- **No token ops.** No mint, burn, swap, or stake. If a network adds a compliant token layer, that folds into settle or becomes a fourteenth op by explicit decision.
- **Fixed Receipt, open vocabularies.** Receipt shape is locked. Fact types, settle op names, and error extensions are open strings with recommended sets.
- **Anti-bloat.** Thin, inspectable, agent-facing. Every addition must earn its place against the three verbs.
- **Closed by default.** Nothing is trusted, fetched, or signed without the operator's explicit grant. The same permission layer can open any grant, but only by the explicit value `ANY`, whose use is logged (see Permissions).
- **Jurisdiction-agnostic.** Privacy and trust primitives are expressed as constraints and optional parameters, never as European-specific or national-specific features. Any deployment profile — EU, sovereign fabric, enterprise — satisfies its rules through adapters and configuration, not core changes.

## Permissions

One rule everywhere: a permission is a list of what the operator grants, empty by default. `ANY` opens a permission explicitly and is logged; there is no other wildcard, and a malformed grant is an error, never an opening.

| Permission | Granted with | Default | Opened with `ANY` |
| --- | --- | --- | --- |
| Which issuers verify on a network | `Plug(trust={network: registry})`, `plug.trust(network, registry)` | none: verify is rejected | any authentic issuer (authenticity is still checked) |
| Narrowing at a call | `check(target, trust_registry=...)` | — | — (a caller's registry only narrows the operator's) |
| Which hosts remote documents come from | `allow_hosts(host, ...)` | none; private addresses need `allow_private_networks()` too | any public host |
| Who signs | an open session on that network | nobody: an adapter signs only for the open session's identity, never for an issuer a caller names | — |
| What a model may prove over MCP | `build_server(fact_types=[...])` | nothing | any type outside the reserved prefixes |
| Which registries a model may name over MCP | `build_server(registries={name: registry})` | none | — |
| How often a model may call | `build_server(rate=(calls, seconds))` | 120 per minute | — |

An adapter may carry operator trust of its own, such as the EUDI profile's trusted lists; it counts as a policy for its network and is narrowed, never replaced, by a caller's registry.

## Core types

- **Identity** — did (string), method (string: key, web, or network-native). DID-method guidance: per-presentation pseudonyms are recommended for privacy-sensitive deployments; core is agnostic, adapters and DID methods own the mechanism.
- **Credential** — issuer, subject, hash, claims, proof. Maps to W3C Verifiable Credentials where applicable.
- **Attestation** — subject_hash (hex, 32 bytes), hash_alg (sha-256 default; sha3-256, sm3), fact_type (open vocabulary, canonicalized to lowercase dotted), issuer (DID), issued_at / expires_at (ISO-8601), proof ({alg, sig, verification_method}), optional role tag, optional meta. Optional salted-hash structure for selective disclosure: {salt, hash} pairs alongside the subject hash, enabling verifiers to check disclosed fields without revealing undisclosed ones. No new op — payload schema only. Optional anchor (StateRef): where the attestation's statement hash was recorded. Ledger adapters set it on a successful attest and require it on verify. Meta keys beginning with `_` are implementation-internal: they are never signed and verifiers ignore them.
- **StateRef** — network, address, kind (asset, ownership, event, market).
- **Receipt** — spec_version (semver), op, status (ok, pending, rejected, error), network, optional state_ref, data, optional error, seq. Canonical serialization is RFC 8785 (JSON Canonicalization Scheme); no library is required to parse. Ledger adapters report finality inside data as `finality: {kind: final | probabilistic, confirmations}`; the receipt shape does not change.
- **NetworkKind** — advisory label only (public, permissioned, enterprise, sovereign). Not enforced by core. Sovereign is the umbrella category: a public chain is sovereign in consensus, a national fabric in governance, Holochain per-agent, an enterprise chain within its org.

## Role tag

Optional on Attestation: execution, preference, identity, asset. Distinguishes a vote attestation from a supply-chain one without coupling core to any governance model.

## Canonical form and hashing

Structured facts are serialized with RFC 8785 before hashing, so every implementation, in any language, derives the same subject hash. Integers beyond 2^53 are carried as strings (I-JSON, RFC 7493). Bytes are hashed as-is, text as UTF-8, and any other JSON value (object, array, number, true, false, null) as its RFC 8785 form; other types are refused. A JSON scalar and the text of its canonical form share bytes (`42` and `"42"` given as text); callers that need the type distinguished wrap facts in an object.

The hash algorithm is deployment configuration, never a core change: sha-256 by default, sha3-256, or sm3 (GB/T 32905) where a profile mandates it. Every supported algorithm yields 32 bytes, so ledger anchors are the same size everywhere. The attestation names its hash_alg.

### Salted commitments (personal data)

A plain hash of low-entropy data — a name, an email, an ID number — can be reversed by hashing guesses, so it remains personal data and cannot be erased from a ledger. With `commitment = salted`, prove anchors H(salt ‖ fact) under a fresh 32-byte salt. The salt is returned to the caller in the receipt and never passed to an adapter or logged. Whoever holds the fact and the salt can open the commitment; nobody else can link it. Deleting the salt and the fact leaves the anchor unlinkable, which is how a ledger deployment honours erasure (GDPR Art. 17, EDPB Guidelines 02/2025) without rewriting history. Only the hash crosses a border; the fact and the salt stay where the data lives. Idempotent retries key on the unsalted digest in memory only.

## Statement

A proof signs, and a ledger anchors, the attestation's **statement**: the subject hash together with every label a verifier acts on.

```
statement      = {"plug.statement": {"subject_hash", "hash_alg", "fact_type", "issuer", "issued_at",
                                     "expires_at", "role", "meta", "disclosure"}}
statement_hash = H(JCS(statement))   under the attestation's hash_alg
```

`subject_hash` is lowercase hex; `expires_at` and `role` are `null` when absent; `meta` omits keys beginning with `_`; `disclosure` is `[]` when absent. Because every label is inside the signed statement, an attestation cannot be relabeled: a halt cannot be presented as a resume, a document hash as an agent action, or one model family's review as another's, without invalidating the proof. `issued_at` is signed as the issuer's claim; it is still never used as the time a key is judged at (see verify).

A receipt from attest carries every statement field, so an implementation can rebuild the attestation it stands for exactly (`Attestation.from_receipt` in the reference implementation).

## Signature suites

Every suite signs the same message, the 32-byte statement hash, and applies its own standard to it:

| alg | standard | verification_method |
| --- | --- | --- |
| ecdsa-secp256k1 | ECDSA, statement hash as digest (Ethereum-compatible) | 0x account address |
| ed25519 | PureEdDSA, RFC 8032 | did:key |
| ecdsa-p256 | ECDSA P-256 with SHA-256 (ES256), r‖s | did:key |
| sm2-sm3 | SM2 with SM3, distinguishing ID 1234567812345678 (GB/T 32918.2, GM/T 0009), r‖s | did:key |

Public keys are validated before any signature is checked. A did:key is accepted only in its canonical form: a 32-byte Ed25519 key or a 33-byte compressed SEC1 point, encoded so that re-encoding yields the same identifier, so one key has exactly one did:key. Ed25519 keys that are not canonical points or lie in the small-order subgroup are rejected; OpenSSL and other libraries verify forged signatures under such keys (an identity key "signs" every message), so implementations must check this themselves. ECDSA signatures are not normalized to low S: a proof's meaning is its statement, and nothing keys on signature bytes.

A proof is valid only when its signature verifies and the issuer DID names the same key: did:key names itself; did:plug:&lt;network&gt;:&lt;address&gt; and did:pkh:eip155:&lt;chain&gt;:&lt;address&gt; name an account. An issuer whose DID method an adapter cannot resolve is unverifiable, never assumed valid. New suites are added by registration, not by new ops.

## Conformance

`spec/vectors/` holds language-neutral test vectors. `jcs.json` (canonical form and digests) is generated by an independent implementation (`generate_jcs.mjs`, Node). `rfc9162.json` holds Merkle tree and inclusion vectors from an independent RFC 9162 implementation. `protocol.json` holds salted, bridge, and batch commitments, inclusion proofs, statements and their hashes, the reserved commitment domain, and Ed25519 and P-256 proofs over statements with issuer binding and relabeling cases, produced by the reference implementation and verified from this specification alone by `verify_protocol.mjs` (Node standard library). An implementation conforms when it reproduces every canonical form, digest, and commitment there and reaches the same verdict on every proof. Signature suites are cross-checked against OpenSSL 3 in both directions.

## Eight core ops

1. **connect** — alias of open. Network handle plus auth (scheme + material). Returns session.
2. **identify** — prove who you are on a network. Takes network plus Identity.
3. **attest** — hash a real-world fact, sign, bind to a record. Core op.
4. **query** — read ledger state back via StateRef.
5. **verify** — check someone else's attestation against that network's rules. Never trusts the issuer. Optional trust_registry parameter: a URL, an inline registry document, or a StateRef pointing at a published issuer registry; adapters resolve it. Core enforces that some trust policy applies (see Permissions): the operator's policy for the network, the caller's registry, or both, in which case both must pass. With none, verify is rejected as `not_authorized`.

   On a ledger network, verify is valid only when all of these hold: the signature recovers to `verification_method`; the issuer DID names that same key; the anchor exists on this network, succeeded, was sent by that key, and carries the statement hash. The receipt reports the anchor block, its timestamp as `anchored_at`, and finality. A signature alone proves possession of a key, not that a fact was recorded or when.

A URL registry is a JSON object `{"issuers": ["did:...", ...]}`. `issuers` is a non-empty list of strings. Adapters fetch it with HTTP or HTTPS only, a 5 second timeout, a 64 KiB cap, and no redirect off http(s). The attestation issuer must be in that list. A StateRef registry is resolved by query. The queried record must be ok and contain a valid `issuers` list; otherwise verify is rejected, never treated as unrestricted. The same membership check applies, and the same key rules apply when the record contains `keys`.

An adapter configured with operator trust, such as the EUDI profile's trusted lists, always applies it; a registry passed to verify narrows that trust and never replaces it.

Registries, trusted lists, and status lists are fetched from attacker-influenced URLs. Adapters fetch them only from public addresses, checked against the address actually connected to on every hop; a deployment with internal registries opts in to private addresses explicitly.

A registry MAY also carry issuer keys: `"keys": {"<issuer DID>": [{"verification_method": "...", "valid_from": "<ISO-8601>", "valid_until": "<ISO-8601>"}]}`. When it lists keys for an issuer, the proof's verification method must be one of them and valid at the **proven time**: the anchored time on a ledger, the time of verification otherwise. A time the issuer claims (`issued_at`) is never used. A key revoked after an anchor still verifies that anchor; a key revoked before it, or any revoked key without an anchor, does not. Registry keys also make issuers verifiable whose DID method no adapter resolves, such as those listed in jurisdictional trust lists.
6. **settle** — final writes: transfer, register, revoke, plus network-native ops via passthrough op name.
7. **bridge** — reference a proof made on one network from another. No relayer and no bridge operator is trusted. What a verifier does trust is its own view of each network: the node or endpoint it reads the source and the target from. A verifier that needs more assurance reads each side from a node it runs, or from several independent endpoints, and requires final status on both. When both networks are plugged in, the plug queries the source proof, then attests the commitment H(JCS({"plug.bridge": source StateRef})) on the target as fact type `plug.bridge`, signed by the target session. The bridge receipt carries the source reference and the target attestation. `check(bridge receipt)` verifies both sides independently: the source proof is ok, the target anchors exactly that commitment, and the target attestation verifies under its network's rules. Only the reference crosses; value never does. Without a target adapter, the source adapter may publish the reference on the source network, and the receipt stays pending there.
8. **subscribe** — event stream for a StateRef.

Every op takes a network handle plus a canonical payload and returns a canonical Receipt. Adapters translate; core never sees network internals.

## Five session ops

open, use, close, active, list_sessions.

Rules: explicit network beats active session; neither exists means error, not guess. A session binds to exactly one network. Credential material never surfaces above the adapter layer. Each session signs with its own credential; core names the active session's subject to the adapter before settle and bridge. Sessions are process-local by default; persistence is adapter-owned.

## Three user-facing verbs

- **prove(fact, fact_type, network?, meta?)** → Receipt. Fact is any bytes, JSON, or file reference.
- **check(target, network?)** → {valid: bool, receipt}. Target is an Attestation, StateRef, or DID string.
- **watch(target, filter?)** → stream handle. Target is a StateRef.

**Batch anchoring.** `prove_batch(facts, fact_type, network?, meta?)` is prove applied to many facts with one anchor; it is not a new operation. The facts' subject hashes (salted individually under `commitment = salted`) are the leaves of an RFC 9162 Merkle tree. The anchored subject is the batch commitment H(JCS({"plug.batch": {"root": root, "size": size}})), attested once as fact type `plug.batch` with meta `{...caller meta, batch_size, batch_fact_type}` and signed once. Each fact's attestation has the batch's issuer, issued_at, and caller meta, the facts' fact_type, and `inclusion: {tree: "rfc9162", index, size, path, root}`; its proof and anchor are those of the batch statement. check verifies the inclusion proof by the RFC 9162 algorithm, recomputes the batch commitment from root and size, rebuilds the batch statement from the fact's attestation (fact type `plug.batch`, `batch_fact_type` set to the fact's type), then verifies it under the network's rules. A fact's type is therefore signed through the batch statement. A member attestation whose meta carries `batch_size` or `batch_fact_type` is rejected: the verifier derives those, and the member never signed its own. A retried salted batch reuses the first call's salts, held in memory only, so it reproduces the same anchor. Cost per fact falls with batch size, and no aggregation server is involved: the issuer batches its own facts.

**Reserved commitment domain.** Bridge and batch commitments and statements are canonical JSON objects keyed `plug.bridge`, `plug.batch`, and `plug.statement`. prove and prove_batch refuse any fact whose bytes begin with `{"plug.`, so no proven fact can be presented as one of these commitments, and a single-fact anchor can never pass as a batch root.

Transports (REST, MCP, CLI, SDKs, webhooks, queues) are thin adapters over these three. The user picks the pipe. The reference MCP transport (`plug.mcp_server`) exposes prove, prove_batch, check, watch, and networks as tools. It holds all keys server-side and accepts no credential material from the model, and it accepts trust registries only by name from a server-side allowlist, never one the model writes. The model does not choose what the server's key vouches for: it may prove only the fact types the operator grants (none by default; `ANY` grants every type outside `agent.`, `control.`, `incident.`, and `grant`, which must be granted by name), `plug.` types are always refused, calls are rate-limited, and `model_family` and `model_id` are set by the server, never taken from the model. Meta that an adapter dereferences, such as a status list reference, is likewise the operator's to set. Nothing returned to the model carries URLs, endpoints, or host addresses, and each call is bounded in batch size and fact size.

## Error model

Nine codes: auth_failed, not_found, not_authorized, unsupported_op, proof_invalid, timeout, rate_limited, bridge_unsupported, finality_unknown. Each carries a retryable flag. timeout, rate_limited, finality_unknown are retryable; the rest are not.

## Idempotency invariant

Receipt hash covers spec_version, op, network, subject_hash, fact_type, issuer, role — never seq. The same subject attested by a different issuer, or under a different fact type, is a different attestation. The plug maintains a 24-hour idempotency cache keyed on the statement (see Statement), so an attestation that differs in any signed label is a new attestation and is anchored. Two refinements: a salted prove keys on the unsalted digest, held in memory only; and where the plug itself sets issued_at (prove, prove_batch), the key leaves issued_at out, so a retry returns the first receipt with its original time. An attestation passed to attest is keyed on its full statement: the same content signed again at a later time is a new statement. Only ok and pending receipts are cached; a rejected or error receipt is retried on the next call. On a cache hit, the cached receipt is cloned and stamped with the call's fresh seq before return. Settle and bridge bypass the cache by design: they have no subject hash to key on, and a bridge's target attestation is keyed on its full statement. This is documented, not implicit.

## Agent oversight profile

A deployment profile for systems in which AI models act on someone's behalf. It treats every model as a potentially compromised insider: authority over the model sits outside it, and evidence of what it did does not depend on the model. No new operations; it fixes vocabulary and rules.

| fact_type | issued by | records |
| --- | --- | --- |
| `agent.action` | the harness that orchestrates the model, never the model | a meaningful action: actor DID, `model_family`, `model_id`, tool, digests of inputs and outputs |
| `agent.review` | an independent reviewer: a person, or a model of a different family | a judgment on an `agent.action`, referencing its receipt hash in meta |
| `control.halt`, `control.resume` | an authorized controller | a containment signal for an actor DID |
| `incident.report` | the operator | a failure or compromise, with what failed and which controls did not hold |

Rules:

1. **Evidence independent of the model.** `agent.action` is signed by a harness key the model cannot use. Verifiers check it against a trust registry of harness keys, so an attestation signed by a model is rejected. Every meaningful action leaves one; the human-readable record stays with the operator, and its hash is anchored.
2. **Independent review.** An automated `agent.review` is valid only when its reviewer's `model_family` differs from the actor's. No model verifies its own work. A deployment can track model families across actors and reviewers the way the prediction-market profile's diversity signal does for forecasts.
3. **Containment.** Before each meaningful action, the harness checks the latest `control.halt` and `control.resume` for its actor against the deployment's controller registry, and stops while a valid halt is the most recent. A signal from an issuer outside the registry has no effect.
4. **Independent rails.** Evidence is anchored on a network the model's operator does not control alone; high-impact actions SHOULD be anchored on more than one.
5. **Disclosure.** `incident.report` uses salted commitments: the anchor fixes when the disclosure was made, and affected parties receive the fact and the salt.

## Grants profile

Consent, an agent's mandate, and a human's approval of one action are one primitive: a **grant**. A grant is an attestation of fact type `grant`, issued by the grantor, whose signed meta carries:

| Field | Meaning |
| --- | --- |
| `grantee` | the DID the grant is to |
| `scope` | `{key: [allowed values]}`; an action is within it when, for every key, its value is listed: `fact_type`, `subject_hash`, and `network` from the action, any other key (`purpose`, `channel`, ...) from its signed meta; a missing value is outside |
| `kind` | optional: `consent`, `mandate`, or `approval` |
| `refs.parent` | for a delegated grant, the statement hash of the grant it derives from |

`expires_at` is required. An approval is a grant whose scope names the one action's `subject_hash` (and network); consent names one purpose per grant and the contact channel, including whether the contact is human or AI.

An action claims authority by naming its grant in signed `meta.refs.grant`. A verifier that requires authority accepts the action only if:

1. the action is authentic;
2. following `refs.parent` from its grant, each grant names as grantee the party that used it, every grant's scope contains the action, each delegated grant's scope narrows its parent's (every key the parent restricts, the child restricts to a subset), and no grant expires later than its parent or before the action's proven time;
3. the root grant verifies under the verifier's trust policy for its network (closed by default: authority starts only from a trusted principal; the agents themselves need not be trusted);
4. no presented revocation applies: a revocation (fact type `grant.revoke`, `meta.refs.revokes` naming a grant's statement hash) counts when issued by that grant's grantor or an ancestor's grantor and proven no later than the action; when either time is unknown it counts. Revocations are final. Withdrawing consent therefore never invalidates actions proven before it (GDPR Art. 7(3)), and short expiry, not revocation, is the first defence.

A chain is judged on one network, the verifier's: an action or grant anchored on another network is rejected, since an anchor is not signed and must not choose the trust policy. Parties are compared by the key or account their DID names, so every spelling of one key (a `#fragment`, address case) is one party, and references are statement hashes compared in lowercase. Verifiers resolve references only from what they are given or can query; nothing is fetched by following a reference.

**References.** `meta.refs` is the one place an attestation names others: `{name: statement hash or [hashes]}`, signed with the statement, so a link cannot be added, removed, or redirected. Recommended names: `grant`, `parent`, `revokes`, `action` (a review, incident, or approval about an action), `data` (consent about a data commitment), and `prev`, the same actor's previous action, which turns an actor's records into a chain in which an omitted or forked record is visible.

## Prediction-market profile

A deployment profile for forecasting markets. Like the agent oversight profile, it adds no operations; it applies only to attestations of fact type `prediction.market`.

**Loop.** An agent submits a forecast through prove (fact_type prediction.market), reads consensus through check against a market aggregate StateRef, and reacts through watch on resolution events. The plug makes every step machine-readable; it does not own the market.

**Diversity signal.** Attestation meta may carry model_family (open string) and optional model_id. Over the last 20 prediction.market attestations per market, if distinct families divided by window size drops below 0.3, the plug emits one prediction.monoculture warning attestation per market per 24 hours — edge-triggered, not level-triggered. Warning subject hashes include a nonce so each emission is unique; no dedup is expected or required.

## Three layers

1. **Attestations — prove.** Binds what happened. Consumers: agents checking counterparty history, oracles, auditors.
2. **Credentials — check.** Identity, authorization, role legitimacy.
3. **Settlement — watch.** Event streams, finality, value movement. Currency enters last, as the final strand.

## Adapter contract

Every adapter implements the eight core ops. Core exports no concrete backend. Adapters own: key management, RPC or gateway details, finality callbacks, optional persistence, and jurisdiction-specific resolution such as trust-list lookups or status-list polling.

A ledger adapter anchors the statement hash in a transaction the ledger itself authenticates, and on verify confirms that the anchor exists, succeeded, carries exactly the statement hash, and was authorized by the key named in the proof. How the ledger authenticates its senders — account signatures on a public network, certificates checked against organizational trust roots on a permissioned one — is the adapter's concern; the guarantee reported to the caller is the same. The reference implementation includes one adapter of each kind, and `scripts/bridge_test.py` verifies a fact proven on one and referenced on the other.

## Oracle adapters

Oracle adapters observe external reality — sensors, webhooks, human witnesses, price and data feeds — and commit observations through prove. The plug never becomes the oracle; it gives oracles a seat at the same table as chains.

An oracle adapter implements the eight core ops like any backend. Its distinctive responsibility: the attest path takes an external observation (a reading, a document hash, a GPS fix), hashes it as the subject, and signs with the oracle's own key. Query returns the latest committed observation for a StateRef. Verify checks the oracle's signature and optionally a trust registry of authorized oracles. Subscribe polls for new observations.

No new ops. No oracle-specific vocabulary in core. Fact types remain an open vocabulary — sensor.reading, gps.fix, doc.sha256 are recommendations, not mandates. The oracle's trustworthiness is a property of the adapter's key and its registry, not of the plug.

## Appendix A: Known problems in existing approaches (informative)

This appendix is not normative. It lists recurring problems in established attestation, timestamping, credential, and cross-network designs, and the part of this specification that addresses each. Approaches are named by category, not by product.

| Problem | Where it occurs | Answer in this specification |
| --- | --- | --- |
| One ledger transaction per attestation, so cost grows linearly with volume | per-attestation on-chain registries | Batch anchoring: one commitment to an RFC 9162 root per batch, an inclusion proof per fact |
| Batching depends on a third-party aggregation server | calendar-based timestamping services | The issuer batches its own facts; no aggregator is trusted or required |
| Naive Merkle trees let an interior node pass as a leaf | ad hoc batching schemes | RFC 9162 domain separation between leaf and node hashes, and a reserved commitment domain separating batch roots from single facts |
| Issuer keys rotate or leak; old signatures become unverifiable, or a stolen key backdates new ones | verifiable credentials, trust lists | Registry keys with validity windows, judged at the proven time, never at a time the issuer claims |
| Trust lists are jurisdiction-specific and often carry no keys | wallet trust frameworks | One registry format, inline or by URL, mapping issuers to keys under any jurisdiction |
| Cross-network transfers rely on trusted relayers or multisignature committees, the source of the largest losses in the field | cross-chain bridges | Relayer-free bridge: only a reference crosses, and check verifies both sides independently |
| Personal data written to immutable ledgers cannot be erased | on-chain attestation schemas | Salted commitments: deleting the salt leaves the anchor unlinkable |
| Hashes differ between implementations because serialization differs | JSON-based credential formats | RFC 8785 canonical form with independently generated conformance vectors |
| A single operator or identity provider is a point of failure and control | centralized transparency logs, keyless signing | Any rail, issuer-held keys, and verification that trusts neither the issuer nor the operator |
| An AI model attests to its own actions | agent frameworks with self-reported logs | Agent oversight profile: the harness signs, reviews come from another model family |
| Agents act with no verifiable "on whose behalf"; consent cannot be proven or withdrawn; approval is replayed | agent frameworks, messaging opt-in, consent banners | Grants profile: one signed, scoped, expiring, revocable grant from a trusted principal; delegation only narrows; withdrawal never undoes earlier actions |
| A signature covers a hash but not its labels, so a signed fact can be presented under another type, time, or issuer | detached-signature and hash-anchoring schemes | The proof signs and the ledger anchors the statement: subject hash, type, issuer, times, role, and meta together |
