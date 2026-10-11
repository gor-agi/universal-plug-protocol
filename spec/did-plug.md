# The did:plug Method

Version 0.1 (draft). Part of the Universal Plug Protocol specification.

## 1. Abstract

`did:plug` identifies an account on a network that is reachable through a Universal Plug Protocol adapter. The identifier names the network and the account; nothing else. There is no registry, no central operator, and no on-ledger DID document: the adapter for the named network resolves the identifier from the network's own state.

The method exists so that one issuer syntax can cover public ledgers, permissioned and sovereign ledgers, and enterprise systems alike, while reusing existing chain-agnostic standards (CAIP-2, CAIP-10) wherever they apply.

## 2. Conformance

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

This method conforms to W3C Decentralized Identifiers (DIDs) v1.0, §8 (Methods).

## 3. Method name

The method name is `plug`. A DID that uses this method MUST begin with `did:plug:`, in lowercase.

## 4. Method-specific identifier

### 4.1 Syntax (ABNF, RFC 5234)

```abnf
plug-did       = "did:plug:" network ":" account
network        = chain-id / local-alias
chain-id       = namespace ":" reference                 ; CAIP-2
namespace      = 3*8( %x61-7A / DIGIT / "-" )             ; [-a-z0-9]{3,8}
reference      = 1*32( ALPHA / DIGIT / "-" / "_" )        ; [-_a-zA-Z0-9]{1,32}
local-alias    = 1*32( %x61-7A / DIGIT / "-" )            ; [-a-z0-9]{1,32}
account        = 1*128( ALPHA / DIGIT / "-" / "." / "%" ) ; CAIP-10 account_address
```

The account never contains `:`, so a parser reads the network as everything between `did:plug:` and the last `:`. A DID URL MAY append a fragment (`#...`) that names a verification method.

### 4.2 Portable and local forms

- **Portable form**: the network is a CAIP-2 chain ID, for example `did:plug:eip155:11155111:0x393F7c6A37700dE739c84F6535D19016CDD447CA`. The pair `chain-id ":" account` is a CAIP-10 account ID. Any identifier that leaves its deployment MUST use this form.
- **Local form**: the network is a single lowercase alias registered in one deployment, for example `did:plug:testnet:alice`. A local alias means nothing outside the deployment that registered it. Verifiers outside that deployment MUST treat a local-form DID as unresolvable.

A network without a CAIP-2 namespace uses the local form until a namespace is registered with the Chain Agnostic Standards Alliance. The method does not mint namespaces of its own.

### 4.3 Reserved identifier

`did:plug:anon` is reserved for an unauthenticated caller. It does not conform to §4.1, MUST NOT resolve, and MUST NOT verify as an issuer.

### 4.4 Equivalence with did:pkh

For a portable-form DID, `did:plug:<caip10>` and `did:pkh:<caip10>` denote the same account controller. Implementations MUST treat them as equivalent when binding an issuer to a key. Where a namespace has a key-derived account (for example `eip155`), deployments SHOULD accept both.

### 4.5 Normalization

The method-specific identifier is case-sensitive, as in CAIP-10. Where a namespace defines a canonical form (for example EIP-55 checksum capitalization for `eip155`), issuers SHOULD emit it, and verifiers MUST compare accounts using the namespace's canonicalization.

## 5. Operations

### 5.1 Create

No registration takes place. A DID exists as soon as a key controls the account on the named network. An implementation derives the identifier from the key and the network: for `eip155`, the account is the address derived from the secp256k1 public key, and the network is `eip155:<chain id>` read from the network itself.

### 5.2 Read (resolve)

Resolution is performed by the adapter for the named network, against that network's own state, by the verifier's own connection to it. A resolver MUST NOT accept a DID document supplied by the subject or by the subject's adapter.

For a namespace whose signatures recover the signing account, the DID document is:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:plug:eip155:11155111:0x393F7c6A37700dE739c84F6535D19016CDD447CA",
  "verificationMethod": [{
    "id": "did:plug:eip155:11155111:0x393F7c6A37700dE739c84F6535D19016CDD447CA#account",
    "type": "EcdsaSecp256k1RecoveryMethod2020",
    "controller": "did:plug:eip155:11155111:0x393F7c6A37700dE739c84F6535D19016CDD447CA",
    "blockchainAccountId": "eip155:11155111:0x393F7c6A37700dE739c84F6535D19016CDD447CA"
  }],
  "authentication": ["did:plug:eip155:11155111:0x393F7c6A37700dE739c84F6535D19016CDD447CA#account"],
  "assertionMethod": ["did:plug:eip155:11155111:0x393F7c6A37700dE739c84F6535D19016CDD447CA#account"]
}
```

For a namespace whose accounts are bound to registered public keys or certificates (as on permissioned ledgers), the adapter reads the key from the network's membership state and emits a `Multikey` verification method with that key, under the same `id` and `controller` rules.

If the network is unreachable, the account does not exist, or the DID is in local form outside its deployment, resolution fails with error `notFound` (DID Resolution) and Plug reports `not_found`.

### 5.3 Update

Not supported. The identifier is bound to one account. A controller that rotates keys obtains a new DID; continuity between the old and new identifiers MAY be stated as an attestation signed by both keys.

### 5.4 Deactivate

Not supported at the method level. Withdrawal of trust is expressed outside the identifier: through trust registries, which list the issuers a verifier accepts, and status lists, which mark individual credentials as revoked.

## 6. Use in the Universal Plug Protocol

- A session's subject is a `did:plug` identifier issued by the adapter that holds the session's key.
- An attestation's `issuer` MUST resolve to the key named by `proof.verification_method` (issuer binding). Signature validity alone is not sufficient.
- On a ledger network, the network named in the issuer DID MUST be the network that verifies the attestation, by CAIP-2 chain ID or by the deployment's local alias.

## 7. Security considerations

- **Network substitution.** A DID names its network so that a signature from one network cannot be presented as evidence on another. Verifiers MUST read the chain ID from their own connection to the network, never from the attestation.
- **Resolver independence.** Resolution relies on the verifier's own access to the network. Delegating resolution to a party chosen by the issuer defeats the method.
- **Local aliases.** Two deployments may use the same alias for different networks. Local-form DIDs MUST NOT be accepted across organizational boundaries.
- **Key compromise.** Because Update and Deactivate are not supported, a compromised key remains able to sign until verifiers remove the DID from their trust registries. Deployments SHOULD publish registries with short refresh intervals.
- **Reorganization and finality.** Evidence anchored on a ledger can be reorganized before finality. Verifiers SHOULD read the finality reported with each verification and set their own threshold.
- **Signature malleability and recovery.** For recovery-based namespaces, implementations MUST normalize the recovery identifier and compare the recovered account using the namespace's canonical form.

## 8. Privacy considerations

- **Correlation.** An account identifier is stable and correlates every attestation made with it. Privacy-sensitive deployments SHOULD use a fresh account per relationship or per presentation.
- **Personal data.** Where the account belongs to a natural person, the DID itself can be personal data. Deployments SHOULD keep personal facts off-ledger and anchor salted commitments only (see SPEC.md, Salted commitments).
- **Minimal disclosure.** The DID document discloses only a verification method. It carries no service endpoints and no metadata about the controller.

## 9. Reference implementation

`plug.suites.parse_account_did`, `plug.suites.issuer_key`, `plug.suites.binds`, and `plug.adapters.live.LiveAdapter` (issuance, issuer binding, and network matching for the `eip155` namespace). Tests: `tests/test_suites.py::test_account_did_grammar`, `tests/test_live_adapter.py::test_issuer_on_another_network_is_rejected`.

## 10. References

- W3C, Decentralized Identifiers (DIDs) v1.0.
- W3C, DID Resolution.
- Chain Agnostic Standards Alliance, CAIP-2 Blockchain ID Specification; CAIP-10 Account ID Specification.
- W3C CCG, did:pkh Method Specification.
- RFC 2119, RFC 8174, RFC 5234.
