# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""ChainMaker adapter: a permissioned ledger with certificate-based membership.

Subject hashes are anchored by calling a minimal EVM contract whose runtime is
a single STOP; the evidence is the signed, block-included transaction payload.
The chain authenticates each sender's certificate against its trust roots, and
the adapter binds that certificate's public key to the attestation issuer.

Requires the ChainMaker Python SDK (chainmaker>=3.0.7) and the suites extra.
"""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from .. import suites
from ..core import Adapter, Attestation, Identity, PlugError, Receipt, StateRef, Status, SPEC_VERSION, parse_time
from .base import LoggingAdapter, registry_key_status, resolve_trust_registry

# Creation code: PUSH1 01 DUP1 PUSH1 0b PUSH1 00 CODECOPY PUSH1 00 RETURN, then runtime STOP.
ANCHOR_CREATION_CODE = "600180600b6000396000f300"
ANCHOR_SIGNATURE = "anchor(bytes32)"
_TX_PREFIX = "cm:"


def _keccak(data: bytes) -> bytes:
    from Crypto.Hash import keccak
    return keccak.new(data=data, digest_bits=256).digest()


def anchor_selector() -> str:
    return _keccak(ANCHOR_SIGNATURE.encode()).hex()[:8]


def anchor_calldata(subject_hash: str) -> str:
    """Hex calldata for anchor(bytes32 subject_hash), as ChainMaker stores it in the payload."""
    return anchor_selector() + bytes.fromhex(subject_hash).hex()


def account_from_public_key(compressed: bytes) -> str:
    """Account under ChainMaker's ETHEREUM address type: last 20 bytes of keccak256(x || y)."""
    from Crypto.PublicKey import ECC
    point = ECC.import_key(compressed, curve_name="P-256").pointQ
    xy = int(point.x).to_bytes(32, "big") + int(point.y).to_bytes(32, "big")
    return "0x" + _keccak(xy)[-20:].hex()


def _compressed_from_pem(pem: bytes) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key = x509.load_pem_x509_certificate(pem).public_key()
    except ValueError:
        key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise PlugError("unsupported_op", "only P-256 member keys are supported")
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def _load_member(material: dict) -> tuple[str, bytes, Any]:
    """(private key hex, compressed public key, SDK signer) from member key and certificate files."""
    from chainmaker.user import User
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key = serialization.load_pem_private_key(open(material["sign_key"], "rb").read(), password=None)
        crt = open(material["sign_crt"], "rb").read()
    except (KeyError, OSError, ValueError) as e:
        raise PlugError("auth_failed", f"member material: {e}") from e
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise PlugError("unsupported_op", "only P-256 member keys are supported")
    public = _compressed_from_pem(crt)
    if key.public_key().public_bytes(serialization.Encoding.X962,
                                     serialization.PublicFormat.CompressedPoint) != public:
        raise PlugError("auth_failed", "signing key does not match the certificate")
    signer = User.from_conf(org_id=material["org_id"], user_sign_key_file_path=material["sign_key"],
                            user_sign_crt_file_path=material["sign_crt"], crypto={"hash": "SHA256"},
                            auth_type="permissionedWithCert")
    return f"{key.private_numbers().private_value:064x}", public, signer


class ChainMakerAdapter(LoggingAdapter, Adapter):
    """One adapter per chain. Sessions bring member credentials as auth material:
    {"scheme": "x509", "material": {"org_id", "sign_key", "sign_crt"}}."""

    def __init__(self, sdk_config: dict, contract: str = "upp_anchor", client=None):
        super().__init__()
        if client is None:
            try:
                from chainmaker.chain_client import ChainClient
            except ImportError as e:
                raise PlugError("not_found", "ChainMaker SDK not installed") from e
            client = ChainClient.from_conf(sdk_config)
        from chainmaker.payload import PayloadBuilder
        self.client = client
        self.chain_id = sdk_config["chain_client"]["chain_id"]
        self.contract = contract
        self._payloads = PayloadBuilder(self.chain_id)
        self._members: dict[str, tuple[str, bytes, Any]] = {}  # DID -> (private hex, public, signer)
        self._bound: Optional[str] = None

    @staticmethod
    def deploy_anchor(client, contract: str, admin: dict) -> Receipt:
        """Install the anchor contract once per chain, endorsed by an organization administrator."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".bin", delete=False) as f:
            f.write(ANCHOR_CREATION_CODE)
        payload = client.create_contract_create_payload(contract, "1.0", f.name, "EVM", None)
        endorsers = client.create_endorsers(payload, [{
            "org_id": admin["org_id"], "user_sign_key_file_path": admin["sign_key"],
            "user_sign_crt_file_path": admin["sign_crt"], "crypto": {"hash": "SHA256"},
            "auth_type": "permissionedWithCert"}])
        r = client.send_contract_manage_request(payload, endorsers, with_sync_result=True)
        ok = r.code == 0 and r.contract_result.code == 0
        return Receipt(SPEC_VERSION, "settle", Status.OK if ok else Status.REJECTED, "",
                       data={"contract": contract, "tx": _TX_PREFIX + r.tx_id},
                       error=None if ok else f"proof_invalid: {r.contract_result.message or r.message}")

    def _height(self) -> int:
        return self.client.get_current_block_height()

    def _did(self, network: str, public: bytes) -> str:
        return f"did:plug:{network}:{account_from_public_key(public)}"

    def _member_for(self, did: Optional[str]) -> tuple[str, bytes, Any]:
        member = self._members.get(did or "")
        if member is None:
            raise PlugError("auth_failed", f"no member credentials for {did or 'anonymous caller'}")
        return member

    def _send(self, signer, calldata: str):
        payload = self._payloads.create_invoke_payload(self.contract, calldata[:8], {"data": calldata})
        try:
            r = self.client.send_request_with_sync_result(payload, with_sync_result=True, signer=signer)
        except Exception as e:
            raise PlugError("timeout" if "timeout" in str(e).lower() else "not_found", str(e)) from e
        return r.tx_id, r.contract_result.code == 0, r.contract_result.message

    def bind(self, subject: Optional[str]) -> None:
        self._bound = subject

    def connect(self, network: str, auth: dict) -> dict:
        private, public, signer = _load_member(auth.get("material") or {})
        did = self._did(network, public)
        self._members[did] = (private, public, signer)
        info = {"scheme": auth.get("scheme", "x509"), "subject": did,
                "org_id": auth["material"]["org_id"], "verification_method": suites.did_key("ecdsa-p256", public)}
        self.log.append({"op": "connect", "network": network, **info})
        return info

    def identify(self, network: str, identity: Identity) -> Receipt:
        parsed = suites.parse_account_did(identity.did)
        rec = {"op": "identify", "did": identity.did, "method": identity.method,
               "controlled": identity.did in self._members}
        self.log.append(rec)
        if parsed is None or parsed[0] != network:
            return Receipt(SPEC_VERSION, "identify", Status.REJECTED, network, data=rec,
                           error="proof_invalid: DID does not name an account on this network")
        return Receipt(SPEC_VERSION, "identify", Status.OK, network, data=rec)

    def attest(self, network: str, att: Attestation) -> Receipt:
        private, public, signer = self._member_for(att.issuer)
        proof = suites.sign("ecdsa-p256", private, att.subject_hash)
        tx_id, ok, message = self._send(signer, anchor_calldata(att.subject_hash))
        ref = StateRef(network, _TX_PREFIX + tx_id, "event")
        found = self.query(ref)
        rec = {"op": "attest", "tx": ref.address, "block": found.data["block"],
               "subject_hash": att.subject_hash, "fact_type": att.fact_type, "issuer": att.issuer,
               "role": att.role.value if att.role else None, "seq": att.meta.get("_seq", 0),
               "org_id": found.data["org_id"], "finality": found.data["finality"]}
        if ok:
            att.proof = proof
            att.anchor = ref
            rec["proof"] = proof
        self.log.append(rec)
        return Receipt(SPEC_VERSION, "attest", Status.OK if ok else Status.REJECTED, network, ref, rec,
                       None if ok else f"proof_invalid: {message}", seq=att.meta.get("_seq", 0))

    def query(self, ref: StateRef, fields: Optional[list] = None) -> Receipt:
        tx_id = ref.address.removeprefix(_TX_PREFIX)
        try:
            info = self.client.get_tx_by_tx_id(tx_id)
        except Exception as e:
            raise PlugError("not_found", f"{ref.address}: {e}") from e
        tx = info.transaction
        signer = tx.sender.signer
        sender = None
        if signer.member_type in (0, 2):  # CERT, PUBLIC_KEY
            sender = suites.did_key("ecdsa-p256", _compressed_from_pem(bytes(signer.member_info)))
        params = {p.key: bytes(p.value).decode("ascii", "replace") for p in tx.payload.parameters}
        ok = tx.result.code == 0
        data = {"block": info.block_height,
                "anchored_at": datetime.fromtimestamp(info.block_timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": tx.result.code, "contract": tx.payload.contract_name, "calldata": params.get("data", ""),
                "sender": sender, "org_id": signer.org_id,
                "finality": {"kind": "final", "confirmations": max(self._height() - info.block_height + 1, 1)}}
        if fields:
            data = {k: data[k] for k in fields if k in data}
        self.log.append({"op": "query", "tx": ref.address})
        return Receipt(SPEC_VERSION, "query", Status.OK if ok else Status.REJECTED, ref.network, ref, data,
                       None if ok else "transaction failed")

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        """Valid only if the signature, issuer binding, and anchor all name the same member key."""
        trust = resolve_trust_registry(self.query, trust_registry, network, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})

        def reject(error: str) -> Receipt:
            self.log.append({"op": "verify", "ok": False, "error": error})
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data, error=error)

        if att.proof.get("alg") != "ecdsa-p256":
            return reject("proof_invalid: unsupported alg")
        ok, method = suites.verify(att.subject_hash, att.proof)
        if not ok:
            return reject(method)
        parsed = suites.parse_account_did(att.issuer)
        if parsed is None or parsed[0] != network:
            return reject("proof_invalid: issuer DID names another network")
        if parsed[1].lower() != account_from_public_key(suites.parse_did_key(method)[1]):
            return reject("proof_invalid: issuer is not bound to the signing key")
        if att.anchor is None:
            return reject("proof_invalid: missing anchor")
        if att.anchor.network != network:
            return reject("proof_invalid: anchor is on another network")
        try:
            found = self.query(att.anchor)
        except PlugError:
            return reject(f"not_found: anchor {att.anchor.address}")
        if found.status != Status.OK:
            return reject("proof_invalid: anchor transaction failed")
        if found.data["contract"] != self.contract:
            return reject("proof_invalid: anchor did not call the anchor contract")
        if found.data["sender"] != method:
            return reject("proof_invalid: anchor was sent by another key")
        if found.data["calldata"] != anchor_calldata(att.subject_hash):
            return reject("proof_invalid: anchor does not carry the subject hash")
        _, err = registry_key_status(data, att.issuer, method, parse_time(found.data["anchored_at"]))
        if err:
            return reject(err)
        data.update({"verified": True, "alg": "ecdsa-p256", "verification_method": method,
                     "anchor": att.anchor.address, "anchored_block": found.data["block"],
                     "anchored_at": found.data["anchored_at"], "org_id": found.data["org_id"],
                     "finality": found.data["finality"]})
        self.log.append({"op": "verify", "ok": True})
        return Receipt(SPEC_VERSION, "verify", Status.OK, network, data=data)

    def settle(self, network: str, op: str, payload: dict) -> Receipt:
        private, public, signer = self._member_for(self._bound)
        digest = hashlib.sha256(f"settle:{op}:{json.dumps(payload, sort_keys=True)}".encode()).hexdigest()
        tx_id, ok, message = self._send(signer, anchor_calldata(digest))
        rec = {"op": "settle", "tx": _TX_PREFIX + tx_id, "settle_op": op}
        self.log.append(rec)
        return Receipt(SPEC_VERSION, "settle", Status.OK if ok else Status.REJECTED, network,
                       StateRef(network, rec["tx"], "event"), rec, None if ok else f"proof_invalid: {message}")

    def bridge(self, src: StateRef, target_network: str) -> Receipt:
        return Receipt(SPEC_VERSION, "bridge", Status.REJECTED, src.network, None, {"source": src.address},
                       "bridge_unsupported: register the target network's adapter to bridge")

    def subscribe(self, ref: StateRef, callback_id: str, filt: Optional[list] = None) -> str:
        handle = f"stream:{ref.network}:{ref.address}:{callback_id}"
        try:
            found = self.query(ref)
            events = [{"type": "tx", "status": found.status.value, "block": found.data["block"]}]
            note = "polled"
        except PlugError as e:
            events, note = [], f"poll failed: {e.message}"
        self.log.append({"op": "subscribe", "handle": handle, "filter": list(filt or []),
                         "events": events, "note": note})
        return handle
