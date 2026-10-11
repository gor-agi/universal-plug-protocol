# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""ChainMaker: a permissioned ledger with certificate-based membership.

Statement hashes are anchored by calling a minimal EVM contract whose runtime is a single STOP; the evidence is
the signed, block-included transaction. The chain authenticates the sender's certificate against its trust roots,
and the issuer is the did:key of that certificate's P-256 key. Needs: pip install universal-plug[chainmaker]
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional

from .. import suites
from ..core import Attestation, Ledger, PlugError, Receipt, StateRef, Status, parse_time, rejected, statement_hash
from ..registry import registry_key_status, resolve_registry

# Creation code: PUSH1 01 DUP1 PUSH1 0b PUSH1 00 CODECOPY PUSH1 00 RETURN, then runtime STOP.
ANCHOR_CREATION_CODE = "600180600b6000396000f300"
ANCHOR_SIGNATURE = "anchor(bytes32)"
_TX_PREFIX = "cm:"


def _keccak(data: bytes) -> bytes:
    import sha3  # safe-pysha3, which the ChainMaker SDK requires
    return sha3.keccak_256(data).digest()


def anchor_selector() -> str:
    return _keccak(ANCHOR_SIGNATURE.encode()).hex()[:8]


def anchor_calldata(subject_hash: str) -> str:
    """Hex calldata for anchor(bytes32 subject_hash), as ChainMaker stores it in the payload."""
    return anchor_selector() + bytes.fromhex(subject_hash).hex()


def account_from_public_key(compressed: bytes) -> str:
    """Account under ChainMaker's ETHEREUM address type: last 20 bytes of keccak256(x || y)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    numbers = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), compressed).public_numbers()
    xy = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
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


class ChainMakerLedger(Ledger):
    """One instance per chain. Sessions bring member credentials: {"member": {"org_id", "sign_key", "sign_crt"}}."""

    def __init__(self, sdk_config: dict, contract: str = "upp_anchor", client=None):
        if client is None:
            try:
                from chainmaker.chain_client import ChainClient
            except ImportError as e:
                raise PlugError("unsupported_op", "ChainMakerLedger needs: pip install universal-plug[chainmaker]") from e
            client = ChainClient.from_conf(sdk_config)
        from chainmaker.payload import PayloadBuilder
        self.client = client
        self.contract = contract
        self._payloads = PayloadBuilder(sdk_config["chain_client"]["chain_id"])
        self._members: dict[str, tuple[str, Any]] = {}  # did:key -> (private hex, SDK signer)
        self._bound: Optional[str] = None

    @staticmethod
    def deploy_anchor(client, contract: str, admin: dict) -> str:
        """Install the anchor contract once per chain, endorsed by an organization administrator. Returns the tx."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".bin", delete=False) as f:
            f.write(ANCHOR_CREATION_CODE)
        payload = client.create_contract_create_payload(contract, "1.0", f.name, "EVM", None)
        endorsers = client.create_endorsers(payload, [{
            "org_id": admin["org_id"], "user_sign_key_file_path": admin["sign_key"],
            "user_sign_crt_file_path": admin["sign_crt"], "crypto": {"hash": "SHA256"},
            "auth_type": "permissionedWithCert"}])
        r = client.send_contract_manage_request(payload, endorsers, with_sync_result=True)
        if r.code != 0 or r.contract_result.code != 0:
            raise PlugError("proof_invalid", r.contract_result.message or r.message)
        return _TX_PREFIX + r.tx_id

    def connect(self, network: str, auth: dict) -> dict:
        private, public, signer = _load_member(auth.get("member") or {})
        did = suites.did_key("ecdsa-p256", public)
        self._members[did] = (private, signer)
        return {"subject": did}

    def bind(self, subject: Optional[str]) -> None:
        self._bound = subject

    def attest(self, network: str, att: Attestation) -> Receipt:
        member = self._members.get(self._bound or "")
        if member is None:
            raise PlugError("auth_failed", "signing needs an open member session on this network")
        if not suites.binds(att.issuer, self._bound):
            raise PlugError("auth_failed", f"{att.issuer} is not the open session's identity")
        private, signer = member
        sh = statement_hash(att)
        proof = suites.sign("ecdsa-p256", private, sh)
        calldata = anchor_calldata(sh)
        payload = self._payloads.create_invoke_payload(self.contract, calldata[:8], {"data": calldata})
        try:
            r = self.client.send_request_with_sync_result(payload, with_sync_result=True, signer=signer)
        except Exception as e:
            raise PlugError("timeout" if "timeout" in str(e).lower() else "not_found", type(e).__name__) from e
        ref = StateRef(network, _TX_PREFIX + r.tx_id)
        if r.contract_result.code != 0:
            return Receipt("attest", Status.REJECTED, network, ref, {"statement_hash": sh},
                           f"proof_invalid: {r.contract_result.message}")
        found = self._transaction(ref.address)
        att.proof, att.anchor = proof, ref
        return Receipt("attest", Status.OK, network, ref,
                       {"proof": proof, "statement_hash": sh, "block": found["block"], "org_id": found["org_id"],
                        "anchored_at": found["anchored_at"], "finality": found["finality"]})

    def _transaction(self, address: str) -> dict:
        try:
            info = self.client.get_tx_by_tx_id(address.removeprefix(_TX_PREFIX))
        except Exception as e:
            raise PlugError("not_found", f"{address} ({type(e).__name__})") from e
        tx = info.transaction
        signer = tx.sender.signer
        sender = None
        if signer.member_type in (0, 2):  # CERT, PUBLIC_KEY
            sender = suites.did_key("ecdsa-p256", _compressed_from_pem(bytes(signer.member_info)))
        params = {p.key: bytes(p.value).decode("ascii", "replace") for p in tx.payload.parameters}
        height = self.client.get_current_block_height()
        return {"block": info.block_height, "status": tx.result.code, "contract": tx.payload.contract_name,
                "anchored_at": datetime.fromtimestamp(info.block_timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "calldata": params.get("data", ""), "sender": sender, "org_id": signer.org_id,
                "finality": {"kind": "final", "confirmations": max(height - info.block_height + 1, 1)}}

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        """Valid only if the signature, the issuer, and the anchor's sender are the same member key."""
        trust = resolve_registry(trust_registry, network, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})
        if att.proof.get("alg") != "ecdsa-p256":
            return rejected(network, "proof_invalid: unsupported alg", data)
        sh = statement_hash(att)
        ok, method = suites.verify(sh, att.proof)
        if not ok:
            return rejected(network, method, data)
        if not suites.binds(att.issuer, method):
            return rejected(network, "proof_invalid: issuer is not bound to the signing key", data)
        if att.anchor is None:
            return rejected(network, "proof_invalid: missing anchor", data)
        if att.anchor.network != network:
            return rejected(network, "proof_invalid: anchor is on another network", data)
        try:
            found = self._transaction(att.anchor.address)
        except PlugError:
            return rejected(network, f"not_found: anchor {att.anchor.address}", data)
        if found["status"] != 0:
            return rejected(network, "proof_invalid: anchor transaction failed", data)
        if found["contract"] != self.contract:
            return rejected(network, "proof_invalid: anchor did not call the anchor contract", data)
        if found["sender"] != method:
            return rejected(network, "proof_invalid: anchor was sent by another key", data)
        if found["calldata"] != anchor_calldata(sh):
            return rejected(network, "proof_invalid: anchor does not carry the statement", data)
        _, err = registry_key_status(data, att.issuer, method, parse_time(found["anchored_at"]))
        if err:
            return rejected(network, err, data)
        data.update({"verified": True, "alg": "ecdsa-p256", "verification_method": method,
                     "anchor": att.anchor.address, "anchored_block": found["block"],
                     "anchored_at": found["anchored_at"], "org_id": found["org_id"], "finality": found["finality"]})
        return Receipt("verify", Status.OK, network, att.anchor, data)
