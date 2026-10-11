# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Live Ethereum adapter for Sepolia testnet.

Real web3.py calls: eth_sendRawTransaction for attest, eth_call for query,
ecrecover for verify, eth_getLogs for subscribe. Tx hashes are prefixed
with 'live:' so they are distinguishable from stub receipts in logs.

Requires: pip install web3
Env: SEPOLIA_RPC_URL, SEPOLIA_PRIVATE_KEY
"""
from __future__ import annotations
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .. import suites
from ..core import Adapter, Attestation, Identity, Receipt, StateRef, Status, PlugError, SPEC_VERSION
from .base import LoggingAdapter, resolve_trust_registry

try:
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware
    from eth_account import Account
    from eth_keys import keys
    _WEB3_AVAILABLE = True
except ImportError:
    _WEB3_AVAILABLE = False


def chain_status(code) -> tuple[Status, Optional[str]]:
    """Map a mined transaction status to a receipt status. 1 is OK, 0 is a revert."""
    try:
        value = int(code)
    except (TypeError, ValueError):
        return Status.ERROR, "finality_unknown"
    if value == 1:
        return Status.OK, None
    return Status.REJECTED, "transaction reverted"


def select_stream_events(filt, tx_event: Optional[dict], logs: list) -> list:
    """Keep the tx event and logs the filter names. An empty filter keeps both."""
    selected = list(filt or [])
    out = []
    if tx_event and (not selected or "tx" in selected):
        out.append(tx_event)
    for entry in logs:
        topic0 = entry.get("topic0", "")
        addr = entry.get("address", "")
        if not selected or "log" in selected or topic0 in selected or addr in selected:
            out.append(entry)
    return out


def sign_subject(subject_hash: str, private_key: str) -> dict:
    """Sign a 32-byte subject hash. The verification method is the signing address."""
    if not _WEB3_AVAILABLE:
        raise PlugError("not_found", "web3 not installed; pip install web3")
    return suites.sign("ecdsa-secp256k1", private_key, subject_hash)


def check_proof(subject_hash: str, proof: dict) -> tuple[bool, str]:
    """Recover the signer and compare it to proof['verification_method'].

    Returns (True, recovered address), (False, recovered address) on a mismatch,
    or (False, "proof_invalid: ...") for a malformed proof.
    """
    if not _WEB3_AVAILABLE:
        raise PlugError("not_found", "web3 not installed; pip install web3")
    expected = (proof or {}).get("verification_method") or ""
    if not expected:
        return False, "proof_invalid: missing verification_method"
    try:
        msg_hash = bytes.fromhex(subject_hash)
        sig_bytes = bytes.fromhex(str(proof.get("sig", "")).replace("0x", ""))
    except ValueError as e:
        return False, f"proof_invalid: {e}"
    return suites._k1_verify(msg_hash, sig_bytes, expected)


def issuer_address(did: str) -> Optional[str]:
    """Checksum account address named by a did:plug or did:pkh identifier; None otherwise."""
    parsed = suites.parse_account_did(did)
    if parsed is None:
        return None
    try:
        return Web3.to_checksum_address(parsed[1])
    except Exception:
        return None


def _hex(value) -> str:
    text = value.hex() if hasattr(value, "hex") else str(value)
    return "0x" + text.lower().removeprefix("0x")


class LiveAdapter(LoggingAdapter, Adapter):
    """Ethereum adapter, Sepolia by default. One adapter instance per network.

    Keys never leave the adapter. The constructor key (or SEPOLIA_PRIVATE_KEY)
    is the default identity; a session may bring its own key as raw auth material.
    """

    def __init__(self, rpc_url: Optional[str] = None, private_key: Optional[str] = None, w3=None):
        super().__init__()
        if not _WEB3_AVAILABLE:
            raise PlugError("not_found", "web3 not installed; pip install web3")
        self.rpc_url = rpc_url or os.environ.get("SEPOLIA_RPC_URL", "")
        if w3 is None:
            if not self.rpc_url:
                raise PlugError("auth_failed", "SEPOLIA_RPC_URL not set")
            w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self.w3 = w3
        self._keys: dict[str, str] = {}    # checksum address -> private key
        self._dids: dict[str, str] = {}    # session DID -> checksum address
        self._nonces: dict[str, int] = {}
        self._bound: Optional[str] = None
        default = private_key or os.environ.get("SEPOLIA_PRIVATE_KEY", "")
        self.address: Optional[str] = self._add_key(default) if default else None

    def _add_key(self, key: str) -> str:
        try:
            address = Account.from_key(key).address
        except Exception as e:
            raise PlugError("auth_failed", "auth material is not a valid private key") from e
        self._keys[address] = key
        return address

    def _key_for(self, did: Optional[str]) -> tuple[str, str]:
        address = self._dids.get(did or "")
        if address is None and did:
            named = issuer_address(did)
            address = named if named in self._keys else None
        if address is None and did in (None, "", "did:plug:anon"):
            address = self.address
        if address is None:
            raise PlugError("auth_failed", f"no key for {did or 'anonymous caller'}")
        return address, self._keys[address]

    def _next_nonce(self, address: str) -> int:
        if address not in self._nonces:
            self._nonces[address] = self.w3.eth.get_transaction_count(address)
        n = self._nonces[address]
        self._nonces[address] = n + 1
        return n

    def _send(self, address: str, key: str, data_hex: str) -> tuple[str, Any]:
        """Send a 0-wei self-transaction carrying data_hex and wait for its receipt."""
        tx = {"from": address, "to": address, "value": 0, "data": data_hex,
              "nonce": self._next_nonce(address), "gasPrice": self.w3.eth.gas_price,
              "chainId": self.w3.eth.chain_id}
        try:
            tx["gas"] = self.w3.eth.estimate_gas(tx)
            signed = self.w3.eth.account.sign_transaction(tx, key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        except Exception:
            self._nonces.pop(address, None)  # re-read from chain on the next send
            raise
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        return "live:" + _hex(tx_hash), receipt

    def _finality(self, block: int) -> dict:
        info = {"confirmations": max(self.w3.eth.block_number - block + 1, 0)}
        try:
            finalized = self.w3.eth.get_block("finalized")["number"]
        except Exception:
            return dict(info, kind="probabilistic")
        return dict(info, kind="final" if block <= finalized else "probabilistic")

    def bind(self, subject: Optional[str]) -> None:
        self._bound = subject

    def chain_id(self) -> str:
        """CAIP-2 identifier of this network."""
        return f"eip155:{self.w3.eth.chain_id}"

    def _names_this_network(self, did: str, network: str) -> bool:
        parsed = suites.parse_account_did(did)
        return parsed is not None and parsed[0] in (self.chain_id(), network)

    def connect(self, network: str, auth: dict) -> dict:
        material = auth.get("material")
        address = self._add_key(material) if material else self.address
        if address is None:
            raise PlugError("auth_failed", "no key: pass raw key material or configure a default key")
        did = f"did:plug:{self.chain_id()}:{address}"
        self._dids[did] = address
        info = {"scheme": auth.get("scheme", "raw"), "subject": did, "address": address,
                "balance_wei": self.w3.eth.get_balance(address)}
        self.log.append({"op": "connect", "network": network, **info})
        return info

    def identify(self, network: str, identity: Identity) -> Receipt:
        address = issuer_address(identity.did)
        rec = {"op": "identify", "did": identity.did, "method": identity.method,
               "address": address, "controlled": address in self._keys}
        self.log.append(rec)
        if address is None:
            return Receipt(SPEC_VERSION, "identify", Status.REJECTED, network, data=rec,
                           error="proof_invalid: DID does not name an account on this network")
        return Receipt(SPEC_VERSION, "identify", Status.OK, network, data=rec)

    def attest(self, network: str, att: Attestation) -> Receipt:
        # A 0-wei self-transaction carries the subject hash: an independently checkable anchor, no contract.
        address, key = self._key_for(att.issuer)
        proof = sign_subject(att.subject_hash, key)
        tx_hex, receipt = self._send(address, key, "0x" + att.subject_hash)
        status, err = chain_status(receipt.status)
        ref = StateRef(network, tx_hex, "event")
        rec = {"op": "attest", "tx": tx_hex, "block": receipt.blockNumber,
               "subject_hash": att.subject_hash, "fact_type": att.fact_type, "issuer": att.issuer,
               "role": att.role.value if att.role else None,
               "seq": att.meta.get("_seq", 0), "gas_used": receipt.gasUsed,
               "chain_status": int(receipt.status), "finality": self._finality(receipt.blockNumber)}
        if status == Status.OK:
            att.proof = proof
            att.anchor = ref
            rec["proof"] = proof
        self.log.append(rec)
        return Receipt(SPEC_VERSION, "attest", status, network, ref, rec, err,
                       seq=att.meta.get("_seq", 0))

    def query(self, ref: StateRef, fields: Optional[list] = None) -> Receipt:
        tx_hex = ref.address[5:] if ref.address.startswith("live:") else ref.address
        try:
            receipt = self.w3.eth.get_transaction_receipt(tx_hex)
            tx = self.w3.eth.get_transaction(tx_hex)
        except Exception as e:
            raise PlugError("not_found", str(e)) from e
        status, err = chain_status(receipt.status)
        data = {"block": receipt.blockNumber, "status": receipt.status,
                "from": tx["from"], "to": tx["to"], "data": _hex(tx["input"]),
                "finality": self._finality(receipt.blockNumber)}
        if fields:
            data = {k: data[k] for k in fields if k in data}
        self.log.append({"op": "query", "tx": ref.address})
        return Receipt(SPEC_VERSION, "query", status, ref.network, ref, data, err)

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        """Valid only if the signature, the issuer binding, and the on-chain anchor all hold."""
        trust = resolve_trust_registry(self.query, trust_registry, network, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})

        def reject(error: str) -> Receipt:
            self.log.append({"op": "verify", "ok": False, "error": error})
            return Receipt(SPEC_VERSION, "verify", Status.REJECTED, network, data=data, error=error)

        alg = att.proof.get("alg", "")
        if alg not in ("ecdsa-secp256k1", "signature"):
            return reject("proof_invalid: unsupported alg")
        ok, detail = check_proof(att.subject_hash, att.proof)
        if not ok:
            if str(detail).startswith("proof_invalid"):
                return reject(detail)
            data["recovered"] = detail
            return reject("proof_invalid: signer mismatch")
        data.update({"alg": alg, "recovered": detail})
        if issuer_address(att.issuer) != detail:
            return reject("proof_invalid: issuer is not bound to the signing key")
        if not self._names_this_network(att.issuer, network):
            return reject("proof_invalid: issuer DID names another network")
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
        if Web3.to_checksum_address(found.data["from"]) != detail:
            return reject("proof_invalid: anchor was sent by another key")
        if found.data["data"] != "0x" + att.subject_hash.lower():
            return reject("proof_invalid: anchor does not carry the subject hash")
        stamp = self.w3.eth.get_block(found.data["block"])["timestamp"]
        data.update({"verified": True, "anchor": att.anchor.address,
                     "anchored_block": found.data["block"],
                     "anchored_at": datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "finality": found.data["finality"]})
        self.log.append({"op": "verify", "ok": True})
        return Receipt(SPEC_VERSION, "verify", Status.OK, network, data=data)

    def settle(self, network: str, op: str, payload: dict) -> Receipt:
        # Settle = a real transaction whose data encodes the op and payload hash.
        address, key = self._key_for(self._bound)
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        data_hex = "0x" + hashlib.sha256(f"settle:{op}:{payload_hash}".encode()).hexdigest()
        tx_hex, receipt = self._send(address, key, data_hex)
        status, err = chain_status(receipt.status)
        rec = {"op": "settle", "tx": tx_hex, "block": receipt.blockNumber, "settle_op": op,
               "chain_status": int(receipt.status)}
        self.log.append(rec)
        return Receipt(SPEC_VERSION, "settle", status, network,
                       StateRef(network, tx_hex, "event"), rec, err)

    def bridge(self, src: StateRef, target_network: str) -> Receipt:
        # Without a target adapter, publish the reference on the source chain; the target side stays pending.
        address, key = self._key_for(self._bound)
        data_hex = "0x" + hashlib.sha256(
            f"bridge:{src.address}:{target_network}".encode()).hexdigest()
        tx_hex, receipt = self._send(address, key, data_hex)
        status, err = chain_status(receipt.status)
        rec = {"op": "bridge", "tx": tx_hex, "block": receipt.blockNumber,
               "source": src.address, "target": target_network,
               "chain_status": int(receipt.status)}
        self.log.append(rec)
        return Receipt(SPEC_VERSION, "bridge", Status.PENDING if status == Status.OK else status, src.network,
                       StateRef(src.network, tx_hex, "event"), rec, err)

    def subscribe(self, ref: StateRef, callback_id: str, filt: Optional[list] = None) -> str:
        # One poll of the transaction receipt. No long-lived socket.
        handle = f"stream:{ref.network}:{ref.address}:{callback_id}"
        selected = list(filt or [])
        tx_hex = ref.address[5:] if str(ref.address).startswith("live:") else str(ref.address)
        events: list = []
        note = "polled"
        try:
            receipt = self.w3.eth.get_transaction_receipt(tx_hex)
            status, _err = chain_status(receipt.status)
            tx_event = {"type": "tx", "status": status.value, "block": receipt.blockNumber}
            logs = []
            for entry in receipt["logs"]:
                topics = entry["topics"]
                topic0 = topics[0].hex() if topics else ""
                if topic0 and not topic0.startswith("0x"):
                    topic0 = "0x" + topic0
                logs.append({"type": "log", "address": entry["address"], "topic0": topic0})
            events = select_stream_events(selected, tx_event, logs)
        except Exception as e:
            note = f"poll failed: {e}"
        self.log.append({"op": "subscribe", "handle": handle, "filter": selected,
                         "events": events, "note": note})
        return handle
