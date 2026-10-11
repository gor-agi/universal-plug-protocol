# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Ethereum (any EVM chain): the statement hash rides in a 0-wei self-transaction, no contract needed.

Issuers are did:pkh:eip155:<chain>:<address>. read_urls (or readers) add independent read endpoints; every read a
verification relies on must agree across all of them, or verification fails. Needs: pip install universal-plug[ethereum]
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
from typing import Any, Optional

from .. import suites
from ..core import Attestation, Ledger, PlugError, Receipt, StateRef, Status, rejected, statement_hash
from ..registry import registry_key_status, resolve_registry

try:
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware
    from eth_account import Account
except ImportError:  # pragma: no cover
    Web3 = None


def _hex(value) -> str:
    text = value.hex() if hasattr(value, "hex") else str(value)
    return "0x" + text.lower().removeprefix("0x")


def _connect(url: str):
    w3 = Web3(Web3.HTTPProvider(url))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def issuer_address(did: str) -> Optional[str]:
    """Checksum address named by a did:pkh, else None."""
    parsed = suites.parse_account_did(did)
    if parsed is None:
        return None
    try:
        return Web3.to_checksum_address(parsed[1])
    except Exception:
        return None


class EthereumLedger(Ledger):
    """One instance per chain. key (or ETH_PRIVATE_KEY) is the key a session uses when it opens without one;
    nothing signs without an open session."""

    def __init__(self, rpc_url: Optional[str] = None, key: Optional[str] = None, w3=None,
                 read_urls: Optional[list[str]] = None, readers: Optional[list] = None):
        if Web3 is None:
            raise PlugError("unsupported_op", "EthereumLedger needs: pip install universal-plug[ethereum]")
        if w3 is None:
            url = rpc_url or os.environ.get("ETH_RPC_URL", "")
            if not url:
                raise PlugError("auth_failed", "no RPC URL (pass rpc_url or set ETH_RPC_URL)")
            w3 = _connect(url)
        self.w3 = w3
        self._readers = [w3] + [_connect(u) for u in (read_urls or [])] + list(readers or [])
        self._keys: dict[str, str] = {}      # session DID -> private key
        self._nonces: dict[str, int] = {}
        self._bound: Optional[str] = None
        self._default = key or os.environ.get("ETH_PRIVATE_KEY") or None
        self._chain: Optional[int] = None

    @staticmethod
    def _rpc(what: str, call):
        """call() with any endpoint failure as a PlugError naming only its type: upstream text can carry the RPC URL,
        and with it a provider API key."""
        try:
            return call()
        except PlugError:
            raise
        except Exception as e:
            code = "timeout" if "timeout" in type(e).__name__.lower() else "not_found"
            raise PlugError(code, f"{what} failed ({type(e).__name__})") from e

    def chain_id(self) -> str:
        if self._chain is None:
            self._chain = self._rpc("chain id", lambda: int(self.w3.eth.chain_id))
        return f"eip155:{self._chain}"

    def _agreed(self, read, what: str):
        """read(w3) on every endpoint; the answer only when all agree. Errors never carry the RPC URL."""
        answers = []
        for w3 in self._readers:
            try:
                answers.append(read(w3))
            except Exception as e:
                raise PlugError("not_found", f"{what} not found ({type(e).__name__})") from e
        if any(a != answers[0] for a in answers[1:]):
            raise PlugError("proof_invalid", f"read endpoints disagree on {what}")
        return answers[0]

    def connect(self, network: str, auth: dict) -> dict:
        key = auth.get("key") or self._default
        if not key:
            raise PlugError("auth_failed", "no key: pass {'key': ...} or configure a default key")
        try:
            address = Account.from_key(key).address
        except Exception as e:
            raise PlugError("auth_failed", "not a valid private key") from e
        did = f"did:pkh:{self.chain_id()}:{address}"
        self._keys[did] = key
        return {"subject": did}

    def bind(self, subject: Optional[str]) -> None:
        self._bound = subject

    def _send(self, address: str, key: str, data_hex: str):
        eth = self.w3.eth
        if address not in self._nonces:
            self._nonces[address] = self._rpc("nonce", lambda: eth.get_transaction_count(address))
        chain = int(self.chain_id().split(":")[1])

        def send():
            tx = {"from": address, "to": address, "value": 0, "data": data_hex, "nonce": self._nonces[address],
                  "gasPrice": eth.gas_price, "chainId": chain}
            tx["gas"] = eth.estimate_gas(tx)
            return eth.send_raw_transaction(eth.account.sign_transaction(tx, key).raw_transaction)
        try:
            tx_hash = self._rpc("sending the anchor", send)
        except PlugError:
            self._nonces.pop(address, None)  # re-read from the chain next time
            raise
        self._nonces[address] += 1
        receipt = self._rpc("anchor receipt", lambda: eth.wait_for_transaction_receipt(tx_hash, timeout=120))
        return _hex(tx_hash), receipt

    def _finality(self, block: int) -> dict:
        """The weakest finality any read endpoint reports; unknown when an endpoint cannot say."""
        confirmations, final = None, True
        for w3 in self._readers:
            try:
                seen = max(w3.eth.block_number - block + 1, 0)
            except Exception:
                return {"confirmations": None, "kind": "unknown"}
            confirmations = seen if confirmations is None else min(confirmations, seen)
            try:
                final = final and block <= w3.eth.get_block("finalized")["number"]
            except Exception:
                final = False
        return {"confirmations": confirmations, "kind": "final" if final else "probabilistic"}

    def attest(self, network: str, att: Attestation) -> Receipt:
        key = self._keys.get(self._bound or "")
        if key is None:
            raise PlugError("auth_failed", "signing needs an open session on this network")
        address = Account.from_key(key).address
        if att.issuer != self._bound and issuer_address(att.issuer) != address:
            raise PlugError("auth_failed", f"{att.issuer} is not the open session's identity")
        sh = statement_hash(att)
        proof = suites.sign("ecdsa-secp256k1", key, sh)
        tx_hex, receipt = self._send(address, key, "0x" + sh)
        ref = StateRef(network, tx_hex)
        data: dict[str, Any] = {"statement_hash": sh, "tx": tx_hex, "block": receipt.blockNumber,
                                "gas_used": receipt.gasUsed}
        if int(receipt.status) != 1:
            return Receipt("attest", Status.REJECTED, network, ref, data, "transaction reverted")
        att.proof, att.anchor = proof, ref
        data.update(proof=proof, finality=self._finality(receipt.blockNumber))
        return Receipt("attest", Status.OK, network, ref, data)

    def _transaction(self, tx_hex: str) -> dict:
        def read(w3):
            receipt, tx = w3.eth.get_transaction_receipt(tx_hex), w3.eth.get_transaction(tx_hex)
            return {"block": receipt.blockNumber, "status": int(receipt.status), "from": tx["from"],
                    "data": _hex(tx["input"])}
        return self._agreed(read, f"transaction {tx_hex}")

    def verify(self, att: Attestation, network: str, trust_registry=None) -> Receipt:
        """Valid only if the signature, the issuer binding, and the on-chain anchor all hold."""
        trust = resolve_registry(trust_registry, network, att.issuer)
        if isinstance(trust, Receipt):
            return trust
        data = dict(trust or {})
        if att.proof.get("alg") != "ecdsa-secp256k1":
            return rejected(network, "proof_invalid: unsupported alg", data)
        sh = statement_hash(att)
        ok, signer = suites.verify(sh, att.proof)
        if not ok:
            return rejected(network, signer, data)
        if issuer_address(att.issuer) != signer:
            return rejected(network, "proof_invalid: issuer is not bound to the signing key", data)
        if att.anchor is None:
            return rejected(network, "proof_invalid: missing anchor", data)
        if att.anchor.network != network:
            return rejected(network, "proof_invalid: anchor is on another network", data)
        try:
            if suites.parse_account_did(att.issuer)[0] != self.chain_id():
                return rejected(network, "proof_invalid: issuer DID names another chain", data)
            found = self._transaction(att.anchor.address)
            if found["status"] != 1:
                return rejected(network, "proof_invalid: anchor transaction failed", data)
            if Web3.to_checksum_address(found["from"]) != signer:
                return rejected(network, "proof_invalid: anchor was sent by another key", data)
            if found["data"] != "0x" + sh:
                return rejected(network, "proof_invalid: anchor does not carry the statement", data)
            stamp = self._agreed(lambda w3: w3.eth.get_block(found["block"])["timestamp"], "anchor block time")
        except PlugError as e:
            return rejected(network, f"{e.code}: {e.message}", data)
        anchored = datetime.fromtimestamp(stamp, timezone.utc)
        _, err = registry_key_status(data, att.issuer, signer, anchored)
        if err:
            return rejected(network, err, data)
        data.update({"verified": True, "alg": "ecdsa-secp256k1", "verification_method": signer,
                     "anchor": att.anchor.address, "anchored_block": found["block"],
                     "anchored_at": anchored.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "finality": self._finality(found["block"])})
        return Receipt("verify", Status.OK, network, att.anchor, data)
