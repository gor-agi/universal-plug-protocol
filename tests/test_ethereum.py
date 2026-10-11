# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""EthereumLedger against an in-memory chain: anchoring, did:pkh issuers, per-session keys, agreed multi-endpoint
reads, finality, registry key windows at block time. No network, except the live test, which runs only when
ETH_RPC_URL and ETH_PRIVATE_KEY are set."""
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_account")

from eth_account import Account
from hexbytes import HexBytes
from web3.datastructures import AttributeDict

from upp import ANY, Attestation, Plug, PlugError, StateRef, Status, sha256_hex, statement_hash, suites
from upp.ledgers.ethereum import EthereumLedger, issuer_address

CHAIN = 11155111
SECRET = "SUPERSECRETAPIKEY123"
SECRET_URL = f"https://sepolia.example/v3/{SECRET}"


def _norm(h) -> str:
    text = h.hex() if isinstance(h, (bytes, bytearray)) else str(h)
    return "0x" + text.lower().removeprefix("0x")


class _FakeAccount:
    def __init__(self, eth):
        self._eth = eth

    def sign_transaction(self, tx, key):
        signed = Account.sign_transaction(tx, key)
        self._eth.pending[bytes(signed.raw_transaction)] = (tx, signed.hash)
        return signed


class _FakeEth:
    """Mines every transaction into its own block. status=0 for data the test marks as reverting."""

    def __init__(self):
        self.account = _FakeAccount(self)
        self.pending = {}
        self.txs = {}
        self.receipts = {}
        self.nonces = {}
        self.block_number = 100
        self.finalized = 90
        self.revert_data = set()
        self.revert_all = False
        self.chain_id = CHAIN
        self.gas_price = 1

    def get_transaction_count(self, address):
        return self.nonces.get(address, 0)

    def get_balance(self, address):
        return 10**18

    def estimate_gas(self, tx):
        return 22000

    def send_raw_transaction(self, raw):
        tx, tx_hash = self.pending.pop(bytes(raw))
        assert tx["nonce"] == self.nonces.get(tx["from"], 0), "nonce reuse or gap"
        self.block_number += 1
        self.nonces[tx["from"]] = self.nonces.get(tx["from"], 0) + 1
        key = _norm(tx_hash)
        self.txs[key] = AttributeDict({"from": tx["from"], "to": tx["to"], "input": HexBytes(tx["data"])})
        self.receipts[key] = AttributeDict({"status": 0 if self.revert_all or tx["data"] in self.revert_data else 1,
                                           "blockNumber": self.block_number, "gasUsed": 21512, "logs": []})
        return HexBytes(tx_hash)

    def wait_for_transaction_receipt(self, tx_hash, timeout=120):
        return self.receipts[_norm(tx_hash)]

    def get_transaction_receipt(self, tx_hash):
        if _norm(tx_hash) not in self.receipts:
            raise ValueError("transaction not found")
        return self.receipts[_norm(tx_hash)]

    def get_transaction(self, tx_hash):
        return self.txs[_norm(tx_hash)]

    def get_block(self, ident):
        if ident == "finalized":
            return {"number": self.finalized}
        return {"number": ident, "timestamp": block_time(ident)}


class _FakeW3:
    def __init__(self):
        self.eth = _FakeEth()


def block_time(block: int) -> int:
    return 1_791_000_000 + block


ALICE = Account.create().key.hex()
BOB = Account.create().key.hex()


def did(key: str, chain: int = CHAIN) -> str:
    return f"did:pkh:eip155:{chain}:{Account.from_key(key).address}"


def setup(*keys):
    w3 = _FakeW3()
    p = Plug(trust={"sepolia": ANY})
    ledger = EthereumLedger(w3=w3)
    p.register("sepolia", ledger)
    sessions = [p.open("sepolia", {"key": k}) for k in keys]
    return p, ledger, w3, sessions


def attestation_from(r, signer=None, **overrides):
    """The receipt's attestation with overrides; signer re-signs the changed statement with that key."""
    att = replace(Attestation.from_receipt(r), **overrides)
    if signer:
        att.proof = suites.sign("ecdsa-secp256k1", signer, statement_hash(att))
    return att


# ---- proofs ----

def test_proof_matches_named_verification_method_only():
    acct, other = Account.create(), Account.create()
    subject = "11" * 32
    proof = suites.sign("ecdsa-secp256k1", acct.key.hex(), subject)
    assert proof["verification_method"] == acct.address
    assert suites.verify(subject, proof) == (True, acct.address)
    forged = dict(proof, verification_method=other.address)
    assert suites.verify(subject, forged) == (False, "proof_invalid: signer mismatch")
    assert suites.verify("22" * 32, proof)[0] is False


# ---- anchoring and checking ----

def test_anchored_attestation_verifies_with_time_and_finality():
    p, _, w3, _ = setup(ALICE)
    r = p.prove(b"bill of lading 42", "doc.sha256")
    assert r.status == Status.OK and r.data["issuer"] == did(ALICE)
    assert r.state_ref == StateRef("sepolia", r.data["tx"])
    assert w3.eth.get_transaction(r.state_ref.address)["input"] == HexBytes("0x" + r.data["statement_hash"])
    v = p.check(attestation_from(r))
    assert v["valid"] is True, v["receipt"].error
    data = v["receipt"].data
    assert data["anchored_block"] == r.data["block"]
    assert data["anchored_at"] == datetime.fromtimestamp(block_time(r.data["block"]), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    assert data["verification_method"] == Account.from_key(ALICE).address
    assert data["finality"]["kind"] == "probabilistic"


def test_signed_but_never_anchored_is_rejected():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"real", "doc.sha256")
    att = attestation_from(r, signer=ALICE, subject_hash=sha256_hex(b"never anchored"))
    v = p.check(att)
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: anchor does not carry the statement"
    assert p.check(attestation_from(r, anchor=None))["receipt"].error == "proof_invalid: missing anchor"


def test_anchor_checks():
    p, _, w3, _ = setup(ALICE)
    r = p.prove(b"anchored", "doc.sha256")
    elsewhere = attestation_from(r, anchor=StateRef("mainnet", r.state_ref.address))
    assert p.check(elsewhere)["receipt"].error == "proof_invalid: anchor is on another network"
    missing = attestation_from(r, anchor=StateRef("sepolia", "0x" + "ab" * 32))
    error = p.check(missing)["receipt"].error
    assert error.startswith("not_found: transaction 0x" + "ab" * 32 + " not found"), error
    assert p.check(attestation_from(r, fact_type="contract.signed"))["receipt"].error == \
        "proof_invalid: signer mismatch"
    key = r.state_ref.address
    w3.eth.receipts[key] = AttributeDict(dict(w3.eth.receipts[key], status=0))
    assert p.check(attestation_from(r))["receipt"].error == "proof_invalid: anchor transaction failed"


def test_only_secp256k1_proofs_are_accepted():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"x", "doc.sha256")
    att = attestation_from(r)
    att.proof = suites.sign("ed25519", suites.generate_key("ed25519"), statement_hash(att))
    assert p.check(att)["receipt"].error == "proof_invalid: unsupported alg"


def test_issuer_impersonation_is_rejected_even_when_registry_lists_victim():
    p, _, _, _ = setup(ALICE, BOB)
    alice = did(ALICE)
    r = p.prove(b"bob's claim", "doc.sha256")  # active session is bob
    assert r.data["issuer"] == did(BOB)
    relabeled = p.check(attestation_from(r, issuer=alice), trust_registry={"issuers": [alice]})
    assert relabeled["receipt"].error == "proof_invalid: signer mismatch"
    v = p.check(attestation_from(r, signer=BOB, issuer=alice), trust_registry={"issuers": [alice]})
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: issuer is not bound to the signing key"


def test_anchor_from_another_key_is_rejected():
    p, _, _, (alice_sid, _) = setup(ALICE, BOB)
    bob_r = p.prove(b"shared fact", "doc.sha256")
    p.use(alice_sid)
    att = attestation_from(bob_r, signer=ALICE, issuer=p.active().subject)
    v = p.check(att)
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: anchor was sent by another key"


def test_each_session_signs_with_its_own_key():
    p, _, w3, (alice_sid, _) = setup(ALICE, BOB)
    bob_r = p.prove(b"same fact", "doc.sha256")
    p.use(alice_sid)
    alice_r = p.prove(b"same fact", "doc.sha256")
    assert alice_r.state_ref.address != bob_r.state_ref.address
    senders = {w3.eth.get_transaction(r.state_ref.address)["from"] for r in (alice_r, bob_r)}
    assert senders == {Account.from_key(ALICE).address, Account.from_key(BOB).address}
    assert p.check(attestation_from(alice_r))["valid"] is True
    assert p.check(attestation_from(bob_r))["valid"] is True
    again = p.prove(b"second", "doc.sha256")
    assert again.status == Status.OK and w3.eth.nonces[Account.from_key(ALICE).address] == 2


def test_only_the_open_session_signs():
    p, _, _, (alice_sid, bob_sid) = setup(ALICE, BOB)
    as_alice = Attestation(sha256_hex(b"x"), "doc.sha256", did(ALICE), "2026-10-10T00:00:00Z")
    with pytest.raises(PlugError) as e:
        p.attest(as_alice, "sepolia")  # bob is the open session; alice's key is known but not bound
    assert e.value.code == "auth_failed"
    p.use(alice_sid)
    assert p.attest(as_alice, "sepolia").status == Status.OK
    stranger = Attestation(sha256_hex(b"y"), "doc.sha256", f"did:pkh:eip155:{CHAIN}:{Account.create().address}",
                           "2026-10-10T00:00:00Z")
    with pytest.raises(PlugError) as e:
        p.attest(stranger, "sepolia")
    assert e.value.code == "auth_failed"


def test_nothing_signs_without_a_session():
    p = Plug()
    p.register("sepolia", EthereumLedger(w3=_FakeW3(), key=ALICE))
    with pytest.raises(PlugError) as e:
        p.prove(b"anonymous", "doc.sha256", network="sepolia")
    assert e.value.code == "auth_failed"
    with pytest.raises(PlugError) as e:
        p.attest(Attestation(sha256_hex(b"a"), "doc.sha256", did(ALICE), "2026-10-10T00:00:00Z"), "sepolia")
    assert e.value.code == "auth_failed"
    p.open("sepolia")  # opening a session is the consent to use the configured key
    r = p.prove(b"consented", "doc.sha256")
    assert r.status == Status.OK and r.data["issuer"] == did(ALICE)


def test_a_session_on_another_network_does_not_sign():
    p = Plug(trust={"chain-a": ANY, "chain-b": ANY})
    a, b = EthereumLedger(w3=_FakeW3()), EthereumLedger(w3=_FakeW3())
    p.register("chain-a", a)
    p.register("chain-b", b)
    p.open("chain-b", {"key": BOB})
    p.open("chain-a", {"key": ALICE})
    with pytest.raises(PlugError) as e:
        p.attest(Attestation(sha256_hex(b"z"), "doc.sha256", did(BOB), "2026-10-10T00:00:00Z"), "chain-b")
    assert e.value.code == "auth_failed"


def test_connect_needs_a_valid_key(monkeypatch):
    monkeypatch.delenv("ETH_PRIVATE_KEY", raising=False)
    p = Plug()
    p.register("sepolia", EthereumLedger(w3=_FakeW3()))
    for credential in (None, {"key": "not a key"}):
        with pytest.raises(PlugError) as e:
            p.open("sepolia", credential)
        assert e.value.code == "auth_failed"
    monkeypatch.delenv("ETH_RPC_URL", raising=False)
    with pytest.raises(PlugError) as e:
        EthereumLedger()
    assert e.value.code == "auth_failed"


def test_issuer_on_another_chain_is_rejected():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"x", "doc.sha256")
    address = Account.from_key(ALICE).address
    other = f"did:pkh:eip155:1:{address}"
    assert p.check(attestation_from(r, signer=ALICE, issuer=other))["receipt"].error == \
        "proof_invalid: issuer DID names another chain"
    for same in (f"did:pkh:eip155:{CHAIN}:{address}", f"did:pkh:eip155:{CHAIN}:{address.lower()}"):
        att = Attestation(sha256_hex(same), "doc.sha256", same, "2026-10-10T00:00:00Z")
        anchored = p.attest(att, "sepolia")
        v = p.check(Attestation.from_receipt(anchored))
        assert v["valid"] is True, (same, v["receipt"].error)
    for bad in ("did:web:example.com", f"did:pkh:eip155:{CHAIN}:not-an-address"):
        assert issuer_address(bad) is None


def test_finality_turns_final_once_block_is_finalized():
    p, _, w3, _ = setup(ALICE)
    r = p.prove(b"x", "doc.sha256")
    assert r.data["finality"] == {"confirmations": 1, "kind": "probabilistic"}
    w3.eth.finalized = w3.eth.block_number
    v = p.check(attestation_from(r))
    assert v["receipt"].data["finality"]["kind"] == "final"


def test_reverted_anchor_carries_no_proof():
    p, _, w3, _ = setup(ALICE)
    w3.eth.revert_all = True
    r = p.prove(b"doomed", "doc.sha256")
    assert r.status == Status.REJECTED and r.error == "transaction reverted"
    assert "proof" not in r.data
    assert p.check(Attestation.from_receipt(r))["valid"] is False


def test_failed_send_rereads_the_nonce():
    p, ledger, w3, _ = setup(ALICE)
    calls = {"n": 0}
    real = w3.eth.send_raw_transaction

    def flaky(raw):
        calls["n"] += 1
        if calls["n"] == 1:
            w3.eth.pending.pop(bytes(raw))
            raise ConnectionError("dropped")
        return real(raw)
    w3.eth.send_raw_transaction = flaky
    with pytest.raises(Exception):
        p.prove(b"lost", "doc.sha256")
    assert p.prove(b"kept", "doc.sha256").status == Status.OK


# ---- trust registries ----

def test_a_ledger_record_is_not_a_registry():
    p, _, _, _ = setup(ALICE, BOB)
    operator_tx = p.prove(b"operator registry publication", "doc.sha256").state_ref
    attacker = p.prove(b"self-signed claim", "doc.sha256")
    v = p.check(Attestation.from_receipt(attacker), trust_registry=operator_tx)
    assert v["valid"] is False
    assert v["receipt"].error == "proof_invalid: a trust registry is a dict or an http(s) URL"


def test_registry_narrows_operator_trust():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"listed", "doc.sha256")
    att = Attestation.from_receipt(r)
    assert p.check(att, trust_registry={"issuers": [did(ALICE)]})["valid"] is True
    assert p.check(att, trust_registry={"issuers": [did(BOB)]})["receipt"].error == \
        "not_authorized: issuer not in trust registry"
    closed = Plug()
    closed.register("sepolia", p._ledger("sepolia"))
    assert closed.check(att, "sepolia")["receipt"].error == \
        "not_authorized: no trust policy for sepolia (closed by default)"
    assert closed.check(att, "sepolia", {"issuers": [did(ALICE)]})["valid"] is True


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_registry_key_windows_are_judged_at_block_time():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"windowed", "doc.sha256")
    att = Attestation.from_receipt(r)
    issuer, address = did(ALICE), Account.from_key(ALICE).address
    anchored = datetime.fromtimestamp(block_time(r.data["block"]), timezone.utc)
    second = timedelta(seconds=1)

    def registry(*entries):
        return {"issuers": [issuer], "keys": {issuer: list(entries)}}

    past_window = registry({"verification_method": address.lower(), "valid_from": _iso(anchored - second),
                            "valid_until": _iso(anchored + second)})
    assert anchored + second < datetime.now(timezone.utc), "the window closed before now"
    v = p.check(att, trust_registry=past_window)
    assert v["valid"] is True, v["receipt"].error
    late = registry({"verification_method": address, "valid_from": _iso(anchored + second)})
    assert p.check(att, trust_registry=late)["receipt"].error == f"proof_invalid: key not valid at {_iso(anchored)}"
    ended = registry({"verification_method": address, "valid_until": _iso(anchored)})
    assert p.check(att, trust_registry=ended)["receipt"].error == f"proof_invalid: key not valid at {_iso(anchored)}"
    rotated = registry({"verification_method": Account.create().address})
    assert p.check(att, trust_registry=rotated)["receipt"].error == \
        "proof_invalid: key not listed for issuer in trust registry"


# ---- reads across endpoints ----

class _Mirror:
    """Another endpoint reading the same chain; `tamper` rewrites what it reports."""

    def __init__(self, source, tamper=None, fail=None):
        outer = self

        class Eth:
            def __getattr__(self, name):
                return getattr(source.eth, name)

            def get_transaction(self, tx_hash):
                if fail:
                    raise fail
                tx = source.eth.get_transaction(tx_hash)
                return tamper(tx) if tamper else tx

            @property
            def block_number(self):
                return source.eth.block_number - outer.lag

        self.lag = 0
        self.eth = Eth()


def test_reads_must_agree_across_endpoints():
    w3 = _FakeW3()
    honest = _Mirror(w3)
    liar = _Mirror(w3, tamper=lambda tx: AttributeDict(dict(tx, input=HexBytes("0x" + "00" * 32))))
    p = Plug(trust={"sepolia": ANY})
    p.register("sepolia", EthereumLedger(w3=w3, readers=[honest]))
    p.open("sepolia", {"key": ALICE})
    r = p.prove(b"quorum", "doc.sha256")
    assert p.check(Attestation.from_receipt(r))["valid"] is True

    lied_to = Plug(trust={"sepolia": ANY})
    lied_to.register("sepolia", EthereumLedger(w3=w3, readers=[liar]))
    v = lied_to.check(Attestation.from_receipt(r), network="sepolia")
    assert v["valid"] is False and v["receipt"].error.startswith("proof_invalid: read endpoints disagree")

    down = Plug(trust={"sepolia": ANY})
    down.register("sepolia", EthereumLedger(w3=w3, readers=[_Mirror(w3, fail=ValueError("gone"))]))
    v = down.check(Attestation.from_receipt(r), network="sepolia")
    assert v["valid"] is False and v["receipt"].error.startswith("not_found: "), "every endpoint must answer"

    honest.lag = 5
    q = p.check(Attestation.from_receipt(r))["receipt"].data["finality"]
    assert q["confirmations"] == max(w3.eth.block_number - r.data["block"] + 1 - 5, 0), "the weakest view wins"
    w3.eth.finalized = w3.eth.block_number

    class NotFinal(_Mirror):
        def __init__(self, source):
            super().__init__(source)
            get_block = source.eth.get_block
            self.eth.get_block = lambda ident: {"number": 0} if ident == "finalized" else get_block(ident)
    split = Plug(trust={"sepolia": ANY})
    split.register("sepolia", EthereumLedger(w3=w3, readers=[NotFinal(w3)]))
    assert split.check(Attestation.from_receipt(r), "sepolia")["receipt"].data["finality"]["kind"] == \
        "probabilistic", "final only when every endpoint says so"


# ---- the RPC URL (it often carries an API key) never leaks into errors ----

class _Throttled:
    """An endpoint over `source` whose transaction reads fail the way web3's HTTP provider does: with the URL."""

    def __init__(self, source):
        class Eth:
            def __getattr__(self, name):
                return getattr(source.eth, name)

            def get_transaction_receipt(self, *args):
                raise RuntimeError(f"429 Client Error: Too Many Requests for url: {SECRET_URL}")
            get_transaction = get_transaction_receipt

        self.eth = Eth()


def test_read_errors_never_reveal_the_rpc_url():
    p, _, w3, _ = setup(ALICE)
    r = p.prove(b"x", "doc.sha256")
    for readers in ([_Throttled(w3)], []):
        throttled = Plug(trust={"sepolia": ANY})
        throttled.register("sepolia", EthereumLedger(w3=_Throttled(w3), readers=readers))
        v = throttled.check(Attestation.from_receipt(r), "sepolia")
        assert v["valid"] is False and v["receipt"].error.startswith("not_found: ")
        assert SECRET not in repr(v)


def test_endpoint_failures_during_verify_never_reveal_the_rpc_url():
    p, _, _, _ = setup(ALICE)
    r = p.prove(b"y", "doc.sha256")
    dead = EthereumLedger(rpc_url=f"http://127.0.0.1:9/v3/{SECRET}")
    checker = Plug(trust={"sepolia": ANY})
    checker.register("sepolia", dead)
    try:
        v = checker.check(Attestation.from_receipt(r), "sepolia")
    except PlugError as e:
        assert SECRET not in str(e)
    except Exception as e:  # anything but a PlugError or a rejected receipt is a leak path
        pytest.fail(f"{type(e).__name__} escaped: {SECRET in str(e) and 'with the RPC URL' or str(e)}")
    else:
        assert v["valid"] is False and SECRET not in repr(v)


def test_endpoint_failures_during_prove_never_reveal_the_rpc_url():
    p, _, w3, _ = setup(ALICE)

    def refuse(*args):
        raise RuntimeError(f"429 Client Error: Too Many Requests for url: {SECRET_URL}")
    w3.eth.send_raw_transaction = refuse
    with pytest.raises(PlugError) as e:
        p.prove(b"z", "doc.sha256")
    assert SECRET not in str(e.value)


# ---- live: a real chain, only when configured ----

@pytest.mark.skipif(not (os.environ.get("ETH_RPC_URL") and os.environ.get("ETH_PRIVATE_KEY")),
                    reason="set ETH_RPC_URL and ETH_PRIVATE_KEY (a funded testnet key) to run against a real chain")
def test_live_prove_and_check():
    ledger = EthereumLedger()
    network = ledger.chain_id()
    p = Plug(trust={network: ANY})
    p.register(network, ledger)
    p.open(network)
    r = p.prove(f"upp live test {datetime.now(timezone.utc).isoformat()}", "doc.sha256")
    assert r.status == Status.OK, r.error
    assert r.data["issuer"] == f"did:pkh:{network}:{Account.from_key(os.environ['ETH_PRIVATE_KEY']).address}"
    v = p.check(Attestation.from_receipt(r))
    assert v["valid"] is True, v["receipt"].error
    assert v["receipt"].data["anchored_block"] == r.data["block"]
    forged = replace(Attestation.from_receipt(r), subject_hash=sha256_hex(b"never anchored"))
    forged.proof = suites.sign("ecdsa-secp256k1", os.environ["ETH_PRIVATE_KEY"], statement_hash(forged))
    assert p.check(forged)["receipt"].error == "proof_invalid: anchor does not carry the statement"
