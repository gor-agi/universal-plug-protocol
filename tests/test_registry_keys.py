# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Keyed trust registries: issuer keys with validity windows, judged at the time the evidence proves."""
import time
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("Crypto")

from plug import suites
from plug.adapters.eudi import EudiAdapter
from plug.core import Attestation, Plug, sha256_hex, statement_hash


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


NOW = datetime.now(timezone.utc)
ISSUER = "did:web:pid-provider.example"  # a DID method no adapter resolves on its own


def eudi_with(subject, issued=NOW):
    p = Plug()
    p.register_adapter("eudi", EudiAdapter())
    p.open("eudi", {"scheme": "raw", "material": "w", "subject": "holder"})
    p.attest("eudi", Attestation(subject, "identity.pid", ISSUER, iso(issued)))
    return p


def signed(key, subject, issued=NOW):
    att = Attestation(subject, "identity.pid", ISSUER, iso(issued))
    att.proof = suites.sign("ecdsa-p256", key, statement_hash(att))
    return att


def test_registry_keys_make_an_unresolvable_issuer_verifiable():
    key = suites.generate_key("ecdsa-p256")
    vm = suites.sign("ecdsa-p256", key, "00" * 32)["verification_method"]
    subject = sha256_hex(b"pid credential")
    p = eudi_with(subject)
    att = signed(key, subject)
    assert p.check(att, network="eudi")["receipt"].error == "proof_invalid: unverifiable"
    registry = {"issuers": [ISSUER], "keys": {ISSUER: [{"verification_method": vm}]}}
    v = p.check(att, network="eudi", trust_registry=registry)
    assert v["valid"] is True, v["receipt"].error
    other = suites.generate_key("ecdsa-p256")
    v = p.check(signed(other, subject), network="eudi", trust_registry=registry)
    assert v["receipt"].error == "proof_invalid: key not listed for issuer in trust registry"


def test_rotated_or_revoked_key_fails_without_an_anchored_time():
    old, new = suites.generate_key("ecdsa-p256"), suites.generate_key("ecdsa-p256")
    vm = lambda k: suites.sign("ecdsa-p256", k, "00" * 32)["verification_method"]
    registry = {"issuers": [ISSUER], "keys": {ISSUER: [
        {"verification_method": vm(old), "valid_until": iso(NOW - timedelta(days=1))},
        {"verification_method": vm(new), "valid_from": iso(NOW - timedelta(days=1))}]}}
    subject = sha256_hex(b"claims backdated issuance")
    month_ago = NOW - timedelta(days=30)
    p = eudi_with(subject, month_ago)
    backdated = signed(old, subject, month_ago)  # issued_at is signed, but it is a claim, not evidence
    v = p.check(backdated, network="eudi", trust_registry=registry)
    assert v["receipt"].error.startswith("proof_invalid: key not valid at")
    assert p.check(signed(new, subject, month_ago), network="eudi", trust_registry=registry)["valid"] is True


def test_ledger_judges_the_key_at_anchored_time():
    pytest.importorskip("web3")
    from eth_account import Account
    from plug.adapters.live import LiveAdapter
    from test_live_adapter import _FakeW3
    w3 = _FakeW3()
    p = Plug()
    p.register_adapter("sepolia", LiveAdapter(w3=w3))
    acct = Account.create()
    p.open("sepolia", {"scheme": "raw", "material": acct.key.hex()})
    r = p.prove(b"signed while the key was valid", "doc.sha256")
    anchored = datetime.fromtimestamp(w3.eth.get_block(r.data["block"])["timestamp"], timezone.utc)
    att = Attestation.from_receipt(r)
    revoked_later = {"issuers": [r.data["issuer"]], "keys": {r.data["issuer"]: [
        {"verification_method": acct.address, "valid_until": iso(anchored + timedelta(seconds=1))}]}}
    assert p.check(att, trust_registry=revoked_later)["valid"] is True, "valid when anchored, revoked since"
    revoked_before = {"issuers": [r.data["issuer"]], "keys": {r.data["issuer"]: [
        {"verification_method": acct.address, "valid_until": iso(anchored - timedelta(seconds=1))}]}}
    assert p.check(att, trust_registry=revoked_before)["receipt"].error.startswith("proof_invalid: key not valid at")


def test_malformed_registry_keys_are_rejected():
    subject = sha256_hex(b"x")
    p = eudi_with(subject)
    att = signed(suites.generate_key("ecdsa-p256"), subject)
    for keys in ({ISSUER: []}, {ISSUER: [{"vm": "x"}]}, {ISSUER: [{"verification_method": "x", "valid_from": "soon"}]},
                 ["nope"]):
        v = p.check(att, network="eudi", trust_registry={"issuers": [ISSUER], "keys": keys})
        assert v["valid"] is False and "trust registry keys" in (v["receipt"].error or ""), keys


def test_ledger_registry_keys_are_enforced():
    from plug.adapters.base import check_signature, resolve_trust_registry
    from plug.core import SPEC_VERSION, Receipt, StateRef, Status
    key = suites.generate_key("ecdsa-p256")
    vm = suites.sign("ecdsa-p256", key, "00" * 32)["verification_method"]
    revoked = {ISSUER: [{"verification_method": vm, "valid_until": iso(NOW - timedelta(days=1))}]}

    def query(record):
        return lambda ref: Receipt(SPEC_VERSION, "query", Status.OK, ref.network, ref, record)

    ref = StateRef("ledger", "registry-1", "asset")
    att = signed(key, sha256_hex(b"pid"))
    data = resolve_trust_registry(query({"issuers": [ISSUER], "keys": revoked}), ref, "eudi", ISSUER)
    assert data["trust_registry"]["keys"] == revoked
    assert check_signature(att, "eudi", data).error.startswith("proof_invalid: key not valid at")
    keys_only = resolve_trust_registry(query({"keys": revoked}), ref, "eudi", ISSUER)
    assert keys_only.status == Status.REJECTED and "issuers" in keys_only.error
    bad = resolve_trust_registry(query({"issuers": [ISSUER], "keys": {ISSUER: []}}), ref, "eudi", ISSUER)
    assert bad.status == Status.REJECTED and "trust registry keys" in bad.error
