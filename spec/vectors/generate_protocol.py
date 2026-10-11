# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Regenerates spec/vectors/protocol.json from this implementation's prove_batch and signature suites.

verify_protocol.mjs re-derives and checks every entry independently in Node.
Usage: python spec/vectors/generate_protocol.py > spec/vectors/protocol.json
"""
from __future__ import annotations
import hashlib
import json
import sys
from dataclasses import replace
from itertools import count
from unittest import mock

from plug import Plug, suites
from plug.adapters import StubAdapter
from plug.core import (
    Attestation, StateRef, batch_commitment, bridge_commitment, canonical, commitment, digest, fact_bytes,
    statement, statement_hash,
)

HASH_ALGS = ("sha-256", "sha3-256", "sm3")


def _seed(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _encode(fact) -> dict:
    if isinstance(fact, (dict, list)):
        return {"json": fact}
    if isinstance(fact, bytes):
        return {"hex": fact.hex()}
    return {"text": fact}


def _salted() -> list:
    facts = [{"name": "Ada Lovelace", "dob": "1815-12-10"}, "alice@example.org", b"\x00\x01\xff", [1, "two", None]]
    out = []
    for alg in HASH_ALGS:
        for i, fact in enumerate(facts):
            salt = _seed(f"salt:{alg}:{i}")
            out.append({"fact": _encode(fact), "salt": salt, "hash_alg": alg,
                        "plain": digest(fact_bytes(fact), alg), "subject_hash": commitment(fact, salt, alg)})
    return out


def _bridge() -> list:
    refs = [StateRef("eip155:11155111", "0x" + "ab" * 32, "event"),
            StateRef("chainmaker:chain1", "tx-0001", "event"),
            StateRef("eudi", "eudi:0x" + "cd" * 32, "ownership")]
    return [{"source": {"network": r.network, "address": r.address, "kind": r.kind}, "hash_alg": alg,
             "commitment": bridge_commitment(r, alg)} for alg in HASH_ALGS for r in refs]


def _batches() -> list:
    sets = [["only"], ["a", "b", "c"], [{"temp": 21.5}, {"temp": 22.0}, "x", b"\x01", [3]],
            [f"reading-{i}" for i in range(8)], [f"r{i}" for i in range(13)]]
    out = []
    for alg in HASH_ALGS:
        for mode in ("plain", "salted"):
            for facts in sets:
                p = Plug(hash_alg=alg, commitment=mode)
                p.register_adapter("testnet", StubAdapter())
                n = count()
                deterministic = lambda k: hashlib.sha256(f"{alg}:{mode}:{len(facts)}:{next(n)}".encode()).digest()[:k]
                with mock.patch("plug.core.secrets.token_bytes", deterministic):
                    receipts = p.prove_batch(facts, "doc.sha256", "testnet")
                root = receipts[0].data["batch_root"]
                out.append({
                    "hash_alg": alg, "commitment": mode, "facts": [_encode(f) for f in facts],
                    "salts": [r.data.get("salt") for r in receipts] if mode == "salted" else None,
                    "subjects": [r.data["subject_hash"] for r in receipts], "root": root, "size": len(facts),
                    "batch_commitment": receipts[0].data["batch_commitment"],
                    "inclusion": [{"index": r.data["inclusion"]["index"], "path": r.data["inclusion"]["path"]}
                                  for r in receipts]})
                assert out[-1]["batch_commitment"] == batch_commitment(root, len(facts), alg)
    return out


def _inclusion_negative(batches: list) -> list:
    b = next(x for x in batches if x["size"] == 5 and x["hash_alg"] == "sha-256" and x["commitment"] == "plain")
    base = {"hash_alg": b["hash_alg"], "root": b["root"], "size": b["size"]}
    inc = b["inclusion"][2]
    flipped = ("0" if inc["path"][0][0] != "0" else "1") + inc["path"][0][1:]
    return [
        dict(base, case="wrong subject", subject_hash=b["subjects"][1], **inc),
        dict(base, case="tampered path", subject_hash=b["subjects"][2], index=inc["index"], path=[flipped] + inc["path"][1:]),
        dict(base, case="wrong index", subject_hash=b["subjects"][2], index=3, path=inc["path"]),
        dict(base, case="index beyond size", subject_hash=b["subjects"][2], index=5, path=inc["path"]),
        dict(base, case="path too short", subject_hash=b["subjects"][2], index=inc["index"], path=inc["path"][:-1]),
        dict(base, case="path too long", subject_hash=b["subjects"][2], index=inc["index"], path=inc["path"] + [b["root"]]),
        dict(base, case="leaf presented as root", subject_hash=b["root"], index=0, path=[], size=1),
    ]


def _att_json(att: Attestation) -> dict:
    return {"subject_hash": att.subject_hash, "hash_alg": att.hash_alg, "fact_type": att.fact_type,
            "issuer": att.issuer, "issued_at": att.issued_at, "expires_at": att.expires_at,
            "role": att.role.value if att.role else None, "meta": att.meta, "disclosure": att.disclosure}


def _statements() -> list:
    subject = digest(b"statement vectors", "sha-256")
    atts = [
        Attestation(subject, "doc.sha256", "did:plug:eip155:1:0x" + "11" * 20, "2026-10-11T00:00:00Z"),
        Attestation(subject, "Agent Action", "did:key:z6MkExample", "2026-10-11T12:00:00Z",
                    expires_at="2027-01-01T00:00:00Z", role="execution",
                    meta={"model_family": " Family-A ", "model_id": "m-7", "tool": "email.send", "n": 3,
                          "ratio": 0.5, "ok": True, "none": None, "nested": {"b": [1, 2], "a": "ü€"},
                          "_seq": 9, "_internal": "excluded"}),
        Attestation(subject, "identity.pid", "did:web:issuer.example", "2026-10-11T00:00:00+02:00",
                    disclosure=[{"salt": "aa" * 16, "hash": "bb" * 32}], role="identity"),
    ]
    out = []
    for alg in HASH_ALGS:
        for att in atts:
            a = Attestation(digest(b"statement vectors", alg), att.fact_type, att.issuer, att.issued_at,
                            expires_at=att.expires_at, role=att.role, meta=dict(att.meta),
                            disclosure=list(att.disclosure), hash_alg=alg)
            out.append({"attestation": _att_json(a), "statement": canonical(statement(a)),
                        "statement_hash": statement_hash(a)})
    return out


def _proofs() -> list:
    keys = {"ed25519": _seed("key:ed25519"), "ecdsa-p256": _seed("key:ecdsa-p256")}
    other = {"ed25519": _seed("key:ed25519:other"), "ecdsa-p256": _seed("key:ecdsa-p256:other")}
    subject = digest(canonical({"temp": 21.5, "unit": "C"}).encode(), "sha-256")
    flip = lambda h: h[:-1] + ("0" if h[-1] != "0" else "1")
    out = []
    for alg in keys:
        did = suites.sign(alg, keys[alg], "00" * 32)["verification_method"]
        other_did = suites.sign(alg, other[alg], "00" * 32)["verification_method"]
        base = Attestation(subject, "control.halt", did, "2026-10-11T00:00:00Z",
                           meta={"actor": "did:plug:agents:a1", "model_family": "family-a"})
        proof = suites.sign(alg, keys[alg], statement_hash(base))
        cross = "ecdsa-p256" if alg == "ed25519" else "ed25519"
        other_issuer = replace(base, issuer=other_did)
        cases = [
            ("valid", base, proof),
            ("issuer DID with fragment", replace(base, issuer=did + "#key-1"),
             suites.sign(alg, keys[alg], statement_hash(replace(base, issuer=did + "#key-1")))),
            ("relabeled fact_type", replace(base, fact_type="control.resume"), proof),
            ("relabeled meta", replace(base, meta=dict(base.meta, model_family="family-b")), proof),
            ("relabeled issued_at", replace(base, issued_at="2020-01-01T00:00:00Z"), proof),
            ("added expires_at", replace(base, expires_at="2999-01-01T00:00:00Z"), proof),
            ("added role", replace(base, role="execution"), proof),
            ("tampered subject", replace(base, subject_hash=flip(subject)), proof),
            ("tampered signature", base, dict(proof, sig=flip(proof["sig"]))),
            ("issuer names another key", other_issuer, suites.sign(alg, keys[alg], statement_hash(other_issuer))),
            ("alg does not match did:key type", base, dict(proof, alg=cross)),
            ("signed the bare subject hash", base, suites.sign(alg, keys[alg], subject)),
        ]
        for case, att, pr in cases:
            ok, detail = suites.verify(statement_hash(att), pr)
            out.append({"case": case, "attestation": _att_json(att), "proof": pr,
                        "valid": bool(ok and suites.binds(att.issuer, detail))})
    return out


def _reserved() -> list:
    facts = [{"plug.batch": {"root": "00" * 32, "size": 1}}, {"plug.bridge": {}}, {"plugin": 1},
             '{"plug.x":1}', ' {"plug.batch":1}', {"z": 1, "plug.batch": 2}]
    out = []
    p = Plug()
    p.register_adapter("testnet", StubAdapter())
    for fact in facts:
        try:
            p.prove(fact, "doc.sha256", "testnet")
            refused = False
        except Exception as e:
            refused = getattr(e, "code", None) == "unsupported_op"
        out.append({"fact": _encode(fact), "refused": refused})
    return out


def build() -> dict:
    batches = _batches()
    return {"description": "Protocol vectors produced by the Python reference; verify_protocol.mjs re-derives them in Node.",
            "salted": _salted(), "bridge": _bridge(), "batches": batches,
            "inclusion_negative": _inclusion_negative(batches), "statements": _statements(), "proofs": _proofs(),
            "reserved": _reserved()}


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")
