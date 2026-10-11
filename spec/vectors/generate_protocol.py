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
from itertools import count
from unittest import mock

from plug import Plug, suites
from plug.adapters import StubAdapter
from plug.core import (
    StateRef, batch_commitment, bridge_commitment, canonical, commitment, digest, fact_bytes,
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


def _proofs() -> list:
    keys = {"ed25519": _seed("key:ed25519"), "ecdsa-p256": _seed("key:ecdsa-p256")}
    other = {"ed25519": _seed("key:ed25519:other"), "ecdsa-p256": _seed("key:ecdsa-p256:other")}
    subject = digest(canonical({"temp": 21.5, "unit": "C"}).encode(), "sha-256")
    flip = lambda h: h[:-1] + ("0" if h[-1] != "0" else "1")
    out = []
    for alg in keys:
        proof = suites.sign(alg, keys[alg], subject)
        other_method = suites.sign(alg, other[alg], subject)["verification_method"]
        cross = "ecdsa-p256" if alg == "ed25519" else "ed25519"
        cases = [
            ("valid", subject, proof["verification_method"], proof),
            ("issuer DID with fragment", subject, proof["verification_method"] + "#key-1", proof),
            ("tampered subject", flip(subject), proof["verification_method"], proof),
            ("tampered signature", subject, proof["verification_method"], dict(proof, sig=flip(proof["sig"]))),
            ("issuer names another key", subject, other_method, proof),
            ("alg does not match did:key type", subject, proof["verification_method"], dict(proof, alg=cross)),
            ("subject not 32 bytes", subject[:-2], proof["verification_method"], proof),
        ]
        for case, subj, issuer, pr in cases:
            ok, detail = suites.verify(subj, pr)
            out.append({"case": case, "subject_hash": subj, "issuer": issuer, "proof": pr,
                        "valid": bool(ok and suites.binds(issuer, detail))})
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
            "inclusion_negative": _inclusion_negative(batches), "proofs": _proofs(), "reserved": _reserved()}


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")
