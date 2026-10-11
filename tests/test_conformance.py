# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Conformance vectors: any Plug implementation, in any language, must reproduce these."""
import json
import os
import shutil
import struct
import subprocess

import pytest

from plug.core import canonical

VECTORS = os.path.join(os.path.dirname(__file__), "..", "spec", "vectors")


def load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


def from_bits(hex_bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(hex_bits))[0]


def test_jcs_numbers_match_ecmascript():
    for v in load("jcs.json")["numbers"]:
        assert canonical(from_bits(v["bits"])) == v["canonical"], v["bits"]


def test_jcs_objects_and_digests():
    from plug.suites import digest
    for v in load("jcs.json")["objects"]:
        c = canonical(json.loads(v["input"]))
        assert c == v["canonical"], v["input"]
        for alg in ("sha-256", "sha3-256", "sm3"):
            assert digest(c.encode("utf-8"), alg) == v[alg], (alg, v["input"])


def test_prove_subject_hash_matches_vectors_under_each_profile():
    from plug.adapters.stub import StubAdapter
    from plug.core import Plug
    for alg in ("sha-256", "sha3-256", "sm3"):
        p = Plug(hash_alg=alg)
        p.register_adapter("t", StubAdapter())
        for v in load("jcs.json")["objects"]:
            fact = json.loads(v["input"])
            if isinstance(fact, (dict, list)):
                r = p.prove(fact, "doc.sha256", network="t")
                assert r.data["subject_hash"] == v[alg] and r.data["hash_alg"] == alg


def test_jcs_rejects_what_ijson_forbids():
    for bad in (float("nan"), float("inf"), 2**53 + 1, "\ud800", {1: "x"}):
        with pytest.raises((ValueError, TypeError)):
            canonical(bad)
    assert canonical(2**53) == "9007199254740992"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_jcs_random_doubles_match_node():
    script = ("const c=require('crypto');const out=[];const v=new DataView(new ArrayBuffer(8));"
              "for(let i=0;i<20000;i++){c.randomFillSync(new Uint8Array(v.buffer));const d=v.getFloat64(0);"
              "if(Number.isFinite(d))out.push([Buffer.from(v.buffer).toString('hex'),JSON.stringify(d)]);}"
              "console.log(JSON.stringify(out))")
    pairs = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout)
    mismatches = [(b, s, canonical(from_bits(b))) for b, s in pairs if canonical(from_bits(b)) != s]
    assert not mismatches, mismatches[:5]
    assert len(pairs) > 19000


def test_protocol_vectors_reproduce():
    pytest.importorskip("Crypto", reason="protocol vectors sign with Ed25519 and P-256")
    import importlib.util
    spec = importlib.util.spec_from_file_location("generate_protocol", os.path.join(VECTORS, "generate_protocol.py"))
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert gen.build() == load("protocol.json"), "regenerate: python spec/vectors/generate_protocol.py > spec/vectors/protocol.json"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_protocol_vectors_verify_in_node():
    out = subprocess.run(["node", os.path.join(VECTORS, "verify_protocol.mjs")], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
