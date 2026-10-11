# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""MCP transport over a real MCP client session (in memory), backed by a local ledger."""
import asyncio
import json

import pytest

pytest.importorskip("mcp")
pytest.importorskip("cryptography")

from mcp.client.client import Client

from upp import ANY, LocalLedger, PlugError, Receipt
from upp.core import Plug
from upp.mcp_server import RESERVED_FACT_TYPES, build_server, plug_from_config

NET = "evidence"


def local_plug(ledger=None, **kw):
    p = Plug(**kw)
    p.register(NET, ledger or LocalLedger())
    p.open(NET, {})
    return p


def server():
    p = local_plug(trust={NET: ANY})
    return build_server(p, registries={"partners": "https://registry.example/partners.json"}, fact_types=["doc.sha256"])


def result(r):
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)


async def call(client, name, **args):
    r = await client.call_tool(name, args)
    assert not r.is_error, r.content
    return result(r)


def run(coro):
    return asyncio.run(coro)


def test_tools_are_prove_check_and_networks_and_expose_no_key_material():
    async def go():
        async with Client(server()) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert set(tools) == {"prove", "prove_batch", "check", "networks"}
            assert set(tools["check"].input_schema["properties"]) == {"attestation", "network", "trust_registry"}
            schemas = json.dumps([t.input_schema for t in tools.values()]).lower()
            assert not any(word in schemas for word in ("material", "private", "secret", "password"))
            nets = await call(client, "networks")
            assert nets["networks"] == [NET] and nets["active"]["subject"].startswith("did:key:z6Mk")
            assert nets["reserved_fact_types"] == list(RESERVED_FACT_TYPES)
            assert nets["registries"] == ["partners"] and nets["fact_types"] == ["doc.sha256"]
    run(go())


def test_prove_then_check_round_trip_and_tamper():
    async def go():
        async with Client(server()) as client:
            out = await call(client, "prove", fact={"invoice": "INV-7", "amount": "1200.00"}, fact_type="doc.sha256")
            assert out["receipt"]["status"] == "ok" and out["salt"] is None
            assert set(out["receipt"]) == {"op", "status", "network", "state_ref", "data", "error"}
            assert set(out["receipt"]["state_ref"]) == {"network", "address"}
            att = out["attestation"]
            assert att["anchor"] == out["receipt"]["state_ref"]
            v = await call(client, "check", attestation=att)
            assert v["valid"] is True, v
            assert v["receipt"]["status"] == "ok" and set(v["receipt"]) == set(out["receipt"])
            for field, value in (("fact_type", "agent.action"), ("meta", {"model_family": "trusted-family"}),
                                 ("issued_at", "2020-01-01T00:00:00Z"), ("subject_hash", "00" * 32)):
                v = await call(client, "check", attestation=dict(att, **{field: value}))
                assert v["valid"] is False, f"relabeled {field} must not verify"
    run(go())


def test_batch_over_mcp_and_registry_allowlist():
    async def go():
        async with Client(server()) as client:
            out = await call(client, "prove_batch", facts=["a", "b", "c"], fact_type="doc.sha256")
            assert len(out["attestations"]) == 3
            for att in out["attestations"]:
                assert (await call(client, "check", attestation=att))["valid"] is True
            ssrf = await call(client, "check", attestation=out["attestations"][0],
                              trust_registry="http://169.254.169.254/latest/meta-data")
            assert ssrf.get("error", "").startswith("not_authorized")
            r = await client.call_tool("check", {"attestation": out["attestations"][0],
                                                 "trust_registry": {"issuers": [out["attestations"][0]["issuer"]]}})
            # the model names registries; it cannot write its own (refused by the schema or by the allowlist)
            assert r.is_error or result(r)["error"].startswith("not_authorized"), r.content
    run(go())


def test_model_cannot_choose_oversight_fact_types_or_its_own_identity():
    async def go():
        seen = []

        class Recording(Plug):
            def prove(self, fact, fact_type, network=None, meta=None):
                seen.append(dict(meta or {}))
                return super().prove(fact, fact_type, network, meta)

        p = Recording()
        p.register(NET, LocalLedger())
        p.open(NET, {})
        stamped = build_server(p, model={"model_family": "family-a", "model_id": "m-7"}, fact_types=ANY)
        async with Client(stamped) as client:
            for ft in ("agent.action", "Agent Review", "control.resume", "incident.report", "upp.batch",
                       "upp.statement", "grant", "grant.revoke"):
                out = await call(client, "prove", fact="x", fact_type=ft)
                assert out.get("error", "").startswith("not_authorized"), ft
                out = await call(client, "prove_batch", facts=["x"], fact_type=ft)
                assert out.get("error", "").startswith("not_authorized"), ft
            out = await call(client, "prove", fact="x", fact_type="doc.sha256",
                             meta={"model_family": "family-b", "model_id": "self-chosen", "_seq": 99, "note": "kept"})
            assert out["receipt"]["status"] == "ok"
            assert out["attestation"]["meta"] == {"model_family": "family-a", "model_id": "m-7", "note": "kept"}
            batch = await call(client, "prove_batch", facts=["a", "b"], fact_type="doc.sha256",
                               meta={"model_family": "family-b"})
            assert all(a["meta"] == {"model_family": "family-a", "model_id": "m-7"} for a in batch["attestations"])
            out = await call(client, "prove", fact={"upp.statement": {}}, fact_type="doc.sha256")
            assert out["error"].startswith("unsupported_op"), "the reserved upp.* fact domain is never proven"
            assert (await call(client, "networks"))["fact_types"] == ANY
        assert seen[0] == {"model_family": "family-a", "model_id": "m-7", "note": "kept"}
        assert len(seen) == 2, "reserved fact types are refused before anything is proven"
        allow = build_server(p, fact_types=["agent.action", "control.halt", "upp.batch"])
        async with Client(allow) as client:
            assert (await call(client, "prove", fact="y", fact_type="agent.action"))["receipt"]["status"] == "ok"
            assert (await call(client, "prove", fact="z", fact_type="control.halt"))["receipt"]["status"] == "ok"
            assert (await call(client, "prove", fact="y", fact_type="doc.sha256"))["error"].startswith("not_authorized")
            out = await call(client, "prove", fact="y", fact_type="upp.batch")
            assert out["error"] == "not_authorized: fact type upp.batch is reserved", "upp.* is never allowlisted"
            assert (await call(client, "networks"))["fact_types"] == ["agent.action", "control.halt", "upp.batch"]
    run(go())


class Failing(LocalLedger):
    """A ledger whose upstream fails the way remote nodes do."""

    def __init__(self, error):
        super().__init__()
        self.error = error

    def verify(self, att, network, trust_registry=None) -> Receipt:
        raise self.error

    def attest(self, network, att) -> Receipt:
        raise self.error


def test_upstream_errors_never_reveal_the_rpc_url():
    secret = "https://sepolia.example/v3/SUPERSECRETAPIKEY123"
    p = local_plug(Failing(PlugError("not_found", f"429 Client Error: Too Many Requests for url: {secret}")),
                   trust={NET: ANY})
    att = {"subject_hash": "ab" * 32, "fact_type": "doc.sha256", "issuer": p.active().subject,
           "issued_at": "2026-10-11T00:00:00Z", "proof": {}, "anchor": {"network": NET, "address": "local:" + "ab" * 32}}

    async def go():
        async with Client(build_server(p, fact_types=["doc.sha256"])) as client:
            for out in (await call(client, "check", attestation=att),
                        await call(client, "prove", fact="x", fact_type="doc.sha256")):
                assert "SUPERSECRETAPIKEY123" not in json.dumps(out) and out["error"].startswith("not_found"), out
                assert "<url>" in out["error"] and out["retryable"] is False
    run(go())


def test_unexpected_failures_return_a_generic_error():
    p = local_plug(Failing(ValueError("node exploded at http://10.0.0.5:8545/?key=SECRET")))

    async def go():
        async with Client(build_server(p, fact_types=["doc.sha256"])) as client:
            out = result(await client.call_tool("prove", {"fact": "x", "fact_type": "doc.sha256"}))
            assert out == {"error": "operation failed", "retryable": False}
    run(go())


def test_malformed_attestations_and_unknown_networks_are_errors_not_crashes():
    async def go():
        async with Client(server()) as client:
            out = await call(client, "check", attestation={"fact_type": "doc.sha256"})
            assert out["error"].startswith("proof_invalid: malformed attestation")
            att = (await call(client, "prove", fact="x", fact_type="doc.sha256"))["attestation"]
            out = await call(client, "check", attestation=att, network="nowhere")
            assert out["error"].startswith("not_found")
            out = await call(client, "prove", fact="x", fact_type="doc.sha256", network="nowhere")
            assert out["error"].startswith("auth_failed"), "proving needs an open session on the network"
    run(go())


def test_receipts_returned_to_the_model_carry_no_registry_url_or_host():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from upp.mcp_server import _redact

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            raw = json.dumps({"issuers": [self.server.issuer]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    p = local_plug()
    httpd.issuer = p.active().subject
    secret_url = f"http://127.0.0.1:{httpd.server_port}/partners.json?token=s3cr3t"

    async def go():
        async with Client(build_server(p, registries={"partners": secret_url}, fact_types=["doc.sha256"])) as client:
            att = (await call(client, "prove", fact="x", fact_type="doc.sha256"))["attestation"]
            out = await call(client, "check", attestation=att, trust_registry="partners")
            assert out["valid"] is True, out
            assert (await call(client, "check", attestation=att))["valid"] is False, "no operator policy: closed"
            text = json.dumps(out)
            assert "s3cr3t" not in text and "127.0.0.1" not in text
    try:
        run(go())
    finally:
        httpd.shutdown()
    assert "10.0.0.5" not in _redact("unavailable: failed to connect to all addresses; ipv4:10.0.0.5:12301")
    assert "10.0.0.5" not in _redact("connect to 10.0.0.5:12301 refused")


def test_batch_and_fact_size_limits():
    p = local_plug()

    async def go():
        async with Client(build_server(p, max_batch=3, max_fact_bytes=16, fact_types=["doc.sha256"])) as client:
            for name, args, error in (
                    ("prove_batch", {"facts": ["a"] * 4, "fact_type": "doc.sha256"}, "at most 3 facts"),
                    ("prove", {"fact": "x" * 17, "fact_type": "doc.sha256"}, "at most 16 bytes"),
                    ("prove", {"fact": 2 ** 60, "fact_type": "doc.sha256"}, "not I-JSON")):
                out = result(await client.call_tool(name, args))
                assert error in out["error"] and out["retryable"] is False, out
            assert (await call(client, "prove_batch", facts=["a"] * 3, fact_type="doc.sha256"))["status"] == "ok"
    run(go())


def test_mcp_is_closed_until_the_operator_grants_fact_types_and_bounded_by_rate():
    p = local_plug(trust={NET: ANY})

    async def go():
        async with Client(build_server(p)) as client:
            out = await call(client, "prove", fact="x", fact_type="doc.sha256")
            assert out["error"] == "not_authorized: this server allows no fact types (closed by default)"
            assert (await call(client, "networks"))["fact_types"] is None
        async with Client(build_server(p, fact_types=["doc.sha256"], rate=(3, 3600))) as client:
            results = [await call(client, "networks") for _ in range(4)]
            assert "error" not in results[2] and results[3]["error"].startswith("rate_limited")
            assert results[3]["retryable"] is True
    run(go())



def test_plug_from_config_for_a_local_ledger(tmp_path, monkeypatch):
    from upp import suites
    from upp.mcp_server import attestation_from_json
    key = suites.generate_key("ed25519")
    issuer = suites.KeySigner("ed25519", key).verification_method
    monkeypatch.setenv("UPP_TEST_KEY", key)
    log = tmp_path / "evidence.jsonl"
    config = {"trust": {NET: {"issuers": [issuer]}}, "registries": {"partners": {"issuers": [issuer]}},
              "hosts": ["registry.example"], "fact_types": ["doc.sha256"], "model": {"model_family": "family-a"},
              "networks": {NET: {"ledger": "local", "path": str(log), "key_env": "UPP_TEST_KEY"},
                           "scratch": {"ledger": "local"}}}
    p, registries = plug_from_config(json.loads(json.dumps(config)))
    assert registries == {"partners": {"issuers": [issuer]}}
    assert sorted(p._ledgers) == [NET, "scratch"] and p.active().network == "scratch"
    assert p.active().subject != issuer, "a network without key_env signs with a fresh key"

    async def go():
        async with Client(build_server(p, registries, fact_types=config["fact_types"], model=config["model"])) as client:
            out = await call(client, "prove", fact="anchored to a file", fact_type="doc.sha256", network=NET)
            assert out.get("error", "").startswith("auth_failed"), "proving needs the session open on that network"
            for sid, s in list(p._sessions.items()):
                if s.network == NET:
                    p.use(sid)
            out = await call(client, "prove", fact="anchored to a file", fact_type="doc.sha256")
            assert out["receipt"]["status"] == "ok" and out["attestation"]["issuer"] == issuer
            assert out["attestation"]["meta"] == {"model_family": "family-a"}
            assert (await call(client, "check", attestation=out["attestation"], trust_registry="partners"))["valid"]
            return out["attestation"]
    att = run(go())
    assert log.read_text().count("\n") == 1
    reloaded, _ = plug_from_config(json.loads(json.dumps(config)))
    assert reloaded.check(attestation_from_json(att), NET)["valid"] is True, "the JSONL log survives a restart"
    with pytest.raises(ValueError):
        plug_from_config({"networks": {"x": {"ledger": "oracle"}}})
