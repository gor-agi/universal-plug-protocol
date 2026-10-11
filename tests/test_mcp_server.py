# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""MCP transport over a real MCP client session (in memory), backed by the Ethereum adapter on an in-memory chain."""
import asyncio
import json

import pytest

pytest.importorskip("mcp")
pytest.importorskip("web3")

from eth_account import Account
from mcp.client.client import Client

from plug.adapters.live import LiveAdapter
from plug.core import Plug
from plug.mcp_server import build_server
from test_live_adapter import _FakeW3


def server():
    p = Plug()
    p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
    p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})
    return build_server(p, registries={"partners": "https://registry.example/partners.json"})


async def call(client, name, **args):
    r = await client.call_tool(name, args)
    assert not r.is_error, r.content
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)


def run(coro):
    return asyncio.run(coro)


def test_tools_are_the_three_verbs_and_expose_no_key_material():
    async def go():
        async with Client(server()) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert set(tools) == {"prove", "prove_batch", "check", "watch", "networks"}
            schemas = json.dumps([t.input_schema for t in tools.values()]).lower()
            assert not any(word in schemas for word in ("material", "private", "secret", "password"))
            nets = await call(client, "networks")
            assert nets["networks"] == ["sepolia"] and nets["active"]["subject"].startswith("did:plug:eip155:")
    run(go())


def test_prove_then_check_round_trip_and_tamper():
    async def go():
        async with Client(server()) as client:
            out = await call(client, "prove", fact={"invoice": "INV-7", "amount": "1200.00"}, fact_type="doc.sha256")
            assert out["receipt"]["status"] == "ok"
            att = out["attestation"]
            v = await call(client, "check", attestation=att)
            assert v["valid"] is True, v
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
            inline = await call(client, "check", attestation=out["attestations"][0],
                                trust_registry={"issuers": [out["attestations"][0]["issuer"]]})
            assert inline["valid"] is True
    run(go())


def test_model_cannot_choose_oversight_fact_types_or_its_own_identity():
    async def go():
        seen = []

        class Recording(Plug):
            def prove(self, fact, fact_type, network=None, meta=None):
                seen.append(dict(meta or {}))
                return super().prove(fact, fact_type, network, meta)

        p = Recording()
        p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
        p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})
        stamped = build_server(p, model={"model_family": "family-a", "model_id": "m-7"})
        async with Client(stamped) as client:
            for ft in ("agent.action", "agent.review", "control.resume", "incident.report", "plug.batch"):
                out = await call(client, "prove", fact="x", fact_type=ft)
                assert out.get("error", "").startswith("not_authorized"), ft
            out = await call(client, "prove", fact="x", fact_type="doc.sha256",
                             meta={"model_family": "family-b", "_seq": 99, "note": "kept"})
            assert out["receipt"]["status"] == "ok"
        assert seen == [{"model_family": "family-a", "model_id": "m-7", "note": "kept"}]
        allow = build_server(p, fact_types=["agent.action"])
        async with Client(allow) as client:
            assert (await call(client, "prove", fact="y", fact_type="agent.action"))["receipt"]["status"] == "ok"
            assert (await call(client, "prove", fact="y", fact_type="doc.sha256"))["error"].startswith("not_authorized")
            assert (await call(client, "networks"))["fact_types"] == ["agent.action"]
    run(go())


def test_model_cannot_point_the_server_at_a_url_through_meta():
    async def go():
        async with Client(server()) as client:
            r = await client.call_tool("prove", {"fact": "x", "fact_type": "doc.sha256",
                                                 "meta": {"status": {"status_list": {"idx": 0,
                                                          "uri": "http://169.254.169.254/latest/meta-data"}}}})
            out = r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)
            assert out["error"] == "not_authorized: meta status is set by the operator, not the model"
    run(go())


def test_upstream_errors_never_reveal_the_rpc_url():
    secret = "https://sepolia.example/v3/SUPERSECRETAPIKEY123"

    class Throttled(_FakeW3):
        def __init__(self):
            super().__init__()

            def refuse(tx_hash):
                raise RuntimeError(f"429 Client Error: Too Many Requests for url: {secret}")
            self.eth.get_transaction_receipt = refuse
            self.eth.get_transaction = refuse

    p = Plug()
    p.register_adapter("sepolia", LiveAdapter(w3=Throttled()))
    p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})

    async def go():
        async with Client(build_server(p)) as client:
            out = await call(client, "check", state_ref={"network": "sepolia", "address": "live:0x" + "ab" * 32,
                                                         "kind": "event"})
            assert "SUPERSECRETAPIKEY123" not in json.dumps(out) and out["error"].startswith("not_found")
    run(go())


def test_unexpected_failures_return_a_generic_error():
    class Broken(_FakeW3):
        def __init__(self):
            super().__init__()

            def boom(*a, **k):
                raise ValueError("node exploded at http://10.0.0.5:8545/?key=SECRET")
            self.eth.estimate_gas = boom

    p = Plug()
    p.register_adapter("sepolia", LiveAdapter(w3=Broken()))
    p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})

    async def go():
        async with Client(build_server(p)) as client:
            r = await client.call_tool("prove", {"fact": "x", "fact_type": "doc.sha256"})
            out = r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)
            assert out == {"error": "operation failed", "retryable": False}
    run(go())


def test_receipts_returned_to_the_model_carry_no_registry_url_or_host():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from plug.mcp_server import _redact

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
    p = Plug()
    p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
    p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})
    httpd.issuer = p.active().credential_subject
    secret_url = f"http://127.0.0.1:{httpd.server_port}/partners.json?token=s3cr3t"

    async def go():
        async with Client(build_server(p, registries={"partners": secret_url})) as client:
            att = (await call(client, "prove", fact="x", fact_type="doc.sha256"))["attestation"]
            out = await call(client, "check", attestation=att, trust_registry="partners")
            assert out["valid"] is True, out
            text = json.dumps(out)
            assert "s3cr3t" not in text and "127.0.0.1" not in text
    try:
        run(go())
    finally:
        httpd.shutdown()
    assert "10.0.0.5" not in _redact("unavailable: failed to connect to all addresses; ipv4:10.0.0.5:12301")
    assert "10.0.0.5" not in _redact("connect to 10.0.0.5:12301 refused")


def test_batch_and_fact_size_limits():
    p = Plug()
    p.register_adapter("sepolia", LiveAdapter(w3=_FakeW3()))
    p.open("sepolia", {"scheme": "raw", "material": Account.create().key.hex()})

    async def go():
        async with Client(build_server(p, max_batch=3, max_fact_bytes=16)) as client:
            for name, args, error in (
                    ("prove_batch", {"facts": ["a"] * 4, "fact_type": "doc.sha256"}, "at most 3 facts"),
                    ("prove", {"fact": "x" * 17, "fact_type": "doc.sha256"}, "at most 16 bytes"),
                    ("prove", {"fact": 2 ** 60, "fact_type": "doc.sha256"}, "not I-JSON")):
                r = await client.call_tool(name, args)
                out = r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)
                assert error in out["error"] and out["retryable"] is False, out
            assert (await call(client, "prove_batch", facts=["a"] * 3, fact_type="doc.sha256"))["status"] == "ok"
    run(go())

