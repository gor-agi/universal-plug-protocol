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
            att["subject_hash"] = "00" * 32
            v = await call(client, "check", attestation=att)
            assert v["valid"] is False
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
