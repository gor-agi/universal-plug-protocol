# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""MCP transport: prove, prove_batch, check, watch, and networks as Model Context Protocol tools.

The server is the harness. It holds every key; sessions are opened server-side and no tool
accepts credential material, so a model can request evidence but never sign it. Trust
registries are accepted inline or by name from a server-side allowlist, never as free URLs.

Run:  python -m plug.mcp_server --config plug-mcp.json   (stdio transport)
"""
from __future__ import annotations
import argparse
import json
import os
from typing import Any, Optional

from .core import Attestation, Plug, PlugError, Receipt, StateRef


def _ref_json(ref: Optional[StateRef]) -> Optional[dict]:
    return {"network": ref.network, "address": ref.address, "kind": ref.kind} if ref else None


def receipt_json(r: Receipt) -> dict:
    return {"spec_version": r.spec_version, "op": r.op, "status": r.status.value, "network": r.network,
            "state_ref": _ref_json(r.state_ref), "data": r.data, "error": r.error, "seq": r.seq}


def attestation_json(r: Receipt) -> dict:
    """A complete attestation from an attest receipt, ready to pass to check."""
    d = r.data
    out = {k: d[k] for k in ("subject_hash", "fact_type", "issuer", "issued_at", "hash_alg", "proof",
                             "inclusion") if d.get(k) is not None}
    out["anchor"] = _ref_json(r.state_ref)
    return out


def attestation_from_json(d: dict) -> Attestation:
    try:
        anchor = StateRef(**d["anchor"]) if d.get("anchor") else None
        return Attestation(subject_hash=d["subject_hash"], fact_type=d["fact_type"], issuer=d["issuer"],
                           issued_at=d.get("issued_at", ""), expires_at=d.get("expires_at"),
                           proof=dict(d.get("proof") or {}), meta=dict(d.get("meta") or {}),
                           disclosure=list(d.get("disclosure") or []), anchor=anchor,
                           hash_alg=d.get("hash_alg", "sha-256"), inclusion=d.get("inclusion"))
    except (KeyError, TypeError) as e:
        raise PlugError("proof_invalid", f"malformed attestation: {e}") from e


def build_server(plug: Plug, registries: Optional[dict[str, str]] = None, name: str = "universal-plug"):
    """An MCP server over an already configured Plug. registries: allowlisted name -> registry URL."""
    from mcp.server.mcpserver import MCPServer

    allowed = dict(registries or {})
    server = MCPServer(name, instructions=(
        "Verifiable evidence across networks. prove records a fact and returns an attestation; "
        "check verifies an attestation, a state reference, or a bridge receipt without trusting the issuer; "
        "watch subscribes to a state reference. Keys are held by this server."))

    def registry(value: Any):
        if value is None or isinstance(value, dict):
            return value
        if isinstance(value, str) and value in allowed:
            return allowed[value]
        raise PlugError("not_authorized", "trust_registry must be inline or one of: " + ", ".join(sorted(allowed)))

    def guarded(fn):
        try:
            return fn()
        except PlugError as e:
            return {"error": f"{e.code}: {e.message}", "retryable": e.retries}

    @server.tool(description="Record a fact. Returns the receipt and an attestation to pass to check.")
    def prove(fact: Any, fact_type: str, network: Optional[str] = None, meta: Optional[dict] = None) -> dict:
        def run():
            r = plug.prove(fact, fact_type, network, meta)
            return {"receipt": receipt_json(r), "attestation": attestation_json(r), "salt": r.data.get("salt")}
        return guarded(run)

    @server.tool(description="Record many facts under one anchor. Returns one attestation per fact.")
    def prove_batch(facts: list, fact_type: str, network: Optional[str] = None, meta: Optional[dict] = None) -> dict:
        def run():
            rs = plug.prove_batch(facts, fact_type, network, meta)
            return {"anchor": _ref_json(rs[0].state_ref), "status": rs[0].status.value,
                    "attestations": [attestation_json(r) for r in rs],
                    "salts": [r.data.get("salt") for r in rs]}
        return guarded(run)

    @server.tool(description="Verify an attestation, a state_ref, or a bridge receipt. Never trusts the issuer.")
    def check(attestation: Optional[dict] = None, state_ref: Optional[dict] = None,
              bridge_receipt: Optional[dict] = None, network: Optional[str] = None,
              trust_registry: Any = None) -> dict:
        def run():
            given = [x for x in (attestation, state_ref, bridge_receipt) if x is not None]
            if len(given) != 1:
                raise PlugError("unsupported_op", "pass exactly one of attestation, state_ref, bridge_receipt")
            if attestation is not None:
                target = attestation_from_json(attestation)
            elif state_ref is not None:
                target = StateRef(**state_ref)
            else:
                b = bridge_receipt
                target = Receipt(b["spec_version"], "bridge", b["status"], b["network"],
                                 StateRef(**b["state_ref"]) if b.get("state_ref") else None, b["data"])
            v = plug.check(target, network, registry(trust_registry))
            return {"valid": v["valid"], "receipt": receipt_json(v["receipt"])}
        return guarded(run)

    @server.tool(description="Subscribe to a state_ref. Returns a stream handle.")
    def watch(state_ref: dict, filter: Optional[list] = None) -> dict:
        return guarded(lambda: {"handle": plug.watch(StateRef(**state_ref), filter)})

    @server.tool(description="Registered networks, the active session subject, and allowlisted trust registries.")
    def networks() -> dict:
        s = plug.active()
        return {"networks": sorted(plug._adapters), "registries": sorted(allowed),
                "active": {"network": s.network, "subject": s.credential_subject} if s else None}

    return server


def plug_from_config(config: dict) -> tuple[Plug, dict]:
    """Plug from a JSON config. Secrets are named by environment variable, never written in the file:
    {"hash_alg": "sha-256", "commitment": "plain", "registries": {"eu": "https://..."},
     "networks": {"sepolia": {"adapter": "live", "rpc_url_env": "SEPOLIA_RPC_URL", "key_env": "SEPOLIA_PRIVATE_KEY"}}}
    """
    plug = Plug(hash_alg=config.get("hash_alg", "sha-256"), commitment=config.get("commitment", "plain"))
    for name, spec in (config.get("networks") or {}).items():
        kind = spec.get("adapter")
        if kind == "live":
            from .adapters.live import LiveAdapter
            plug.register_adapter(name, LiveAdapter(rpc_url=os.environ[spec["rpc_url_env"]]))
            plug.open(name, {"scheme": "raw", "material": os.environ[spec["key_env"]]})
        elif kind == "chainmaker":
            from .adapters.chainmaker import ChainMakerAdapter
            with open(spec["sdk_config"]) as f:
                plug.register_adapter(name, ChainMakerAdapter(json.load(f), contract=spec.get("contract", "upp_anchor")))
            plug.open(name, {"scheme": "x509", "material": spec["member"]})
        elif kind in ("oracle", "eudi", "stub"):
            from .adapters import EudiAdapter, OracleAdapter, StubAdapter
            cls = {"oracle": OracleAdapter, "eudi": EudiAdapter, "stub": StubAdapter}[kind]
            plug.register_adapter(name, cls(**(spec.get("options") or {})))
        else:
            raise ValueError(f"unknown adapter {kind!r} for network {name!r}")
    return plug, dict(config.get("registries") or {})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Universal Plug Protocol MCP server (stdio)")
    parser.add_argument("--config", required=True, help="JSON config; secrets come from environment variables")
    args = parser.parse_args(argv)
    with open(args.config) as f:
        plug, registries = plug_from_config(json.load(f))
    build_server(plug, registries).run("stdio")


if __name__ == "__main__":
    main()
