# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""MCP server: prove, prove_batch, check, and networks as Model Context Protocol tools.

The server holds every key and opens every session, so a model can ask for evidence but never sign as anyone.
Closed by default: no fact types, no trust registries, and no remote hosts unless the operator's config grants them.

Run:  python -m upp.mcp_server --config upp-mcp.json   (stdio)
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import re
import time
from typing import Any, Optional

from .core import ANY, Attestation, Plug, PlugError, Receipt, StateRef, canon_fact_type, fact_bytes

# Evidence about the model itself, grants, and the protocol's own domain: a model never has these signed for it
# under ANY; agent./control./incident./grant types can be allowlisted by name, upp.* never.
RESERVED_FACT_TYPES = ("agent.", "control.", "incident.", "grant", "upp.")
_MODEL_META = ("model_family", "model_id")
_LOG = logging.getLogger("upp.mcp_server")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]+"
                  r"|\bipv[46]:[^\s'\",]+"
                  r"|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")


def _redact(value):
    """What reaches the model never carries URLs or addresses (RPC endpoints with API keys, internal hosts)."""
    if isinstance(value, str):
        return _URL.sub("<url>", value)
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


def _ref_json(ref: Optional[StateRef]) -> Optional[dict]:
    return {"network": ref.network, "address": ref.address} if ref else None


def receipt_json(r: Receipt) -> dict:
    return {"op": r.op, "status": r.status.value, "network": r.network, "state_ref": _ref_json(r.state_ref),
            "data": _redact(r.data), "error": _redact(r.error)}


def attestation_json(r: Receipt) -> dict:
    """The attestation an attest receipt stands for, ready to pass to check."""
    d = r.data
    out = {k: d[k] for k in ("subject_hash", "fact_type", "issuer", "issued_at", "expires_at", "hash_alg", "meta",
                             "proof", "inclusion") if d.get(k) is not None}
    out["anchor"] = _ref_json(r.state_ref)
    return out


def attestation_from_json(d: dict) -> Attestation:
    try:
        anchor = d.get("anchor")
        return Attestation(subject_hash=d["subject_hash"], fact_type=d["fact_type"], issuer=d["issuer"],
                           issued_at=d.get("issued_at", ""), expires_at=d.get("expires_at"),
                           proof=dict(d.get("proof") or {}), meta=dict(d.get("meta") or {}),
                           anchor=StateRef(anchor["network"], anchor["address"]) if anchor else None,
                           hash_alg=d.get("hash_alg", "sha-256"), inclusion=d.get("inclusion"))
    except (KeyError, TypeError, ValueError) as e:
        raise PlugError("proof_invalid", f"malformed attestation: {e}") from e


def build_server(plug: Plug, registries: Optional[dict] = None, name: str = "universal-plug", fact_types: Any = None,
                 model: Optional[dict] = None, max_batch: int = 1000, max_fact_bytes: int = 1 << 20,
                 rate: tuple[int, float] = (120, 60.0)):
    """An MCP server over a configured Plug.

    registries: trust registries the model may name (name -> registry); it cannot pass its own.
    fact_types: what the model may prove. None allows nothing; ANY allows any type outside RESERVED_FACT_TYPES.
    model: {"model_family", "model_id"} stamped into meta by the server, replacing whatever the model sends.
    max_batch, max_fact_bytes, rate (calls, seconds) bound what the model can make the server do.
    """
    from mcp.server.mcpserver import MCPServer

    allowed = dict(registries or {})
    if fact_types == ANY:
        _LOG.warning("MCP fact types opened to ANY non-reserved type")
    allowed_types = fact_types if fact_types in (None, ANY) else {canon_fact_type(t) for t in fact_types}
    calls, per = rate
    budget = {"tokens": float(calls), "at": time.monotonic()}
    stamp = {k: str(v) for k, v in (model or {}).items() if k in _MODEL_META}
    server = MCPServer(name, instructions=(
        "Verifiable evidence. prove records a fact and returns an attestation; check verifies an attestation "
        "without trusting its issuer. Keys are held by this server."))

    def registry(value: Any):
        if value is None:
            return None
        if isinstance(value, str) and value in allowed:
            return allowed[value]
        raise PlugError("not_authorized", "trust_registry must be one of: " + (", ".join(sorted(allowed)) or "(none)"))

    def admit(fact_type: str) -> str:
        ft = canon_fact_type(fact_type)
        if ft.startswith("upp.") or (allowed_types == ANY and ft.startswith(RESERVED_FACT_TYPES)):
            raise PlugError("not_authorized", f"fact type {ft} is reserved")
        if allowed_types is None:
            raise PlugError("not_authorized", "this server allows no fact types (closed by default)")
        if allowed_types != ANY and ft not in allowed_types:
            raise PlugError("not_authorized", f"fact type {ft} is not allowed by this server")
        return ft

    def bounded(fact: Any) -> Any:
        if len(fact_bytes(fact)) > max_fact_bytes:
            raise PlugError("unsupported_op", f"a fact is at most {max_fact_bytes} bytes")
        return fact

    def server_meta(meta: Optional[dict]) -> dict:
        out = {k: v for k, v in (meta or {}).items() if k not in _MODEL_META and not str(k).startswith("_")}
        out.update(stamp)
        return out

    def guarded(fn):
        now = time.monotonic()
        budget["tokens"] = min(float(calls), budget["tokens"] + (now - budget["at"]) * calls / per)
        budget["at"] = now
        if budget["tokens"] < 1:
            return {"error": f"rate_limited: at most {calls} calls per {per:g} seconds", "retryable": True}
        budget["tokens"] -= 1
        try:
            return fn()
        except PlugError as e:
            return {"error": _redact(f"{e.code}: {e.message}"), "retryable": e.retries}
        except Exception:
            _LOG.exception("tool call failed")  # details stay in the operator's log
            return {"error": "operation failed", "retryable": False}

    @server.tool(description="Record a fact. Returns the receipt and an attestation to pass to check.")
    def prove(fact: Any, fact_type: str, network: Optional[str] = None, meta: Optional[dict] = None) -> dict:
        def run():
            r = plug.prove(bounded(fact), admit(fact_type), network, server_meta(meta))
            return {"receipt": receipt_json(r), "attestation": attestation_json(r), "salt": r.data.get("salt")}
        return guarded(run)

    @server.tool(description="Record many facts under one anchor. Returns one attestation per fact.")
    def prove_batch(facts: list, fact_type: str, network: Optional[str] = None, meta: Optional[dict] = None) -> dict:
        def run():
            if not isinstance(facts, list) or len(facts) > max_batch:
                raise PlugError("unsupported_op", f"a batch holds at most {max_batch} facts")
            rs = plug.prove_batch([bounded(f) for f in facts], admit(fact_type), network, server_meta(meta))
            return {"anchor": _ref_json(rs[0].state_ref), "status": rs[0].status.value,
                    "attestations": [attestation_json(r) for r in rs], "salts": [r.data.get("salt") for r in rs]}
        return guarded(run)

    @server.tool(description="Verify an attestation. Never trusts its issuer.")
    def check(attestation: dict, network: Optional[str] = None, trust_registry: Optional[str] = None) -> dict:
        def run():
            v = plug.check(attestation_from_json(attestation), network, registry(trust_registry))
            return {"valid": v["valid"], "receipt": receipt_json(v["receipt"])}
        return guarded(run)

    @server.tool(description="Networks, the active signer, trust registries, and fact types this server allows.")
    def networks() -> dict:
        def run():
            s = plug.active()
            return {"networks": sorted(plug._ledgers), "registries": sorted(allowed),
                    "fact_types": allowed_types if allowed_types in (None, ANY) else sorted(allowed_types),
                    "reserved_fact_types": list(RESERVED_FACT_TYPES),
                    "active": {"network": s.network, "subject": s.subject} if s else None}
        return guarded(run)

    return server


def plug_from_config(config: dict) -> tuple[Plug, dict]:
    """A Plug from a JSON config. Secrets are named by environment variable, never written in the file:

    {"trust": {"local": {"issuers": ["did:key:..."]}}, "registries": {"eu": "https://..."},
     "hosts": ["registry.example"], "fact_types": ["doc.sha256"], "model": {"model_family": "..."},
     "networks": {"local": {"ledger": "local", "path": "evidence.jsonl", "key_env": "UPP_KEY"},
                  "sepolia": {"ledger": "ethereum", "rpc_url_env": "ETH_RPC_URL", "key_env": "ETH_PRIVATE_KEY"},
                  "cm": {"ledger": "chainmaker", "sdk_config": "sdk.json",
                         "member": {"org_id": "...", "sign_key": "member.key", "sign_crt": "member.crt"}}}}
    """
    from .registry import allow_hosts
    plug = Plug(hash_alg=config.get("hash_alg", "sha-256"), commitment=config.get("commitment", "plain"),
                trust=config.get("trust"))
    hosts = config.get("hosts") or []
    allow_hosts(*([hosts] if hosts == ANY else hosts))
    for name, spec in (config.get("networks") or {}).items():
        kind = spec.get("ledger")
        key = os.environ[spec["key_env"]] if spec.get("key_env") else None
        if kind == "local":
            from .ledgers.local import LocalLedger
            plug.register(name, LocalLedger(spec.get("path")))
            plug.open(name, {"key": key, "alg": spec.get("alg", "ed25519")} if key else {})
        elif kind == "ethereum":
            from .ledgers.ethereum import EthereumLedger
            plug.register(name, EthereumLedger(os.environ[spec["rpc_url_env"]],
                                               read_urls=[os.environ[v] for v in spec.get("read_url_envs", [])]))
            plug.open(name, {"key": key})
        elif kind == "chainmaker":
            from .ext.chainmaker import ChainMakerLedger
            with open(spec["sdk_config"]) as f:
                plug.register(name, ChainMakerLedger(json.load(f), contract=spec.get("contract", "upp_anchor")))
            plug.open(name, {"member": spec["member"]})
        else:
            raise ValueError(f"unknown ledger {kind!r} for network {name!r}")
    return plug, dict(config.get("registries") or {})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Universal Plug Protocol MCP server (stdio)")
    parser.add_argument("--config", required=True, help="JSON config; secrets come from environment variables")
    args = parser.parse_args(argv)
    with open(args.config) as f:
        config = json.load(f)
    plug, registries = plug_from_config(config)
    build_server(plug, registries, fact_types=config.get("fact_types"), model=config.get("model")).run("stdio")


if __name__ == "__main__":
    main()
