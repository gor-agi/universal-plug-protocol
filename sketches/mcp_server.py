# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
# MCP Server Sketch (plug)
# Three tools over the same Plug instance. REST/CLI/SDK are sibling adapters.
# Status: sketch - not wired into the package yet.

tools = [
  {
    "name": "prove",
    "description": "Bind a real-world fact to a verifiable receipt. IDEMPOTENT: identical fact+fact_type+network returns the cached receipt (24h). Safe for autonomous agent retry.",
    "inputSchema": {
      "type": "object",
      "required": ["fact", "fact_type"],
      "properties": {
        "fact": {"description": "Payload: JSON, text, or file reference", "oneOf": [{"type":"object"},{"type":"string"}]},
        "fact_type": {"description": "Open vocabulary, canonicalized to lowercase dotted (e.g. sensor.reading)", "type": "string"},
        "network": {"description": "Optional; defaults to active session", "type": "string"},
        "meta": {"description": "Optional metadata (model_family, market_id, ...)", "type": "object"}
      }
    }
  },
  {
    "name": "check",
    "description": "Verify a claim or read state. IDEMPOTENT read. Safe for autonomous agent retry.",
    "inputSchema": {
      "type": "object",
      "required": ["target"],
      "properties": {
        "target": {"description": "Attestation object, StateRef, or DID string", "oneOf": [{"type":"object"},{"type":"string"}]},
        "network": {"description": "Optional; defaults to active session", "type": "string"}
      }
    }
  },
  {
    "name": "watch",
    "description": "Subscribe to state changes on a StateRef. Returns a stream handle. NOT idempotent in the sense of side effects (opens a subscription), but repeated identical calls are harmless.",
    "inputSchema": {
      "type": "object",
      "required": ["target"],
      "properties": {
        "target": {"description": "StateRef or asset/DID identifier", "oneOf": [{"type":"object"},{"type":"string"}]},
        "filter": {"description": "Optional event-type filter", "type": "array", "items": {"type": "string"}}
      }
    }
  }
]
