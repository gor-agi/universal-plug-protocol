# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""Universal Plug Protocol - network-agnostic layer for attestations and identity."""
from .core import (
    ANY, Plug, Adapter, Attestation, Identity, Credential, StateRef, Receipt, Session,
    Status, Role, FactType, PlugError, SPEC_VERSION, canonical, sha256_hex, canon_fact_type,
    digest, commitment, fact_bytes,
)

__version__ = "0.4.1"
__all__ = [
    "ANY", "Plug", "Adapter", "Attestation", "Identity", "Credential", "StateRef", "Receipt", "Session",
    "Status", "Role", "FactType", "PlugError", "SPEC_VERSION", "canonical", "sha256_hex",
    "canon_fact_type", "digest", "commitment", "fact_bytes", "__version__",
]
