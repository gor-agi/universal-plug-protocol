# SPDX-License-Identifier: Apache-2.0
"""Ledgers: where statements are signed and anchored. EthereumLedger imports web3 only when used."""
from .local import LocalLedger

__all__ = ["LocalLedger", "EthereumLedger"]


def __getattr__(name):
    if name == "EthereumLedger":
        from .ethereum import EthereumLedger
        return EthereumLedger
    raise AttributeError(name)
