# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
import pytest

from upp import ANY, allow_hosts, allow_private_networks, reset_fetch_policy


@pytest.fixture(autouse=True)
def local_document_servers():
    """Tests serve registries and status lists from 127.0.0.1, so they open fetching explicitly.
    Production is closed: no host is fetched until allowed, and only public addresses."""
    allow_private_networks(True)
    allow_hosts(ANY)
    yield
    reset_fetch_policy()
