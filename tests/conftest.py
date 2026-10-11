# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
import pytest

from plug import ANY
from plug.adapters import base


@pytest.fixture(autouse=True)
def local_document_servers():
    """Tests serve registries and status lists from 127.0.0.1, so they open fetching explicitly.
    Production is closed: no host is fetched until allowed, and only public addresses."""
    base.allow_private_networks(True)
    base.allow_hosts(ANY)
    yield
    base.reset_fetch_policy()
