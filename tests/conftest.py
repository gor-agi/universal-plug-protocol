# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
import pytest

from plug.adapters import base


@pytest.fixture(autouse=True)
def local_document_servers():
    """Tests serve registries and status lists from 127.0.0.1; production defaults to public addresses only."""
    base.allow_private_networks(True)
    yield
    base.allow_private_networks(False)
