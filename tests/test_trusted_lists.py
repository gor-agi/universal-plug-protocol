# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""ETSI TS 119 612 trusted lists, verified against a real one: Luxembourg's list (sequence 66) with the signer
certificates the EU list of trusted lists pins for it (tests/data/trusted-lists)."""
import base64
import json
import os
from datetime import datetime, timezone

import pytest

pytest.importorskip("signxml")

from upp import ANY, PlugError
from upp.ext.eudi.trusted_lists import verify_trusted_list

DATA = os.path.join(os.path.dirname(__file__), "data", "trusted-lists")
AT = datetime(2026, 6, 1, tzinfo=timezone.utc)  # between the list's issue (2026-05-20) and next update (2026-11-20)
CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"


@pytest.fixture(scope="module")
def lu():
    with open(os.path.join(DATA, "lu-tsl-66.xml"), "rb") as f:
        xml = f.read()
    with open(os.path.join(DATA, "lu-signers.json")) as f:
        pinned = [base64.b64decode(c) for c in json.load(f)["signer_certificates"]]
    return xml, pinned


def test_a_real_national_trusted_list_verifies_and_yields_its_anchors(lu):
    xml, pinned = lu
    tl = verify_trusted_list(xml, pinned, [CA_QC], at=AT)
    assert tl.territory == "LU" and tl.sequence == 66
    assert "ILNAS" in tl.signer.subject.rfc4514_string()
    assert tl.anchors and all(s["type"] == CA_QC for s in tl.services)
    everything = verify_trusted_list(xml, pinned, ANY, at=AT)
    assert len(everything.anchors) > len(tl.anchors)


def test_closed_unless_service_types_are_named(lu):
    xml, pinned = lu
    for types in (None, []):
        with pytest.raises(PlugError, match="closed by default"):
            verify_trusted_list(xml, pinned, types, at=AT)
    with pytest.raises(PlugError, match="no pinned signer"):
        verify_trusted_list(xml, [], [CA_QC], at=AT)


def test_tampered_unpinned_or_stale_lists_are_rejected(lu):
    xml, pinned = lu
    with pytest.raises(PlugError, match="does not verify"):
        verify_trusted_list(xml.replace(b"LuxTrust", b"EvilTrust", 1), pinned, [CA_QC], at=AT)
    with pytest.raises(PlugError, match="does not verify"):
        verify_trusted_list(xml, pinned[:1], [CA_QC], at=AT)  # pinned, but not the certificate that signed it
    with pytest.raises(PlugError, match="past its next update"):
        verify_trusted_list(xml, pinned, [CA_QC], at=datetime(2026, 11, 21, tzinfo=timezone.utc))
    with pytest.raises(PlugError, match="issued in the future"):
        verify_trusted_list(xml, pinned, [CA_QC], at=datetime(2026, 5, 1, tzinfo=timezone.utc))


def test_an_unsigned_service_cannot_be_wrapped_in(lu):
    """Signature wrapping: a service appended outside the signed content must not become an anchor."""
    xml, pinned = lu
    fake = (b"<TSPService xmlns=\"http://uri.etsi.org/02231/v2#\"><ServiceInformation><ServiceTypeIdentifier>"
            + CA_QC.encode() + b"</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"en\">Evil CA</Name>"
            b"</ServiceName><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>"
            b"</ServiceInformation></TSPService>")
    wrapped = xml.replace(b"</TrustServiceProviderList>", fake + b"</TrustServiceProviderList>", 1)
    with pytest.raises(PlugError):
        verify_trusted_list(wrapped, pinned, [CA_QC], at=AT)
