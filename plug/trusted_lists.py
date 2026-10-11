# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""ETSI TS 119 612 trusted lists: verify the list's XAdES signature against pinned signer certificates and return
the certificates of granted services as trust anchors.

Pin the signer certificates from a source you already trust: for a national list, the pointer to it in the EU list
of trusted lists (LOTL); for the LOTL, the certificates the EU publishes in the Official Journal. Requires the
`eudi` extra (signxml, lxml, cryptography).
"""
from __future__ import annotations
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional

from .core import ANY, PlugError

NS = {"t": "http://uri.etsi.org/02231/v2#", "ds": "http://www.w3.org/2000/09/xmldsig#"}
GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"


@dataclass(frozen=True)
class TrustedList:
    territory: str
    sequence: int
    issued: datetime
    next_update: datetime
    signer: object                 # cryptography x509.Certificate that verified the list
    anchors: tuple                 # x509.Certificate of each granted service of the requested types
    services: tuple                # ({"name", "type", "status", "certificate"}, ...) for those anchors
    pointers: tuple                # ({"territory", "location", "certificates"}, ...): lists this one points to (LOTL)


def _certificate(value):
    from cryptography import x509
    if isinstance(value, x509.Certificate):
        return value
    data = value.encode() if isinstance(value, str) else bytes(value)
    return x509.load_pem_x509_certificate(data) if data.lstrip().startswith(b"-----BEGIN") \
        else x509.load_der_x509_certificate(data)


def _time(root, path: str) -> datetime:
    text = root.findtext(path, namespaces=NS)
    if not text:
        raise PlugError("proof_invalid", f"trusted list has no {path}")
    return datetime.fromisoformat(text.strip().replace("Z", "+00:00")).astimezone(timezone.utc)


def verify_trusted_list(xml: bytes, signer_certificates: Iterable, service_types, at: Optional[datetime] = None) \
        -> TrustedList:
    """Verify a trusted list and return its granted services of `service_types` (a list of ServiceTypeIdentifier
    URIs, or ANY) as anchors. Fails closed: an unverifiable, expired, or malformed list raises PlugError."""
    from cryptography import x509
    from signxml import InvalidInput, InvalidSignature, SignatureConfiguration, XMLVerifier
    from signxml.exceptions import InvalidCertificate, InvalidDigest
    if service_types is None or (service_types != ANY and not list(service_types)):
        raise PlugError("not_authorized", "name the service types to trust, or ANY (closed by default)")
    at = at or datetime.now(timezone.utc)
    pinned = [_certificate(c) for c in signer_certificates]
    if not pinned:
        raise PlugError("not_authorized", "no pinned signer certificate")
    signed, signer, failures = None, None, []
    for cert in pinned:
        if not cert.not_valid_before_utc <= at <= cert.not_valid_after_utc:
            failures.append("pinned certificate not valid at verification time")
            continue
        for references in (2, 1, 3):
            try:
                results = XMLVerifier().verify(
                    xml, x509_cert=cert, expect_config=SignatureConfiguration(require_x509=True,
                                                                             expect_references=references))
            except (InvalidSignature, InvalidDigest, InvalidCertificate, InvalidInput) as e:
                failures.append(f"{type(e).__name__}: {e}")
                continue
            results = results if isinstance(results, list) else [results]
            # Read only what the signature covers: the whole-document reference, never the unsigned input.
            whole = [r.signed_xml for r in results if r.signed_xml is not None
                     and r.signed_xml.tag == f"{{{NS['t']}}}TrustServiceStatusList"]
            if whole:
                signed, signer = whole[0], cert
                break
        if signed is not None:
            break
    if signed is None:
        raise PlugError("proof_invalid", "trusted list signature does not verify under any pinned certificate"
                        + (f" ({failures[-1]})" if failures else ""))
    issued, next_update = _time(signed, ".//t:ListIssueDateTime"), _time(signed, ".//t:NextUpdate/t:dateTime")
    if at >= next_update:
        raise PlugError("proof_invalid", "trusted list is past its next update")
    if at < issued:
        raise PlugError("proof_invalid", "trusted list is issued in the future")
    services, anchors = [], []
    for service in signed.findall(".//t:TSPService/t:ServiceInformation", NS):
        kind = service.findtext("t:ServiceTypeIdentifier", namespaces=NS)
        status = service.findtext("t:ServiceStatus", namespaces=NS)
        if status != GRANTED or (service_types != ANY and kind not in service_types):
            continue
        name = service.findtext("t:ServiceName/t:Name", namespaces=NS)
        for b64 in service.findall("t:ServiceDigitalIdentity/t:DigitalId/t:X509Certificate", NS):
            cert = x509.load_der_x509_certificate(base64.b64decode("".join(b64.text.split())))
            anchors.append(cert)
            services.append({"name": name, "type": kind, "status": status, "certificate": cert})
    pointers = []
    for pointer in signed.findall(".//t:PointersToOtherTSL/t:OtherTSLPointer", NS):
        certs = [x509.load_der_x509_certificate(base64.b64decode("".join(c.text.split())))
                 for c in pointer.findall(".//t:X509Certificate", NS)]
        pointers.append({"territory": pointer.findtext(".//t:SchemeTerritory", namespaces=NS),
                         "location": pointer.findtext("t:TSLLocation", namespaces=NS), "certificates": certs})
    return TrustedList(territory=signed.findtext(".//t:SchemeTerritory", namespaces=NS) or "",
                       sequence=int(signed.findtext(".//t:TSLSequenceNumber", namespaces=NS) or 0),
                       issued=issued, next_update=next_update, signer=signer, anchors=tuple(anchors),
                       services=tuple(services), pointers=tuple(pointers))
