# SPDX-License-Identifier: Apache-2.0
"""Prove a customer opted in, without putting their personal data anywhere.

A business records each opt-in as a salted commitment: the log holds only a hash, unlinkable without the salt.
When a regulator or the customer asks, the business hands over the record and its salt; anyone can check the
record existed unaltered when it was logged, and was signed by the business.

Run:  python examples/consent_record.py
"""
from upp import Attestation, LocalLedger, Plug, commitment

business = Plug(commitment="salted")
ledger = LocalLedger()  # in production: a log file, or a public ledger such as EthereumLedger
business.register("log", ledger)
business.open("log")

opt_in = {"phone": "+1 555 0100", "channel": "whatsapp", "purpose": "order-updates",
          "text": "Reply YES to get order updates", "reply": "YES", "at": "2026-10-11T09:30:00Z"}
receipt = business.prove(opt_in, "consent.opt-in")
attestation, salt = Attestation.from_receipt(receipt), receipt.data["salt"]
print("logged:", attestation.subject_hash[:16], "(a hash; the log holds no phone number)")

# Months later, a regulator receives the record, its salt, and the attestation.
regulator = Plug(trust={"log": {"issuers": [attestation.issuer]}})
regulator.register("log", ledger)


def inspect(label, record):
    matches = commitment(record, salt) == attestation.subject_hash
    valid = regulator.check(attestation)["valid"]
    print(f"{label:28} {'CONFIRMED' if matches and valid else 'REJECTED'}")


inspect("record as logged", opt_in)
inspect("record with a changed reply", dict(opt_in, reply="NO"))
inspect("record with a later purpose", dict(opt_in, purpose="marketing"))
