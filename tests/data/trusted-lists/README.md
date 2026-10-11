# Trusted list test data

- `lu-tsl-66.xml`: Luxembourg's trusted list, sequence 66 (issued 2026-05-20, next update 2026-11-20), from https://trusted-list.lu/tsl.xml, unmodified.
- `lu-signers.json`: the signer certificates the EU list of trusted lists (sequence 395, issued 2026-09-24) pins for that list.

`tests/test_trusted_lists.py` verifies the list at a fixed time inside its validity window. To refresh, fetch both again and update the fixed time and sequence numbers.
