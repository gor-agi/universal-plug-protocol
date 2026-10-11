# Contributing

Thank you for helping build a neutral interface for evidence and identity across networks.

## Ground rules

1. **The specification governs.** [SPEC.md](SPEC.md) is normative. When code and specification disagree, the code is wrong. Behavioral changes include a specification change in the same pull request.
2. **Neutrality.** Core (`plug/core.py`, `plug/suites.py`) names no network, vendor, jurisdiction, or product. Network-specific logic belongs in adapters; jurisdiction-specific rules belong in deployment profiles and configuration.
3. **Operation budget.** The protocol has thirteen operations. A proposal that adds one must remove or demote another, and states which.
4. **No emulation.** A feature that depends on a backend, library, or network ships only when it runs against the real thing. Unavailable dependencies raise `unsupported_op`; they are never simulated.
5. **Conformance first.** A change to canonical serialization, hashing, signature suites, or receipt hashing regenerates the vectors in `spec/vectors/` with an independent implementation and keeps every vector passing.

## Developer Certificate of Origin

Every commit carries a `Signed-off-by` line certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/):

```bash
git commit -s -m "fix: describe the change"
```

The sign-off name and email match the commit author. Pull requests with unsigned commits are not merged.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,live,suites]"
git config core.hooksPath .githooks
pytest -rs
```

The hooks in `.githooks/` add your `Signed-off-by` line to each commit, and before a push to `main` they refuse unsigned commits and run the test suite and `scripts/check_vectors.sh`. Use `git push --no-verify` only in an emergency; CI runs the same checks.

Cross-implementation checks run when the tools are present: OpenSSL 3 for signature suites, Node.js for RFC 8785 vectors and `scripts/check_vectors.sh`. CI installs both. To regenerate vectors:

```bash
node spec/vectors/generate_jcs.mjs > spec/vectors/jcs.json
```

## Pull requests

- One logical change per pull request, with tests that fail without it.
- Negative cases are required for anything that verifies: tampered input, wrong key, wrong network, malformed data.
- Commit subjects use a type prefix: `fix:`, `feat:`, `spec:`, `test:`, `docs:`, `chore:`.
- New source files start with the SPDX header used throughout the repository.

## Reporting security issues

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).
