# Governance

## Principles

- **Neutrality.** No network, vendor, jurisdiction, or model provider receives preferential treatment in the core protocol. Their specifics live in adapters and deployment profiles.
- **Openness.** Specification, reference implementation, and conformance vectors are developed in the open under the Apache License 2.0.
- **Evidence over assertion.** Decisions about protocol behavior are settled with tests, vectors, and interoperability results.

## Roles

- **Contributors** submit issues, specifications, code, and reviews under the [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin).
- **Maintainers**, listed in [MAINTAINERS.md](MAINTAINERS.md), review and merge contributions, cut releases, and handle security reports.

A contributor becomes a maintainer after sustained, high-quality contributions and a nomination by an existing maintainer, approved by a majority of maintainers. Maintainers inactive for six months may be moved to emeritus status.

## Decisions

- **Code and documentation:** lazy consensus. A pull request merges after approval by one maintainer other than the author when at least two maintainers exist, and no maintainer objection within three business days.
- **Specification changes** (`SPEC.md`, `spec/`): approval by a majority of maintainers, with a public comment period of at least seven days.
- **Operation budget changes:** as specification changes, plus a written statement of which operation is removed or demoted.
- Disagreements that lazy consensus does not resolve are decided by a majority vote of maintainers.

## Foundation

The project is intended for contribution to a vendor-neutral open-source foundation. On acceptance, the foundation's charter and policies supersede this document where they conflict.
