# Release notes

## 0.2.2

- Package the Prometheus/cAdvisor collector and automatic Compose routing annotations in the runner.
- Keep site-specific endpoints, instances and source directories in deployment configuration.
- Validate literal service prefixes and handle null Compose network declarations.
- Enforce private audit storage ownership and directory modes.

- Bundle PyYAML in the runner using hash-verified wheels installed during the image build.
- Support Compose inventory collectors without runtime package downloads.

## 0.2.1

- Report images without deployed digests as unassessed without resolving mutable tags.
- Continue scanning pinned images, mark coverage incomplete, and preserve the last successful report.
- Missing digests are coverage warnings (exit 0); collection and scan failures still exit 2.
- Show the missing-digest reason in both dashboard tabs.

## 0.2.0

- Replace node SSH collection with Syft registry scanning of digest-pinned images
  and explicit platforms. Bundle Syft and Grype in a non-root runner.
- Remove privileged host helpers, SSH credentials, node workspaces and helper
  release assets from the pipeline. Input is now `--images` registry inventory.
- Preserve the grouped Vulnerabilities / Packages dashboard, service-routing
  filters, affected ranges, advisory links and private caches.
- Treat service state/routing as supplied inventory, with declared state distinct
  from observed running services. Store findings and packages once per image.
- Add deployment handoff notes for retiring the old SSH provisioning and reviewing
  Kestra's mount and edit permissions.

## 0.1.2

- Add a named `audit` account (UID:GID `1111:1111`) so OpenSSH works when the
  runner uses that storage identity. Custom builds can set `AUDIT_UID` and
  `AUDIT_GID`.
- Run integration checks as `1111:1111` and verify the runner's account entry.
  Build the disposable SSH host independently to avoid conflicting account IDs.
- Document the runner identity and required output directory ownership.

## 0.1.1

- Add manual host helper releases for an existing numeric tag, including uploads
  to a release without helper assets. Existing assets are never overwritten.
- Remove one-time repository setup instructions from the release guide and
  shorten repeated setup guidance in the README.

## 0.1.0

- Initial Swarm image inventory, cached Syft SBOMs, Grype vulnerability scans,
  restricted SSH helpers, and searchable static HTML reports.
