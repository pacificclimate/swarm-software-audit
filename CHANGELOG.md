# Release notes

## 0.1.2 (unreleased)

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
