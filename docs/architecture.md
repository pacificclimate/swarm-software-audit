# Registry scanning

The input is an inventory of immutable registry image references and platform,
optionally associated with services. Syft explicitly uses its registry source,
which verifies registry content by digest, with TLS verification enabled.

The runner bundles Syft and Grype, uses standard-library Python, and runs as the
non-root `audit` account. It downloads images from registries and vulnerability
data from Grype's database service. It writes reports and caches under the path
passed to `--root` (`/audit` in the container examples).

For private images, provide registry download credentials in a Docker authentication
`config.json` file. Mount it read-only and set `DOCKER_CONFIG` to its directory.

## Inventory and identity

`examples/images.json` defines the input format. Image references must include the
registry and a full SHA256 digest. An OCI index
reference is assessed for the explicitly selected platform, default `linux/amd64`.
The SBOM records the input reference and platform alongside Syft's configuration ID.

An optional `unassessed` list records fully qualified tag-only references, platform,
services and `reason: missing-digest`. These observations do not reach Syft, Grype
or the registry. Their presence produces coverage warnings and exit 0, but keeps
the assessment incomplete while pinned images are still scanned. The report retains their service associations and missing-digest
reason; no registry manifest digest is invented.

Service metadata comes from the supplied inventory.
Use `source` and optionally `observed_at` to identify its origin. Deployment files
establish declared state; only an observed inventory should label a service running.
Deployment collectors supply observed image references and service metadata;
collection is separate from the registry scanner.

Routing categories describe Traefik configuration, direct published ports, no
observed route, or unknown, according to the supplied inventory. Vulnerability
findings are package/advisory matches for the listed images and platform.

## Cache and publication

SBOM cache identity includes reference, platform, Syft version and catalog policy.
The catalog policy is `registry-v1`. Syft's raw image configuration/manifest
metadata is removed before caching. Private SBOMs and
findings can still reveal application details.

Grype updates its database once per run, then scans a private snapshot. Findings
cache identity includes the SBOM content hash, Grype version, database hash and
scan policy. Invalid caches are regenerated. Used objects are retained; unused
objects expire after the configured retention period.

Only selected package and advisory fields are embedded in HTML, once per image.
Service associations are separate. Both tabs group by package identity/version or
image; filters apply before grouping. Expanded details preserve advisory namespace,
affected ranges, fixes and service associations. Different package URLs and
ecosystems stay distinct. JSON embedding and text rendering escape untrusted data;
advisory links allow only HTTP(S).

A failed assessment publishes an incomplete latest attempt without replacing the
last complete page. Only `published/` is intended to be served. Keep reports internal.

## Scheduling and recovery

The scanner can run from reviewed CI, a host-managed schedule, or a restricted
Kestra flow. Deployment administrators control flow-edit permissions, runtime
users and permitted mounts. Limit writable mounts to the audit output directory.

Runs are serialized using `.run-lock/`. After an abrupt termination, confirm no
runner remains before removing that specific stale lock. Retention removes recognized audit
history directories and unused cache objects.
