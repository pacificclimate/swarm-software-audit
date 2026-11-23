# swarm-software-audit

Scan digest-pinned registry images with Syft and Grype, cache SBOMs and publish a
searchable static dashboard. Python uses only its standard library.

## Run

Build the registry runner and prepare an image inventory:

```bash
docker build -t pcic/swarm-software-audit:local .
mkdir -p config audit-output
cp examples/images.json config/images.json
```

Replace the example reference with a real `registry/repository@sha256:digest` and
set its platform. List associated services with cluster, name and routing:
`traefik`, `published-ports`, `none` or `unknown`. State defaults to `declared`;
use `running` only for an observed deployment snapshot. Combine services sharing
one reference/platform into one entry. The example digest is a placeholder.

The image runs as UID:GID `1111:1111`; provision the output directory writable by
that identity. For another storage identity, build with `AUDIT_UID` / `AUDIT_GID`.

```bash
docker run --rm --read-only --tmpfs /tmp:rw,nosuid,size=2g \
  --mount "type=bind,source=$PWD/config,target=/config,readonly" \
  --mount "type=bind,source=$PWD/audit-output,target=/audit" \
  pcic/swarm-software-audit:local \
  --images /config/images.json --root /audit
```

Optional: `--clusters live,drac` selects service associations;
`--retention-days 30` controls history and unused-cache retention.
For private images, mount a Docker authentication `config.json` file with registry
download credentials read-only and set `DOCKER_CONFIG` to its directory.
See [registry authentication](https://oss.anchore.com/docs/guides/private-registries/).

## Reports

Serve only `audit-output/published/`. `index.html` shows the latest attempt;
`last-successful.html` preserves the latest complete assessment. Keep raw `cache/`
and `runs/` private. Reports contain software inventory and vulnerability details.

Vulnerabilities and Packages (SBOM) tabs group by package/version or image, with
expandable advisories and service locations. Filters focus on Traefik-configured
services and can include non-Traefik or unknown routing. Service state and routing
filters use the supplied inventory.

A complete assessment exits 0. An unavailable image, failed scan, unusable database
or empty package catalog makes the assessment incomplete and exits 2 after reporting.
The assessment covers packages inside the listed registry images, matched against
Grype's vulnerability database.

## Development

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Optional registry smoke test, with `syft` on PATH:

```bash
python3 tests/integration/registry_test.py --reference registry.example.org/app@sha256:REPLACE_ME
```

Browser checks use an existing Chromium installation and a generated report:
`python3 tests/integration/browser_test.py --browser /path/to/chromium --report /path/to/index.html`.
See [architecture](docs/architecture.md), [releases](docs/releases.md), and
[deployment migration handoff](docs/deployment-handoff.md).

## License

GNU GPLv3. See [LICENSE](LICENSE). Extracted from the GPLv3-licensed
`pacificclimate/portainer-deployment` project.
