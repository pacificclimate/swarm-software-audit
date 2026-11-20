# swarm-software-audit

Docker Swarm software inventory and vulnerability assessment using Syft and Grype,
with cached SBOMs and searchable static HTML reports.

Restricted SSH helpers inventory each node's local images and containers. Syft
catalogs uncached images from temporary archives on the source Swarm's storage.
The central runner deduplicates SBOMs, updates Grype's database, scans and publishes
HTML. Image layers are not transferred over SSH; the runner needs no Docker socket.

## Prerequisites

- Docker on the runner host; the published runner image targets `linux/amd64`.
- Matching host helpers and the restricted `kestra-audit` account on each target.
- Verified SSH host keys and a dedicated private key, mode 0600.
- Writable output storage and outbound HTTPS for Grype database updates.

The [deployment runbook](https://github.com/pacificclimate/portainer-deployment/blob/main/apps/live/kestra/software-audit.md)
covers Ansible, Kestra, storage permissions and nginx. Read
[architecture and helper security](docs/architecture.md) before provisioning
privileged helpers. See [releases](docs/releases.md) for publishing and rebuilds.
Production keys, site configuration and reports are excluded from this repository.

## Run

Copy `examples/targets.json` to `config/targets.json` and replace the example hosts.
Put verified host keys in `config/known_hosts` and the private key in
`config/id_ed25519`. Install the matching helpers before running collection.

```bash
mkdir -p audit-output
docker run --rm --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD/config,target=/config,readonly" \
  --mount "type=bind,source=$PWD/audit-output,target=/audit" \
  pcic/swarm-software-audit:0.1.0 \
  --targets /config/targets.json --known-hosts /config/known_hosts \
  --key /config/id_ed25519 --root /audit
```

Optional arguments:

- `--clusters primary,secondary`: select clusters.
- `--nodes node-a,node-b`: select nodes for a pilot.
- `--inventory-only`: collect metadata without Syft or Grype; exits 2.
- `--retention-days 30`: retain run history and unused cache objects for 30 days.

## Output and exit status

Serve only `audit-output/published/`. `index.html` shows the latest attempt;
`last-successful.html` preserves the latest complete assessment. Raw `cache/` and
`runs/` directories are private and must not be served.

A complete assessment exits 0. Missing coverage, failed scans, stale/unavailable
databases and empty package catalogs produce an incomplete assessment and exit 2
after publishing status. Operational exceptions exit nonzero. Incomplete results
are not treated as clean scans.

## Tests

Python 3.13 is used in the runner; unit tests use the standard library.

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
docker build -t pcic/swarm-software-audit:local .
docker run --rm pcic/swarm-software-audit:local --help
```

Optional integration tests use disposable containers on the local Docker daemon:

```bash
docker pull anchore/syft:v1.57.2
docker build -t swarm-software-audit-test-host:local -f tests/integration/Dockerfile.host .
docker build -t swarm-software-audit-test-image:local -f tests/integration/Dockerfile.image .
python3 tests/integration/local_test.py
```

The harness refuses remote daemons, removes its containers/network, and writes
`tests/integration/preview.html` (gitignored). Only the disposable host receives
the Docker socket. It creates no host accounts and uses no production credentials.
Grype needs HTTPS. Optional browser checks use
`python3 tests/integration/browser_test.py --browser /path/to/chromium`.

## Limitations

Coverage includes local Docker images, including undeployed images, and their
current container/service associations. Host packages, BuildKit cache blobs,
mounted data, writable-layer changes, desired service specs and zero-replica
services are outside scope. Findings do not establish exploitability.
Collection is sequential; target inventory must match cluster membership.
See [recovery](docs/architecture.md#recovery) for interrupted runs.

## License

GNU GPLv3. See [LICENSE](LICENSE). Extracted from the GPLv3-licensed
`pacificclimate/portainer-deployment` project.
