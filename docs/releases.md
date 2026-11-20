# Releases

The workflows have separate purposes:

- `docker-publish.yml`: tests on PRs, main, numeric tags and manual runs; image
  publishing depends on tests and is skipped for PRs.
- `helper-release.yml`: tests and checksummed helper assets for numeric tags;
  can also run manually with a `release_tag` input.

Pushes to `main` publish `main` and `latest` after unit tests pass. Other branch
pushes do not publish images automatically. Numeric tags publish the versioned
image and matching GitHub helper release. Release tags do not use a `v` prefix.
Wait for both publishing workflows before provisioning a new release, and pin
the deployment image digest.

Update [release notes](../CHANGELOG.md), then, after CI passes on `main`, publish
the next version (for example):

```bash
git tag -a 0.1.2 -m "0.1.2"
git push origin 0.1.2
```

Each GitHub release includes `host.py`, `dispatch.py`, `LICENSE` and `SHA256SUMS`.
Deployment automation downloads helpers from that tag and verifies the checksums.
The Docker publishing job summary shows the image digest; pin it in deployment
configuration. Changed source needs a new version. Manual helper releases check
out the requested tag and can upload assets to an existing release; existing
assets are never overwritten.

To rebuild the image for the **same source version**, rerun its Docker publishing
job or manually dispatch that workflow at the existing tag:

```bash
gh workflow run docker-publish.yml --ref 0.1.2
```

Manual dispatch disables the build cache, allowing OS package installation to run
again. Digest-pinned base images remain pinned. This updates the Docker Hub image
tag, without recreating the helper release. Deployments pinned to the previous
image digest stay unchanged until explicitly updated to the rebuilt digest.
Only use trusted releases; the installed helpers run privileged Docker operations.


See [helper security](architecture.md) before installing a release. Deployment
steps are in the
[deployment runbook](https://github.com/pacificclimate/portainer-deployment/blob/main/apps/live/kestra/software-audit.md).
