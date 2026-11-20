# Releases

The workflows have separate purposes:

- `docker-publish.yml`: tests on PRs, main, numeric tags and manual runs; image
  publishing depends on tests and is skipped for PRs.
- `helper-release.yml`: tests and checksummed helper assets for new numeric tags.

Pushes to `main` publish `main` and `latest` after unit tests pass. Other branch
pushes do not publish images automatically. Tags such as `0.1.0` publish the versioned image and matching GitHub helper
release. Release tags do not use a `v` prefix. Wait for both publishing workflows before
provisioning a new release, and pin the deployment image digest.

Allow this repository to access the existing organization Actions secrets, or
create repository secrets with these names:

- `pcicdevops_at_dockerhub_username`
- `pcicdevops_at_dockerhub_password` (a Docker Hub access token with push access)

Configure the Docker Hub repository as public before release. Never put credentials
in workflow YAML. The workflow uses a scoped GitHub token to create release assets;
it does not require a personal GitHub token.

After CI passes on `main`, publish a new version:

```bash
git tag 0.1.0
git push origin 0.1.0
```

Each GitHub release includes `host.py`, `dispatch.py`, `LICENSE` and `SHA256SUMS`.
Deployment automation downloads helpers from that tag and verifies the checksums.
The Docker publishing job summary shows the image digest; pin it in deployment
configuration. Do not overwrite source tags or helper assets: changed application
or helper source needs a new version.

To rebuild the image for the **same source version**, rerun its Docker publishing
job or manually dispatch that workflow at the existing tag:

```bash
gh workflow run docker-publish.yml --ref 0.1.0
```

Manual dispatch disables the build cache, allowing OS package installation to run
again. Digest-pinned base images remain pinned. This updates the Docker Hub image
tag, without recreating the helper release. Deployments pinned to the previous
image digest stay unchanged until explicitly updated to the rebuilt digest.
Only use trusted releases; the installed helpers run privileged Docker operations.


See [helper security](architecture.md) before installing a release. Deployment
steps are in the
[deployment runbook](https://github.com/pacificclimate/portainer-deployment/blob/main/apps/live/kestra/software-audit.md).
