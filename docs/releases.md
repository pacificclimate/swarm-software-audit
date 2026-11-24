# Releases

`docker-publish.yml` runs tests on pull requests, `main`, numeric tags and manual
runs. Publishing depends on passing tests and is skipped for pull requests.

Pushes to `main` publish `main` and `latest`. Numeric tags publish the versioned
runner image. The registry runner contains both Syft and Grype; there are no host
helper release assets.

Update [release notes](../CHANGELOG.md), commit the changes, then create an
annotated version tag and push the branch and tag together:

```bash
git tag -a 0.2.1 -m "0.2.1"
git push origin main --follow-tags
```

Wait for the versioned publishing run to pass, then pin its image digest in
deployment configuration. Changed source
needs a new version; do not move published tags.

To rebuild the same source version for OS package updates:

```bash
gh workflow run docker-publish.yml --ref 0.2.1
```

Manual dispatch disables the build cache; base images remain digest-pinned.
Deployments using the prior image digest remain unchanged until explicitly updated.
The registry design starts with 0.2.0; older releases use the SSH collector.
