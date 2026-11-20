# Architecture and helper security

The runner collects image and container metadata through restricted SSH helpers.
SBOMs are deduplicated centrally; Grype scans use a database snapshot per run.
Images remain on their source nodes, and Swarms can use separate storage.

## Host protocol and trust boundary

An SSH account named `kestra-audit` accepts exactly:

| Command | Input | Result |
|---|---|---|
| `audit inventory-v1` | None | Selected image/container metadata and scanner identity |
| `audit sbom-v1` | One JSON object with a full `image_id` | Syft JSON for that existing image |

The application assumes these installed paths:

- Root-owned `/usr/local/libexec/kestra-audit-root`, from `host/host.py`.
- Root-owned `/usr/local/libexec/kestra-audit-dispatch`, from `host/dispatch.py`.
- Root-owned `/etc/kestra-audit/config.json` selecting a digest-pinned scanner,
  e.g. `{"syft_image":"anchore/syft@sha256:<verified digest>",
  "workspace_root":"/storage/audit/work/node-a",
  "workspace_uid":1111,"workspace_gid":1111,"workspace_mount":"/storage"}`.
  Workspace IDs are site configuration; the UID/GID must match storage ownership.
- A dedicated empty Docker client config directory `/etc/kestra-audit/docker`.

Provisioning must enforce a locked password, a root-managed authorized-key file,
`restrict` and a forced dispatcher, verified source restrictions, no supplementary
Docker group, and sudo limited to the two fixed helper invocations. No SSH shell,
SFTP/SCP, arbitrary Docker commands, scanner image selection or custom mounts are
accepted. Do not execute a group-writable checkout as the privileged helper.

Only the small root helper accesses Docker. It saves the selected image to a
private archive workspace and runs Syft as the configured workspace UID:GID with
**no Docker socket**. Filesystem operations and cleanup use that storage identity;
only fixed Docker CLI children regain effective root. Syft receives the archive
read-only and private writable scratch, with no network, dropped capabilities,
a read-only root filesystem and CPU/memory/PID limits. SELinux labeling is disabled
for this scanner container to avoid relabeling NFS mounts; see
[Docker security options](https://docs.docker.com/reference/cli/docker/container/run/#security-opt).
A single 15-minute deadline covers export and scanning. The helper removes the
scanner, archive and scratch afterward, including on normal failures.
Raw image config/manifest metadata is removed from returned SBOMs.

Provision a mode-0700 workspace owned by `workspace_uid:workspace_gid`. Shared
NFS storage is supported, including root squash. Use a separate directory per
node; each scan creates and removes a unique subdirectory. The helper and Docker
daemon must see the same absolute workspace path. `workspace_mount`, when set,
requires that mount to be present before any scan, preventing local-disk fallback.

`max_archive_bytes` (default 20 GiB) and `min_free_bytes` (default 1 GiB) are integer
byte counts. The helper checks capacity for approximately two uncompressed image
copies plus reserve, bounds archive/SBOM output, and monitors free space. These
checks are not a filesystem quota. Archives stay within the source Swarm's storage;
only SBOMs are returned over SSH.

The helper requires privileged Docker access. Release permissions and helper
updates require review.
The account cannot change its root-owned code or config. Checksums detect corrupted
assets; a manifest downloaded from the same release does not independently verify
its publisher. Protect release/tag permissions, review helper changes and deploy
only trusted versions. Keep raw SBOMs/findings private: package metadata can reveal
application details.

The runner image defines a non-login `audit` account with UID:GID `1111:1111`.
OpenSSH requires a passwd entry for the container process UID. Builds for another
storage identity can set `AUDIT_UID` and `AUDIT_GID`; the runtime user and output
ownership must match those IDs.

The runner verifies SSH host keys and copies the provided private key into a
temporary mode-0600 file. Grype requires outbound HTTPS for DB updates; Syft scans
require no registry access after provisioning has pre-pulled its pinned image.


## Cache policy

The node helper's `local-archive-v2` profile must change if cataloging policy changes,
so existing SBOMs are invalidated. A Syft image digest change also invalidates SBOM
cache entries. Findings cache identity includes SBOM hash, Grype version, DB hash
and scan policy. Invalid findings caches are regenerated with Grype. Used cache
objects are retained; unused objects expire after the configured retention period.


## Recovery

A killed runner can leave `.run-lock/owner.json` under the output root. Confirm no
runner remains before removing that specific stale lock. Locks are not stolen
automatically. Normal helper timeout paths remove their scanner container; inspect
and clean up orphaned `kestra-audit-*` containers only after verifying ownership.


See the [README](../README.md) for usage and the
[deployment runbook](https://github.com/pacificclimate/portainer-deployment/blob/main/apps/live/kestra/software-audit.md)
for installation and site configuration.
