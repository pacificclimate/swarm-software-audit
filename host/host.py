#!/usr/bin/python3 -I
"""Root-owned audit helper. Never execute the config-sync copy as root."""
import json
import fcntl
import functools
import os
import resource
import shutil
import stat
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid

CONFIG = Path('/etc/kestra-audit/config.json')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/var/empty', 'DOCKER_CONFIG': '/etc/kestra-audit/docker'}
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']


def docker(*args, timeout=60):
    return subprocess.check_output(DOCKER + list(args), env=ENV, timeout=timeout, stderr=subprocess.PIPE)


def inspect(kind, identity):
    return json.loads(docker(kind, 'inspect', identity))[0]


def scanner(config):
    return {'image': config['syft_image'], 'scope': 'squashed', 'profile': 'local-archive-v2'}


def inventory(config):
    images = []
    for identity in sorted(set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().split())):
        image = inspect('image', identity)
        images.append({
            'id': image['Id'], 'tags': image.get('RepoTags') or [],
            'digests': image.get('RepoDigests') or [], 'os': image.get('Os', ''),
            'architecture': image.get('Architecture', ''), 'variant': image.get('Variant', ''),
            'size': image.get('Size', 0), 'layers': image.get('RootFS', {}).get('Layers', []),
        })
    containers = []
    for identity in docker('container', 'ls', '--all', '--quiet', '--no-trunc').decode().split():
        item = inspect('container', identity)
        labels = item.get('Config', {}).get('Labels') or {}
        containers.append({
            'id': item['Id'], 'name': item.get('Name', '').lstrip('/'),
            'image_id': item['Image'], 'image_ref': item.get('Config', {}).get('Image', ''),
            'state': item.get('State', {}).get('Status', ''),
            'service': labels.get('com.docker.swarm.service.name', ''),
            'task_id': labels.get('com.docker.swarm.task.id', ''),
            'stack': labels.get('com.docker.stack.namespace', ''),
        })
    # Explicit projection: Docker info/inspect contain sensitive configuration.
    info = json.loads(docker('info', '--format', '{{json .}}'))
    return {'schema': 1, 'scanner': scanner(config), 'node_id': info.get('Swarm', {}).get('NodeID', ''),
            'engine_id': info.get('ID', ''), 'images': images, 'containers': containers}


def validate_request(raw):
    if len(raw) > 256:
        raise ValueError('request too large')
    request = json.loads(raw)
    if not isinstance(request, dict) or set(request) != {'image_id'}:
        raise ValueError('expected image_id only')
    identity = request['image_id']
    if not isinstance(identity, str) or not IMAGE_ID.fullmatch(identity):
        raise ValueError('expected full sha256 image ID')
    return identity


def sanitize_sbom(sbom):
    # Syft may include the image's raw config (including baked-in environment).
    metadata = sbom.get('source', {}).get('metadata', {})
    for key in list(metadata):
        if key not in {'imageID', 'manifestDigest', 'mediaType', 'tags', 'size', 'layers',
                       'repoDigests', 'architecture', 'os', 'variant'}:
            del metadata[key]
    return sbom


MAX_SBOM_BYTES = 256 * 1024 * 1024


class InsufficientWorkspaceSpace(ValueError):
    pass


def workspace_identity(config):
    uid, gid = config.get('workspace_uid'), config.get('workspace_gid')
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0:
        raise ValueError('workspace requires a non-root numeric UID and GID')
    return uid, gid


def enter_workspace_identity(config):
    # Filesystem operations, parsing and cleanup use the storage identity, including
    # on root-squashed NFS. Saved root is used only by fixed Docker CLI children.
    uid, gid = workspace_identity(config)
    os.setgroups([])
    os.setresgid(gid, gid, 0)
    os.setresuid(uid, uid, 0)


def docker_privileges(maximum=None):
    # Runs only after fork, immediately before exec of the fixed Docker binary.
    # Keep the real UID so the storage-identity parent can kill a timed-out CLI.
    os.seteuid(0)
    os.setegid(0)
    if maximum is not None:
        file_size_limit(maximum)


def workspace_settings(config):
    root = Path(config.get('workspace_root', '/var/lib/kestra-audit'))
    if not root.is_absolute() or '..' in root.parts or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root)):
        raise ValueError('invalid workspace path')
    mount = config.get('workspace_mount')
    if mount is not None:
        mount = Path(mount)
        if not mount.is_absolute() or not os.path.ismount(mount) or mount.resolve() not in root.resolve().parents:
            raise ValueError('workspace storage mount is unavailable or does not contain workspace')
    info = root.lstat()
    uid, gid = workspace_identity(config)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
            or info.st_mode & 0o077):
        raise ValueError('workspace must be a private directory owned by its configured UID:GID')
    maximum = config.get('max_archive_bytes', 20 * 1024 ** 3)
    reserve = config.get('min_free_bytes', 1024 ** 3)
    if type(maximum) is not int or type(reserve) is not int or maximum <= 0 or reserve <= 0:
        raise ValueError('workspace limits must be positive integer byte counts')
    return root, maximum, reserve


def file_size_limit(maximum):
    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))


def run_bounded(args, output, workspace, reserve, maximum, deadline):
    # Limit each Docker CLI output file; scan scratch is also watched for low space.
    with tempfile.TemporaryFile(dir=workspace) as errors:
        with subprocess.Popen(DOCKER + args, env=ENV, stdout=output, stderr=errors,
                              preexec_fn=functools.partial(docker_privileges, maximum)) as process:
            try:
                while True:
                    if shutil.disk_usage(workspace).free < reserve:
                        raise InsufficientWorkspaceSpace('workspace reserve exhausted')
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(DOCKER + args, 900)
                    try:
                        status = process.wait(timeout=min(1, remaining))
                    except subprocess.TimeoutExpired:
                        continue
                    if status:
                        raise subprocess.CalledProcessError(status, DOCKER + args)
                    return
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def sbom(config, identity):
    deadline = time.monotonic() + 900
    image = inspect('image', identity)
    if image['Id'] != identity:
        raise ValueError('image identity changed')
    enter_workspace_identity(config)
    root, maximum, reserve = workspace_settings(config)
    size = int(image.get('Size', 0))
    if size < 0 or size > maximum:
        raise ValueError('image exceeds archive limit')
    if shutil.disk_usage(root).free < 2 * size + reserve + 16 * 1024 ** 2:
        raise InsufficientWorkspaceSpace('not enough space for archive and scan scratch')
    name = 'kestra-audit-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='scan-', dir=root) as directory:
        work = Path(directory)
        archive = work / 'image.tar'
        scratch = work / 'scratch'
        scratch.mkdir(mode=0o700)
        try:
            with archive.open('xb') as output:
                run_bounded(['image', 'save', identity], output, root, reserve, maximum, deadline)
            # The scanner can read only this archive and write only its private scratch.
            archive.chmod(0o400)
            uid, gid = workspace_identity(config)
            args = ['run', '--rm', '--pull=never', '--name', name, '--network=none', '--read-only',
                    '--user=' + str(uid) + ':' + str(gid), '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                    '--security-opt=label=disable',
                    '--pids-limit=128', '--cpus=0.5', '--memory=1g',
                    '--volume=' + str(archive) + ':/input/image.tar:ro',
                    '--volume=' + str(scratch) + ':/tmp:rw',
                    '--env=HOME=/tmp', '--env=SYFT_CHECK_FOR_APP_UPDATE=false', '--entrypoint=/syft',
                    config['syft_image'], 'scan', 'docker-archive:/input/image.tar', '--scope=squashed',
                    '-o', 'syft-json']
            with tempfile.TemporaryFile(dir=work) as output:
                run_bounded(args, output, root, reserve, MAX_SBOM_BYTES, deadline)
                if output.tell() > MAX_SBOM_BYTES:
                    raise ValueError('SBOM exceeds 256 MiB')
                output.seek(0)
                result = json.load(output)
            if result.get('source', {}).get('metadata', {}).get('imageID') != identity:
                raise ValueError('SBOM source does not match requested image')
            return sanitize_sbom(result)
        finally:
            subprocess.run(DOCKER + ['container', 'rm', '--force', name], env=ENV,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
                           preexec_fn=docker_privileges)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {'inventory-v1', 'sbom-v1'}:
        raise ValueError('operation denied')
    config = json.loads(CONFIG.read_text())
    if not re.fullmatch(r'anchore/syft@sha256:[0-9a-f]{64}', config['syft_image']):
        raise ValueError('scanner must be pinned by digest')
    if sys.argv[1] == 'inventory-v1':
        result = inventory(config)
    else:
        # An authenticated client must not keep a privileged reader open forever.
        signal.alarm(20)
        identity = validate_request(sys.stdin.buffer.read(257))
        signal.alarm(0)
        with open('/run/kestra-audit.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = sbom(config, identity)
    json.dump(result, sys.stdout)
    sys.stdout.write('\n')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never print raw subprocess output: image metadata may contain secrets.
        print('Audit operation failed: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
