#!/usr/bin/env python3
"""Disposable integration test. Refuses non-local Docker endpoints; no Swarm access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parents[2]


def docker(*args, **kwargs):
    return subprocess.check_output(['docker', *args], **kwargs).decode().strip()


def main():
    context = json.loads(docker('context', 'inspect'))[0]
    endpoint = os.environ.get('DOCKER_HOST', context['Endpoints']['docker']['Host'])
    if not endpoint.startswith('unix://'):
        raise SystemExit('Refusing integration test against a non-local Docker endpoint')
    suffix = uuid.uuid4().hex[:8]
    network, hostname, fixture, runner = ('audit-test-net-' + suffix, 'audit-test-host-' + suffix,
                                         'audit-test-stopped-' + suffix, 'audit-test-runner-' + suffix)
    volume = 'audit-test-workspace-' + suffix
    with tempfile.TemporaryDirectory(prefix='kestra-audit-local-') as temporary:
        work = Path(temporary)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(work / 'key')], check=True)
        (work / 'authorized_keys').write_text('restrict,command="/usr/local/libexec/kestra-audit-dispatch" ' + (work / 'key.pub').read_text())
        syft = json.loads(docker('image', 'inspect', 'anchore/syft:v1.57.2'))[0]['RepoDigests'][0]
        docker('volume', 'create', volume)
        mountpoint = json.loads(docker('volume', 'inspect', volume))[0]['Mountpoint']
        workspace = mountpoint + '/audit'
        (work / 'config.json').write_text(json.dumps({'syft_image': syft, 'workspace_root': workspace,
                                                   'workspace_uid': 1111, 'workspace_gid': 1111}))
        identity = json.loads(docker('image', 'inspect', 'swarm-software-audit-test-image:local'))[0]['Id']
        (work / 'image-id').write_text(identity)
        docker('network', 'create', network)
        try:
            docker('create', '--name', fixture, 'swarm-software-audit-test-image:local', 'true')
            docker('run', '-d', '--name', hostname, '--network', network, '--network-alias', 'audit-test-host',
                   '--mount', 'type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock',
                   '--mount', 'type=volume,source=' + volume + ',target=' + mountpoint,
                   'swarm-software-audit-test-host:local')
            docker('exec', hostname, 'mkdir', '-m', '700', workspace)
            docker('exec', hostname, 'chown', '1111:1111', workspace)
            docker('cp', str(work / 'authorized_keys'), hostname + ':/var/empty/kestra-audit/.ssh/authorized_keys')
            docker('exec', hostname, 'chmod', '644', '/var/empty/kestra-audit/.ssh/authorized_keys')
            docker('exec', hostname, 'chown', '0:0', '/var/empty/kestra-audit/.ssh/authorized_keys')
            assert docker('exec', hostname, 'stat', '-c', '%u %a', '/var/empty/kestra-audit/.ssh/authorized_keys') == '0 644'
            docker('cp', str(work / 'config.json'), hostname + ':/etc/kestra-audit/config.json')
            docker('cp', str(REPO / 'tests/integration/workspace_check.py'), hostname + ':/workspace_check.py')
            print(docker('exec', hostname, 'python3', '-I', '/workspace_check.py'))
            public = docker('exec', hostname, 'cat', '/etc/ssh/ssh_host_ed25519_key.pub')
            (work / 'known_hosts').write_text('audit-test-host ' + public + '\n')
            # Wait for the disposable local daemon, not any production host.
            for _ in range(30):
                try:
                    docker('exec', hostname, 'test', '-f', '/run/sshd.pid', stderr=subprocess.DEVNULL)
                    break
                except subprocess.CalledProcessError:
                    time.sleep(.2)
            subprocess.run(['docker', 'exec', hostname, '/usr/bin/sudo', '-u', 'kestra-audit', '/usr/bin/sudo', '-n',
                            '/usr/local/libexec/kestra-audit-root', 'inventory-v1'],
                           stdout=subprocess.DEVNULL, check=True)
            docker('create', '--name', runner, '--network', network,
                   '--entrypoint', 'python', 'pcic/swarm-software-audit:local', '/integration/check.py')
            docker('cp', str(REPO / 'tests/integration'), runner + ':/integration')
            docker('cp', str(work), runner + ':/test')
            subprocess.run(['docker', 'start', '--attach', runner], check=True)
            if docker('inspect', '--format', '{{.State.ExitCode}}', runner) != '0':
                raise RuntimeError('local runner failed')
            assert docker('exec', hostname, 'ls', '-A', workspace) == '', 'scan workspace leaked'
            # Save only the HTML artifact; never copy the generated test key into the repo.
            report = REPO / 'tests/integration/preview.html'
            docker('cp', runner + ':/test/results/published/index.html', str(report))
            print('Local preview: ' + str(report))
        except Exception:
            subprocess.run(['docker', 'logs', hostname], check=False)
            raise
        finally:
            for container in (runner, hostname, fixture):
                subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
