"""Run inside the local runner on the disposable SSH-host network."""
import importlib.util
import json
import os
import pwd
from pathlib import Path
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('audit', '/opt/swarm-software-audit/audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
assert os.getuid() == 1111 and os.getgid() == 1111, 'runner must match Kestra UID:GID'
assert pwd.getpwuid(os.getuid()).pw_name == 'audit', 'OpenSSH requires a passwd entry'
key, known = Path('/test/key'), Path('/test/known_hosts')
node = {'cluster': 'local-test', 'name': 'fixture', 'host': 'audit-test-host'}
identity = Path('/test/image-id').read_text().strip()
root = Path('/test/results')
root.mkdir(exist_ok=True)

try:
    inventory = audit.ssh(node, 'inventory-v1', key, known)
except subprocess.CalledProcessError as error:
    print(error.stderr.decode())
    raise
assert 'must-never-appear-in-report' not in json.dumps(inventory)
selected = [image for image in inventory['images'] if image['id'] == identity]
assert len(selected) == 1, 'test image missing from inventory'
assert any(c['image_id'] == identity and c['state'] == 'created' for c in inventory['containers']), 'stopped container missing'

# Exact command restrictions over real SSH, including a shell injection attempt.
denied = subprocess.run(['ssh', '-F', '/dev/null', '-i', str(key), '-o', 'BatchMode=yes',
                        '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known),
                        'kestra-audit@audit-test-host', 'audit inventory-v1; id'], capture_output=True)
assert denied.returncode == 126, denied.stderr.decode()

calls = []


def remote(target, operation, key, known, payload=None):
    calls.append(operation)
    if operation == 'inventory-v1':
        result = dict(inventory)
        result['images'] = selected
        return result
    return audit.ssh(target, operation, key, known, payload)


records, images, problems = audit.collect([node], root, key, known, remote)
assert not problems, problems
assert images[0]['status'] == 'ok'
sbom = audit.read_json(images[0]['sbom'])['sbom']
assert 'must-never-appear-in-report' not in json.dumps(sbom)
assert len(sbom['artifacts']) > 0
_, second, problems = audit.collect([node], root, key, known, remote)
assert not problems and second[0]['cached']
assert calls.count('sbom-v1') == 1, 'cache did not avoid a second remote scan'
with tempfile.TemporaryDirectory() as directory:
    environment, database = audit.prepare_database(root, Path(directory))
    assert not audit.scan(images, root, Path(directory), environment, database)
    first_stamp = images[0]['scanned_at']
    assert not audit.scan(images, root, Path(directory), environment, database)
    assert images[0]['scanned_at'] == first_stamp, 'unchanged DB did not reuse findings'
summary = {'run_id': '20261119T000000Z-aaaaaaaa', 'started_at': audit.now(), 'finished_at': audit.now(),
           'complete': True, 'problems': [], 'nodes_total': 1, 'database': database}
audit.publish(root, summary, records, images)
assert (root / 'published/index.html').exists()
print(json.dumps({'result': 'passed', 'packages': len(sbom['artifacts']), 'matches': summary['unique_matches'],
                  'checks': ['runner UID:GID 1111:1111', 'real restricted SSH', 'stopped-container association', 'local Syft container',
                             'raw-config redaction', 'SBOM cache', 'Grype DB update', 'Grype scan/cache', 'HTML publication']}))
