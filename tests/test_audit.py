import copy
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open, patch

REPO = Path(__file__).resolve().parents[1]
SUPPORT = REPO


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


audit = module('audit', SUPPORT / 'audit.py')
host = module('host', REPO / 'host/host.py')
dispatch = module('dispatch', REPO / 'host/dispatch.py')
ID = 'sha256:' + 'a' * 64
SCANNER = {'image': 'anchore/syft@sha256:' + 'b' * 64, 'scope': 'squashed', 'profile': 'local-archive-v2'}
IMAGE = {'id': ID, 'os': 'linux', 'architecture': 'amd64', 'variant': '', 'layers': ['sha256:layer'], 'tags': ['demo:latest']}
HOST_CONFIG = {'syft_image': SCANNER['image'], 'workspace_uid': 1111, 'workspace_gid': 1111}
SBOM = {'artifacts': [], 'source': {'metadata': {'imageID': ID}}}
NODES = [{'cluster': 'primary', 'name': 'one', 'host': 'one.example'},
         {'cluster': 'secondary', 'name': 'two', 'host': 'two.example'}]


def inventory():
    return {'schema': 1, 'scanner': copy.deepcopy(SCANNER), 'images': [copy.deepcopy(IMAGE)], 'containers': []}


class SecurityTests(unittest.TestCase):
    def test_privileged_request_read_has_a_deadline(self):
        config = SimpleNamespace(read_text=lambda: json.dumps({'syft_image': SCANNER['image']}))
        stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps({'image_id': ID}).encode()))
        with patch.object(host, 'CONFIG', config), patch.object(host.sys, 'argv', ['helper', 'sbom-v1']), \
             patch.object(host.sys, 'stdin', stdin), patch.object(host.sys, 'stdout', io.StringIO()), \
             patch.object(host.signal, 'alarm') as alarm, patch.object(host.fcntl, 'flock'), \
             patch('builtins.open', mock_open()), patch.object(host, 'sbom', return_value=SBOM):
            host.main()
        self.assertEqual([call.args[0] for call in alarm.call_args_list], [20, 0])

    def test_exact_dispatch_only(self):
        for command in ['', 'sh', 'audit inventory-v1; id', 'audit sbom-v1 --privileged', ' audit inventory-v1', 'internal-sftp']:
            with self.subTest(command=command), patch.dict(os.environ, SSH_ORIGINAL_COMMAND=command), patch.object(dispatch.os, 'execve') as execute:
                self.assertEqual(dispatch.main(), 126)
                execute.assert_not_called()
        with patch.dict(os.environ, SSH_ORIGINAL_COMMAND='audit sbom-v1'), patch.object(dispatch.os, 'execve') as execute:
            dispatch.main()
            self.assertEqual(execute.call_args.args[1][-2:], ['/usr/local/libexec/kestra-audit-root', 'sbom-v1'])

    def test_reject_request_injection(self):
        for value in [b'{}', b'[]', b'{"image_id":"alpine:latest"}',
                      json.dumps({'image_id': ID, 'args': '--privileged'}).encode(),
                      json.dumps({'image_id': ID + '; id'}).encode(), b'x' * 257]:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                host.validate_request(value)
        self.assertEqual(host.validate_request(json.dumps({'image_id': ID}).encode()), ID)

    def test_raw_config_removed_from_sbom(self):
        value = copy.deepcopy(SBOM)
        value['source']['metadata'].update(rawConfig='PASSWORD=secret', rawManifest='anything', unknown='secret')
        self.assertEqual(host.sanitize_sbom(value), SBOM)

    def test_inventory_projects_metadata(self):
        image = {'Id': ID, 'RepoTags': ['demo'], 'Config': {'Env': ['PASSWORD=secret']}}
        container = {'Id': 'container', 'Image': ID, 'Config': {'Image': 'demo', 'Env': ['PASSWORD=secret'],
                     'Labels': {'com.docker.swarm.service.name': 'service', 'password': 'secret'}}}

        def docker(*args, **kwargs):
            if args[:2] == ('image', 'ls'):
                return ID.encode()
            if args[:2] == ('container', 'ls'):
                return b'container'
            return b'{"Swarm":{"NodeID":"node"},"ID":"engine","secret":"secret"}'

        with patch.object(host, 'docker', side_effect=docker), patch.object(host, 'inspect', side_effect=[image, container]):
            result = host.inventory({'syft_image': SCANNER['image']})
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(result['containers'][0]['service'], 'service')

    def test_targets_cannot_inject_ssh_options(self):
        for field, value in [('host', '-oProxyCommand=id'), ('host', 'host;id'), ('port', '22;id')]:
            nodes = copy.deepcopy(NODES)
            nodes[0][field] = value
            with self.assertRaises(ValueError):
                audit.validate_nodes({'nodes': nodes})


class CollectionTests(unittest.TestCase):
    def test_dedup_cache_and_node_associations(self):
        calls = []

        def remote(node, operation, *args):
            calls.append(operation)
            return inventory() if operation == 'inventory-v1' else copy.deepcopy(SBOM)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            records, images, errors = audit.collect(NODES, root, None, None, remote)
            self.assertEqual(errors, [])
            self.assertEqual(len(images), 1)
            self.assertEqual(len(images[0]['locations']), 2)
            self.assertEqual(calls.count('sbom-v1'), 1)
            self.assertEqual({r['service'] for r in audit.report_rows(records, images)}, {'(local-only)'})
            _, images, _ = audit.collect(NODES, root, None, None, remote)
            self.assertTrue(images[0]['cached'])
            self.assertEqual(calls.count('sbom-v1'), 1)

    def test_fallback_to_another_holder(self):
        def remote(node, operation, *args):
            if operation == 'inventory-v1':
                return inventory()
            if node['name'] == 'one':
                raise TimeoutError()
            return copy.deepcopy(SBOM)
        with tempfile.TemporaryDirectory() as temp:
            _, images, errors = audit.collect(NODES, Path(temp), None, None, remote)
            self.assertEqual(images[0]['status'], 'ok')
            self.assertEqual(errors, [])

    def test_unreachable_node_is_not_empty_success(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(audit, 'ssh', side_effect=TimeoutError()):
                records, images, errors = audit.collect(NODES, Path(temp), None, None,
                                                       remote=lambda *args: (_ for _ in ()).throw(TimeoutError()))
            self.assertEqual(len(errors), 2)
            self.assertEqual(images, [])
            self.assertTrue(all(n['status'] == 'failed' for n in records))

    def test_wrong_image_sbom_is_rejected(self):
        wrong = copy.deepcopy(SBOM)
        wrong['source']['metadata']['imageID'] = 'sha256:' + 'c' * 64
        with tempfile.TemporaryDirectory() as temp:
            _, images, errors = audit.collect(NODES, Path(temp), None, None,
                remote=lambda n, op, *args: inventory() if op == 'inventory-v1' else wrong)
            self.assertEqual(images[0]['status'], 'failed')
            self.assertTrue(errors)

    def test_platform_and_scanner_invalidate_cache(self):
        original = audit.image_key(IMAGE, SCANNER)
        self.assertNotEqual(original, audit.image_key(dict(IMAGE, architecture='arm64'), SCANNER))
        self.assertNotEqual(original, audit.image_key(IMAGE, dict(SCANNER, profile='new')))

    def test_inventory_only_never_starts_scanner(self):
        calls = []
        def remote(node, operation, *args):
            calls.append(operation)
            return inventory()
        with tempfile.TemporaryDirectory() as temp:
            audit.collect(NODES, Path(temp), None, None, remote, inventory_only=True)
        self.assertEqual(calls, ['inventory-v1', 'inventory-v1'])


class FindingsCacheTests(unittest.TestCase):
    def fixture(self, root):
        value = dict(copy.deepcopy(SBOM), artifacts=[{'name': 'fixture'}])
        sbom = root / 'sbom.json'
        audit.atomic_json(sbom, {'sbom': value})
        image = {'status': 'ok', 'sbom': sbom, 'image': IMAGE}
        database = {'sha256': 'database-hash', 'grype': {'version': 'fixture'}}
        identity = audit.digest({'sbom': audit.digest(value), 'db': database['sha256'],
                                 'grype': database['grype'], 'policy': 'default-all-findings-v1'})
        cache = root / 'cache/findings' / (identity + '.json')
        valid = {'identity': identity, 'scanned_at': '2026-11-20T00:00:00+00:00', 'report': {'matches': []}}
        return image, database, cache, valid

    @staticmethod
    def grype(*args, **kwargs):
        kwargs['stdout'].write(json.dumps({'matches': []}))

    def test_invalid_cache_regenerated_and_reused(self):
        cases = ['{truncated', 'null', '[]', '{}',
                 {'identity': 'wrong', 'scanned_at': 'old', 'report': {'matches': []}},
                 {'identity': None, 'scanned_at': 'old', 'report': {'matches': []}},
                 {'scanned_at': '', 'report': {'matches': []}},
                 {'scanned_at': 123, 'report': {'matches': []}},
                 {'scanned_at': 'old', 'report': None},
                 {'scanned_at': 'old', 'report': {'matches': {}}}]
        for bad in cases:
            with self.subTest(cache=bad), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image, database, cache, valid = self.fixture(root)
                cache.parent.mkdir(parents=True)
                if isinstance(bad, str):
                    cache.write_text(bad)
                else:
                    audit.atomic_json(cache, dict(valid, **bad))
                with patch.object(audit.subprocess, 'run', side_effect=self.grype) as run:
                    self.assertEqual(audit.scan([image], root, root, {}, database), [])
                    self.assertEqual(image['scan_status'], 'ok')
                    self.assertEqual(audit.read_json(cache)['report'], {'matches': []})
                    self.assertEqual(audit.scan([image], root, root, {}, database), [])
                    run.assert_called_once()

    def test_valid_cache_does_not_run_grype(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, database, cache, valid = self.fixture(root)
            audit.atomic_json(cache, valid)
            with patch.object(audit.subprocess, 'run') as run:
                self.assertEqual(audit.scan([image], root, root, {}, database), [])
            run.assert_not_called()
            self.assertEqual(image['scanned_at'], valid['scanned_at'])

    def test_failed_regeneration_retries_next_run(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, database, cache, valid = self.fixture(root)
            audit.atomic_json(cache, {})
            with patch.object(audit.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'grype')):
                self.assertTrue(audit.scan([image], root, root, {}, database))
            self.assertEqual(image['scan_status'], 'failed')
            with patch.object(audit.subprocess, 'run', side_effect=self.grype) as run:
                self.assertEqual(audit.scan([image], root, root, {}, database), [])
            run.assert_called_once()
            self.assertEqual(image['scan_status'], 'ok')


class ReportTests(unittest.TestCase):
    def test_failed_database_publishes_coverage_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit.atomic_json(root / 'targets.json', {'nodes': NODES[:1]})
            (root / 'key').write_text('disposable test key')
            args = SimpleNamespace(root=root / 'output', targets=root / 'targets.json', key=root / 'key',
                                   known_hosts=root / 'known_hosts', clusters='', nodes='', inventory_only=False, retention_days=30)
            records = [dict(NODES[0], status='failed', error='TimeoutError')]
            previous_umask = os.umask(0o022)
            try:
                with patch.object(sys, 'stdout', io.StringIO()), \
                     patch.object(audit, 'collect', return_value=(records, [], ['one: inventory failed'])), \
                     patch.object(audit, 'prepare_database', side_effect=RuntimeError('untrusted raw error')):
                    self.assertEqual(audit.run(args), 2)
            finally:
                os.umask(previous_umask)
            self.assertFalse((args.root / '.run-lock').exists())
            self.assertFalse((args.root / 'published/last-successful.html').exists())
            self.assertIn('Database preparation failed (RuntimeError)', (args.root / 'published/index.html').read_text())
            self.assertNotIn('untrusted raw error', (args.root / 'published/index.html').read_text())
            self.assertEqual((args.root / 'runs').stat().st_mode & 0o777, 0o700)

    def test_empty_sbom_is_not_a_clean_assessment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = root / 'sbom.json'
            audit.atomic_json(cache, {'sbom': copy.deepcopy(SBOM)})
            images = [{'status': 'ok', 'sbom': cache, 'image': IMAGE}]
            with patch.object(audit.subprocess, 'run') as execute:
                errors = audit.scan(images, root, root, {}, {})
            execute.assert_not_called()
            self.assertEqual(images[0]['scan_status'], 'no-packages')
            self.assertTrue(errors)

    def test_safe_partial_publication_and_last_successful(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nodes = [dict(NODES[0], status='ok', inventory=inventory())]
            images = [{'image': IMAGE, 'locations': [{'cluster': 'primary', 'node': 'one', 'tags': ['</script><script>alert(1)</script>']}],
                       'status': 'ok', 'scan_status': 'ok', 'findings': []}]
            summary = {'run_id': '20261119T000000Z-aaaaaaaa', 'complete': True, 'nodes_total': 1, 'problems': []}
            audit.publish(root, summary, nodes, images)
            last = (root / 'published/last-successful.html').read_text()
            self.assertNotIn('</script><script>alert(1)</script>', last)
            self.assertIn('\\u003c/script', last)
            self.assertIn('href=\"last-successful.html\"', last)
            snapshot = (root / 'published/runs/20261119T000000Z-aaaaaaaa/index.html').read_text()
            self.assertIn('href=\"../../last-successful.html\"', snapshot)
            summary.update(run_id='20261119T000001Z-bbbbbbbb', complete=False, problems=['Node unavailable'])
            audit.publish(root, summary, nodes, images)
            self.assertEqual((root / 'published/last-successful.html').read_text(), last)
            self.assertIn('Node unavailable', (root / 'published/index.html').read_text())
            self.assertEqual((root / 'published/index.html').stat().st_mode & 0o777, 0o644)

    def test_zero_findings_is_distinct_from_failed_scan(self):
        nodes = [dict(NODES[0], inventory=inventory())]
        entry = {'image': IMAGE, 'locations': [{'cluster': 'primary', 'node': 'one', 'tags': []}], 'scan_status': 'ok'}
        self.assertEqual(audit.report_rows(nodes, [entry])[0]['severity'], 'None')
        entry['scan_status'] = 'failed'
        self.assertEqual(audit.report_rows(nodes, [entry])[0]['severity'], 'Unknown')



class ReleaseTests(unittest.TestCase):
    def test_release_helpers_match_checksums(self):
        import hashlib
        release = module('release', REPO / 'scripts/release_assets.py')
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            release.build(target)
            self.assertEqual({p.name for p in target.iterdir()}, {'host.py', 'dispatch.py', 'LICENSE', 'SHA256SUMS'})
            for line in (target / 'SHA256SUMS').read_text().splitlines():
                checksum, filename = line.split()
                self.assertEqual(checksum, hashlib.sha256((target / filename).read_bytes()).hexdigest())
            self.assertEqual((target / 'host.py').read_bytes(), (REPO / 'host/host.py').read_bytes())

    def test_example_targets_are_generic_and_valid(self):
        nodes = audit.validate_nodes(json.loads((REPO / 'examples/targets.json').read_text()))
        self.assertTrue(all(node['host'].endswith('.example.org') for node in nodes))


class ArchiveBoundaryTests(unittest.TestCase):
    def test_scanner_has_no_socket_or_daemon_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs = []
            def bounded(args, output, *unused):
                runs.append(args)
                if args[:2] == ['image', 'save']:
                    output.write(b'local archive')
                else:
                    archive_mount = next(a for a in args if ':/input/image.tar:' in a)
                    archive = Path(archive_mount.split('=', 1)[1].split(':/input/image.tar:', 1)[0])
                    self.assertEqual(archive.read_bytes(), b'local archive')
                    self.assertEqual(archive.stat().st_mode & 0o777, 0o400)
                    self.assertTrue(archive_mount.endswith(':ro'))
                    output.write(json.dumps(SBOM).encode())
            with patch.object(host, 'inspect', return_value={'Id': ID, 'Size': 100}), \
                 patch.object(host, 'workspace_settings', return_value=(root, 1000, 1)), \
                 patch.object(host.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**9)), \
                 patch.object(host, 'run_bounded', side_effect=bounded), patch.object(host, 'enter_workspace_identity'), \
                 patch.object(host.subprocess, 'run') as cleanup:
                self.assertEqual(host.sbom(HOST_CONFIG, ID), SBOM)
            command = runs[1]
            self.assertEqual(runs[0], ['image', 'save', ID])
            self.assertIn('--user=1111:1111', command)
            self.assertIn('docker-archive:/input/image.tar', command)
            self.assertIn('--network=none', command)
            self.assertIn('--security-opt=label=disable', command)
            self.assertFalse(any(arg.endswith(',Z') for arg in command))
            self.assertFalse(any('docker.sock' in arg or 'DOCKER_HOST' in arg for arg in command))
            self.assertEqual(sum(arg.startswith('--volume=') for arg in command), 2)
            self.assertEqual(list(root.iterdir()), [], 'temporary archive/scratch leaked')
            cleanup.assert_called_once()

    def test_scan_failure_removes_container_and_workspace(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(host, 'inspect', return_value={'Id': ID, 'Size': 100}), \
                 patch.object(host, 'workspace_settings', return_value=(root, 1000, 1)), \
                 patch.object(host.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**9)), \
                 patch.object(host, 'enter_workspace_identity'), patch.object(host.subprocess, 'run') as cleanup, \
                 patch.object(host, 'run_bounded', side_effect=subprocess.TimeoutExpired('scan', 900)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    host.sbom(HOST_CONFIG, ID)
            self.assertEqual(list(root.iterdir()), [])
            cleanup.assert_called_once()

    def test_refuses_low_space_and_oversize_before_export(self):
        with tempfile.TemporaryDirectory() as directory:
            for size, free, expected in [(100, 0, host.InsufficientWorkspaceSpace), (1001, 10**9, ValueError)]:
                with patch.object(host, 'inspect', return_value={'Id': ID, 'Size': size}), \
                     patch.object(host, 'workspace_settings', return_value=(Path(directory), 1000, 1)), \
                     patch.object(host.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)), \
                     patch.object(host, 'run_bounded') as execute, \
                     patch.object(host, 'enter_workspace_identity'):
                    with self.assertRaises(expected):
                        host.sbom(HOST_CONFIG, ID)
                    execute.assert_not_called()

    def test_workspace_rejects_symlink_and_writable_permissions(self):
        import stat
        config = dict(HOST_CONFIG, workspace_root='/var/lib/kestra-audit')
        for mode, owner in [(stat.S_IFDIR | 0o777, 0), (stat.S_IFLNK | 0o700, 0), (stat.S_IFDIR | 0o700, 1000), (stat.S_IFDIR | 0o700, 0)]:
            with patch.object(host.Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=owner, st_gid=1111)):
                with self.assertRaises(ValueError):
                    host.workspace_settings(config)
        with patch.object(host.Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1111, st_gid=1111)):
            root, maximum, reserve = host.workspace_settings(config)
            self.assertEqual(root, Path('/var/lib/kestra-audit'))
            self.assertEqual(maximum, 20 * 1024**3)
            self.assertEqual(reserve, 1024**3)

    def test_missing_mount_refuses_scan_even_if_workspace_directory_exists(self):
        config = dict(HOST_CONFIG, workspace_root='/storage/data/audit/work/node', workspace_mount='/storage/data')
        with patch.object(host.os.path, 'ismount', return_value=False):
            with self.assertRaisesRegex(ValueError, 'mount is unavailable'):
                host.workspace_settings(config)


    def test_storage_identity_is_used_for_files_and_only_docker_children_elevate(self):
        with patch.object(host.os, 'setgroups') as groups, \
             patch.object(host.os, 'setresgid') as gid, patch.object(host.os, 'setresuid') as uid, \
             patch.object(host.os, 'seteuid') as effective_uid, patch.object(host.os, 'setegid') as effective_gid:
            host.enter_workspace_identity(HOST_CONFIG)
            groups.assert_called_once_with([])
            gid.assert_called_once_with(1111, 1111, 0)
            uid.assert_called_once_with(1111, 1111, 0)
            host.docker_privileges()
            effective_uid.assert_called_once_with(0)
            effective_gid.assert_called_once_with(0)

    def test_rejects_root_missing_and_non_numeric_workspace_identity(self):
        for uid, gid in [(None, None), (0, 1111), (1111, 0), ('1111', 1111), (True, 1111)]:
            with self.subTest(uid=uid, gid=gid), self.assertRaises(ValueError):
                host.workspace_identity({'workspace_uid': uid, 'workspace_gid': gid})



if __name__ == '__main__':
    unittest.main()
