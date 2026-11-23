import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('audit', REPO / 'audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
ID = 'sha256:' + 'a' * 64
REFERENCE = 'registry.example.org/apps/web@' + ID
SBOM = {'artifacts': [], 'source': {'type': 'image', 'metadata': {'imageID': 'sha256:' + 'b' * 64}}}
IMAGE = {'id': ID}
VERSION = b'{"version":"fixture"}'


def inventory():
    return {'images': [{'reference': REFERENCE, 'platform': 'linux/amd64', 'services': [
        {'cluster': 'live', 'name': 'web', 'routing': 'traefik'},
        {'cluster': 'drac', 'name': 'web', 'routing': 'traefik'}]}]}


class RegistryTests(unittest.TestCase):
    def test_only_digest_pinned_registry_references_are_accepted(self):
        for reference in ['nginx:latest', 'docker.io/library/nginx:latest', 'dir:/etc',
                          'docker:nginx', 'registry.example.org/user:password@app@' + ID,
                          REFERENCE + ';id', '--config=/etc/passwd', 'pcic/web@' + ID]:
            value = inventory(); value['images'][0]['reference'] = reference
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                audit.validate_inventory(value)
        self.assertEqual(audit.validate_inventory(inventory())[0]['reference'], REFERENCE)

    def test_empty_duplicate_and_invalid_metadata_are_rejected(self):
        with self.assertRaises(ValueError): audit.validate_inventory({'images': []})
        value = inventory(); value['images'] *= 2
        with self.assertRaises(ValueError): audit.validate_inventory(value)
        for field, value in [('routing', 'public-proven'), ('state', 'imaginary'), ('name', 'bad;name')]:
            source = inventory(); source['images'][0]['services'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): audit.validate_inventory(source)
        source = inventory(); source['images'][0]['platform'] = '--config=/etc/passwd'
        with self.assertRaises(ValueError): audit.validate_inventory(source)

    def test_malformed_sboms_are_rejected_consistently(self):
        for value in [None, [], {}, {'artifacts': [], 'source': None},
                      {'artifacts': [], 'source': {'type': 'image', 'metadata': None}}]:
            with self.subTest(value=value), self.assertRaises(ValueError): audit.validate_sbom(value)

    def test_catalog_uses_registry_only_and_strips_image_config(self):
        value = copy.deepcopy(SBOM)
        value['source']['metadata'].update(rawConfig='PASSWORD=secret', rawManifest='secret')
        def execute(command, **kwargs):
            self.assertEqual(command[:3], ['syft', 'scan', 'registry:' + REFERENCE])
            self.assertIn('--platform=linux/amd64', command)
            self.assertEqual(kwargs['env']['SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY'], 'false')
            kwargs['stdout'].write(json.dumps(value).encode())
        with tempfile.TemporaryDirectory() as directory, patch.object(audit.subprocess, 'run', side_effect=execute):
            result = audit.registry_sbom(audit.validate_inventory(inventory())[0], Path(directory))
        self.assertNotIn('secret', json.dumps(result))
        # A registry index digest is distinct from the scanned configuration ID.
        self.assertNotEqual(result['source']['metadata']['imageID'], ID)

    def test_one_catalog_for_multiple_services_and_cache_reuse(self):
        calls = []
        def catalog(target, work): calls.append(target['reference']); return copy.deepcopy(SBOM)
        with tempfile.TemporaryDirectory() as directory, patch.object(audit.subprocess, 'check_output', return_value=VERSION):
            root = Path(directory); targets = audit.validate_inventory(inventory())
            images, errors = audit.collect(targets, root, root, catalog)
            self.assertEqual(errors, []); self.assertEqual(len(calls), 1)
            self.assertEqual(len(audit.report_associations(images)), 2)
            second, errors = audit.collect(targets, root, root, catalog)
            self.assertTrue(second[0]['cached']); self.assertEqual(len(calls), 1)
            cache = second[0]['sbom']; cache.write_text('{broken')
            audit.collect(targets, root, root, catalog)
            self.assertEqual(len(calls), 2)

    def test_platform_and_scanner_changes_invalidate_sbom_cache(self):
        targets = audit.validate_inventory(inventory()); calls = []
        def catalog(target, work): calls.append(target['platform']); return copy.deepcopy(SBOM)
        with tempfile.TemporaryDirectory() as directory, patch.object(audit.subprocess, 'check_output', return_value=VERSION) as version:
            root = Path(directory)
            first, _ = audit.collect(targets, root, root, catalog)
            targets[0]['platform'] = 'linux/arm64'
            second, _ = audit.collect(targets, root, root, catalog)
            self.assertNotEqual(first[0]['key'], second[0]['key'])
            version.return_value = b'{"version":"new"}'
            third, _ = audit.collect(targets, root, root, catalog)
            self.assertNotEqual(second[0]['key'], third[0]['key'])
            self.assertEqual(len(calls), 3)

    def test_unavailable_image_is_incomplete_without_hiding_other_images(self):
        value = inventory(); value['images'].append(dict(value['images'][0], reference=REFERENCE.replace('apps/web', 'apps/api')))
        def catalog(target, work):
            if 'apps/web@' in target['reference']: raise subprocess.CalledProcessError(1, 'syft')
            return copy.deepcopy(SBOM)
        with tempfile.TemporaryDirectory() as directory, patch.object(audit.subprocess, 'check_output', return_value=VERSION):
            root = Path(directory)
            images, errors = audit.collect(audit.validate_inventory(value), root, root, catalog)
            self.assertEqual([i['status'] for i in images], ['failed', 'ok'])
            self.assertEqual(len(errors), 1)


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
    def fixture(self, root):
        target = audit.validate_inventory(inventory())[0]
        sbom = root / 'sbom.json'
        value = copy.deepcopy(SBOM)
        value['artifacts'] = [{'name': 'demo', 'version': '1.0', 'type': 'deb'},
                              {'name': 'no-findings', 'version': '2.0', 'metadata': 'private'}]
        audit.atomic_json(sbom, {'sbom': value})
        return dict(key='fixture', image=IMAGE, reference=REFERENCE, platform='linux/amd64',
                    services=target['services'], status='ok', scan_status='ok', sbom=sbom, findings=[
                    {'artifact': {'name': 'demo', 'version': '1.0', 'type': 'deb'},
                     'vulnerability': {'id': 'CVE-demo', 'severity': 'High', 'fix': {'versions': ['2.0']}},
                     'matchDetails': [{'found': {'versionConstraint': '< 2.0'}}]}])

    def test_report_keeps_versions_distinct_and_deduplicates_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); image = self.fixture(root)
            row = audit.finding_rows(image)[0]
            self.assertEqual((row['version'], row['affected'], row['fix']), ('1.0', '< 2.0', '2.0'))
            summary = {'run_id': 'fixture', 'complete': True}
            audit.publish(root, summary, [image])
            page = (root / 'published/index.html').read_text()
            data = json.loads(page.split('<script id="audit-data" type="application/json">')[1].split('</script>')[0])
            self.assertEqual(len(data['associations']), 2)
            self.assertEqual(len(data['findings']['fixture']), 1)
            self.assertEqual(len(data['packages']['fixture']), 2)
            self.assertNotIn('private', json.dumps(data))
            self.assertEqual(summary['services_total'], 2)

    def test_partial_publication_preserves_last_success_and_escapes_package_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); image = self.fixture(root)
            image['services'][0]['service'] = '</script><script>alert(1)</script>'
            summary = {'run_id': '20261123T000000Z-aaaaaaaa', 'complete': True}
            audit.publish(root, summary, [image])
            successful = (root / 'published/last-successful.html').read_text()
            self.assertNotIn('</script><script>alert(1)</script>', successful)
            self.assertIn('\\u003c/script', successful)
            summary.update(run_id='20261123T000001Z-bbbbbbbb', complete=False)
            audit.publish(root, summary, [image])
            self.assertEqual((root / 'published/last-successful.html').read_text(), successful)
            snapshot = (root / 'published/runs/20261123T000001Z-bbbbbbbb/index.html').read_text()
            self.assertIn('../../last-successful.html', snapshot)

    def test_empty_package_catalog_is_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); sbom = root / 'sbom.json'
            audit.atomic_json(sbom, {'sbom': SBOM})
            image = dict(status='ok', sbom=sbom, image=IMAGE)
            with patch.object(audit.subprocess, 'run') as execute:
                self.assertTrue(audit.scan([image], root, root, {}, {}))
            execute.assert_not_called()
            self.assertEqual(image['scan_status'], 'no-packages')

    def test_database_failure_publishes_incomplete_report_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); image = self.fixture(root)
            audit.atomic_json(root / 'images.json', inventory())
            args = SimpleNamespace(images=root / 'images.json', root=root / 'output', clusters='', retention_days=30)
            previous = os.umask(0o022)
            try:
                with patch.object(audit, 'collect', return_value=([image], [])), \
                     patch.object(audit, 'prepare_database', side_effect=RuntimeError('private failure')), \
                     patch('sys.stdout', io.StringIO()):
                    self.assertEqual(audit.run(args), 2)
            finally: os.umask(previous)
            self.assertFalse((args.root / '.run-lock').exists())
            self.assertFalse((args.root / 'published/last-successful.html').exists())
            self.assertNotIn('private failure', (args.root / 'published/index.html').read_text())
            self.assertEqual((args.root / 'runs').stat().st_mode & 0o777, 0o700)

    def test_example_and_unknown_cluster(self):
        self.assertTrue(audit.validate_inventory(audit.read_json(REPO / 'examples/images.json')))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); audit.atomic_json(root / 'images.json', inventory())
            args = SimpleNamespace(images=root / 'images.json', root=root / 'output', clusters='missing', retention_days=30)
            with self.assertRaises(ValueError): audit.run(args)
            self.assertFalse(args.root.exists())


if __name__ == '__main__':
    unittest.main()
