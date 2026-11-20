#!/usr/bin/env python3
"""Sequential SSH collection, content-addressed SBOM cache, Grype, static report."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}\Z')


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x') as stream:
            json.dump(data, stream, separators=(',', ':'))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_json(path):
    return json.loads(Path(path).read_text())


def validate_nodes(config):
    nodes = config['nodes']
    if not nodes:
        raise ValueError('no targets configured')
    seen = set()
    for node in nodes:
        for field in ('name', 'cluster', 'host'):
            if not isinstance(node[field], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', node[field]):
                raise ValueError('invalid node ' + field)
        if not isinstance(node.get('port', 22), int) or not 1 <= node.get('port', 22) <= 65535:
            raise ValueError('invalid SSH port')
        if (node['cluster'], node['name']) in seen:
            raise ValueError('duplicate target')
        seen.add((node['cluster'], node['name']))
    return nodes


def ssh(node, operation, key, known_hosts, payload=None):
    command = ['ssh', '-F', '/dev/null', '-T', '-i', str(key), '-p', str(node.get('port', 22)),
               '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + str(known_hosts), '-o', 'GlobalKnownHostsFile=/dev/null',
               '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
               'kestra-audit@' + node['host'], 'audit ' + operation]
    # Bound memory use: large SBOM output is spooled to a local private file.
    with tempfile.TemporaryFile() as output:
        subprocess.run(command, input=json.dumps(payload).encode() if payload else b'',
                       stdout=output, stderr=subprocess.PIPE, check=True,
                       timeout=1000 if payload else 300)
        if output.tell() > 256 * 1024 * 1024:
            raise ValueError('response exceeds 256 MiB')
        output.seek(0)
        return json.load(output)


def image_key(image, scanner):
    if not IMAGE_ID.fullmatch(image['id']):
        raise ValueError('invalid image ID')
    return digest({'image_id': image['id'], 'os': image['os'], 'architecture': image['architecture'],
                   'variant': image.get('variant', ''), 'layers': image.get('layers', []), 'scanner': scanner})


def validate_sbom(sbom, identity):
    if not isinstance(sbom.get('artifacts'), list):
        raise ValueError('invalid Syft SBOM')
    if sbom.get('source', {}).get('metadata', {}).get('imageID') != identity:
        raise ValueError('SBOM image mismatch')


def collect(nodes, root, key, known_hosts, remote=ssh, inventory_only=False):
    records, problems = [], []
    groups = defaultdict(list)
    for node in nodes:
        record = dict(node, status='failed')
        records.append(record)
        try:
            value = remote(node, 'inventory-v1', key, known_hosts)
            if value['schema'] != 1 or not isinstance(value['containers'], list):
                raise ValueError('unsupported inventory schema')
            # Validate everything before accepting any image from this node.
            entries = [(image_key(image, value['scanner']), image) for image in value['images']]
            record.update(status='ok', inventory=value)
            for cache_key, image in entries:
                groups[cache_key].append((node, image, value['scanner']))
        except Exception as error:
            record['error'] = type(error).__name__
            problems.append(node['name'] + ': inventory failed (' + type(error).__name__ + ')')
    images = []
    for cache_key, candidates in sorted(groups.items()):
        node, image, scanner = candidates[0]
        result = {'key': cache_key, 'image': image, 'scanner': scanner, 'status': 'failed',
                  'locations': [{'cluster': n['cluster'], 'node': n['name'], 'tags': i['tags']}
                                for n, i, _ in candidates]}
        images.append(result)
        if inventory_only:
            result['status'] = 'skipped'
            continue
        cache = root / 'cache' / 'sboms' / (cache_key + '.json')
        try:
            cached = read_json(cache)
            validate_sbom(cached['sbom'], image['id'])
            if cached['scanner'] != scanner:
                raise ValueError('scanner cache mismatch')
            result.update(status='ok', sbom=cache, cataloged_at=cached['cataloged_at'], cached=True)
            continue
        except (OSError, ValueError, KeyError, TypeError):
            pass
        # Retry another holder if an image disappears or a node fails mid-run.
        for holder, candidate, _ in candidates:
            try:
                value = remote(holder, 'sbom-v1', key, known_hosts, {'image_id': candidate['id']})
                validate_sbom(value, image['id'])
                stamp = now()
                atomic_json(cache, {'scanner': scanner, 'cataloged_at': stamp, 'sbom': value})
                result.update(status='ok', sbom=cache, cataloged_at=stamp, cached=False)
                break
            except Exception as error:
                result['error'] = type(error).__name__
        if result['status'] != 'ok':
            problems.append(image['id'] + ': SBOM generation failed')
    return records, images, problems


def grype_environment(database):
    return dict(os.environ, GRYPE_DB_CACHE_DIR=str(database), GRYPE_DB_AUTO_UPDATE='false',
                GRYPE_CHECK_FOR_APP_UPDATE='false', GRYPE_DB_VALIDATE_AGE='true',
                GRYPE_DB_MAX_ALLOWED_BUILT_AGE='120h')


def prepare_database(root, work):
    database = work / 'db'
    source = root / 'cache' / 'grype-db'
    if source.exists():
        shutil.copytree(source, database)
    else:
        database.mkdir()
    environment = grype_environment(database)
    version = subprocess.check_output(['grype', 'version', '-o', 'json'], env=environment, timeout=30)
    # A failed update makes this run incomplete, even if an older DB exists.
    subprocess.run(['grype', 'db', 'update'], env=environment, check=True, timeout=600,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    status = json.loads(subprocess.check_output(['grype', 'db', 'status', '-o', 'json'],
                                               env=environment, stderr=subprocess.PIPE, timeout=30))
    files = sorted(database.rglob('*.db'))
    if not files:
        raise ValueError('Grype database missing')
    checksum = hashlib.sha256()
    for file in files:
        with file.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                checksum.update(block)
    # The outer run lock serializes writers; scans use the private local copy.
    if source.exists():
        shutil.rmtree(source)
    shutil.copytree(database, source)
    return environment, {'status': status, 'sha256': checksum.hexdigest(),
                         'grype': json.loads(version), 'updated_at': now()}


def scan(images, root, work, environment, database):
    problems = []
    for image in images:
        if image['status'] != 'ok':
            continue
        value = read_json(image['sbom'])['sbom']
        image['package_count'] = len(value['artifacts'])
        if not value['artifacts']:
            image.update(scan_status='no-packages', scan_error='No packages cataloged')
            problems.append(image['image']['id'] + ': no packages cataloged; assessment unavailable')
            continue
        identity = digest({'sbom': digest(value), 'db': database['sha256'],
                           'grype': database['grype'], 'policy': 'default-all-findings-v1'})
        cache = root / 'cache' / 'findings' / (identity + '.json')
        try:
            finding = None
            try:
                cached = read_json(cache)
                if (cached['identity'] != identity
                        or not isinstance(cached['scanned_at'], str) or not cached['scanned_at']
                        or not isinstance(cached['report']['matches'], list)):
                    raise ValueError('invalid findings cache')
                finding = cached
            except (OSError, ValueError, KeyError, TypeError):
                pass
            if finding is None:
                target = work / 'image.sbom.json'
                atomic_json(target, value)
                output = work / 'findings.json'
                with output.open('w') as stream:
                    subprocess.run(['grype', 'sbom:' + str(target), '-o', 'json'], env=environment,
                                   stdout=stream, stderr=subprocess.PIPE, check=True, timeout=900)
                report = read_json(output)
                if not isinstance(report['matches'], list):
                    raise ValueError('invalid Grype output')
                finding = {'identity': identity, 'scanned_at': now(), 'report': report}
                atomic_json(cache, finding)
            cache.touch()
            image.update(scan_status='ok', findings=finding['report']['matches'], scanned_at=finding['scanned_at'])
        except Exception as error:
            image.update(scan_status='failed', scan_error=type(error).__name__)
            problems.append(image['image']['id'] + ': vulnerability scan failed')
    return problems


def report_rows(nodes, images):
    lookup = {(n['cluster'], n['name']): n.get('inventory', {}) for n in nodes}
    rows = []
    for entry in images:
        for location in entry['locations']:
            containers = [c for c in lookup[(location['cluster'], location['node'])].get('containers', [])
                          if c['image_id'] == entry['image']['id']]
            associations = sorted({(c['service'] or '(standalone)', c['state']) for c in containers})
            associations = associations or [('(local-only)', 'unused')]
            matches = entry.get('findings', [])
            for service, state in associations:
                common = dict(location, service=service, state=state, image_id=entry['image']['id'],
                              scan_status=entry.get('scan_status', 'failed'),
                              scanned_at=entry.get('scanned_at', ''), cataloged_at=entry.get('cataloged_at', ''))
                if not matches:
                    rows.append(dict(common, severity='Unknown' if common['scan_status'] != 'ok' else 'None',
                                     vulnerability='', package='', version='', fix=''))
                for match in matches:
                    vulnerability, artifact = match['vulnerability'], match['artifact']
                    rows.append(dict(common, severity=vulnerability.get('severity') or 'Unknown',
                                     vulnerability=vulnerability['id'], package=artifact['name'],
                                     version=artifact.get('version', ''),
                                     fix=', '.join(vulnerability.get('fix', {}).get('versions') or [])))
    return rows


def publish(root, summary, nodes, images):
    rows = report_rows(nodes, images)
    summary['unique_matches'] = sum(len(i.get('findings', [])) for i in images)
    summary['sbom_cache_hits'] = sum(bool(i.get('cached')) for i in images)
    summary['nodes_ok'] = sum(n['status'] == 'ok' for n in nodes)
    summary['images_total'] = len(images)
    summary['images_scanned'] = sum(i.get('scan_status') == 'ok' for i in images)
    private = root / 'runs' / summary['run_id']
    atomic_json(private / 'summary.json', summary)
    atomic_json(private / 'inventory.json', nodes)
    atomic_json(private / 'images.json', [{k: v for k, v in i.items() if k != 'sbom'} for i in images])
    # JSON embedded in HTML must never be able to terminate its script element.
    data = json.dumps({'summary': summary, 'nodes': [{k: v for k, v in n.items() if k != 'inventory'} for n in nodes],
                       'rows': rows}, separators=(',', ':')).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    template = Path(__file__).with_name('dashboard.html').read_text()
    def render(last_successful):
        return template.replace('AUDIT_LAST_SUCCESSFUL_URL', last_successful).replace('AUDIT_DATA_PLACEHOLDER', data)

    page = render('last-successful.html')
    published = root / 'published'
    published.mkdir(parents=True, exist_ok=True)
    published.chmod(0o755)
    (published / 'runs').mkdir(exist_ok=True)
    (published / 'runs').chmod(0o755)
    run = published / 'runs' / summary['run_id']
    run.mkdir(mode=0o755, exist_ok=False)
    (run / 'index.html').write_text(render('../../last-successful.html'))
    (run / 'index.html').chmod(0o644)
    # Atomic replacement keeps the last complete page visible until this is ready.
    latest = published / ('.index-' + summary['run_id'])
    latest.write_text(page)
    latest.chmod(0o644)
    os.replace(latest, published / 'index.html')
    if summary['complete']:
        successful = published / ('.successful-' + summary['run_id'])
        successful.write_text(page)
        successful.chmod(0o644)
        os.replace(successful, published / 'last-successful.html')
    return summary


def prune(root, days):
    cutoff = time.time() - days * 86400
    for parent in (root / 'runs', root / 'published' / 'runs'):
        if parent.exists():
            for child in parent.iterdir():
                if child.is_dir() and re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', child.name) and child.stat().st_mtime < cutoff:
                    shutil.rmtree(child)
    # Cache files are touched when used; only unused objects expire.
    for parent in (root / 'cache' / 'sboms', root / 'cache' / 'findings'):
        if parent.exists():
            for child in parent.glob('*.json'):
                if child.stat().st_mtime < cutoff:
                    child.unlink()


def run(args):
    os.umask(0o077)
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)
    nodes = validate_nodes(read_json(args.targets))
    if args.clusters:
        requested = set(args.clusters.split(','))
        if requested - {n['cluster'] for n in nodes}:
            raise ValueError('unknown cluster requested')
        nodes = [n for n in nodes if n['cluster'] in requested]
    if args.nodes:
        requested = set(args.nodes.split(','))
        if requested - {n['name'] for n in nodes}:
            raise ValueError('unknown node requested for selected clusters')
        nodes = [n for n in nodes if n['name'] in requested]
    # mkdir works across NFS clients; never silently steal an apparently stale lock.
    lock = root / '.run-lock'
    lock.mkdir()
    try:
        atomic_json(lock / 'owner.json', {'started_at': now(), 'pid': os.getpid()})
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
        summary = {'run_id': stamp, 'started_at': now(), 'nodes_total': len(nodes), 'problems': []}
        with tempfile.TemporaryDirectory(prefix='software-audit-') as directory:
            work = Path(directory)
            # Docker secret stays outside the script's logs and SSH insists on mode 0600.
            key = work / 'identity'
            key.write_bytes(args.key.read_bytes())
            key.chmod(0o600)
            records, images, problems = collect(nodes, root, key, args.known_hosts,
                                                inventory_only=args.inventory_only)
            summary['problems'].extend(problems)
            if not args.inventory_only:
                try:
                    environment, database = prepare_database(root, work)
                    summary['database'] = database
                    summary['problems'].extend(scan(images, root, work, environment, database))
                except Exception as error:
                    summary['problems'].append('Database preparation failed (' + type(error).__name__ + ')')
            else:
                summary['problems'].append('Inventory-only diagnostic run; vulnerability assessment skipped')
            for image in images:
                for cache in (root / 'cache' / 'sboms' / (image['key'] + '.json'),):
                    if cache.exists():
                        cache.touch()
            summary['finished_at'] = now()
            summary['complete'] = not summary['problems']
            publish(root, summary, records, images)
            prune(root, args.retention_days)
            print(json.dumps(summary, indent=2))
            return 0 if summary['complete'] else 2
    finally:
        (lock / 'owner.json').unlink(missing_ok=True)
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--targets', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--known-hosts', type=Path, required=True)
    parser.add_argument('--clusters', default='')
    parser.add_argument('--nodes', default='', help='optional comma-separated node names for a pilot run')
    parser.add_argument('--retention-days', type=int, default=30)
    parser.add_argument('--inventory-only', action='store_true')
    args = parser.parse_args()
    if args.retention_days < 1:
        parser.error('retention must be at least one day')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
