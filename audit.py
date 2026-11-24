#!/usr/bin/env python3
"""Scan digest-pinned registry images with Syft and Grype; publish a static report."""
import argparse
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


ROUTING = {'traefik': 'Traefik configured', 'published-ports': 'Published ports',
           'none': 'No route observed', 'unknown': 'Unknown'}
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\Z')
PLATFORM = re.compile(r'[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9_.-]+)?\Z')
REFERENCE = re.compile(r'(?P<registry>[a-z0-9][a-z0-9.-]*(?::[0-9]+)?)/'
                       r'[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*'
                       r'(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?'
                       r'@sha256:[0-9a-f]{64}\Z')


UNPINNED_REFERENCE = re.compile(REFERENCE.pattern.replace(r'@sha256:[0-9a-f]{64}', ''))


def validate_inventory(config):
    targets, seen = [], set()
    entries = [(entry, False) for entry in config.get('images', [])]
    entries.extend((entry, True) for entry in config.get('unassessed', []))
    for entry, unassessed in entries:
        reference, platform = entry['reference'], entry.get('platform', 'linux/amd64')
        policy = UNPINNED_REFERENCE if unassessed else REFERENCE
        match = policy.fullmatch(reference) if isinstance(reference, str) else None
        if not match or not any(c in match['registry'] for c in '.:') and match['registry'] != 'localhost':
            raise ValueError('expected a fully qualified registry image; scanned images require a sha256 digest')
        if unassessed and entry.get('reason') != 'missing-digest':
            raise ValueError('unassessed images require reason missing-digest')
        if not isinstance(platform, str) or not PLATFORM.fullmatch(platform):
            raise ValueError('invalid image platform')
        if (reference, platform) in seen:
            raise ValueError('duplicate image and platform; combine their services in one entry')
        seen.add((reference, platform))
        services = entry.get('services') or [dict(cluster='unassigned', name='unassigned')]
        selected = []
        for service in services:
            if any(not isinstance(service.get(field), str) or not NAME.fullmatch(service[field])
                   for field in ('cluster', 'name')):
                raise ValueError('invalid service cluster or name')
            state, routing = service.get('state', 'declared'), service.get('routing', 'unknown')
            if state not in {'declared', 'running', 'stopped'} or routing not in ROUTING:
                raise ValueError('invalid service state or routing')
            selected.append(dict(cluster=service['cluster'], service=service['name'], state=state,
                                 routing=ROUTING[routing]))
        target = dict(reference=reference, platform=platform, services=selected)
        if unassessed:
            target['unassessed_reason'] = 'No scan — no deployed digest'
        targets.append(target)
    if not targets:
        raise ValueError('no registry images configured')
    return targets


def validate_sbom(sbom):
    if not isinstance(sbom, dict) or not isinstance(sbom.get('artifacts'), list):
        raise ValueError('invalid image SBOM')
    source = sbom.get('source')
    if not isinstance(source, dict) or source.get('type') != 'image' or not isinstance(source.get('metadata'), dict):
        raise ValueError('invalid image SBOM')
    identity = source['metadata'].get('imageID')
    if not isinstance(identity, str) or not IMAGE_ID.fullmatch(identity):
        raise ValueError('SBOM configuration identity missing')


def registry_sbom(target, work):
    # Explicit registry source prevents Docker-daemon or filesystem fallback.
    output = work / 'catalog.sbom.json'
    environment = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE='false',
                       SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY='false', SYFT_REGISTRY_INSECURE_USE_HTTP='false')
    with output.open('wb') as stream:
        subprocess.run(['syft', 'scan', 'registry:' + target['reference'],
                        '--platform=' + target['platform'], '--scope=squashed', '-o', 'syft-json'],
                       env=environment, stdout=stream, stderr=subprocess.PIPE, check=True, timeout=900)
    if output.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('SBOM exceeds 256 MiB')
    value = read_json(output)
    validate_sbom(value)
    metadata = value['source']['metadata']
    # Image configuration can contain baked-in environment values.
    for key in list(metadata):
        if key not in {'imageID', 'manifestDigest', 'mediaType', 'tags', 'size', 'layers',
                       'repoDigests', 'architecture', 'os', 'variant'}:
            del metadata[key]
    return value


def collect(targets, root, work, catalog=registry_sbom):
    images, problems = [], []
    try:
        version = (json.loads(subprocess.check_output(['syft', 'version', '-o', 'json'], timeout=30))
                   if any('unassessed_reason' not in target for target in targets) else {})
        scanner = {'syft': version, 'scope': 'squashed', 'profile': 'registry-v1'}
        scanner_error = None
    except Exception as error:
        scanner, scanner_error = {}, type(error).__name__
    for target in targets:
        key = digest(dict(reference=target['reference'], platform=target['platform'], scanner=scanner))
        identity = (target['reference'].split('@', 1)[1] if '@' in target['reference']
                    else 'unassessed:' + digest(dict(reference=target['reference'], platform=target['platform'])))
        result = dict(key=key, image={'id': identity},
                      reference=target['reference'], platform=target['platform'], scanner=scanner,
                      services=target['services'], status='failed')
        images.append(result)
        if 'unassessed_reason' in target:
            result.update(scan_status='unassessed', error=target['unassessed_reason'])
            problems.append(target['reference'] + ': ' + target['unassessed_reason'])
            continue
        if scanner_error:
            problems.append(target['reference'] + ': Syft unavailable (' + scanner_error + ')')
            continue
        cache = root / 'cache' / 'sboms' / (key + '.json')
        try:
            cached = read_json(cache)
            if (cached['reference'] != target['reference'] or cached['platform'] != target['platform']
                    or cached['scanner'] != scanner):
                raise ValueError('SBOM cache request mismatch')
            validate_sbom(cached['sbom'])
            result.update(status='ok', sbom=cache, cataloged_at=cached['cataloged_at'], cached=True)
            cache.touch()
            continue
        except (OSError, ValueError, KeyError, TypeError):
            pass
        try:
            value = catalog(target, work)
            validate_sbom(value)
            stamp = now()
            atomic_json(cache, dict(reference=target['reference'], platform=target['platform'],
                                    scanner=scanner, cataloged_at=stamp, sbom=value))
            result.update(status='ok', sbom=cache, cataloged_at=stamp, cached=False)
        except Exception as error:
            result['error'] = type(error).__name__
            problems.append(target['reference'] + ' [' + target['platform'] + ']: SBOM generation failed ('
                            + type(error).__name__ + ')')
    return images, problems


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


def report_associations(images):
    return [dict(service, tags=[entry['reference']], image_id=entry['image']['id'], image_key=entry['key'],
                 platform=entry['platform'], reference=entry['reference'],
                 scan_status=entry.get('scan_status', 'failed'), scan_error=entry.get('error', ''),
                 scanned_at=entry.get('scanned_at', ''),
                 cataloged_at=entry.get('cataloged_at', ''))
            for entry in images for service in entry['services']]


def finding_rows(entry):
    rows = []
    for match in entry.get('findings', []):
        vulnerability, artifact = match['vulnerability'], match['artifact']
        constraints = sorted({str(detail['found']['versionConstraint'])
                              for detail in (match.get('matchDetails') or [])
                              if isinstance(detail.get('found'), dict)
                              and detail['found'].get('versionConstraint')})
        rows.append(dict(severity=vulnerability.get('severity') or 'Unknown',
                         vulnerability=vulnerability['id'], package=artifact['name'],
                         version=artifact.get('version', ''), type=artifact.get('type', ''),
                         purl=artifact.get('purl', ''), namespace=vulnerability.get('namespace', ''),
                         aliases=sorted({v['id'] for v in (match.get('relatedVulnerabilities') or [])
                                         if v.get('id') and v['id'] != vulnerability['id']}),
                         affected='; '.join(constraints), advisory=vulnerability.get('dataSource', ''),
                         fix=', '.join(vulnerability.get('fix', {}).get('versions') or [])))
    return rows


def report_packages(images):
    catalogs = {}
    for entry in images:
        key = entry.get('key', entry['image']['id'])
        packages = None
        if entry.get('sbom') and entry['status'] == 'ok':
            value = read_json(entry['sbom'])['sbom']
            # A searchable projection, not the full SBOM or arbitrary package metadata.
            packages = [{field: artifact.get(field, '') for field in ('name', 'version', 'type', 'purl')}
                        for artifact in value['artifacts']]
        catalogs[key] = packages
    return catalogs


def publish(root, summary, images):
    summary['unique_matches'] = sum(len(i.get('findings', [])) for i in images)
    summary['sbom_cache_hits'] = sum(bool(i.get('cached')) for i in images)
    associations = report_associations(images)
    service_scans = {}
    for association in associations:
        service_scans.setdefault((association['cluster'], association['service']), []).append(association['scan_status'])
    summary['services_total'] = len(service_scans)
    summary['services_scanned'] = sum(all(status == 'ok' for status in statuses) for statuses in service_scans.values())
    summary['images_total'] = len(images)
    summary['images_scanned'] = sum(i.get('scan_status') == 'ok' for i in images)
    private = root / 'runs' / summary['run_id']
    atomic_json(private / 'summary.json', summary)
    atomic_json(private / 'images.json', [{k: v for k, v in i.items() if k != 'sbom'} for i in images])
    # JSON embedded in HTML must never be able to terminate its script element.
    data = json.dumps({'summary': summary,
                       'findings': {i['key']: finding_rows(i) for i in images},
                       'associations': associations, 'packages': report_packages(images)},
                      separators=(',', ':')).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
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
    inventory = read_json(args.images)
    targets = validate_inventory(inventory)
    if args.clusters:
        requested = set(args.clusters.split(','))
        known = {service['cluster'] for target in targets for service in target['services']}
        if requested - known:
            raise ValueError('unknown cluster requested')
        targets = [dict(target, services=[s for s in target['services'] if s['cluster'] in requested])
                   for target in targets]
        targets = [t for t in targets if t['services']]
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)
    lock = root / '.run-lock'
    lock.mkdir()
    try:
        atomic_json(lock / 'owner.json', {'started_at': now(), 'pid': os.getpid()})
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
        summary = {'run_id': stamp, 'started_at': now(), 'problems': [],
                   'inventory_source': inventory.get('source', 'Supplied image inventory'),
                   'inventory_observed_at': inventory.get('observed_at', '')}
        with tempfile.TemporaryDirectory(prefix='software-audit-') as directory:
            work = Path(directory)
            images, problems = collect(targets, root, work)
            warnings = {image['reference'] + ': ' + image['error'] for image in images
                        if image.get('scan_status') == 'unassessed'}
            summary['coverage_warnings'] = sorted(warnings)
            summary['problems'].extend(problem for problem in problems if problem not in warnings)
            if any(image['status'] == 'ok' for image in images):
                try:
                    environment, database = prepare_database(root, work)
                    summary['database'] = database
                    summary['problems'].extend(scan(images, root, work, environment, database))
                except Exception as error:
                    summary['problems'].append('Database preparation failed (' + type(error).__name__ + ')')
            summary['finished_at'] = now()
            summary['complete'] = not summary['problems'] and not summary['coverage_warnings']
            publish(root, summary, images)
            prune(root, args.retention_days)
            print(json.dumps(summary, indent=2))
            return 0 if not summary['problems'] else 2
    finally:
        (lock / 'owner.json').unlink(missing_ok=True)
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', type=Path, required=True, help='digest-pinned image/service inventory JSON')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--clusters', default='')
    parser.add_argument('--retention-days', type=int, default=30)
    args = parser.parse_args()
    if args.retention_days < 1:
        parser.error('retention must be at least one day')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
