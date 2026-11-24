#!/usr/bin/env python3
"""Collect recent Swarm image observations from Prometheus and annotate Compose routing."""
import argparse
import sys
import json
import hashlib
import yaml
import math
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import urlopen

LABEL = 'container_label_com_docker_swarm_service_name'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\Z')


def query(base, expression):
    with urlopen(base + '/api/v1/query?' + urlencode({'query': expression}), timeout=30) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError('Prometheus response exceeds 16 MiB')
    payload = json.loads(raw)
    if payload.get('status') != 'success' or payload.get('warnings') or payload.get('infos'):
        raise ValueError('Prometheus query failed or returned partial-result annotations')
    if payload['data']['resultType'] != 'vector':
        raise ValueError('Expected a Prometheus instant vector')
    return payload['data']['result']


def reference(value, unpinned=False):
    repository, separator, digest = value.partition('@')
    if separator and (unpinned or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest)):
        raise ValueError('invalid deployed sha256 digest')
    if not separator and not unpinned:
        raise ValueError('missing deployed sha256 digest')
    tag = 'latest'
    if repository.rfind(':') > repository.rfind('/'):
        repository, tag = repository.rsplit(':', 1)
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', tag):
        raise ValueError('invalid image tag')
    first = repository.split('/')[0]
    if '/' not in repository or not ('.' in first or ':' in first or first == 'localhost'):
        repository = 'docker.io/' + repository
    repository = re.sub(r'^(?:index\.docker\.io|registry-1\.docker\.io)/', 'docker.io/', repository)
    if repository.startswith('docker.io/') and repository.count('/') == 1:
        repository = 'docker.io/library/' + repository.split('/', 1)[1]
    if not re.fullmatch(r'[a-z0-9][a-z0-9.:-]*/[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*', repository):
        raise ValueError('invalid registry repository')
    return repository + ('@' + digest if separator else ':' + tag)


def configured_routing(config, selected):
    candidates, files = defaultdict(list), {}
    config_root = Path(config.get('compose_root', '/deployment/apps')).resolve()
    roots = [(cluster, source) for cluster in sorted(selected)
             for source in config['clusters'][cluster].get('compose_sources', [])]
    for cluster, source in roots:
        tier = source['directory']
        root = (config_root / tier).resolve()
        if not root.is_relative_to(config_root):
            raise ValueError('Compose source directory must be inside compose_root')
        if not root.is_dir():
            raise ValueError('Missing synced Compose directory: ' + tier)
        for path in sorted(root.rglob('docker-compose.y*')):
            if path.suffix not in {'.yml', '.yaml'}:
                continue
            raw = path.read_bytes()
            if not path.resolve().is_relative_to(config_root):
                raise ValueError('Compose file escapes compose_root')
            relative = path.relative_to(config_root).as_posix()
            files[relative] = hashlib.sha256(raw).hexdigest()
            try:
                compose = yaml.safe_load(raw) or {}
            except yaml.YAMLError:
                raise ValueError('Invalid Compose YAML in ' + relative) from None
            project = path.parent.relative_to(root).as_posix()
            prefix = source.get('stack_prefix', '')
            aliases = {project, project if project.startswith(prefix) else prefix + project}
            for name, service in (compose.get('services') or {}).items():
                labels = (service.get('deploy') or {}).get('labels') or {}
                if isinstance(labels, list):
                    labels = dict(item.split('=', 1) if '=' in item else (item, '') for item in labels)
                labels = {str(key).lower(): str(value).lower() for key, value in labels.items()}
                enabled = labels.get('traefik.enable', '')
                routers = any(key.startswith(('traefik.http.routers.', 'traefik.tcp.routers.',
                                              'traefik.udp.routers.')) for key in labels)
                networks = service.get('networks') or []
                ingress = any(name == 'web_ingress' or ((compose.get('networks') or {}).get(name) or {}).get('name') == 'web_ingress'
                              for name in networks)
                implicit = ingress and labels.get('traefik-env') in {'dev', 'live'}
                category = ('traefik' if enabled != 'false' and (routers or enabled == 'true' or implicit)
                            else 'published-ports' if service.get('ports')
                            else 'none' if enabled == 'false' else 'unknown')
                for stack in aliases:
                    candidates[cluster + '/' + stack + '_' + name].append(category)
    services = {name: values[0] if len(set(values)) == 1 else 'unknown'
                for name, values in candidates.items()}
    return dict(source='Synced Compose deploy labels; stack names matched by project and tier prefix',
                files=files, services=services)


def export(config, clusters='', service_prefix='', fetch=query, clock=time.time):
    base = config['prometheus_url'].rstrip('/')
    parsed = urlsplit(base)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Expected a Prometheus URL without credentials, query or fragment')
    platform = config['platform']
    if not re.fullmatch(r'[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9_.-]+)?', platform):
        raise ValueError('Invalid explicitly configured platform')
    maximum_age = int(config.get('max_sample_age_seconds', 300))
    if not 30 <= maximum_age <= 3600:
        raise ValueError('max_sample_age_seconds must be between 30 and 3600 seconds')
    sites = config['clusters']
    if not sites or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in sites):
        raise ValueError('Invalid configured cluster names')
    selected = set(filter(None, clusters.split(','))) or set(sites)
    if selected - set(sites):
        raise ValueError('Unknown cluster requested')
    prefix = service_prefix
    if len(prefix) > 128 or any(character not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-' for character in prefix):
        raise ValueError('Service prefix must be at most 128 letters, digits, dots, underscores or hyphens')
    all_instances = {}
    for cluster, site in sites.items():
        if not site.get('instances'):
            raise ValueError('Expected at least one instance per configured cluster')
        for instance in site['instances']:
            if not isinstance(instance, str) or not instance or instance in all_instances:
                raise ValueError('Expected unique instance names across clusters')
            all_instances[instance] = cluster
    instances = {instance: cluster for instance, cluster in all_instances.items() if cluster in selected}
    # Compare underlying sample timestamps, not the API evaluation timestamp.
    health = fetch(base, f'up * (timestamp(up) > bool (time() - {maximum_age}))')
    healthy = defaultdict(list)
    for row in health:
        instance = row['metric'].get('instance')
        if instance in instances:
            healthy[instance].append(float(row['value'][1]))
    problems = [instance + ': scrape down, stale or absent' for instance in sorted(instances)
                if not healthy[instance] or any(value != 1 for value in healthy[instance])]
    expression = ('max by (image,instance,' + LABEL + ') '
                  '(timestamp(container_start_time_seconds{image!="",name!="",' + LABEL + '=~".+"}))')
    rows = fetch(base, expression)
    routing_config = configured_routing(config, selected)
    groups, unassessed, observed = defaultdict(dict), defaultdict(dict), set()
    checked_at = clock()
    for row in rows:
        labels = row['metric']
        instance, service = labels['instance'], labels[LABEL]
        if instance not in instances:
            # An unexpected Swarm target must not silently disappear from a full inventory.
            if instance not in all_instances:
                problems.append(instance + ': unknown Swarm target; update expected hosts')
            continue
        observed.add(instance)
        if not service.startswith(prefix):
            continue
        image = labels['image']
        stamp = float(row['value'][1])
        age = checked_at - stamp
        if not math.isfinite(stamp) or age > maximum_age or age < -60:
            problems.append(instance + ' / ' + service + ': stale image sample or clock mismatch')
            continue
        try:
            missing_digest = '@' not in image
            pinned = reference(image, unpinned=missing_digest)
        except ValueError as error:
            problems.append(instance + ' / ' + service + ' / ' + image + ': ' + str(error))
            continue
        if not NAME.fullmatch(service):
            problems.append(instance + ': invalid service name')
            continue
        cluster = instances[instance]
        destination = unassessed if missing_digest else groups
        entry = destination[(pinned, platform)].setdefault((cluster, service), dict(
            cluster=cluster, name=service, state='declared',
            routing=routing_config['services'].get(cluster + '/' + service, 'unknown'), observations=[]))
        entry['observations'].append(dict(instance=instance, sample_at=datetime.fromtimestamp(stamp, timezone.utc).isoformat()))
    problems.extend(instance + ': no container inventory samples' for instance in sorted(set(instances) - observed))
    if not groups and not unassessed:
        problems.append('No service images in the selected scope')
    if problems:
        raise ValueError('Inventory incomplete; no scan started:\n' + '\n'.join(sorted(set(problems))))
    return dict(source=f'Prometheus cAdvisor container observations; service prefix {prefix!r} (empty means all); platform configured {platform}; routing from Compose declarations; task state unverified',
                observed_at=datetime.fromtimestamp(checked_at, timezone.utc).isoformat(),
                provenance=dict(prometheus_url=base, query=expression, routing_configuration=routing_config,
                                max_sample_age_seconds=maximum_age,
                                expected_instances=sorted(instances), service_prefix=prefix,
                                scope='Recently scraped Swarm container metrics; excludes unused images and standalone containers'),
                images=[dict(reference=pinned, platform=platform, services=[services[key] for key in sorted(services)])
                        for (pinned, platform), services in sorted(groups.items())],
                unassessed=[dict(reference=ref, platform=platform, reason='missing-digest',
                                 services=[services[key] for key in sorted(services)])
                            for (ref, platform), services in sorted(unassessed.items())])


def emit_inventory(inventory):
    print('::' + json.dumps({'outputs': {'inventory': inventory}}, separators=(',', ':')) + '::')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True, help='collector JSON configuration')
    parser.add_argument('--clusters', default=os.environ.get('AUDIT_CLUSTERS', ''))
    parser.add_argument('--service-prefix', default=os.environ.get('SERVICE_PREFIX', ''))
    parser.add_argument('--kestra', action='store_true', help='emit structured Kestra output')
    args = parser.parse_args()
    try:
        inventory = export(json.loads(args.config.read_text()), args.clusters, args.service_prefix)
        if args.kestra:
            emit_inventory(inventory)
        else:
            print(json.dumps(inventory, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        print('Inventory collection failed: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
