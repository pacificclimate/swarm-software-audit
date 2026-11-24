import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('inventory',Path(__file__).resolve().parents[1] / 'inventory.py')
inventory=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(inventory)
NOW=1800000000
PIN='sha256:'+'a'*64
LABEL=inventory.LABEL

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root=Path(self.temporary.name)
        for tier in ('live','recovery'):
            directory=root/tier/'web'; directory.mkdir(parents=True)
            (directory/'docker-compose.yaml').write_text('''services:
  frontend:
    image: example/web:latest
    environment: {PASSWORD: must-not-export}
    networks: [backend]
    deploy:
      labels: ['traefik.http.routers.web.rule=PathPrefix(`/`)']
networks:
''')
        self.config=dict(prometheus_url='https://prometheus.example.org',compose_root=str(root),
            platform='linux/amd64',max_sample_age_seconds=300,clusters={
                'production':dict(instances=['node01.example.org:43927','node02.example.org:43927'],
                                  compose_sources=[dict(directory='live',stack_prefix='live-')]),
                'recovery':dict(instances=['node03.example.org:43927'],
                                compose_sources=[dict(directory='recovery',stack_prefix='live-')])})
        self.instances=[instance for site in self.config['clusters'].values() for instance in site['instances']]
        self.rows=[self.row(instance) for instance in self.instances]
        self.health=[dict(metric=dict(instance=instance),value=[NOW,'1']) for instance in self.instances]
        self.requests=[]

    def row(self,instance,image='example/web:1@'+PIN,service='live-web_frontend',stamp=NOW):
        return dict(metric=dict(instance=instance,image=image,**{LABEL:service}),value=[NOW,str(stamp)])

    def export(self,rows=None,health=None,config=None,**kwargs):
        def fetch(base,expression):
            self.requests.append(expression)
            return (self.health if health is None else health) if expression.startswith('up *') else (self.rows if rows is None else rows)
        return inventory.export(config or self.config,fetch=fetch,clock=lambda:NOW,**kwargs)

    def test_deduplicates_digests_and_keeps_deployment_observations(self):
        result=self.export()
        self.assertEqual(len(result['images']),1)
        target=result['images'][0]
        self.assertEqual(target['reference'],'docker.io/example/web@'+PIN)
        self.assertEqual(len(target['services']),2)
        self.assertEqual(sum(len(service['observations']) for service in target['services']),3)
        self.assertTrue(all(service['routing']=='traefik' for service in target['services']))
        self.assertNotIn('must-not-export',json.dumps(result))
        self.assertIn('timestamp(container_start_time_seconds',self.requests[1])

    def test_missing_digests_are_separate_and_scope_is_literal(self):
        rows=self.rows+[self.row(self.instances[0],image='portainer/agent:lts',service='agent')]
        result=self.export(rows)
        self.assertEqual(result['unassessed'][0]['reference'],'docker.io/portainer/agent:lts')
        self.assertEqual(result['unassessed'][0]['reason'],'missing-digest')
        self.assertEqual(self.export(rows,service_prefix='live-')['unassessed'],[])
        result=self.export([self.row(instance,image='portainer/agent:lts',service='agent') for instance in self.instances])
        self.assertEqual(result['images'],[])
        self.assertEqual(len(result['unassessed']),1)

    def test_rejects_regex_and_oversized_prefix_before_querying(self):
        for prefix in ('(a+)+$', 'live-.*', 'a'*129, 'live;id'):
            self.requests=[]
            with self.subTest(prefix=prefix),self.assertRaisesRegex(ValueError,'Service prefix'):
                self.export(service_prefix=prefix)
            self.assertEqual(self.requests,[])

    def test_missing_down_stale_or_future_data_fail(self):
        for health in (self.health[:-1],[dict(row,value=[NOW,'0']) for row in self.health]):
            with self.assertRaisesRegex(ValueError,'scrape down'):
                self.export(health=health)
        with self.assertRaisesRegex(ValueError,'no container inventory'):
            self.export(rows=self.rows[:-1])
        for stamp in (NOW-301,NOW+61,float('nan')):
            with self.subTest(stamp=stamp),self.assertRaisesRegex(ValueError,'stale image'):
                self.export(rows=self.rows+[self.row(self.instances[0],stamp=stamp)])

    def test_unknown_nodes_bad_digests_and_configuration_fail(self):
        with self.assertRaisesRegex(ValueError,'unknown Swarm target'):
            self.export(rows=self.rows+[self.row('unknown.example.org:43927')])
        with self.assertRaisesRegex(ValueError,'invalid deployed'):
            self.export(rows=self.rows+[self.row(self.instances[0],image='example/web@sha256:bad')])
        with self.assertRaisesRegex(ValueError,'Unknown cluster'):
            self.export(clusters='missing')
        value=self.export(clusters='recovery')
        self.assertEqual({service['cluster'] for target in value['images'] for service in target['services']},{'recovery'})
        bad=copy.deepcopy(self.config)
        bad['clusters']['recovery']['instances']=[self.instances[0]]
        with self.assertRaisesRegex(ValueError,'unique instance'):
            self.export(config=bad)

    def test_http_and_https_are_supported_and_credentials_are_rejected(self):
        value=copy.deepcopy(self.config); value['prometheus_url']='http://prometheus.example.org'
        self.assertTrue(self.export(config=value)['images'])
        value['prometheus_url']='https://user:password@prometheus.example.org'
        with self.assertRaises(ValueError): self.export(config=value)

    def test_routing_refreshes_and_network_membership_is_not_a_route(self):
        path=Path(self.config['compose_root'])/'live/web/docker-compose.yaml'
        path.write_text('''services:
  frontend:
    networks: [web_ingress]
networks: {web_ingress: {external: true}}
''')
        first=self.export()
        production=next(service for service in first['images'][0]['services'] if service['cluster']=='production')
        self.assertEqual(production['routing'],'unknown')
        path.write_text('''services:
  frontend:
    deploy:
      labels: {traefik.enable: 'false'}
''')
        second=self.export()
        production=next(service for service in second['images'][0]['services'] if service['cluster']=='production')
        self.assertEqual(production['routing'],'none')
        self.assertNotEqual(first['provenance']['routing_configuration']['files'],second['provenance']['routing_configuration']['files'])
        bad=copy.deepcopy(self.config)
        bad['clusters']['production']['compose_sources'][0]['directory']='../outside'
        with self.assertRaisesRegex(ValueError,'inside compose_root'): self.export(config=bad)

    def test_invalid_yaml_does_not_echo_configuration_secrets(self):
        path=Path(self.config['compose_root'])/'live/web/docker-compose.yaml'
        path.write_text('services: {web: {password: "must-not-leak}')
        with self.assertRaisesRegex(ValueError,'Invalid Compose YAML') as raised:
            self.export()
        self.assertNotIn('must-not-leak',str(raised.exception))

    def test_kestra_output_is_structured_and_cli_failure_is_nonzero(self):
        value=self.export()
        with patch('sys.stdout',new_callable=io.StringIO) as output:
            inventory.emit_inventory(value)
        line=output.getvalue().strip()
        self.assertEqual(json.loads(line[2:-2])['outputs']['inventory'],value)
        with patch('sys.argv',['inventory.py','--config','/missing-config.json']),patch('sys.stderr',new_callable=io.StringIO):
            self.assertEqual(inventory.main(),2)

if __name__=='__main__': unittest.main()
