#!/usr/bin/env python3
"""Test the local fixture report with an already installed headless Chromium."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

CHECKS = '''<script>
function assertAudit(value,message){if(!value)throw new Error(message);}
function selectAudit(id,value){const node=document.getElementById(id);node.value=value;node.dispatchEvent(new Event('input'));}
function openAuditDetails(){for(const node of document.querySelectorAll('#rows details')){node.open=true;node.dispatchEvent(new Event('toggle'));}}
try {
 assertAudit(groupedRows().every(g=>[...g.contexts.values()].every(c=>!el('routing').value||c.routing===el('routing').value)),'default routing scope failed');
 for(const id of ['routing','deployment'])selectAudit(id,'');
 assertAudit(document.querySelectorAll('#rows tr').length>0,'initial groups missing');
 selectAudit('search','no-such-audit-package-987654');
 assertAudit(document.querySelectorAll('#rows tr').length===0,'search failed');
 selectAudit('search','');
 const severity=document.getElementById('severity');
 selectAudit('severity',severity.options[1].value);
 assertAudit(groupedRows().every(g=>[...g.items.values()].every(r=>r.severity===severity.value)),'severity filter failed');
 selectAudit('severity',''); selectAudit('fix','yes'); openAuditDetails();
 assertAudit(!document.getElementById('rows').textContent.includes('Fixed in: Not provided'),'fix filter failed');
 selectAudit('fix','');
 for(const route of ['Traefik configured','No route observed','Unknown']){
  selectAudit('routing',route);
  assertAudit(groupedRows().every(g=>[...g.contexts.values()].every(c=>c.routing===route)),'routing filter failed');
 }
 selectAudit('routing',''); document.getElementById('packages-tab').click();
 assertAudit(document.getElementById('packages-tab').getAttribute('aria-selected')==='true','package tab failed');
 assertAudit(document.getElementById('severity-filter').hidden,'finding filters remained on package tab');
 const artifact=Object.values(data.packages).find(items=>items&&items.length)?.[0];
 assertAudit(Boolean(artifact),'fixture requires a package catalog');
 selectAudit('search',artifact.name);
 assertAudit(document.querySelectorAll('#rows tr').length>0,'package search failed');
 selectAudit('search','no-such-audit-package-987654');
 assertAudit(document.querySelectorAll('#rows tr').length===0,'package search did not filter');
 selectAudit('search','');
 document.getElementById('vulnerabilities-tab').click(); openAuditDetails();
 assertAudit(!document.querySelector('a[href^="javascript:"]'),'unsafe advisory link');
 assertAudit(!document.getElementById('audit-data').textContent.includes('must-never-appear-in-report'),'fixture secret leaked');
 // Regression fixture: the same package and advisory in two images must collapse,
 // while another installed version stays separate. Locations remain searchable.
 contextsByImage.clear(); data.findings={}; data.packages={};
 for(let i=0;i<3;i++){
  const key='fixture-'+i,version=i===2?'2.0':'1.0';
  const context={image_key:key,image_id:key,tags:[key],cluster:'fixture',reference:'registry.example.org/fixture@sha256:'+String(i).repeat(64),platform:'linux/amd64',service:'web-'+i,state:'running',routing:'Traefik configured',scan_status:'ok'};
  contextsByImage.set(key,[context]);
  const row={package:'shared-lib',name:'shared-lib',version,type:'deb',purl:'pkg:deb/shared-lib@'+version,
   vulnerability:'CVE-DEMO',severity:'High',affected:'< 3.0',fix:'3.0',advisory:'javascript:alert(1)'};
  data.findings[key]=[row]; data.packages[key]=[row];
 }
 selectAudit('grouping','package');
 assertAudit(document.querySelectorAll('#rows tr').length===2,'same packages did not collapse or versions merged');
 let first=document.querySelector('#rows tr');
 assertAudit(first.lastElementChild.textContent.includes('2 images'),'affected images were lost');
 openAuditDetails();
 assertAudit(first.textContent.includes('1 advisory matches'),'same CVE repeated per image');
 assertAudit(first.textContent.includes('web-0')&&first.textContent.includes('web-1'),'collapsed locations missing');
 assertAudit(!document.querySelector('a[href^="javascript:"]'),'grouped advisory link unsafe');
 selectAudit('search','web-1');
 assertAudit(document.querySelectorAll('#rows tr').length===1,'service search did not scope groups');
 assertAudit(document.querySelector('#rows tr').textContent.includes('1 images'),'image count ignored search scope');
 selectAudit('search',''); selectAudit('grouping','image');
 assertAudit(document.querySelectorAll('#rows tr').length===3,'image grouping failed');
 document.getElementById('packages-tab').click(); selectAudit('grouping','package');
 assertAudit(document.querySelectorAll('#rows tr').length===2,'SBOM packages did not collapse');
 // A missing SBOM remains visibly unavailable, rather than appearing clean.
 data.packages['fixture-2']=null; render();
 assertAudit(document.getElementById('rows').textContent.includes('SBOM unavailable'),'missing SBOM hidden');
 data.packages['fixture-1']=null; render();
 const missing=[...document.querySelectorAll('#rows tr')].filter(r=>r.firstElementChild.textContent==='SBOM unavailable');
 assertAudit(missing.length===1&&missing[0].textContent.includes('2 images'),'missing SBOMs repeated per image or coverage lost');
 // Pagination is over groups, not the original per-image matches.
 data.packages['fixture-0']=Array.from({length:55},(_,i)=>({name:'page-fixture-'+i,version:'1.0',type:'deb'}));
 render(); document.getElementById('next').click();
 assertAudit(document.getElementById('page').textContent.startsWith('Page 2 '),'group pagination failed');
 document.documentElement.dataset.auditTests='passed';
}catch(error){document.documentElement.dataset.auditTests=error.message;}
</script>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', type=Path, required=True)
    parser.add_argument('--report', type=Path, default=Path(__file__).with_name('preview.html'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='audit-browser-') as directory:
        work = Path(directory)
        page = work / 'index.html'
        page.write_text(args.report.read_text().replace('</body>', CHECKS + '</body>'))
        result = subprocess.check_output([str(args.browser), '--headless', '--no-sandbox', '--disable-gpu',
                                          '--disable-dev-shm-usage', '--user-data-dir=' + str(work / 'profile'),
                                          '--dump-dom', page.as_uri()], timeout=60).decode()
        status = re.search(r'data-audit-tests="([^"]+)"', result)
        if not status or status.group(1) != 'passed':
            raise RuntimeError(status.group(1) if status else 'dashboard did not execute')
    print('Chromium: grouping, deduplication, versions, locations, filters, missing SBOMs and safe rendering passed')


if __name__ == '__main__':
    main()
