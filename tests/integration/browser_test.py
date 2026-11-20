#!/usr/bin/env python3
"""Test the local fixture report with an already installed headless Chromium."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

CHECKS = '''<script>
function assertAudit(value,message){if(!value)throw new Error(message);}
try {
 assertAudit(document.querySelectorAll('#rows tr').length>0,'initial rows missing');
 const search=document.getElementById('search');
 search.value='no-such-audit-package-987654';search.dispatchEvent(new Event('input'));
 assertAudit(document.querySelectorAll('#rows tr').length===0,'search failed');
 search.value='';search.dispatchEvent(new Event('input'));
 const severity=document.getElementById('severity');
 severity.value=severity.options[1].value;severity.dispatchEvent(new Event('input'));
 assertAudit([...document.querySelectorAll('#rows tr')].every(row=>row.children[3].textContent===severity.value),'severity filter failed');
 severity.value='';severity.dispatchEvent(new Event('input'));
 const fix=document.getElementById('fix');fix.value='yes';fix.dispatchEvent(new Event('input'));
 assertAudit([...document.querySelectorAll('#rows tr')].every(row=>row.children[6].textContent!=='—'),'fix filter failed');
 fix.value='';fix.dispatchEvent(new Event('input'));
 if(data.rows.length>100){document.getElementById('next').click();assertAudit(document.getElementById('page').textContent.startsWith('Page 2 '),'pagination failed');document.getElementById('previous').click();}
 assertAudit(!document.getElementById('audit-data').textContent.includes('must-never-appear-in-report'),'fixture secret leaked');
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
    print('Chromium: search, severity/fix filters, pagination and secret redaction passed')


if __name__ == '__main__':
    main()
