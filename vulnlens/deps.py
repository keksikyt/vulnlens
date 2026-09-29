"""Opt-in OSV.dev audit for exact-pinned Python requirements."""
import argparse, json, re, sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ENDPOINT = 'https://api.osv.dev/v1/querybatch'
PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*(?:#.*)?$")

def parse_requirements(path):
    packages=[]; skipped=[]
    for number, raw in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
        line=raw.strip()
        if not line or line.startswith('#') or line.startswith(('-', '--')): continue
        match=PIN.match(line)
        if not match:
            skipped.append({'line':number,'requirement':line[:160],'reason':'Not an exact == pin; skipped safely'})
            continue
        name, version=match.groups()
        packages.append({'name':re.sub(r'[-_.]+','-',name).lower(),'version':version,'line':number})
    return packages, skipped

def query_osv(packages, timeout=20):
    if not packages: return []
    queries=[{'package':{'name':p['name'],'ecosystem':'PyPI'},'version':p['version']} for p in packages]
    payload=json.dumps({'queries':queries}).encode()
    req=Request(ENDPOINT,data=payload,headers={'Content-Type':'application/json','User-Agent':'VulnLens/0.2.0'},method='POST')
    try:
        with urlopen(req,timeout=timeout) as response: data=json.loads(response.read().decode())
    except (HTTPError,URLError,TimeoutError,json.JSONDecodeError) as exc:
        raise RuntimeError('OSV lookup failed: '+str(exc)) from exc
    if not isinstance(data, dict) or not isinstance(data.get('results'), list):
        raise RuntimeError('OSV lookup returned an invalid response shape')
    results = data['results']
    if len(results) != len(packages) or any(not isinstance(item, dict) for item in results):
        raise RuntimeError('OSV lookup returned an incomplete or invalid batch response')
    findings=[]
    for package,result in zip(packages,results):
        vulns = result.get('vulns', [])
        if not isinstance(vulns, list) or any(not isinstance(v, dict) for v in vulns):
            raise RuntimeError('OSV lookup returned an invalid vulnerability list')
        for vuln in vulns:
            aliases = vuln.get('aliases', [])
            references = vuln.get('references', [])
            if not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases):
                raise RuntimeError('OSV lookup returned invalid vulnerability aliases')
            if not isinstance(references, list) or any(not isinstance(x, dict) for x in references):
                raise RuntimeError('OSV lookup returned invalid vulnerability references')
            summary = vuln.get('summary') or vuln.get('details') or 'No summary provided.'
            if not isinstance(summary, str):
                summary = 'No summary provided.'
            findings.append({'package':package['name'],'version':package['version'],'line':package['line'],
                'id':vuln.get('id') if isinstance(vuln.get('id'), str) else 'UNKNOWN',
                'aliases':aliases,
                'summary':summary[:400],
                'references':[x['url'] for x in references if isinstance(x.get('url'), str) and x['url']][:5],
                'modified':vuln.get('modified') if isinstance(vuln.get('modified'), str) else None})
    return findings

def main(argv=None):
    parser=argparse.ArgumentParser(description='Audit exact-pinned Python requirements against OSV.dev')
    parser.add_argument('requirements',nargs='?',default='requirements.txt')
    parser.add_argument('--json',dest='json_file')\n    parser.add_argument('--offline', action='store_true', help='Do not contact OSV; report packages as not audited')
    args=parser.parse_args(argv); path=Path(args.requirements)
    if not path.is_file(): parser.error('requirements file not found: '+str(path))
    packages,skipped=parse_requirements(path)
    print('VulnLens OSV audit: %d exact-pinned packages; %d skipped.'%(len(packages),len(skipped)))
    try: findings=query_osv(packages)
    except RuntimeError as exc:
        print(str(exc),file=sys.stderr); return 2
    report={'tool':'VulnLens OSV audit','source':'https://osv.dev','requirements_file':str(path),
        'packages_checked':len(packages),'vulnerabilities':findings,'skipped':skipped,
        'notice':'Sends package names and exact versions to OSV.dev. Coverage is not exhaustive.'}
    print('Known vulnerability records: %d'%len(findings))
    for f in findings:
        print('[VULNERABLE] %s==%s — %s — %s'%(f['package'],f['version'],f['id'],f['summary'].splitlines()[0][:160]))
        for ref in f['references'][:2]: print('  '+ref)
    if args.json_file: Path(args.json_file).write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    return 1 if findings else 0

if __name__=='__main__': raise SystemExit(main())
