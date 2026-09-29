from pathlib import Path
import argparse, json, re

SKIP = {'.git', '.venv', 'venv', '__pycache__', 'node_modules', 'dist', 'build'}
MAX_BYTES = 1_000_000
PATTERNS = [
    ('AWS access key ID', re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('Private key material', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('Credential-like assignment', re.compile(r'''(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*[\'\"]?[A-Za-z0-9_./+=-]{12,}''')),
    ('GitHub token pattern', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b')),
]

def files(root):
    for p in root.rglob('*'):
        if not any(part in SKIP for part in p.parts) and p.is_file():
            try:
                if p.stat().st_size <= MAX_BYTES: yield p
            except OSError: pass

def item(rule, severity, path, line, message, fix):
    return {'rule':rule,'severity':severity,'file':path.as_posix(),'line':line,'message':message,'remediation':fix}

def scan(root):
    root=Path(root).resolve(); found=[]
    for p in files(root):
        try: lines=p.read_text(encoding='utf-8',errors='ignore').splitlines()
        except OSError: continue
        for n,line in enumerate(lines,1):
            for label,pattern in PATTERNS:
                if pattern.search(line):
                    found.append(item('VL001','high',p.relative_to(root),n,'Possible '+label+' detected; value redacted.','Revoke/rotate any real credential, remove it from source and use a secret manager.'))
                    break
        if p.name.lower()=='dockerfile' or p.name.lower().startswith('dockerfile.'):
            has_user=any(re.match(r'\s*USER\s+\S+',x,re.I) for x in lines)
            for n,line in enumerate(lines,1):
                if re.match(r'^\s*USER\s+root\b',line,re.I):
                    found.append(item('VL101','medium',p.relative_to(root),n,'Container explicitly runs as root.','Use a dedicated unprivileged user and USER instruction.'))
                if re.match(r'^\s*ADD\s+https?://',line,re.I):
                    found.append(item('VL102','low',p.relative_to(root),n,'ADD downloads a remote URL.','Verify artifact integrity; prefer checksum-verified download or COPY.'))
            if not has_user:
                found.append(item('VL103','low',p.relative_to(root),1,'No USER instruction found; image may run as root.','Add a non-root user and USER instruction where compatible.'))
    wf=root/'.github'/'workflows'
    if wf.is_dir():
        for p in wf.rglob('*'):
            if p.is_file() and p.suffix.lower() in {'.yml','.yaml'}:
                try: lines=p.read_text(encoding='utf-8',errors='ignore').splitlines()
                except OSError: continue
                for n,line in enumerate(lines,1):
                    if re.search(r'uses\s*:\s*[^#\s]+@(main|master|v[0-9]+)\s*(?:#.*)?$',line):
                        found.append(item('VL201','medium',p.relative_to(root),n,'Action reference uses mutable branch or version tag.','Pin third-party actions to a full commit SHA.'))
                    if re.search(r'(?i)\bpermissions\s*:\s*write-all',line):
                        found.append(item('VL202','medium',p.relative_to(root),n,'Workflow grants broad write-all permissions.','Use least-privilege token permissions.'))
    counts={s:sum(x['severity']==s for x in found) for s in ['critical','high','medium','low','info']}
    return {'tool':'VulnLens','version':'0.1.0','target':str(root),'summary':{'total':len(found),'by_severity':counts},'findings':found,'notice':'Heuristic results can have false positives and false negatives; review findings.'}

def main():
    ap=argparse.ArgumentParser(description='Local-first repository security checks')
    ap.add_argument('path',nargs='?',default='.'); ap.add_argument('--json',dest='json_file'); ap.add_argument('--fail-on',choices=['critical','high','medium','low','never'],default='never')
    args=ap.parse_args(); root=Path(args.path)
    if not root.is_dir(): ap.error('path must be a directory')
    report=scan(root); print('VulnLens 0.1.0 — %d finding(s)'%report['summary']['total'])
    for f in report['findings']: print('[%s] %s:%s %s — %s\n  Fix: %s'%(f['severity'].upper(),f['file'],f['line'],f['rule'],f['message'],f['remediation']))
    print(report['notice'])
    if args.json_file: Path(args.json_file).write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    rank={'critical':0,'high':1,'medium':2,'low':3,'never':99}
    return int(args.fail_on!='never' and any(rank[f['severity']]<=rank[args.fail_on] for f in report['findings']))

if __name__=='__main__': raise SystemExit(main())
