#!/usr/bin/env python3
"""On-demand proof selection. Never called by CI, release gates, or hooks."""
import argparse
import datetime
import hashlib
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ASK = ['crates/vox-tui/src/room_ask.rs',
       'apps/macos/Vox/RoomAsk.swift']
# Concrete boundaries of the unmapped hook/status/decline fixture. It never joins
# a room, posts a body, forwards a service, or drives a Session.
ASK_CLI = [
    'crates/vox-tui/src/' + name + '.rs' for name in
    ['room_ask', 'room_map', 'host', 'cli', 'agent_hook', 'agent_setup', 'agent_room',
     'setup', 'wake', 'coord', 'client', 'daemon', 'daemon_client', 'node_tasks', 'app']
]
ASK_CLI += ['crates/vox-core/src/node/' + name + '.rs' for name in
            ['daemonipc', 'paths', 'api', 'app', 'actor', 'channel']]
ASK_CLI += ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
            'crates/vox-tui/Cargo.toml', 'crates/vox-core/Cargo.toml']
ASK_APP = ASK_CLI + ['apps/macos/Vox/RoomAsk.swift', 'apps/macos/Vox/AppModel.swift',
                    'apps/macos/Vox/NodeModel.swift', 'apps/macos/VoxAppProofs/Stager.swift',
                    'scripts/app-proof-stager.py', 'scripts/app-proofs.sh', 'scripts/app-proofs-vm.py']

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()

def discover():
    rows = {}
    for file in sorted(ROOT.glob('crates/*/tests/*.rs')):
        text = file.read_text()
        package = re.search(r'^name\s*=\s*"([^"]+)"', (file.parent.parent/'Cargo.toml').read_text(), re.M)[1]
        optional_names=set()
        for macro in re.finditer(r'not_run!\s*\((.*?)\);',text,re.S):
            optional_names.update(re.findall(r'\b[a-z][a-z0-9_]+\b',macro[1]))
        file_optional=bool(re.search(r'#!\[cfg\(feature\s*=\s*"optional-proofs"',text))
        mask,_=lexical_mask(text)
        for m in re.finditer(r'(?P<attrs>(?:\s*#\[[^\n]+\]\s*)+)\s*(?:async\s+)?fn\s+(\w+)\s*\(', mask):
            if not re.search(r'#\[(?:tokio::)?test(?:\]|\()', m['attrs']):
                continue
            name = m[2]; optional=file_optional or name in optional_names or 'optional-proofs' in text[m.start():m.end()]; key = f'rust:{package}:{file.stem}:{name}'
            cmd = ['cargo', 'test', '--release', '-p', package, '--test', file.stem]
            manifest=(file.parent.parent/'Cargo.toml').read_text()
            features=[]
            if re.search(r'^test-knobs\s*=',manifest,re.M): features.append('test-knobs')
            if optional and re.search(r'^optional-proofs\s*=',manifest,re.M): features.append('optional-proofs')
            if features: cmd += ['--features',','.join(features)]
            cmd += [name, '--', '--exact', '--nocapture']
            if '#[ignore' in m['attrs']: cmd.append('--ignored')
            rows[key] = dict(id=key, kind='rust', source=str(file.relative_to(ROOT)), optional=optional, command=cmd)
    for file in sorted(ROOT.glob('apps/macos/*Proofs/*.swift')):
        mask,_=lexical_mask(file.read_text())
        for name in re.findall(r'^    func\s+(test\w+)\s*\(', mask,re.M):
            key = 'app:FirstRunProof/' + name
            rows[key] = dict(id=key, kind='app', source=str(file.relative_to(ROOT)), optional=False,
                             command=['scripts/app-proofs.sh', 'FirstRunProof/'+name])
    # Shell proofs have public entry points, not Cargo/XCTest functions.
    for path in ['scripts/family-lan-proof.sh']:
        if (ROOT/path).exists():
            key='shell:'+path
            rows[key]=dict(id=key,kind='manual',source=path,optional=True,command=[],
                           unavailable='real interface/registered helper privilege premise; automatic runner never uses sudo')
    rows['app:LaunchProof']=dict(id='app:LaunchProof',kind='app',source='scripts/app-launch-proof.py',optional=False,command=['scripts/app-proofs.sh','LaunchProof'])
    app='app:FirstRunProof/testSessionsAreDrivenWhereTheyAreShown'
    cli='rust:vox-tui:agent_hook_proof:a_session_works_in_the_room_its_start_directory_is_mapped_to'
    for key in [app, cli]:
        if key not in rows: raise RuntimeError('room-ask adapter has no existing proof: '+key)
        row=dict(rows[key]); row.update(id=key+'#room-ask', parent=key, step='room-ask', dependencies=list(ASK_APP if row['kind']=='app' else ASK_CLI))
        rows[row['id']]=row
    return rows

@lru_cache(maxsize=None)
def source(path, commit=None):
    if commit:
        try: return subprocess.check_output(['git','show',commit+':'+path],cwd=ROOT)
        except subprocess.CalledProcessError: return b'MISSING'
    return (ROOT/path).read_bytes() if (ROOT/path).is_file() else b'MISSING'

@lru_cache(maxsize=1024)
def lexical_mask(text):
    """Mask comments/literals for braces; retain literal bytes separately in source hashes."""
    masked=list(text); commentless=list(text); i=0
    raw_pattern=re.compile(r'(?:br|r)(#{0,255})"')
    swift_raw_pattern=re.compile(r'(#+)("""|")')
    char_pattern=re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]+\}|.)|[^'\n])'")
    def erase(a,b,comment=False):
        for k in range(a,b):
            if text[k]!='\n':
                masked[k]=' '
                if comment: commentless[k]=' '
    while i<len(text):
        if text.startswith('//',i):
            end=text.find('\n',i); end=len(text) if end<0 else end
            erase(i,end,True); i=end
        elif text.startswith('/*',i):
            start=i; depth=1; i+=2
            while i<len(text) and depth:
                if text.startswith('/*',i): depth+=1; i+=2
                elif text.startswith('*/',i): depth-=1; i+=2
                else: i+=1
            if depth: raise RuntimeError('unclosed source comment')
            erase(start,i,True)
        else:
            raw=raw_pattern.match(text,i)
            swift_raw=swift_raw_pattern.match(text,i)
            if raw:
                delimiter='"'+raw[1]; start=i; i=raw.end(); end=text.find(delimiter,i)
                if end<0: raise RuntimeError('unclosed Rust raw string')
                i=end+len(delimiter); erase(start,i)
            elif swift_raw:
                delimiter=swift_raw[2]+swift_raw[1]; start=i; i=swift_raw.end(); end=text.find(delimiter,i)
                if end<0: raise RuntimeError('unclosed Swift raw string')
                i=end+len(delimiter); erase(start,i)
            elif text.startswith('"""',i):
                start=i; i+=3; end=text.find('"""',i)
                if end<0: raise RuntimeError('unclosed multiline string')
                i=end+3; erase(start,i)
            elif text[i]=='"':
                start=i; i+=1
                while i<len(text):
                    if text[i]=='\\': i+=2
                    elif text[i]=='"': i+=1; break
                    else: i+=1
                else: raise RuntimeError('unclosed source string')
                erase(start,i)
            elif text[i]=="'" and char_pattern.match(text,i):
                char=char_pattern.match(text,i); erase(i,char.end()); i=char.end()
            else: i+=1
    return ''.join(masked),''.join(commentless)

def function_spans(text,swift=False):
    mask,clean=lexical_mask(text); spans=[]
    pattern=r'^    (?:private )?func\s+(test\w+)\s*\(' if swift else r'^(?:async )?fn\s+(\w+)\s*\('
    for match in re.finditer(pattern,mask,re.M):
        opening=mask.find('{',match.end())
        if opening<0: raise RuntimeError('function has no body: '+match[1])
        depth=1; end=opening+1
        while end<len(mask) and depth:
            depth += (mask[end]=='{')-(mask[end]=='}'); end+=1
        if depth: raise RuntimeError('function body unclosed: '+match[1])
        spans.append((match[1],match.start(),end))
    return spans,clean

def flow_apparatus(row,commit=None):
    text=source(row['source'],commit).decode()
    if row['kind']=='app' and row['id']=='app:LaunchProof': return text
    if row['kind']=='manual': return text
    swift=row['kind']=='app'; spans,clean=function_spans(text,swift)
    name=row['id'].split('/',1)[1] if swift else row['id'].rsplit(':',1)[1]
    name=name.split('#',1)[0]
    own=next(((a,b) for n,a,b in spans if n==name),None)
    if own is None: raise RuntimeError('cannot bind exact proof function: '+row['id'])
    if swift:
        exclude=spans
        selected=clean[own[0]:own[1]]
    else:
        # Bind only top-level helpers called by this proof; another test/helper is not its setup.
        bodies={n:(a,b) for n,a,b in spans}; reached={name}; queue=[name]
        while queue:
            called=queue.pop(); a,b=bodies[called]
            code,_=lexical_mask(text[a:b])
            for symbol in re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\::<[^;\n]+>)?\s*\(',code):
                if symbol in bodies and symbol not in reached:
                    reached.add(symbol); queue.append(symbol)
        selected='\n'.join(clean[a:b] for n,a,b in spans if n in reached)
        exclude=spans
    shared=clean
    for _,a,b in reversed(exclude): shared=shared[:a]+shared[b:]
    return selected+'\nSHARED APPARATUS\n'+shared


def step_apparatus(row, commit=None):
    text=source(row['source'],commit).decode()
    if row['kind']=='rust':
        # Shared process/CLI apparatus and the exact selected helper, excluding other claims.
        helper=dict(row); helper['id']=row['id'].split('#',1)[0].rsplit(':',1)[0]+':room_ask_step'
        return flow_apparatus(helper,commit)
    start=text.index('    func testSessionsAreDrivenWhereTheyAreShown()')
    end=text.index('    /// A keyring change',start)
    method=text[start:end]
    begin=method.index("        // Claude Code's two sessions")
    event=method.index('        func event(',begin)
    after=method.index('        var pendingHookPid:',event)
    rm=method.index('        // RM-1/3/5:')
    # Actual minimum setup, event encoder, selected RM assertions, and common UI apparatus.
    spans,shared=function_spans(text,True)
    for _,a,b in reversed(spans): shared=shared[:a]+shared[b:]
    return method[:begin]+method[event:after]+method[rm:]+'\nSHARED APPARATUS\n'+shared

_bindings={}
def fingerprint(row, commit=None):
    key=(row["id"],commit)
    if key in _bindings: return _bindings[key]
    # Bind behavior/setup inputs, never the entire compiled binary.
    paths=row.get('dependencies') or [str(p.relative_to(ROOT)) for p in ROOT.glob('crates/*/src/**/*.rs')]
    if row['kind']=='app' and not row.get('step'):
        paths += [str(p.relative_to(ROOT)) for p in ROOT.glob('apps/macos/Vox/*.swift')]
        paths += ASK_APP
    if row['kind']=='rust':
        support=ROOT/Path(row['source']).parent/'support'
        paths += [str(p.relative_to(ROOT)) for p in support.glob('**/*.rs')]
    paths=sorted(set(paths+[row['source']]))
    h=hashlib.sha256()
    for path in paths:
        body=(step_apparatus(row,commit) if row.get('step') else flow_apparatus(row,commit)).encode() if path==row['source'] else source(path,commit)
        h.update(path.encode()+b'\0'+body+b'\0')
    h.update(json.dumps(row['command'],sort_keys=True).encode())
    h.update(row.get('step','').encode())
    result=(h.hexdigest(),paths)
    _bindings[key]=result
    return result

def terminal_failure(row,text):
    lines=text.splitlines(); candidates=[]
    if row['kind']=='rust':
        name=row['command'][row['command'].index('--')-1]
        for index,line in enumerate(lines):
            if re.search(r"^thread '"+re.escape(name)+r"'.* panicked at",line):
                for payload in lines[index+1:]:
                    if payload.startswith(('note:', 'test ', 'failures:', "thread '")): break
                    kind=re.search(r'\b(PRODUCT|APPARATUS|CANNOT MEASURE)\b',payload)
                    if kind:
                        candidates.append((kind[1],payload)); break
    elif row['kind']=='app':
        name=row['id'].split('/',1)[-1].split('#',1)[0]
        for line in lines:
            if ' error: -[' in line and name in line and re.search(r' : failed(?: -|:)',line):
                kind=re.search(r'\b(PRODUCT|APPARATUS|CANNOT MEASURE)\b',line)
                if kind: candidates.append((kind[1],line))
        if not candidates:
            for line in lines:
                if re.match(r'^app-proofs: APPARATUS(?:[: (])',line): candidates.append(('APPARATUS',line))
    return candidates[-1] if candidates else ('APPARATUS','APPARATUS: runner failed without an attributable terminal proof verdict')

def executed(row, text):
    if row.get('step') and 'SELECTED PROOF STEP: '+row['step'] not in text: return False
    if row['kind']=='rust':
        name=row['command'][row['command'].index('--')-1]
        return (re.search(r'^running 1 test$',text,re.M) is not None
                and re.search(r'^test '+re.escape(name)+r' \.\.\. ok$',text,re.M) is not None
                and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;',text,re.M) is not None)
    if row['kind']=='app':
        if row['id']=='app:LaunchProof':
            return '[proof]' in text and 'LaunchProof' in text
        method=row['id'].split('/',1)[1].split('#',1)[0]
        return re.search(r"Test Case .*"+re.escape(method)+r".* passed",text) is not None
    return False

def main():
    p=argparse.ArgumentParser(description=__doc__)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--full',action='store_true')
    mode.add_argument('--changed',metavar='BASE')
    mode.add_argument('--since-last-full',action='store_true')
    mode.add_argument('--record-receipt',type=Path,help='import an actual source-bound previous result; run nothing')
    p.add_argument('--plan',action='store_true',help='print selection, run nothing')
    p.add_argument('--only',action='append',default=[],help='exact discovered flow ID; unsupported steps fail')
    p.add_argument('--optional',action='store_true')
    p.add_argument('--evidence',type=Path,default=Path(git('rev-parse','--git-path','proof-evidence')))
    p.add_argument('--repair',action='append',default=[],metavar='FLOW=DIAGNOSIS_LOG',help='existing diagnosis evidence plus changed relevant sources; never an unchanged retry')
    args=p.parse_args(); rows=discover(); current=git('rev-parse','HEAD')
    if not args.evidence.is_absolute(): args.evidence=ROOT/args.evidence
    args.evidence.mkdir(parents=True,exist_ok=True)
    dbpath=args.evidence/'results.json'; db=json.loads(dbpath.read_text()) if dbpath.exists() else {'flows':{}}
    if args.record_receipt:
        receipt=json.loads(args.record_receipt.read_text())
        if receipt.get('schema')!='vox.proof.result/1': raise RuntimeError('unsupported actual result receipt')
        key=receipt['flow']; row=rows.get(key)
        if not row: raise RuntimeError('receipt names an unsupported proof/step: '+key)
        commit=git('rev-parse',receipt['commit']+'^{commit}')
        log=Path(receipt['log']); text=log.read_text()
        if hashlib.sha256(log.read_bytes()).hexdigest()!=receipt['log_sha256']:
            raise RuntimeError('actual result log digest differs')
        if receipt.get('command')!=row['command'] or receipt.get('step','')!=row.get('step',''):
            raise RuntimeError('receipt must bind the exact executed command and selected portion')
        code=receipt['exit']; status,terminal=terminal_failure(row,text)
        if code==0 and executed(row,text): status='pass'; terminal='actual selected proof passed'
        elif code==0: status='APPARATUS'; terminal='APPARATUS: receipt contains no actual selected proof execution'
        fp,paths=fingerprint(row,commit)
        db['flows'][key]=dict(status=status,commit=commit,fingerprint=fp,paths=paths,log=str(log.resolve()),exit=code,terminal=terminal)
        dbpath.write_text(json.dumps(db,indent=2)+'\n')
        print('RECORDED '+key+': '+status+'; source '+commit+'; evidence '+str(log))
        return
    if args.since_last_full:
        if 'last_full' not in db: raise RuntimeError('no recorded explicitly requested full suite run')
        base=db['last_full']; changed=git('diff','--name-only',base).splitlines()
        print('LAST FULL RESULT: '+('complete' if db.get('last_full_complete',False) else 'incomplete/pending; no suite pass claimed'))
        print('COMMITS since last full:\n'+git('log','--oneline',base+'..HEAD'))
    elif args.changed:
        base=git('rev-parse',args.changed+'^{commit}'); changed=git('diff','--name-only',base).splitlines()
    else: changed=[]
    reasons={}
    if args.full:
        selected={k for k,v in rows.items() if not v.get('step')}
        reasons={k:'explicit full suite request' for k in selected}
    elif changed and all(path in ASK for path in changed):
        selected={k for k,v in rows.items() if v.get('step')=='room-ask'}
        reasons={k:'room-ask behavior reached by '+', '.join(changed) for k in selected}
    else:
        selected=set()
        for key,row in rows.items():
            if row.get('step'): continue
            _, paths=fingerprint(row)
            reached=sorted(set(paths)&set(changed))
            if reached:
                selected.add(key); reasons[key]='relevant source/setup changed: '+', '.join(reached)
        unknown=[path for path in changed if not any(path in fingerprint(row)[1] for row in rows.values())]
        if unknown:
            selected.update(k for k,v in rows.items() if not v.get('step'))
            for key in selected: reasons.setdefault(key,'conservative unmapped change: '+', '.join(unknown))
    # A previous failure is always reported pending, even outside this diff.
    selected.update(k for k,v in db['flows'].items() if v['status']!='pass' and k in rows)
    for key in sorted(k for k,v in db['flows'].items() if v['status']!='pass'):
        print('PENDING LAST RED '+key+': '+db['flows'][key]['status']+'; '+db['flows'][key]['log'])
    if args.only:
        for key in args.only:
            if key not in rows: raise RuntimeError('unsupported proof/step: '+key)
        selected=set(args.only)
        for key in selected: reasons.setdefault(key,'explicit flow request')
    repairs={}
    for item in args.repair:
        key,sep,path=item.partition('=')
        if not sep or not Path(path).is_file() or not Path(path).read_text().strip(): raise RuntimeError('repair requires a nonempty existing diagnosis log')
        diagnosis=json.loads(Path(path).read_text())
        old=db['flows'].get(key)
        if not old or old['status']=='pass': raise RuntimeError('repair has no pending failure: '+key)
        prior=Path(old['log'])
        evidence=Path(diagnosis.get('diagnosis_evidence',''))
        repair_commit=diagnosis.get('repair_commit','')
        if (not prior.is_file() or diagnosis.get('failed_log_sha256')!=hashlib.sha256(prior.read_bytes()).hexdigest()
                or not evidence.is_file() or not evidence.read_text().strip() or not diagnosis.get('cause')):
            raise RuntimeError('diagnosis must bind the actual failed log and nonempty investigation evidence')
        resolved=git('rev-parse',repair_commit+'^{commit}')
        subprocess.run(['git','merge-base','--is-ancestor',resolved,current],cwd=ROOT,check=True)
        if fingerprint(rows[key],old['commit'])[0]==fingerprint(rows[key],resolved)[0]:
            raise RuntimeError('repair commit changes no relevant product/apparatus input: '+key)
        repairs[key]=path
    if args.since_last_full:
        print('AREAS: '+', '.join(sorted({str(Path(x).parent) for x in changed})))
        for key in sorted(selected): print('TOUCHES '+key+': '+reasons.get(key,'last result remains pending'))
        return
    outcomes=[]
    for key in sorted(selected):
        row=rows[key]; fp,paths=fingerprint(row); old=db['flows'].get(key)
        if row['optional'] and not args.optional:
            print('OPTIONAL PROOF NOT RUN: '+key); outcomes.append(False); continue
        if old and old['status']=='pass' and old['fingerprint']==fp and not args.full:
            print(f"RETAINED {key}: source {old['commit']}, evidence {old['log']}, behavior/setup {fp}"); continue
        if old and old['status']!='pass':
            repair=repairs.get(key)
            if old['fingerprint']==fp or not repair:
                print(f"PENDING {key}: {old['status']}; {old['log']}; diagnosis and relevant product/apparatus repair required")
                outcomes.append(False); continue
            print('REPAIRED '+key+': changed source/setup '+fp+'; diagnosis '+repair)
        if row.get('unavailable'):
            print('CANNOT MEASURE: '+key+': '+row['unavailable']); outcomes.append(False); continue
        print('SELECT '+key+': '+reasons.get(key,'last-red repaired')+'; binding '+fp)
        print('COMMAND '+json.dumps(row['command'])+('; VOX_PROOF_STEP='+row['step'] if row.get('step') else ''))
        if args.plan: continue
        if git('status','--porcelain','--untracked-files=no'):
            raise RuntimeError('commit source first; evidence must bind exact behavior/apparatus source')
        command=list(row['command']); env=os.environ.copy()
        for control in ['VOX_PROOF_STEP','VOX_PROOF_FROM','VOX_PROOF_REBOOT_PHASE','VOX_PROOF_REBOOT_SPIKE','VOX_PROOF_UPDATE_SPIKE']:
            env.pop(control,None)
        if row.get('step'): env['VOX_PROOF_STEP']=row['step']
        stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        log=args.evidence/(hashlib.sha256(key.encode()).hexdigest()[:12]+'-'+stamp+'.log')
        with log.open('w') as output:
            process=subprocess.Popen(command,cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            for line in process.stdout:
                print(line,end='',flush=True); output.write(line); output.flush()
            code=process.wait()
        text=log.read_text()
        ran=executed(row,text)
        status,terminal=terminal_failure(row,text)
        if code==0 and ran: status='pass'; terminal='actual selected proof passed'
        if code==0 and not ran: status='APPARATUS'; terminal='APPARATUS: selected proof did not execute'
        if code==0 and ('OPTIONAL PROOF NOT RUN' in text or 'Executed 0 tests' in text): status='APPARATUS'; terminal='APPARATUS: selected proof did not run'
        db['flows'][key]=dict(status=status,commit=current,fingerprint=fp,paths=paths,log=str(log),exit=code,terminal=terminal)
        if status!='pass': print(terminal)
        dbpath.write_text(json.dumps(db,indent=2)+'\n'); outcomes.append(status=='pass')
    if args.full and not args.plan:
        db['last_full']=current
        db['last_full_complete']=all(outcomes)
        dbpath.write_text(json.dumps(db,indent=2)+'\n')
    if not args.plan and not all(outcomes): raise SystemExit(1)

if __name__=='__main__':
    try: main()
    except (RuntimeError,ValueError,OSError,subprocess.CalledProcessError) as error:
        print('APPARATUS: '+str(error),file=sys.stderr); raise SystemExit(2)
