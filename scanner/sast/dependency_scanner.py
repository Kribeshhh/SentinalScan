"""Read manifests, never resolve/install packages or run builds. Query exact versions only."""
import json
from dataclasses import replace
import re
import time
from pathlib import PurePosixPath
from packaging.requirements import Requirement,InvalidRequirement
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from cvss import CVSS2,CVSS3,CVSS4
from integrations.network import request,RemoteError
from scanner.sast.common import add, check_budget
from scanner.sast import dependency_manifests


def pinned(value,ecosystem):
    if ecosystem=='PyPI':
        return bool(re.fullmatch(r'[0-9][A-Za-z0-9.!+_-]*',value))
    return bool(re.fullmatch(r'\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?',value))


def manifests(ctx):
    records=[];errors=[];unsupported=[];limited=[]
    def record(path,line,ecosystem,name,version):
        if not re.fullmatch(r'[A-Za-z0-9@_.:/-]{1,200}',name) or any(t in name for t in ('://','..')) or len(version)>150:
            return
        if len(records)>=1000:
            limited.append(path);return
        records.append({'path':path,'line':line,'ecosystem':ecosystem,'package':name,'version':version,'exact':pinned(version,ecosystem),
                        'version_evidence':'lockfile' if PurePosixPath(path).name in ('package-lock.json','npm-shrinkwrap.json') else 'manifest declaration',
                        'reachability':'Not assessed'})
    for path in ctx['paths']:
        check_budget(ctx)
        name=PurePosixPath(path).name
        if name in dependency_manifests.UNSUPPORTED:unsupported.append(path)
        if name not in {'requirements.txt','package.json','pom.xml','build.gradle'} | dependency_manifests.SUPPORTED:
            continue
        text=(ctx['root']/path).read_text(encoding='utf-8-sig')
        try:
            if name in dependency_manifests.SUPPORTED:
                if dependency_manifests.parse(path,text,record):limited.append(path)
            elif name=='requirements.txt':
                for line_number,line in enumerate(text.splitlines(),1):
                    line=line.split(' #',1)[0].strip()
                    if not line or line.startswith(('#','-')):
                        continue
                    try:
                        dependency=Requirement(line)
                    except InvalidRequirement:
                        continue
                    if dependency.url:
                        continue
                    specs=list(dependency.specifier)
                    exact=len(specs)==1 and specs[0].operator in ('==','===') and '*' not in specs[0].version
                    record(path,line_number,'PyPI',dependency.name,specs[0].version if exact else str(dependency.specifier) or 'unversioned')
            elif name=='package.json':
                document=json.loads(text)
                for group in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
                    for package,version in document.get(group,{}).items():
                        if isinstance(version,str):
                            from analysis.dependency_solution import package_line
                            found=package_line(text,package,version)
                            record(path,found[0] if found else 1,'npm',package,version)
            elif name=='pom.xml':
                root=ElementTree.fromstring(text)
                for node in root.iter():
                    node.tag=node.tag.split('}')[-1]
                properties={child.tag:(child.text or '').strip() for parent in root.findall('properties') for child in parent}
                for dependency in root.findall('.//dependencies/dependency'):
                    group=dependency.findtext('groupId','').strip();artifact=dependency.findtext('artifactId','').strip();version=dependency.findtext('version','unresolved').strip()
                    if version.startswith('${') and version.endswith('}'):
                        version=properties.get(version[2:-1],'unresolved')
                    if group and artifact:
                        record(path,1,'Maven',group+':'+artifact,version)
            else:
                for match in re.finditer(r'''(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|compile|testCompile)\s*\(?\s*["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"']{1,150})["']''',text):
                    record(path,text.count('\n',0,match.start())+1,'Maven',match.group(1)+':'+match.group(2),match.group(3))
        except (ValueError,TypeError,AttributeError,ElementTree.ParseError,DefusedXmlException,RecursionError):
            errors.append(path)
    ctx['_unsupported_manifests']=unsupported
    ctx['_limited_manifests']=sorted(set(limited))
    return records[:500],errors,len(records)>500 or bool(limited)


def severity_of(vulnerability):
    scores=[]
    for item in vulnerability.get('severity',[]):
        try:
            vector=item.get('score','');kind=item.get('type','')
            parser={'CVSS_V2':CVSS2,'CVSS_V3':CVSS3,'CVSS_V4':CVSS4}.get(kind)
            if parser:
                scores.append(float(parser(vector).scores()[0]))
        except Exception:
            continue
    if scores:
        score=max(scores)
        return ('Critical' if score>=9 else 'High' if score>=7 else 'Medium' if score>=4 else 'Low' if score>0 else 'Informational'),score
    raw=str(vulnerability.get('database_specific',{}).get('severity','')).upper()
    return {'CRITICAL':'Critical','HIGH':'High','MODERATE':'Medium','MEDIUM':'Medium','LOW':'Low'}.get(raw,'Informational'),None


def query(package,version,ecosystem):
    payload=json.dumps({'package':{'name':package,'ecosystem':ecosystem},'version':version}).encode()
    status,_,body=request('api.osv.dev','/v1/query',method='POST',body=payload,headers={'Content-Type':'application/json'},seconds=6,limit=2_000_000)
    if status!=200:
        raise RemoteError('OSV did not complete the vulnerability query.')
    try:
        data=json.loads(body)
        if not isinstance(data,dict) or not isinstance(data.get('vulns',[]),list):
            raise ValueError()
        return data
    except (ValueError,UnicodeError):
        raise RemoteError('OSV returned an invalid response.') from None


def run(ctx):
    records,errors,capped=manifests(ctx)
    checked={};failures=0;end=time.monotonic()+60;emitted={}
    for dependency in records:
        check_budget(ctx)
        dependency['lookup']='Disabled' if not ctx['osv_enabled'] else 'Unresolved version'
        if not ctx['osv_enabled'] or not dependency['exact']:
            continue
        key=(dependency['package'],dependency['version'],dependency['ecosystem'])
        if key not in checked:
            if len(checked)>=50 or failures>=3 or time.monotonic()>=end:
                dependency['lookup']='Query budget exhausted';continue
            try:
                checked[key]=query(*key)
            except RemoteError:
                checked[key]=None;failures+=1
        data=checked[key]
        if data is None:
            dependency['lookup']='OSV unavailable';continue
        dependency['lookup']='Partial' if data.get('next_page_token') or len(data.get('vulns',[]))>10 else 'Checked'
        dependency['vulnerabilities']=[]
        dependency['assessment']='No known advisory returned for this version; not proof of safety'
        seen_advisories = set()
        for vulnerability in data.get('vulns',[])[:10]:
            if vulnerability.get('withdrawn'):
                continue
            identifier=str(vulnerability.get('id',''))
            if not re.fullmatch('[A-Za-z0-9_.-]{1,100}',identifier):
                continue
            aliases = {identifier} | {str(item) for item in vulnerability.get('aliases', []) if re.fullmatch('[A-Za-z0-9_.-]{1,100}', str(item))}
            if aliases & seen_advisories:
                continue
            seen_advisories.update(aliases)
            severity,score=severity_of(vulnerability)
            affected=[item for item in vulnerability.get('affected',[]) if item.get('package',{}).get('name','').lower()==dependency['package'].lower() and item.get('package',{}).get('ecosystem')==dependency['ecosystem']]
            if not affected:continue
            dependency['assessment']='Vulnerable dependency version reported; functionality reachability not assessed'
            advisory={'id':identifier,'severity':severity,'cvss_score':score,'description':str(vulnerability.get('summary') or vulnerability.get('details') or 'See the advisory for details.')[:1200],
                      'affected':[{'ranges':item.get('ranges',[])[:10],'versions':item.get('versions',[])[:30]} for item in affected[:5]],'reference':'https://osv.dev/vulnerability/'+identifier}
            dependency['vulnerabilities'].append(advisory)
            identity=(dependency['ecosystem'],dependency['package'].lower(),identifier,str(PurePosixPath(dependency['path']).parent))
            occurrence={k:dependency[k] for k in ('path','version','version_evidence')}
            if identity in emitted:
                index=emitted[identity];prior=ctx['findings'][index]
                context=json.loads(prior.context_json)
                info=context['analysis']['dependency']
                if occurrence not in info['occurrences'] and len(info['occurrences'])<20:info['occurrences'].append(occurrence)
                ctx['findings'][index]=replace(prior,context_json=json.dumps(context))
                continue
            evidence=json.dumps({'package':dependency['package'],'version':dependency['version'],'ecosystem':dependency['ecosystem'],
                'version_evidence':dependency['version_evidence'],'reachability':'Not assessed',**advisory},ensure_ascii=False)
            if len(evidence)>4000:
                evidence=json.dumps({'package':dependency['package'],'version':dependency['version'],'ecosystem':dependency['ecosystem'],
                    'id':identifier,'reference':advisory['reference'],'reachability':'Not assessed',
                    'note':'Advisory detail exceeds local evidence limit; inspect the referenced advisory.'})
            start=len(ctx['findings'])
            add(ctx,dependency['path'],dependency['line'],'Vulnerable dependency: '+dependency['package']+' ('+identifier+')','Dependency',evidence,
                'Review the linked advisory and upgrade to a fixed compatible version. Confirm the declared version is actually installed and assess reachability.',severity,'High',
                impact='OSV reports the declared package/version as affected. Application impact depends on installed versions and use of the vulnerable functionality.')
            if len(ctx['findings'])>start:
                finding=ctx['findings'][-1];context=json.loads(finding.context_json)
                context['analysis']['dependency']={'ecosystem':dependency['ecosystem'],'package':dependency['package'],
                    'advisory':identifier,'occurrences':[occurrence],'reachability':'Not assessed'}
                ctx['findings'][-1]=replace(finding,context_json=json.dumps(context));emitted[identity]=start
    ctx['dependencies']=records
    return {'dependencies':records,'unparsed_manifests':errors,'inventory_capped':capped,'queried_packages':len(checked),'lookup_failures':failures,'unsupported_manifests':ctx.get('_unsupported_manifests',[]),'limited_manifests':ctx.get('_limited_manifests',[]),
            'note':'Only exact declared or locked versions are queried; unsupported formats are explicitly listed; no dependency installation, transitive resolution or guessing of version ranges. Unknown advisory severity is Informational. Private package names/versions are sent to OSV only when enabled.'}
