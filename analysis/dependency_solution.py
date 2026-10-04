"""Use recorded advisory data and a matched manifest entry; never invent fixed releases."""
import json
import re
from packaging.version import Version,InvalidVersion


def package_line(source, package, version):
    pattern=re.compile(r'"'+re.escape(package)+r'"\s*:\s*"'+re.escape(version)+r'"')
    matches=list(pattern.finditer(source))
    if len(matches)!=1:return None
    match=matches[0]
    return source.count('\n',0,match.start())+1,match.group(),match.start(),match.end()


def outside_recorded_ranges(version, affected):
    """Only illustrate a concrete release when every retained range excludes it."""
    candidate=Version(version)
    for entry in affected:
        if version in entry.get('versions',[]):return False
        for interval in entry.get('ranges',[]):
            if interval.get('type') not in ('SEMVER','ECOSYSTEM'):return False
            active=False; opened=False; previous=None
            for event in interval.get('events',[]):
                if not isinstance(event,dict) or len(event)!=1:return False
                kind,value=next(iter(event.items()))
                if kind not in ('introduced','fixed') or not isinstance(value,str):return False
                if value!='0' and not re.fullmatch(r'\d+\.\d+\.\d+',value):return False
                boundary=Version(value)
                if (previous is not None and boundary<previous) or (kind=='introduced')==opened:return False
                opened=kind=='introduced';previous=boundary
                if kind=='introduced' and candidate>=boundary:active=True
                elif kind=='fixed' and candidate>=boundary:active=False
            if active:return False
    return True


def dependency_solution(result,finding,source=None):
    try:data=json.loads(finding['evidence'])
    except (ValueError,TypeError):data={}
    package=data.get('package','');version=data.get('version','');advisory=data.get('id','')
    result.update(examples=[],before=None,matched=True,exact=False,
        summary=f"{package or 'Dependency'} {version}: {data.get('description','Review the recorded advisory.')}",
        action='Review the affected package and the remediation information below.',
        notes=[f"Severity comes from advisory {advisory or 'metadata'} ({finding.get('severity','Unknown')}); it does not prove this application exposes the vulnerable behavior.",
               'The manifest declares this version. Installation, runtime reachability, and compatibility have not been verified.'],
        verification=['Regenerate the lockfile using the project package manager, run application tests, and rescan with dependency lookup enabled.'])
    if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',advisory):result['reference']='https://osv.dev/vulnerability/'+advisory
    fixed=set()
    for affected in data.get('affected',[]):
        for interval in affected.get('ranges',[]):
            if interval.get('type') not in ('SEMVER','ECOSYSTEM'):continue
            for event in interval.get('events',[]):
                value=event.get('fixed','')
                if re.fullmatch(r'\d+\.\d+\.\d+',value):fixed.add(value)
    candidates=[]
    try:candidates=sorted((v for v in fixed if Version(v)>Version(version)),key=Version)
    except InvalidVersion:pass
    if not candidates:
        result['action']='No fixed release is recorded in this advisory. Do not guess a replacement version. Review the advisory for a mitigation, remove the affected feature, or migrate away from the package.'
    else:
        result['action']='Advisory fixed releases newer than the declared version: '+', '.join(candidates)+'. Review release compatibility and all other advisories for this package before upgrading.'
    # A manifest-shaped illustration is useful even without a matched source file.
    # These versions are advisory candidates, not a universal safety guarantee.
    ecosystem=data.get('ecosystem')
    valid_package=isinstance(package,str) and bool(re.fullmatch(r'(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]{1,150}',package))
    if valid_package and ecosystem in ('npm','PyPI'):
        verified=[v for v in candidates if outside_recorded_ranges(v,data.get('affected',[]))]
        chosen=verified[0] if verified else '<verified-safe-version>'
        code=json.dumps({'dependencies':{package:chosen}},indent=2) if ecosystem=='npm' else package+'=='+chosen
        note=('This release is recorded as fixed by this advisory only; check all affected ranges, other advisories and compatibility before selecting it.' if verified else
              'Placeholder only: select a compatible fixed version from the advisory/package documentation. A fixed release may not exist.')
        result['dependency_example']=dict(language='package.json · illustrative fragment' if ecosystem=='npm' else 'requirements.txt · illustrative entry',
            code=code,kind='Example Secure Pattern',note=note+' This is not the repository’s actual manifest. Regenerate the lockfile and test the upgrade.')
    if source is None or data.get('ecosystem')!='npm':return
    found=package_line(source,package,version)
    if not found:
        result['source_status']='The package/version could not be uniquely matched in this manifest. No exact replacement is proposed.'
        return
    line,before,start,end=found;lines=source.splitlines()
    result['context']='\n'.join(f'{n:>4} {">" if n==line else " "} {lines[n-1]}' for n in range(max(1,line-2),min(len(lines),line+2)+1))
    result['before']=before;result['before_label']=f'Actual dependency entry · line {line}'
    result['source_status']='Actual package entry from the scanned commit. Severity applies to the dependency advisory, not the surrounding JSON.'
    if candidates:
        candidate=candidates[0]
        replacement=json.dumps(package)+': '+json.dumps(candidate)
        try:json.loads(source[:start]+replacement+source[end:])
        except ValueError:return
        result['examples']=[{'language':'package.json · candidate upgrade (review required)','code':replacement+'\n'}]
        result['notes'].append('This candidate uses a fixed release named by THIS advisory only. Other vulnerabilities or breaking changes may require a different version. It is not a universally safe or automatically verified upgrade.')
