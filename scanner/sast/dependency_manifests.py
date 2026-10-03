"""Additional static manifest readers. No dependency resolution or package execution."""
import json
import tomllib
from pathlib import PurePosixPath
from packaging.requirements import Requirement,InvalidRequirement

SUPPORTED={'pyproject.toml','package-lock.json','npm-shrinkwrap.json'}
UNSUPPORTED={'yarn.lock','pnpm-lock.yaml','pnpm-lock.yml','Gemfile','Gemfile.lock','go.mod','go.sum','poetry.lock','uv.lock'}


def parse(path,text,record):
    name=PurePosixPath(path).name
    if name=='pyproject.toml':
        data=tomllib.loads(text);project=data.get('project',{})
        dependencies=project.get('dependencies',[])
        if not isinstance(dependencies,list):raise ValueError('Invalid dependencies')
        optional=project.get('optional-dependencies',{})
        if not isinstance(optional,dict):raise ValueError('Invalid optional dependencies')
        specs=list(dependencies)
        for group in optional.values():
            if not isinstance(group,list):raise ValueError('Invalid optional group')
            specs.extend(group)
        for spec in specs[:1000]:
            try:item=Requirement(spec)
            except (InvalidRequirement,TypeError):raise ValueError('Invalid dependency declaration') from None
            if item.url:continue
            versions=list(item.specifier)
            exact=len(versions)==1 and versions[0].operator in ('==','===') and '*' not in versions[0].version
            record(path,1,'PyPI',item.name,versions[0].version if exact else str(item.specifier) or 'unversioned')
        return bool('dependencies' in project.get('dynamic',[]) or 'poetry' in data.get('tool',{}) or len(specs)>1000)
    data=json.loads(text)
    if not isinstance(data,dict) or data.get('lockfileVersion') not in (1,2,3):raise ValueError('Unsupported lockfile version')
    if data['lockfileVersion'] in (2,3):
        packages=data.get('packages')
        if not isinstance(packages,dict):raise ValueError('Missing packages')
        for location,item in list(packages.items())[:2000]:
            if not isinstance(item,dict):raise ValueError('Invalid locked package')
            if not location or item.get('link'):continue
            if 'node_modules/' not in location:continue
            package=item.get('name') or location.rsplit('node_modules/',1)[1]
            version=item.get('version')
            # Do not send arbitrary git/file URLs or credentials to advisory lookup.
            if isinstance(package,str) and isinstance(version,str):record(path,1,'npm',package,version)
        return len(packages)>2000
    entries=data.get('dependencies',{})
    if not isinstance(entries,dict):raise ValueError('Missing dependencies')
    pending=[(entries,0)];count=0
    while pending and count<2000:
        entries,depth=pending.pop()
        if depth>20:return True
        for package,item in entries.items():
            count+=1
            if count>2000:return True
            if not isinstance(item,dict):raise ValueError('Invalid locked dependency')
            version=item.get('version')
            if isinstance(version,str):record(path,1,'npm',package,version)
            nested=item.get('dependencies',{})
            if not isinstance(nested,dict):raise ValueError('Invalid nested dependencies')
            if nested:pending.append((nested,depth+1))
    return bool(pending)
