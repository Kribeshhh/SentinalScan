"""Optional engines against vetted source only, with no automatic installation."""
from pathlib import Path
import shutil
import tempfile
import time
from scanner.engines.process import run_tool,ToolFailure
from scanner.engines.sarif import import_results


def executable(config,name,root):
    value=config.get(name+'_BINARY',name.lower())
    found=shutil.which(value)
    if not found:return None
    path=Path(found).resolve()
    if path.is_relative_to(root.resolve()):raise ToolFailure('Engine executable cannot come from the scanned repository.')
    return str(path)


def semgrep(ctx):
    config=ctx.get('engine_config',{})
    if not config.get('SEMGREP_ENABLED',False):return {'status':'Skipped','note':'Semgrep is disabled.'}
    if not any(Path(p).suffix.lower() in ('.py','.js','.jsx','.mjs','.cjs') for p in ctx['paths']):
        return {'status':'Skipped','note':'No source supported by the bundled Semgrep rules.'}
    try:
        tool=executable(config,'SEMGREP',ctx['root'])
        if not tool:return {'status':'Skipped','note':'Semgrep is not installed.'}
        with tempfile.TemporaryDirectory(prefix='sentinelscan-semgrep-') as directory:
            work=Path(directory);output=work/'result.sarif'
            args=[tool,'scan','--config',str(Path(__file__).with_name('semgrep_rules.yml')),
                  '--sarif','--output',str(output),'--dataflow-traces','--metrics=off',
                  '--disable-version-check','--no-rewrite-rule-ids','--disable-nosem','--no-git-ignore',
                  '--jobs=1','--max-memory=512','--timeout=5','--max-target-bytes=524288',str(ctx['root'].resolve())]
            data=run_tool(args,work,min(30,ctx['deadline']-time.monotonic()),output)
            return import_results(data,ctx,'Semgrep')
    except ToolFailure as exc:return {'status':'Failed','note':str(exc)}


def codeql(ctx):
    config=ctx.get('engine_config',{})
    if not config.get('CODEQL_ENABLED',False):return {'status':'Skipped','note':'CodeQL is disabled.'}
    languages=[]
    if any(p.lower().endswith('.py') for p in ctx['paths']):languages.append(('python','codeql/python-queries'))
    if any(p.lower().endswith(('.js','.jsx','.mjs','.cjs')) for p in ctx['paths']):languages.append(('javascript','codeql/javascript-queries'))
    if not languages:return {'status':'Skipped','note':'Only Python and JavaScript no-build extraction is supported.'}
    try:
        tool=executable(config,'CODEQL',ctx['root'])
        if not tool:return {'status':'Skipped','note':'CodeQL is not installed.'}
        search=config.get('CODEQL_SEARCH_PATH','')
        if search and (not Path(search).is_absolute() or Path(search).resolve().is_relative_to(ctx['root'].resolve())):
            raise ToolFailure('CodeQL query packs must be installed outside scanned source.')
        results=[];stop=min(ctx['deadline'],time.monotonic()+120)
        with tempfile.TemporaryDirectory(prefix='sentinelscan-codeql-') as directory:
            work=Path(directory)
            for language,pack in languages:
                db=work/(language+'-db');output=work/(language+'.sarif')
                try:
                    run_tool([tool,'database','create',str(db),'--language='+language,'--build-mode=none',
                        '--source-root='+str(ctx['root'].resolve()),'--threads=1','--ram=1024'],work,stop-time.monotonic())
                    args=[tool,'database','analyze',str(db),pack,'--format=sarifv2.1.0','--output='+str(output),
                          '--threads=1','--ram=1024','--timeout=30','--no-sarif-add-file-contents']
                    if search:args.append('--search-path='+str(Path(search).resolve()))
                    payload=run_tool(args,work,stop-time.monotonic(),output)
                    results.append(dict(import_results(payload,ctx,'CodeQL'),language=language))
                except ToolFailure as exc:results.append({'language':language,'status':'Failed','note':str(exc)})
        statuses={r['status'] for r in results}
        return {'status':'Completed' if statuses=={'Completed'} else 'Failed' if statuses=={'Failed'} else 'Partial',
                'languages':results,'note':'No-build extraction only. Installed query packs required; no automatic downloads or builds.'}
    except ToolFailure as exc:return {'status':'Failed','note':str(exc)}
