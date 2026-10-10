"""Strict bounded SARIF candidate import. Never persist snippets or tool messages."""
from dataclasses import replace
import json
from pathlib import Path
import re
from urllib.parse import unquote,urlsplit
from analysis.redaction import scrub
from scanner.sast.common import add
from scanner.engines.process import ToolFailure,OUTPUT_LIMIT


def coordinate(location,ctx):
    physical=location.get('physicalLocation',{})
    artifact=physical.get('artifactLocation',{})
    uri=artifact.get('uri')
    if not isinstance(uri,str) or len(uri)>2000:raise ValueError()
    parsed=urlsplit(uri)
    if parsed.scheme not in ('','file') or parsed.netloc or parsed.query or parsed.fragment:raise ValueError()
    path=Path(unquote(parsed.path))
    root=ctx['root'].resolve()
    target=(path if path.is_absolute() else root/path).resolve()
    relative=target.relative_to(root).as_posix()
    if relative not in ctx['paths'] or target.is_symlink():raise ValueError()
    region=physical.get('region',{})
    start=region.get('startLine');end=region.get('endLine',start)
    if type(start) is not int or type(end) is not int or not 1<=start<=end<=1000000:raise ValueError()
    return {'file':relative,'start_line':start,'end_line':end}


def invocation_status(invocations):
    """SARIF note/none diagnostics do not mean incomplete analysis.

    Missing notification levels default conservatively to warning. Do not persist
    tool messages, which may include source text or credentials.
    """
    if not isinstance(invocations,list) or len(invocations)>100:raise ValueError()
    partial=False
    for invocation in invocations:
        if not isinstance(invocation,dict):raise ValueError()
        if 'executionSuccessful' in invocation and type(invocation['executionSuccessful']) is not bool:raise ValueError()
        if invocation.get('executionSuccessful') is False:partial=True
        for key in ('toolExecutionNotifications','toolConfigurationNotifications'):
            notifications=invocation.get(key,[])
            if not isinstance(notifications,list) or len(notifications)>10000:raise ValueError()
            for notification in notifications:
                if not isinstance(notification,dict):raise ValueError()
                level=notification.get('level','warning')
                if level not in ('none','note','warning','error'):raise ValueError()
                if level in ('warning','error'):partial=True
    return partial


def import_results(payload,ctx,engine):
    try:
        if len(payload)>OUTPUT_LIMIT:raise ValueError()
        doc=json.loads(payload)
        if not isinstance(doc,dict) or doc.get('version')!='2.1.0' or not isinstance(doc.get('runs'),list):raise ValueError()
        if len(doc['runs'])>10:raise ValueError()
        candidates=[];rejected=0;partial=False
        for run in doc['runs']:
            if not isinstance(run,dict) or not isinstance(run.get('results'),list):raise ValueError()
            invocations=run.get('invocations',[])
            if invocation_status(invocations):partial=True
            rules=run.get('tool',{}).get('driver',{}).get('rules',[])
            if not isinstance(rules,list) or len(rules)>10000:raise ValueError()
            by_id={r['id']:r for r in rules if isinstance(r,dict) and isinstance(r.get('id'),str)}
            if len(run['results'])>1500:partial=True
            for item in run['results'][:1500]:
                try:
                    rule_id=item['ruleId']
                    if not isinstance(rule_id,str) or not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,200}',rule_id):raise ValueError()
                    if item.get('suppressions'):continue
                    loc=coordinate(item['locations'][0],ctx)
                    rule=by_id.get(rule_id,{})
                    properties=rule.get('properties',{})
                    tags=properties.get('tags',[])
                    if not isinstance(tags,list):raise ValueError()
                    cwes=[]
                    for tag in tags[:100]:
                        if not isinstance(tag,str):continue
                        match=re.fullmatch(r'(?:external/cwe/)?cwe-(\d{1,4})',tag,re.I)
                        if match:cwes.append('CWE-'+str(int(match[1])))
                    severity={'error':'High','warning':'Medium','note':'Low','none':'Informational'}.get(item.get('level',rule.get('defaultConfiguration',{}).get('level','warning')),'Medium')
                    score=properties.get('security-severity')
                    if score is not None:
                        score=float(score)
                        if not 0<=score<=10:raise ValueError()
                        severity='Critical' if score>=9 else 'High' if score>=7 else 'Medium' if score>=4 else 'Low' if score>0 else 'Informational'
                    path=[];path_complete=True
                    flows=item.get('codeFlows',[])
                    if flows:
                        steps=flows[0]['threadFlows'][0]['locations']
                        if not isinstance(steps,list):raise ValueError()
                        path_complete=len(steps)<=20
                        for step in steps[:20]:path.append(coordinate(step['location'],ctx))
                    candidates.append((rule_id,loc,cwes,severity,path,path_complete))
                except (ValueError,KeyError,TypeError,IndexError,AttributeError):rejected+=1
    except (ValueError,TypeError,KeyError,AttributeError,RecursionError):
        raise ToolFailure('Malformed analysis output; deterministic results are retained.') from None
    seen=set();imported=0
    for rule,loc,cwes,severity,path,complete in candidates:
        key=(rule,loc['file'],loc['start_line'])
        if key in seen:continue
        seen.add(key)
        confidence='Medium' if len(path)>=2 and complete else 'Low'
        evidence=f'{engine} rule {rule} reported a static candidate at line {loc["start_line"]}. '
        evidence+=('An engine-reported path is available; endpoints are not independently verified. ' if path else 'No source-to-sink path was supplied. ')
        evidence+='Tool agreement or a reported path does not prove runtime exploitability.'
        before=len(ctx['findings'])
        add(ctx,loc['file'],loc['start_line'],f'{engine} candidate: {rule}','Code Security',evidence,
            'Review the rule, source context and any reported flow. Confirm sink-specific protections before changing code; validate and test a proposed fix.',severity,confidence)
        if len(ctx['findings'])==before:break
        finding=ctx['findings'][-1];context=json.loads(finding.context_json);analysis=context['analysis']
        analysis.update(engine=engine,rule_id=rule,cwe=cwes[0] if cwes else None,cwes=cwes,
            end_line=loc['end_line'],data_flow=path,source=[path[0]] if len(path)>=2 else [],
            sink=path[-1] if len(path)>=2 else None,evidence_kind='external engine candidate',
            reachability='Engine-reported path; runtime reachability not proven' if path else 'Potential pattern',
            path_complete=complete,flow_scope='engine-reported',verification_status='Not verified')
        ctx['findings'][-1]=replace(finding,context_json=json.dumps(scrub(context,ctx.get('secrets',()))));imported+=1
    return {'candidates':imported,'rejected_results':rejected,'status':'Partial' if rejected or partial else 'Completed'}
