"""Conservative candidate correlation, evidence review and incremental persistence."""
from dataclasses import replace
import json
from analysis.finding_engine import sanitize_finding,save_finding
from analysis.redaction import scrub
from scanner.sast.security_context import ContextRetriever,digest


def review(ctx,finding):
    finding=sanitize_finding(finding,ctx.get('secrets',()))
    context=json.loads(finding.context_json);analysis=context.get('analysis',{})
    retriever=ctx.setdefault('_retriever',ContextRetriever(ctx))
    package=retriever.retrieve(analysis)
    anchor=package.pop('anchor',None)
    supported=bool(package['available'] and analysis.get('source') and analysis.get('sink') and
        analysis.get('engine') in ('python-ast','tree-sitter') and
        str(analysis.get('reachability','')).startswith('Static source-to-sink'))
    state='Strongly Supported' if supported else 'Likely' if package['available'] and finding.confidence in ('High','Medium') else 'Needs Review'
    if finding.status=='False Positive':state='Rejected / False Positive'
    # A missing evidence package must not preserve an unsupported High flow claim.
    confidence='Medium' if finding.confidence=='High' and (not package['available'] or (analysis.get('evidence_kind')=='semantic candidate' and not supported)) else finding.confidence
    if analysis.get('engine') not in ('python-ast','tree-sitter') and state=='Strongly Supported':state='Likely'
    provenance={'engine':analysis.get('engine','Unknown'),'rule_id':analysis.get('rule_id'),
        'evidence':finding.evidence[:500],'confidence':finding.confidence,
        'source':analysis.get('source',[])[:4],'sink':analysis.get('sink'),
        'data_flow':analysis.get('data_flow',[])[:8]}
    # Bounded evidence independent of snippets, suitable for later explicit review.
    package.update(source=analysis.get('source',[]),sink=analysis.get('sink'),
        data_flow=analysis.get('data_flow',[])[:10],sanitizers=analysis.get('sanitizers',[]),validators=[],
        framework=context.get('framework'),reachability=analysis.get('reachability','Not established'))
    analysis.update(verification_status=state,confidence=confidence,evidence_package=package,detected_by=[provenance])
    key=None
    if anchor and analysis.get('cwe'):
        identity=[ctx['repository'],analysis.get('file'),anchor['scope'],analysis['cwe'],anchor['name'],anchor['signature']]
        analysis['logical_fingerprint']=digest(json.dumps(identity))
        # Include exact occurrence for within-scan correlation. Identical calls in
        # distinct locations are not merged just because their code is identical.
        key=(analysis['logical_fingerprint'],anchor['start'],anchor.get('column'),anchor['end'])
        analysis['correlation_basis']='Same parsed operation, file, enclosing scope and CWE; no merge based on CWE alone.'
    else:
        analysis['correlation_basis']='No unambiguous semantic anchor; retained as a separate candidate.'
    context['analysis']=analysis
    payload=json.dumps(scrub(context,ctx.get('secrets',())),ensure_ascii=False)
    if len(payload)>19000:
        analysis['evidence_package']['snippets']=[]
        analysis['evidence_package']['note']='Source excerpts omitted to respect the finding context limit.'
        context['scanner_evidence']=finding.evidence[:1000]
        payload=json.dumps(scrub(context,ctx.get('secrets',())),ensure_ascii=False)
    result=replace(finding,confidence=confidence,context_json=payload)
    return result,key


def persist_candidates(db,scan_id,ctx,candidates):
    groups=ctx.setdefault('_correlated',{})
    for candidate in candidates:
        finding,key=review(ctx,candidate)
        if key and key in groups:
            previous,fid=groups[key]
            old=json.loads(previous.context_json);new=json.loads(finding.context_json)
            a,b=old['analysis'],new['analysis']
            # Separate rules from one engine can describe different issues at the same sink.
            engines={item['engine'] for item in a['detected_by']}
            if b['engine'] not in engines and len(a['detected_by'])<3:
                a['detected_by'].extend(b['detected_by'])
                # Agreement preserves the representative confidence; it does not prove a flaw.
                previous=replace(previous,context_json=json.dumps(old,ensure_ascii=False))
                groups[key]=(previous,fid)
                saved=db.execute('SELECT data_json FROM finding_solutions WHERE finding_id=?',(fid,)).fetchone()
                if saved:
                    solution=json.loads(saved[0]);solution['finding_context']=old
                    with db:db.execute('UPDATE finding_solutions SET data_json=? WHERE finding_id=?',(json.dumps(scrub(solution,ctx.get('secrets',()))),fid))
                continue
        existing=db.execute('SELECT id FROM findings WHERE scan_id=? AND fingerprint=?',(scan_id,finding.fingerprint)).fetchone()
        if existing:continue
        fid=save_finding(db,scan_id,finding)
        if key and key not in groups:groups[key]=(finding,fid)
