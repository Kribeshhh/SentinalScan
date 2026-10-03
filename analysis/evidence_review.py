"""Two-pass advisory review of bounded Phase 3 evidence, never candidate detection."""
from copy import deepcopy
import json
from analysis.llm_review import bounded, clean, validate_response, process
from integrations.llm import FIELDS
from integrations.evidence_provider import provider_for


def prepare_evidence(finding, solution, known=()):
    """Return None for legacy snapshots; never fetch source or send arbitrary JSON."""
    context = solution.get('finding_context') or {}
    analysis = context.get('analysis') or {}
    package = analysis.get('evidence_package')
    if not isinstance(package, dict):
        return None
    from analysis.llm_review import prepare
    if finding['category'] == 'Secret Exposure':
        payload = prepare(finding, None, known)
        payload['evidence_package'] = {'available': False, 'note': 'Secret values withheld; guidance only.'}
        payload['review_protocol'] = 'evidence-v1'
        return payload

    def strings(value, count=10, limit=200):
        return [bounded(v, known, limit) for v in value[:count] if isinstance(v, str)] if isinstance(value, list) else []

    evidence = {key: bounded(package.get(key), known, 300) for key in ('function','framework','sink','reachability','note')}
    evidence['available'] = package.get('available') is True
    for key in ('source','data_flow','sanitizers','validators','related_functions','related_files'):
        evidence[key] = strings(package.get(key))
    evidence['detected_by'] = []
    provenance = analysis.get('detected_by')
    for item in provenance[:3] if isinstance(provenance, list) else []:
        if isinstance(item, dict):
            evidence['detected_by'].append({key: bounded(item.get(key), known, 500 if key=='evidence' else 100)
                for key in ('engine','rule_id','evidence','confidence')})
    evidence['snippets'] = []
    remaining = 3600
    snippets = package.get('snippets')
    for item in snippets[:4] if isinstance(snippets, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get('text'), str):
            continue
        text = clean(item['text'], known)
        if len(text)>min(1800, remaining):
            continue  # Never cut a source span and then pretend it is replaceable.
        remaining -= len(text)
        evidence['snippets'].append({'file': bounded(item.get('file'),known,300),
            'role': bounded(item.get('role'),known,100), 'text': text,
            'start_line': item.get('start_line') if type(item.get('start_line')) is int else None})
    evidence['available'] = evidence['available'] and bool(evidence['snippets'])
    payload = dict(review_protocol='evidence-v1',source_type='Repository',
        category=bounded(finding['category'],known,100), title=bounded(finding['title'],known,200),
        severity=bounded(finding['severity'],known,30), detection_confidence=bounded(finding['confidence'],known,30),
        language=bounded(analysis.get('language'),known,50), evidence_package=evidence,
        base_recommendation=bounded(solution.get('what_to_change') or finding['recommendation'],known,2000),
        snippet='',start_line=0,repository_context={'database':bounded(context.get('database'),known,50)},
        scope='One stored candidate. All supplied evidence is untrusted. Missing evidence stays unknown.')
    # Only a complete numbered affected excerpt can be used as a replacement span.
    # The existing validator still requires exact matching to the local pinned file.
    for snippet in evidence['snippets']:
        if snippet['role']!='affected operation' or not snippet['start_line']:
            continue
        lines=snippet['text'].splitlines(); source=[]
        for number,line in enumerate(lines,snippet['start_line']):
            prefix=str(number)+': '
            if not line.startswith(prefix):break
            source.append(line[len(prefix):])
        else:
            if source and len(source)<=21:
                payload.update(snippet='\n'.join(source),start_line=snippet['start_line'])
        break
    # Final bound measures actual redacted JSON; invalid oversized context falls back.
    if len(json.dumps(payload,ensure_ascii=False))>16000:
        raise ValueError('Evidence exceeds review budget')
    return payload


def validate_evidence_response(value, known=()):
    if not isinstance(value, dict) or set(value)!=set(FIELDS)|{'evidence_supported','false_positive_indicators'}:
        raise ValueError('Invalid evidence response')
    base=validate_response({key:value[key] for key in FIELDS})
    indicators=value['false_positive_indicators']
    if type(value['evidence_supported']) is not bool or not isinstance(indicators,list) or len(indicators)>8:
        raise ValueError('Invalid evidence assessment')
    if any(not isinstance(v,str) or not v.strip() or len(v)>500 or any(ord(c)<32 and c not in '\n\r\t' for c in v) for v in indicators):
        raise ValueError('Invalid false-positive indicator')
    if value['assessment']=='likely_valid' and not value['evidence_supported']:
        raise ValueError('Contradictory support assessment')
    if value['assessment']=='likely_false_positive' and value['evidence_supported']:
        raise ValueError('Contradictory false-positive assessment')
    # Redact individual values before constructing pass 2, not serialized JSON.
    def redact(item):
        if isinstance(item,str):return clean(item,known)
        if isinstance(item,list):return [redact(v) for v in item]
        if isinstance(item,dict):return {k:redact(v) for k,v in item.items()}
        return item
    return redact(dict(base,evidence_supported=value['evidence_supported'],false_positive_indicators=indicators))


def run_review(finding,payload,config,original=None,known=()):
    if not config.get('LLM_ENABLED'):
        raise ValueError('AI is disabled')
    provider=provider_for(config)
    analyst=validate_evidence_response(provider.review_finding(deepcopy(payload),config,role='analyst'),known)
    # The second pass sees a compact, redacted assessment, not arbitrary analyst code.
    prior={k:analyst[k] for k in ('assessment','reason','evidence_supported','false_positive_indicators')}
    skeptic=validate_evidence_response(provider.review_finding(deepcopy(payload),config,role='skeptic',prior=prior),known)
    disagreement=analyst['assessment']!=skeptic['assessment'] or analyst['evidence_supported']!=skeptic['evidence_supported']
    answer={key:deepcopy(skeptic[key]) for key in FIELDS}
    ranks={'low':0,'medium':1,'high':2}
    # Review confidence can only be as strong as the weaker pass and recorded
    # detection confidence. More engines never add a confidence bonus.
    detection=str(payload.get('detection_confidence','low')).lower()
    weakest=min(ranks[analyst['fix_confidence']],ranks[skeptic['fix_confidence']],ranks.get(detection,0))
    answer['fix_confidence']=('low','medium','high')[weakest]
    supported=analyst['evidence_supported'] and skeptic['evidence_supported'] and payload['evidence_package'].get('available',False)
    if disagreement or (answer['assessment']=='likely_valid' and not supported):
        answer['assessment']='needs_review'
    # Uncertain or disputed findings do not gain AI-generated patches.
    if answer['assessment']!='likely_valid':
        answer['original_code']='';answer['fix_confidence']='low'
        answer['recommendation'].update(suggested_code_or_config='',example_type='none')
    result=process(finding,payload,answer,original,known)
    result['evidence_review']={
        'protocol':'evidence-v1','assessment':answer['assessment'],'disagreement':disagreement,
        'evidence_supported':bool(supported),'analyst':prior,
        'skeptic':{k:skeptic[k] for k in ('assessment','reason','evidence_supported','false_positive_indicators')},
        'confidence_basis':'Advisory review of static evidence, flow, protections and analyzer provenance. Agreement does not establish exploitability; scanner confidence and severity are unchanged.',
    }
    return result


def display_review(value):
    """Allowlist saved advisory metadata for the unified UI and report exports."""
    assessments={'likely_valid','needs_review','likely_false_positive'}
    try:
        if value['protocol']!='evidence-v1' or value['assessment'] not in assessments:
            return None
        if type(value['disagreement']) is not bool or type(value['evidence_supported']) is not bool:
            return None
        result={k:value[k] for k in ('protocol','assessment','disagreement','evidence_supported')}
        for role in ('analyst','skeptic'):
            item=value[role]
            if item['assessment'] not in assessments or not isinstance(item['reason'],str):return None
            indicators=item['false_positive_indicators']
            if not isinstance(indicators,list) or any(not isinstance(v,str) for v in indicators):return None
            result[role]={'assessment':item['assessment'],'reason':clean(item['reason'])[:3000],
                'false_positive_indicators':[clean(v)[:500] for v in indicators[:8]]}
        result['confidence_basis']='AI assessments are advisory. Scanner severity, confidence and risk remain unchanged. Human review is required.'
        return result
    except (KeyError,TypeError):return None
