"""One presentation recommendation; scanner and advisory AI records stay separate."""
from copy import deepcopy
import json
from flask import current_app
from analysis.redaction import scrub


def compose(finding, base, review=None, enabled=False):
    f=dict(finding); result=deepcopy(base)
    result.update(ai_assisted=False,recommendation_source='Deterministic')
    evidence_review=None
    if enabled and isinstance(review,dict) and isinstance(review.get('evidence_review'),dict):
        from analysis.evidence_review import display_review
        evidence_review=display_review(review['evidence_review'])
    failed_candidate=False
    validated_answer=None
    if enabled and isinstance(review,dict) and f.get('status')!='False Positive':
        try:
            from analysis.llm_review import validate_response,clean,website_example
            rec=review.get('recommendation')
            if rec is None:
                # Read old stored reviews; never relax the live provider schema.
                code=review.get('suggested_code','')
                rec=dict(what_to_change=review['remediation'],suggested_code_or_config=code,
                    example_type='source_specific' if code else 'none',why=review['reason'],additional_actions=[])
            answer=validate_response({key:review[key] for key in ('assessment','reason','original_code','fix_confidence')} | {'recommendation':rec})
            validated_answer=answer
            rec=answer['recommendation'];code=rec['suggested_code_or_config'];kind=rec['example_type']
            if evidence_review and evidence_review['assessment']!='likely_valid':
                raise ValueError('Disputed evidence keeps deterministic guidance')
            validation=review.get('validation',{}).get('status','Not Available')
            if validation=='Failed':
                failed_candidate=True
                raise ValueError('Failed AI candidate')
            if code and kind=='source_specific' and validation!='Passed':raise ValueError('Unvalidated source replacement')
            if f['source']=='Website' and (kind=='source_specific' or not website_example(code,f['category'])):raise ValueError('Unsupported website code')
            if f['category']=='Secret Exposure' and code:raise ValueError('Secret code requires deterministic policy')
            # Clean text independently; code was sanitized before AI persistence.
            rec={k:[clean(x) for x in v] if isinstance(v,list) else clean(v) for k,v in rec.items()}
            code=scrub(code)
            normalize=lambda value: ' '.join(str(value or '').split()).casefold()
            # Valid JSON is not evidence of useful contribution. Keep the base for
            # generic non-actions and exact repeats, without claiming semantic quality.
            if normalize(rec['what_to_change']).rstrip('.') in ('review the code','review code','fix the issue','fix the vulnerability','follow best practices','no changes needed'):
                raise ValueError('No actionable enhancement')
            same_code=not code or any(normalize(item['code'])==normalize(code) for item in result.get('examples',[]))
            same_notes=all(normalize(note) in {normalize(n) for n in result.get('notes',[])} for note in rec['additional_actions'])
            if normalize(rec['what_to_change'])==normalize(result.get('action')) and normalize(rec['why'])==normalize(result.get('why')) and same_code and same_notes:
                raise ValueError('No recommendation contribution')
            # One chosen example replaces the base examples, never appends a copy.
            if code:
                example=dict(language='Configuration' if f['source']=='Website' else result.get('finding_context',{}).get('language') or 'Source',code=code)
                if kind=='source_specific':example['validation']={'status':'Passed'}
                result.update(examples=[example],before=clean(answer['original_code']) if kind=='source_specific' else None,
                              exact=kind=='source_specific',source_matched=kind=='source_specific',example_type=kind,
                              validation_status='Passed' if kind=='source_specific' else 'Not Available',unavailable=None)
            # Guidance-only AI can improve prose without discarding useful base code.
            result.update(action=rec['what_to_change'],why=rec['why'],ai_assisted=True,recommendation_source='AI-assisted',
                fix_confidence=answer['fix_confidence'].capitalize(),fix_reason='AI confidence is advisory. Review the evidence and test intended behavior; this is not a guaranteed fix.')
            result['notes']=list(dict.fromkeys(list(result.get('notes',[]))+rec['additional_actions']))
        except (ValueError,KeyError,TypeError,AttributeError):
            result=deepcopy(base);result.update(ai_assisted=False,recommendation_source='Deterministic')
    if validated_answer is not None:
        result['ai_review_details']={'assessment':validated_answer['assessment'],
            'reason':clean(validated_answer['reason']),
            'note':clean(review.get('note','')) if isinstance(review.get('note',''),str) else ''}
    if failed_candidate:
        result['validation_notice']='Suggested code failed static validation and requires manual review.'
        result['rejected_suggestion_status']='Failed'
    if evidence_review:
        result['evidence_review']=evidence_review
    # Add only a safe illustration when no usable code survived composition.
    if not result.get('examples') or all(e.get('language')=='Dependency update checklist' for e in result['examples']):
        from analysis.recommendation import example_secure_pattern
        example=example_secure_pattern(f,result)
        if example:
            result.update(examples=[example],example_type='illustrative',exact=False,source_matched=False,
                          validation_status='Not Available',fix_confidence='Low')
    # Deduplicate equal snippets without collapsing alternatives with different behavior.
    examples=[];seen=set()
    for item in result.get('examples',[]):
        identity='\n'.join(line.rstrip() for line in item['code'].strip().splitlines())
        if identity not in seen:examples.append(item);seen.add(identity)
    result['examples']=examples
    result['source_type']=f['source']
    result['what_to_change']=result.get('action','')
    result['suggested_code_or_config']=examples
    result['additional_actions']=list(dict.fromkeys(note for note in result.get('notes',[])+result.get('verification',[]) if not note.startswith('DAST cannot identify the exact source change. The framework labels')))
    result['summary']=result['what_to_change']
    kind=result.get('example_type','none')
    result['kind']={'source_specific':'Suggested Source Fix','illustrative':'Illustrative Secure Example','configuration':'Configuration Example','none':'Remediation guidance'}[kind]
    result['solution_heading']={'source_specific':'Suggested Code Solution','illustrative':'Illustrative Secure Example','configuration':'Configuration Example','none':'Suggested Solution'}[kind]
    result['validation_message']='Requires implementation and re-scan.' if f['source']=='Website' else result.get('validation_status','Not Available')
    if f['source']=='Website' and (not examples or kind=='illustrative'):
        result['unavailable']='Source-specific code unavailable because the website scanner does not have access to the backend implementation.'
    from analysis.recommendation import paired_code
    result['code_pair']=paired_code(f,result)
    return scrub(result)


def final_solution(db,finding,draft=None):
    from analysis.remediation_workflow import finding_solution
    base=finding_solution(db,finding,draft)
    failed=base.pop('_ai_review_failed',False)
    if draft:
        row=db.execute('SELECT data_json FROM finding_solutions WHERE finding_id=?',(finding['id'],)).fetchone()
        if row:
            try:failed=bool(json.loads(row['data_json']).get('_ai_review_failed'))
            except (ValueError,TypeError):pass
    review=None
    if current_app.config.get('LLM_ENABLED',False) and not failed:
        row=db.execute('SELECT data_json FROM ai_reviews WHERE finding_id=?',(finding['id'],)).fetchone()
        if row:
            try:review=json.loads(row['data_json'])
            except (ValueError,TypeError):pass
    return compose(finding,base,review,current_app.config.get('LLM_ENABLED',False))


def record_attempt(db,finding,failed):
    """Retain old AI records, but show deterministic output after a failed refresh."""
    from analysis.remediation_workflow import finding_solution
    snapshot=finding_solution(db,finding)
    snapshot['_ai_review_failed']=bool(failed)
    with db:db.execute('INSERT OR REPLACE INTO finding_solutions VALUES (?,?)',(finding['id'],json.dumps(snapshot)))
