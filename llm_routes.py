"""AI never runs in scan workers; one explicit request reviews one existing finding."""
import json
import threading
from flask import abort,request,redirect,url_for,flash
from database import get_db
from integrations.llm import review
from analysis.llm_review import prepare,process
from analysis.recommendation_composer import record_attempt


def register_llm(app):
    lock=threading.Lock()

    @app.post('/findings/<int:finding_id>/ai-review')
    def ai_review(finding_id):
        if not app.config.get('LLM_ENABLED'):abort(404)
        db=get_db();finding=db.execute('SELECT * FROM findings WHERE id=?',(finding_id,)).fetchone()
        if finding is None:abort(404)
        if request.form.get('share_context')!='yes':abort(400)
        if not lock.acquire(blocking=False):
            flash('An AI review is already running. Try again shortly.')
            return redirect(url_for('finding_detail',finding_id=finding_id)+'#ai-review',code=303)
        try:
            from repository_routes import stored_token
            known=tuple(x for x in (app.config.get('LLM_API_KEY'),stored_token()) if x)
            context=db.execute('SELECT * FROM finding_context WHERE finding_id=?',(finding_id,)).fetchone()
            from analysis.remediation_workflow import finding_solution
            solution=finding_solution(db,finding)
            draft=db.execute('SELECT original FROM remediation_drafts WHERE finding_id=?',(finding_id,)).fetchone()
            from analysis.evidence_review import prepare_evidence,run_review
            payload=prepare_evidence(finding,solution,known) if finding['source']=='Repository' else None
            if payload is not None:
                result=run_review(finding,payload,app.config,draft['original'] if draft else None,known)
            else:
                # Historical snapshots and DAST keep the existing bounded interface.
                payload=prepare(finding,context,known,solution=solution)
                provider=app.config.get('LLM_REVIEW_PROVIDER',review)
                response=provider(payload,app.config)
                result=process(finding,payload,response,draft['original'] if draft else None,known)
            result['model']=app.config.get('LLM_MODEL','Configured provider')
            with db:db.execute("INSERT INTO ai_reviews(finding_id,data_json) VALUES (?,?) ON CONFLICT(finding_id) DO UPDATE SET data_json=excluded.data_json,created_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",(finding_id,json.dumps(result)))
            record_attempt(db,finding,False)
            flash('AI review saved. Scanner evidence and finding status are unchanged.')
        except Exception:
            # Never expose API bodies, credentials, source or exception messages.
            record_attempt(db,finding,True)
            flash('AI review unavailable or invalid. Deterministic guidance remains available and is shown; any earlier AI review is retained.')
        finally:lock.release()
        return redirect(url_for('finding_detail',finding_id=finding_id)+'#ai-review',code=303)

    @app.context_processor
    def ai_context():
        name='the configured AI provider' if app.config.get('LLM_EVIDENCE_PROVIDER') or app.config.get('LLM_REVIEW_PROVIDER') else 'OpenAI'
        return {'ai_enabled':app.config.get('LLM_ENABLED',False),'ai_provider_name':name}
