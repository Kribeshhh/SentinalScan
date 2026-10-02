"""AI never runs in scan workers; one explicit request reviews one existing finding."""
import json
import threading
from flask import abort,request,redirect,url_for,flash,has_request_context
from database import get_db
from integrations.llm import review
from analysis.llm_review import prepare,process


def register_llm(app):
    lock=threading.Lock()

    @app.post('/findings/<int:finding_id>/ai-review')
    def ai_review(finding_id):
        if not app.config.get('LLM_ENABLED'):abort(404)
        db=get_db();finding=db.execute('SELECT * FROM findings WHERE id=?',(finding_id,)).fetchone()
        if finding is None or finding['source']!='Repository':abort(404)
        if request.form.get('share_context')!='yes':abort(400)
        if not lock.acquire(blocking=False):
            flash('An AI review is already running. Try again shortly.')
            return redirect(url_for('finding_detail',finding_id=finding_id)+'#ai-review',code=303)
        try:
            from repository_routes import stored_token
            known=tuple(x for x in (app.config.get('LLM_API_KEY'),stored_token()) if x)
            context=db.execute('SELECT * FROM finding_context WHERE finding_id=?',(finding_id,)).fetchone()
            payload=prepare(finding,context,known)
            provider=app.config.get('LLM_REVIEW_PROVIDER',review)
            response=provider(payload,app.config)
            draft=db.execute('SELECT original FROM remediation_drafts WHERE finding_id=?',(finding_id,)).fetchone()
            result=process(finding,payload,response,draft['original'] if draft else None,known)
            result['model']=app.config.get('LLM_MODEL','Configured provider')
            with db:db.execute("INSERT INTO ai_reviews(finding_id,data_json) VALUES (?,?) ON CONFLICT(finding_id) DO UPDATE SET data_json=excluded.data_json,created_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",(finding_id,json.dumps(result)))
            flash('AI review saved. Scanner evidence and finding status are unchanged.')
        except Exception:
            # Never expose API bodies, credentials, source or exception messages.
            flash('AI review unavailable or invalid. Deterministic guidance remains available; any earlier AI review is unchanged.')
        finally:lock.release()
        return redirect(url_for('finding_detail',finding_id=finding_id)+'#ai-review',code=303)

    @app.context_processor
    def ai_context():
        finding_id=(request.view_args or {}).get('finding_id') if has_request_context() else None
        if not isinstance(finding_id,int) or not 0<finding_id<2**63:finding_id=None
        row=get_db().execute('SELECT * FROM ai_reviews WHERE finding_id=?',(finding_id,)).fetchone() if finding_id else None
        return {'ai_enabled':app.config.get('LLM_ENABLED',False),'ai_review_data':json.loads(row['data_json']) if row else None,'ai_review_date':row['created_at'] if row else None}
