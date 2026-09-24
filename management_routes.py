"""Comparison, risk history and report endpoints. Every write uses the app CSRF guard."""
import json
from flask import request,render_template,redirect,url_for,abort,send_file,flash
from database import get_db
from analysis.validation import record_id
from analysis.management import compare_scans,risk_trend
from reports.report_generator import FORMATS,generate_report,open_report


def register_management(app):
    @app.route('/comparisons',methods=['GET','POST'])
    def comparisons():
        error=None
        if request.method=='POST':
            try:
                previous=record_id(request.form.get('baseline',''));current=record_id(request.form.get('current',''))
                db=get_db()
                with db:
                    db.execute('BEGIN IMMEDIATE')
                    result=compare_scans(db,previous,current)
                    db.execute("INSERT INTO scan_comparisons(baseline_scan_id,current_scan_id,summary_json) VALUES (?,?,?) ON CONFLICT(baseline_scan_id,current_scan_id) DO UPDATE SET summary_json=excluded.summary_json,created_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",(previous,current,json.dumps(result)))
                    comparison_id=db.execute('SELECT id FROM scan_comparisons WHERE baseline_scan_id=? AND current_scan_id=?',(previous,current)).fetchone()[0]
                flash('Scan comparison saved.')
                return redirect(url_for('comparison_detail',comparison_id=comparison_id),code=303)
            except ValueError as exc:
                error=str(exc) if str(exc).startswith(('Select','Only','Scans','The baseline')) else 'Select valid scan IDs.'
        db=get_db()
        rows=db.execute("SELECT id,target,scan_type,created_at FROM scans WHERE status='Completed' ORDER BY created_at DESC,id DESC LIMIT 500").fetchall()
        history=db.execute('SELECT c.*,s.target FROM scan_comparisons c JOIN scans s ON s.id=c.current_scan_id ORDER BY c.created_at DESC,c.id DESC LIMIT 50').fetchall()
        return render_template('comparisons.html',title='Scan comparison',scans=rows,comparisons=history,error=error),400 if error else 200

    @app.get('/comparisons/<int:comparison_id>')
    def comparison_detail(comparison_id):
        row=get_db().execute('SELECT * FROM scan_comparisons WHERE id=?',(comparison_id,)).fetchone()
        if not row:
            abort(404)
        return render_template('comparison_detail.html',title='Comparison results',comparison=json.loads(row['summary_json']),comparison_id=comparison_id)

    @app.get('/risk-trends')
    def risk_trends():
        scan_id=request.args.get('scan_id','')
        try:
            selected=record_id(scan_id) if scan_id else None
            points=risk_trend(get_db(),selected)
        except ValueError:
            abort(400)
        options=get_db().execute("SELECT id,target,scan_type FROM scans WHERE status='Completed' ORDER BY created_at DESC,id DESC LIMIT 500").fetchall()
        return render_template('risk_trends.html',title='Risk trends',points=points,options=options,selected=selected)

    @app.post('/reports/generate')
    def report_generate():
        try:
            scan_id=record_id(request.form.get('scan_id',''))
            report_id=generate_report(scan_id,request.form.get('format',''))
        except ValueError:
            abort(400)
        flash('Report generated. View or download the saved snapshot below.')
        return redirect(url_for('reports',generated=report_id),code=303)

    def deliver_report(report_id,attachment):
        row=get_db().execute('SELECT * FROM reports WHERE id=?',(report_id,)).fetchone()
        if not row or row['format'] not in FORMATS:
            abort(404)
        try:
            handle=open_report(row)
        except OSError:
            abort(404)
        mime={'HTML':'text/html','JSON':'application/json','CSV':'text/csv'}[row['format']]
        response=send_file(handle,mimetype=mime,as_attachment=attachment or row['format']=='CSV',download_name=f"sentinelscan-scan-{row['scan_id']}-report-{row['id']}.{row['format'].lower()}",conditional=False,etag=False)
        response.call_on_close(handle.close)
        return response

    @app.get('/reports/<int:report_id>/download')
    def report_download(report_id):
        return deliver_report(report_id,True)

    @app.get('/reports/<int:report_id>/view')
    def report_view(report_id):
        return deliver_report(report_id,False)
