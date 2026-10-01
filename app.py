"""SentinelScan academic security assessment platform. Run with python3 app.py."""
import hmac
import secrets
import json
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for, jsonify
from werkzeug.exceptions import HTTPException, SecurityError
from werkzeug.serving import WSGIRequestHandler
from config import settings
from database import get_db, init_app
from analysis.finding_engine import STATUSES, SOURCES
from analysis.risk_engine import SEVERITY_WEIGHTS, calculate_risk
from scanner.target import validate_target, TargetError
from scanner.directory_scanner import paths_from_text, DEFAULT_PATHS
from scanner.website_scanner import ScanManager, QueueFull
from repository_routes import register_routes
from management_routes import register_management
from remediation_routes import register_remediation
from analysis.management import scan_metrics, risk_trend
from analysis.validation import record_id
from analysis.redaction import redact_text
from analysis.solution_engine import solution_for
from analysis.remediation_workflow import workflow_data, finding_solution
from workflow_routes import register_workflow


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(settings())
    if test_config:
        app.config.update(test_config)
    init_app(app)
    app.extensions["scan_manager"] = ScanManager(app)
    register_routes(app)
    register_management(app)
    register_remediation(app)
    register_workflow(app)

    @app.before_request
    def csrf_protection():
        for value in (request.view_args or {}).values():
            if isinstance(value, int):
                try:
                    record_id(value)
                except ValueError:
                    abort(404)
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.files:
                abort(400)  # No upload endpoint; do not accept unexpected file parts.
            token = request.form.get("csrf_token", "")
            if not hmac.compare_digest(session["csrf_token"].encode(), token.encode()):
                abort(400, description="The form expired or could not be verified. Reload the page and try again.")

    @app.after_request
    def secure_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        if request.endpoint == 'report_view':
            response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.context_processor
    def shared_context():
        return dict(severities=SEVERITY_WEIGHTS, statuses=STATUSES, sources=SOURCES)

    @app.get("/")
    def dashboard():
        db = get_db()
        scans = dict(db.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type").fetchall())
        severity_counts = dict(db.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall())
        risk_rows = db.execute("SELECT severity, status FROM findings WHERE status = 'Open'").fetchall()
        return render_template("dashboard.html", title="Dashboard", scan_counts=scans,
            total_scans=sum(scans.values()), severity_counts=severity_counts, points=risk_trend(db),
            risk=calculate_risk(risk_rows), unresolved=len(risk_rows),
            finding_count=sum(severity_counts.values()),
            recent_scans=db.execute("SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT 5").fetchall(),
            recent_findings=db.execute("SELECT * FROM findings ORDER BY created_at DESC, id DESC LIMIT 5").fetchall(),
            categories=db.execute("SELECT category AS label, COUNT(*) AS count FROM findings GROUP BY category ORDER BY count DESC, category").fetchall(),
            source_counts=db.execute("SELECT source AS label, COUNT(*) AS count FROM findings GROUP BY source ORDER BY count DESC, source").fetchall())

    @app.route("/website-scan", methods=["GET", "POST"])
    def website_scan():
        form = dict(url="", paths="\n".join(DEFAULT_PATHS), allow_private=False, authorized=False)
        error, validation = None, None
        if request.method == "POST":
            form = dict(url=request.form.get("url", "").strip(), paths=request.form.get("paths", ""),
                        allow_private=request.form.get("allow_private") == "yes",
                        authorized=request.form.get("authorized") == "yes")
            try:
                if not form["authorized"]:
                    raise TargetError("Confirm that you own this target or have permission to assess it.")
                paths = paths_from_text(form["paths"])
                target = validate_target(form["url"], form["allow_private"])
                action = request.form.get("action")
                if action == "start":
                    scan_id = app.extensions["scan_manager"].submit(target, paths)
                    return redirect(url_for("scan_detail", scan_id=scan_id), code=303)
                if action != "validate":
                    raise TargetError("Invalid scan action.")
                validation = {"host": target.host, "addresses": target.addresses}
            except (TargetError, ValueError, QueueFull) as exc:
                error = str(exc)
                form['url'] = redact_text(form['url'])
                form['paths'] = redact_text(form['paths'])
        return render_template("website_scan.html", title="Website Scan", form=form, error=error, validation=validation), 400 if error else 200

    def scan_record(scan_id):
        record = get_db().execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if record is None:
            abort(404)
        return record

    @app.get("/scans/<int:scan_id>")
    def scan_detail(scan_id):
        scan = scan_record(scan_id)
        db = get_db()
        modules = [dict(row) for row in db.execute("SELECT * FROM scan_modules WHERE scan_id=? ORDER BY id", (scan_id,))]
        for module in modules:
            module["formatted_data"] = json.dumps(json.loads(module["data_json"]), indent=2, ensure_ascii=False)
        rows = db.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, id", (scan_id,)).fetchall()
        return render_template("scan_detail.html", title="Scan summary", scan=scan, modules=modules, findings=rows,
                               verification_findings=db.execute("SELECT f.id,f.title,v.result FROM remediation_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.scan_id=?", (scan_id,)).fetchall(),
                               risk=calculate_risk(rows), warnings=sum(m["status"] in ("Failed", "Skipped", "Partial") for m in modules))

    @app.get("/scans/<int:scan_id>/status")
    def scan_status(scan_id):
        scan = scan_record(scan_id)
        modules = get_db().execute("SELECT name,status,error FROM scan_modules WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return jsonify(status=scan["status"], progress=scan["progress"], modules=[dict(row) for row in modules])

    def page_number():
        try:
            page = int(request.args.get("page", "1"))
        except ValueError:
            abort(400)
        if not 1 <= page <= 1000000:
            abort(400)
        return page

    @app.get("/scans")
    def scans():
        page = page_number()
        db = get_db()
        rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT 26 OFFSET ?", ((page-1)*25,)).fetchall()
        return render_template("scans.html", title="Scan History", scans=[scan_metrics(db,row) for row in rows[:25]], page=page, has_next=len(rows)>25)

    @app.get("/findings")
    def findings():
        page = page_number()
        db=get_db()
        categories=[row[0] for row in db.execute('SELECT DISTINCT category FROM findings ORDER BY category')]
        filters = {name: request.args.get(name, "") for name in ("severity", "confidence", "category", "status", "source", "scan_id", "q")}
        allowed = {"severity": SEVERITY_WEIGHTS, "confidence":('High','Medium','Low'), "category":categories,"status": STATUSES, "source": SOURCES}
        clauses, values = [], []
        for name in allowed:
            value=filters[name]
            if value:
                if value not in allowed[name]:
                    abort(400)
                clauses.append(name + " = ?")  # column names are fixed above, never user supplied
                values.append(value)
        if filters['scan_id']:
            try:
                scan_id=record_id(filters['scan_id'])
                if scan_id<1:
                    raise ValueError()
            except ValueError:
                abort(400)
            clauses.append('scan_id = ?');values.append(scan_id)
        if filters['q']:
            if len(filters['q'])>200 or any(ord(c)<32 for c in filters['q']):
                abort(400)
            literal=filters['q'].replace('!', '!!').replace('%','!%').replace('_','!_')
            search_fields=('title','location','description','evidence','recommendation')
            clauses.append('('+' OR '.join(field+" LIKE ? ESCAPE '!'" for field in search_fields)+')')
            values.extend(['%'+literal+'%']*len(search_fields))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = get_db().execute("SELECT * FROM findings" + where + " ORDER BY created_at DESC, id DESC LIMIT 26 OFFSET ?", (*values, (page-1)*25)).fetchall()
        return render_template("findings.html", title="Findings", findings=rows[:25], filters=filters, categories=categories, scan_options=db.execute("SELECT id,target FROM scans ORDER BY created_at DESC,id DESC LIMIT 500").fetchall(), page=page, has_next=len(rows)>25)

    @app.get("/findings/<int:finding_id>")
    def finding_detail(finding_id):
        finding = get_db().execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if finding is None:
            abort(404)
        workflow = workflow_data(get_db(),finding)
        draft = workflow['draft']
        return render_template("finding_detail.html", title="Finding details", finding=finding,
            solution=finding_solution(get_db(),finding,draft), source_loaded=bool(draft), workflow=workflow, finding_id=finding_id)

    @app.post("/findings/<int:finding_id>/status")
    def update_finding_status(finding_id):
        status = request.form.get("status")
        if status not in STATUSES:
            abort(400)
        db = get_db()
        with db:
            updated = db.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
            if updated.rowcount == 0:
                abort(404)
            scan_id = db.execute("SELECT scan_id FROM findings WHERE id=?", (finding_id,)).fetchone()[0]
            rows = db.execute("SELECT severity,status FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
            db.execute("UPDATE scans SET risk_score=? WHERE id=?", (calculate_risk(rows),scan_id))
        flash("Finding status updated.")
        return redirect(url_for("finding_detail", finding_id=finding_id), code=303)

    @app.get("/reports")
    def reports():
        page = page_number()
        try:
            selected = record_id(request.args['scan_id']) if request.args.get('scan_id') else None
        except ValueError:
            abort(400)
        rows = get_db().execute("SELECT reports.id, reports.scan_id, reports.format, reports.created_at, scans.target, scans.scan_type FROM reports JOIN scans ON scans.id = reports.scan_id ORDER BY reports.created_at DESC, reports.id DESC LIMIT 26 OFFSET ?", ((page-1)*25,)).fetchall()
        return render_template("reports.html", title="Reports", reports=rows[:25], selected=selected, scan_options=get_db().execute("SELECT id,target,status FROM scans WHERE status IN ('Completed','Failed') ORDER BY created_at DESC,id DESC LIMIT 500").fetchall(), page=page, has_next=len(rows)>25)

    @app.errorhandler(HTTPException)
    def http_error(error):
        if isinstance(error, SecurityError):
            # Host rejection happens before routing, so url_for is unavailable.
            return "Invalid request host.", 400, {"Content-Type": "text/plain; charset=utf-8"}
        messages = {400: "Invalid request. Check your input or reload the form and try again.", 404: "We could not find that page or record.", 405: "This action is not available.", 413: "The submitted request is too large."}
        return render_template("error.html", title="Request unavailable", code=error.code, message=messages.get(error.code, "The request could not be completed.")), error.code

    @app.errorhandler(Exception)
    def unexpected_error(error):
        # Avoid exception payloads, targets, source code, or credentials in logs.
        app.logger.error("Request failed (%s)", type(error).__name__)
        return render_template("error.html", title="Something went wrong", code=500, message="An internal error occurred. Please try again later."), 500

    return app


class PrivateRequestHandler(WSGIRequestHandler):
    """Access logs must not include target URLs, query strings or credentials."""

    def log_request(self, code="-", size="-"):
        self.log("info", "Request completed: %s", code)

    def log_error(self, format, *args):
        self.log("error", "HTTP request failed")


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False, request_handler=PrivateRequestHandler)
