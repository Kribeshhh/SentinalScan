"""Deliberately insecure, loopback-only educational target. Never deploy this app."""
import sqlite3
from flask import Flask, request, make_response
from markupsafe import escape

app = Flask(__name__)


@app.get('/')
def index():
    q = request.args.get('q', 'hello')
    db = sqlite3.connect(':memory:')
    try:
        # Deliberate vulnerability for the SQL error detector; no real data or credentials.
        db.execute("SELECT 'educational row' WHERE 'hello' = '" + q + "'").fetchall()
        error = ''
    except sqlite3.Error as exc:
        error = 'sqlite3.OperationalError: ' + str(exc)
    finally:
        db.close()
    # Deliberate JavaScript-context interpolation for harmless marker detection.
    response = make_response('<!doctype html><html><head><title>SentinelScan educational lab</title></head><body><h1>Local assessment lab</h1><p>No real credentials or application data.</p><script>const search = "' + q + '";</script><pre>' + error + '</pre></body></html>')
    response.set_cookie('lab_session', 'LAB_COOKIE_VALUE_MUST_NOT_BE_STORED')
    if request.headers.get('Origin'):
        response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


@app.get('/.env')
def configuration():
    return 'APP_MODE=educational\nEXAMPLE_FLAG=enabled\n', 200, {'Content-Type':'text/plain'}


@app.get('/safe')
def safe_reflection():
    return '<!doctype html><html><body><p>' + str(escape(request.args.get('q', ''))) + '</p></body></html>'


@app.get('/.git/HEAD')
def git_head():
    return 'ref: refs/heads/educational-lab\n', 200, {'Content-Type':'text/plain'}


@app.get('/redirect-external')
def redirect_external():
    return '', 302, {'Location':'http://169.254.169.254/latest/meta-data/'}


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=False)
