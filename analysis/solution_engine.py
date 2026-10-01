"""Deterministic remediation examples. Never interpolate scanned evidence into code."""
from pathlib import PurePosixPath
import re

VERSION = 2


def example(language, code):
    return {'language': language, 'code': code.strip()+'\n'}


def catalogue_solution(finding):
    f=dict(finding)
    title=f['title'].lower();category=f['category'];website=f['source']=='Website'
    suffix=PurePosixPath(re.sub(r':\d+$','',f['location'])).suffix.lower()
    java=suffix=='.java';js=suffix in ('.js','.jsx','.mjs','.cjs')
    result={'version':VERSION,'matched':True,'summary':'','examples':[],
        'notes':['Illustrative solution: adapt names, APIs and configuration to your application. This is not an automatically verified patch.'],
        'verification':['Test normal behavior and the previously vulnerable case, then re-scan. Saving or copying this example does not resolve the finding.']}
    if website:
        result['notes'].append('DAST cannot identify the exact source change. The framework labels below are examples, not detected technologies.')
    def use(summary,language,code,notes=None):
        result['summary']=summary;result['examples']=[example(language,code)]
        if notes: result['notes'].append(notes)
        return result
    if category=='Security Headers':
        headers={
            'Missing Content-Security-Policy':('Content-Security-Policy',"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
            'Permissive Content-Security-Policy':('Content-Security-Policy',"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
            'Missing X-Content-Type-Options':('X-Content-Type-Options','nosniff'),
            'Invalid MIME sniffing protection':('X-Content-Type-Options','nosniff'),
            'Missing Referrer-Policy':('Referrer-Policy','strict-origin-when-cross-origin'),
            'Permissive Referrer-Policy':('Referrer-Policy','no-referrer'),
            'Missing Permissions-Policy':('Permissions-Policy','camera=(), microphone=(), geolocation=()'),
            'Missing or invalid framing protection':('Content-Security-Policy',"frame-ancestors 'none'"),
            'Missing or disabled HSTS':('Strict-Transport-Security','max-age=31536000'),
        }
        if f['title'] in headers:
            name,value=headers[f['title']]
            return use('Set the response header at the application or reverse proxy.', 'Python / Flask',
                f'@app.after_request\ndef security_header(response):\n    response.headers[{name!r}] = {value!r}\n    return response',
                'Merge CSP directives with your existing policy; test required scripts/resources and embedding. Enable HSTS only after HTTPS is working reliably. Verify headers on actual deployed responses, including errors.')
    if category=='Cookie Security':
        return use('Apply cookie protections when issuing the affected cookie.','Python / Flask',
            'response.set_cookie(\n    "session_id", session_id,\n    secure=True, httponly=True, samesite="Lax"\n)',
            'Use the actual cookie name. Secure requires HTTPS. For deliberately cross-site cookies, assess CSRF protections and use SameSite=None with Secure; HttpOnly suits cookies JavaScript does not need to read.')
    if 'sql injection' in title:
        result['reference']='https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        if java:
            return use('Bind input values rather than constructing SQL text.','Java / JDBC',
                'try (PreparedStatement stmt = connection.prepareStatement(\n        "SELECT id FROM users WHERE username = ?")) {\n    stmt.setString(1, username);\n    try (ResultSet rows = stmt.executeQuery()) {\n        // Consume the result set here.\n    }\n}')
        return use('Keep SQL structure constant and bind untrusted values.','Python / sqlite3',
            'rows = connection.execute(\n    "SELECT id FROM users WHERE username = ?",\n    (username,),\n).fetchall()', 'Placeholder syntax depends on the database driver. Dynamic column/table names need a fixed allowlist; value placeholders cannot bind identifiers.')
    if 'xss' in title or 'cross-site scripting' in title or 'dom html' in title or 'document.write' in title:
        result['reference']='https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
        return use('Render untrusted input as text instead of interpreting it as markup.','JavaScript / DOM',
            'const output = document.querySelector("#result");\noutput.textContent = userInput;',
            'This protects DOM text insertion only. Server templates need contextual escaping; URLs require scheme validation. For intentional rich HTML, use a maintained sanitizer with an explicit policy.')
    if 'dynamic python' in title:
        return use('Parse structured data rather than executing user-provided code.','Python',
            'import json\n\ndef parse_input(raw):\n    if len(raw) > 10000:\n        raise ValueError("Input too large")\n    value = json.loads(raw)\n    if not isinstance(value, dict):\n        raise ValueError("Expected an object")\n    return value', 'JSON parsing is appropriate for data input, not a drop-in replacement for expressions. For commands, dispatch only explicitly allowed operations.')
    if 'dynamic javascript' in title:
        return use('Parse data and validate its structure rather than calling eval or Function.','JavaScript',
            'function parseInput(raw) {\n  if (raw.length > 10000) throw new Error("Input too large");\n  const value = JSON.parse(raw);\n  if (value === null || Array.isArray(value) || typeof value !== "object") {\n    throw new Error("Expected an object");\n  }\n  return value;\n}')
    if 'shell' in title or 'process execution' in title:
        if java:
            return use('Use a fixed executable and validate every argument.','Java',
                'if (!java.util.Set.of("status", "version").contains(operation)) {\n    throw new IllegalArgumentException("Unsupported operation");\n}\nProcess process = new ProcessBuilder("/opt/app/bin/tool", operation).start();',
                'Replace the example executable with your trusted program. Drain output, enforce a timeout and avoid shell interpreters.')
        return use('Use an argument list with shell=False and a strict argument allowlist.','Python',
            'import subprocess\n\nif operation not in {"status", "version"}:\n    raise ValueError("Unsupported operation")\nresult = subprocess.run(\n    ["/opt/app/bin/tool", operation],\n    shell=False, check=True, timeout=10,\n)', 'Replace the executable with your trusted program. shell=False alone does not prevent dangerous program options or path traversal.')
    if 'deserialization' in title:
        if java:
            return use('Replace untrusted Java object deserialization with a bounded data-only format.','Java / Jackson example',
                'record RequestData(String action) {}\n// Keep polymorphic default typing disabled.\nif (body.length() > 10000) throw new IllegalArgumentException("Too large");\nvar mapper = new com.fasterxml.jackson.databind.ObjectMapper();\nRequestData input = mapper.readValue(body, RequestData.class);\nif (!java.util.Set.of("status", "version").contains(input.action())) {\n    throw new IllegalArgumentException("Unsupported action");\n}', 'Requires a maintained Jackson dependency and a Java version supporting records. Also bound request size before buffering.')
        if 'yaml' in f.get('evidence','').lower():
            return use('Use safe YAML loading for untrusted data.','Python / PyYAML',
                'import yaml\n\nif len(raw) > 10000:\n    raise ValueError("Input too large")\ndata = yaml.safe_load(raw)', 'Validate the schema and restrict nesting/aliases and processing time. safe_load blocks object construction, not resource exhaustion.')
        return use('Replace pickle or other object deserialization with bounded, validated JSON.','Python',
            'import json\n\nif len(raw) > 10000:\n    raise ValueError("Input too large")\ndata = json.loads(raw)\nif not isinstance(data, dict):\n    raise ValueError("Expected an object")', 'Validate expected keys and types. This requires changing the producer as well as the consumer; do not merely wrap unsafe deserialization.')
    if category=='Cryptography':
        if java:
            return use('Choose a primitive appropriate to the security purpose.','Java',
                '// For a security-sensitive digest (not password storage):\nbyte[] digest = java.security.MessageDigest.getInstance("SHA-256")\n    .digest(data);\n\n// For encryption, use authenticated encryption:\njavax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");',
                'For AES-GCM, initialize with a securely generated key and a fresh unique nonce per key, retain the authentication tag, and verify it on decryption. Passwords need a dedicated password hash, not SHA-256.')
        return use('Use SHA-256 for digests; use a dedicated password hash for passwords.','Python',
            'import hashlib\nfrom werkzeug.security import generate_password_hash, check_password_hash\n\ndigest = hashlib.sha256(data).hexdigest()\nstored_hash = generate_password_hash(password, method="scrypt")\nvalid = check_password_hash(stored_hash, candidate_password)', 'The password example requires Werkzeug. Migrate existing hashes carefully; some MD5/SHA1 uses are non-security checksums and need contextual review.')
    if category=='Secret Exposure':
        language='Java' if java else ('JavaScript / Node.js' if js else 'Python')
        code=('String credential = System.getenv("SERVICE_CREDENTIAL");\nif (credential == null || credential.isBlank()) {\n    throw new IllegalStateException("Missing service credential");\n}' if java else
              'const credential = process.env.SERVICE_CREDENTIAL;\nif (!credential) throw new Error("Missing service credential");' if js else
              'import os\n\ncredential = os.environ["SERVICE_CREDENTIAL"]')
        return use('Remove the hardcoded value and inject the replacement at runtime.',language,code,
            'Revoke/rotate the exposed credential first, including affected sessions/keys. Review Git history and logs. Supply the new value through a secret manager or protected runtime environment; never expose it in frontend JavaScript.')
    if category=='Dependency':
        return use('Upgrade the affected dependency to a verified fixed release.','Dependency update checklist',
            '# 1. Open the advisory named in this finding.\n# 2. Choose a compatible release outside every affected range.\n# 3. Update the manifest and regenerate its lockfile.\n# 4. Run application and security regression tests.\n# 5. Re-scan the updated dependency set.',
            'No version is invented here. A fixed version may not exist; use the advisory and vendor guidance, or remove/replace the dependency. Run package-manager changes in your development environment.')
    if category=='CORS':
        return use('Allow only explicitly trusted browser origins.','Python / Flask',
            'TRUSTED_ORIGINS = {"https://app.example.com"}\n\n@app.after_request\ndef cors(response):\n    origin = request.headers.get("Origin")\n    if origin in TRUSTED_ORIGINS:\n        response.headers["Access-Control-Allow-Origin"] = origin\n    response.vary.add("Origin")\n    return response', 'Import request from flask. Replace the example origin. Remove conflicting proxy headers; implement required preflight methods/headers explicitly. Only enable credentials when needed; CORS is not authentication or CSRF protection.')
    if category in ('TLS','Transport Security') or 'unencrypted http' in title or 'external resource transport' in title:
        return use('Serve content through a correctly configured HTTPS endpoint.','Nginx configuration example',
            'server {\n    listen 80;\n    server_name app.example.com;\n    return 308 https://app.example.com$request_uri;\n}\nserver {\n    listen 443 ssl;\n    server_name app.example.com;\n    ssl_certificate /etc/nginx/tls/fullchain.pem;\n    ssl_certificate_key /etc/nginx/tls/privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    location / {\n        proxy_pass http://127.0.0.1:8000;\n    }\n}', 'Replace hostname, upstream and certificate paths. Obtain/renew a trusted certificate covering the hostname and test renewal automation. Updating config alone does not issue a certificate. Change HTTP links and form actions to HTTPS too.')
    if 'password form' in title:
        return use('Submit credentials in a POST body over HTTPS.','HTML / Jinja example',
            '<form method="post" action="/login">\n  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">\n  <input type="password" name="password" autocomplete="current-password" required>\n  <button type="submit">Sign in</button>\n</form>', 'Serve the page over HTTPS. Generate and validate the CSRF token on the server; a hidden input alone does not implement CSRF protection. Reject GET-based login submissions and keep credentials out of logs.')
    if 'debug' in title or 'verbose application error' in title:
        return use('Disable debug output in production and return generic errors.','Python / Flask',
            'app.config["DEBUG"] = False\n\n@app.errorhandler(500)\ndef internal_error(error):\n    return "An internal error occurred.", 500', 'Also disable debug/development mode in your deployment command/environment. Record sanitized diagnostics privately, without credentials or raw request bodies.')
    if 'wildcard allowed hosts' in title:
        return use('List only the deployment hostnames.','Python / Django settings',
            'ALLOWED_HOSTS = ["app.example.com"]', 'Replace the hostname and review reverse-proxy host handling. Flask applications can use TRUSTED_HOSTS instead.')
    if 'security control disabled' in title:
        evidence=f.get('evidence','').lower()
        settings={'session_cookie_secure':'SESSION_COOKIE_SECURE = True','session_cookie_httponly':'SESSION_COOKIE_HTTPONLY = True',
            'wtf_csrf_enabled':'WTF_CSRF_ENABLED = True','csrf_enabled':'CSRF_ENABLED = True',
            'verify_ssl':'verify_ssl = True','ssl_verify':'ssl_verify = True','check_hostname':'check_hostname = True','server.ssl.enabled':'server.ssl.enabled=true'}
        for key,value in settings.items():
            if re.search(r'\b'+re.escape(key)+r'\b',evidence):
                return use('Enable the detected security control in the effective runtime configuration.','Configuration example',value,
                    'Use the actual setting name and syntax required by your framework. CSRF also requires middleware/token validation; HTTPS requires valid certificates. A configuration flag alone may not implement the protection.')
    if 'directory listing' in title:
        return use('Disable automatic directory indexes.','Nginx / location block','location / {\n    autoindex off;\n    try_files $uri $uri/ =404;\n}', 'Merge this into the existing static-file location; do not replace application routing blindly.')
    if 'exposed git' in title or 'environment configuration' in title:
        return use('Remove sensitive files from the served directory and deny requests for them.','Nginx / server block',
            'location ~ (^|/)\\.git(?:/|$) { deny all; }\nlocation ~ (^|/)\\.env(?:[./]|$) { deny all; }',
            'Verify location precedence and ensure no other route serves these files. Rotate any exposed secrets and review access logs; blocking future requests does not undo exposure.')
    if 'version disclosed' in title:
        return use('Minimize banners while keeping the software patched.','Nginx / http or server block',
            'server_tokens off;\n# For a proxied application:\nproxy_hide_header X-Powered-By;', 'This does not remove every banner or fix vulnerable software. Review other layers and responses; version disclosure alone is informational.')
    if 'source map' in title:
        return use('Keep production source maps private if they disclose sensitive implementation details.','Nginx / server block',
            'location ~ \\.map$ {\n    return 404;\n}', 'Prefer excluding maps from the public deployment and uploading them privately to your error tracker. Remove references where appropriate and verify rule precedence. Public source maps are not inherently vulnerabilities.')
    if 'sensitive html comment' in title:
        return use('Remove sensitive comments from the delivered HTML.','HTML',
            '<!-- Keep only non-sensitive public documentation here. -->\n<main>Application content</main>', 'Remove actual sensitive notes rather than replacing unrelated markup. Rotate any disclosed credentials; check generated HTML and build artifacts.')
    result['matched']=False
    result['summary']='No reviewed code example is available for this finding type. Follow its recommendation and inspect the affected component before changing code.'
    return result


def solution_for(finding, source=None):
    """Pair examples with replacement boundaries; exact edits require matching source."""
    f=dict(finding);result=catalogue_solution(f)
    title=f['title'].lower();category=f['category']
    before=None
    if 'sql injection' in title:
        before=('statement.executeQuery("SELECT id FROM users WHERE username = \'" + username + "\'");'
                if '.java' in f['location'] else 'connection.execute("SELECT id FROM users WHERE username = \'" + username + "\'")')
    elif 'dom html' in title: before='output.innerHTML = userInput;'
    elif 'document.write' in title: before='document.write(userInput);'
    elif 'xss' in title: before='output.innerHTML = userInput;'
    elif 'dynamic python' in title: before='value = eval(raw)'
    elif 'dynamic javascript' in title: before='const value = eval(raw);'
    elif 'shell' in title: before='subprocess.run("tool " + operation, shell=True)'
    elif 'process execution' in title: before='Runtime.getRuntime().exec(command);'
    elif 'deserialization' in title:
        before='input.readObject();' if '.java' in f['location'] else 'data = yaml.load(raw, Loader=yaml.Loader)' if 'yaml' in f.get('evidence','').lower() else 'data = pickle.loads(raw)'
    elif category=='Secret Exposure': before='# Hardcoded credential assignment — value intentionally omitted.'
    elif 'debug' in title or 'verbose application error' in title: before='DEBUG = True'
    elif 'wildcard allowed hosts' in title: before='ALLOWED_HOSTS = ["*"]'
    elif 'password form' in title: before='<form method="get" action="/login"> ... </form>'
    elif 'directory listing' in title: before='autoindex on;'
    elif category=='Cookie Security': before='response.set_cookie("session_id", session_id)'
    elif category=='CORS': before='# Unconditionally reflecting the incoming Origin header:\nresponse.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin")'
    if 'dom html' in title:
        result['examples'].append(example('JavaScript / DOMPurify · intentional HTML',
            'output.innerHTML = DOMPurify.sanitize(userInput, {USE_PROFILES: {html: true}});'))
        result['notes'].append('Choose textContent only for plain text. For intended HTML, import a maintained DOMPurify version first and review its policy. These are alternatives, not sequential steps; outerHTML also has different element-replacement behavior.')
    result['before']=before
    result['before_label']='Illustrative vulnerable pattern — not retrieved source'
    result['action']='Replace the vulnerable operation, adapting the example to the surrounding code.'
    if category=='Security Headers':
        result['action']='Add this header at the response-producing layer, or update the existing header. Do not replace the whole application or overwrite unrelated CSP directives.'
    elif category in ('TLS','Transport Security','Configuration','Information Disclosure'):
        result['action']='Change the affected configuration or deployment setting; merge the example into your existing configuration.'
    elif category=='Dependency': result['action']='Update the affected manifest entry and lockfile after checking the advisory. There is no universal code replacement.'
    result['source_status']=('Source context was not captured for this older scan. Run a new scan to show code automatically, or use the source editor.'
        if f['source']=='Repository' else 'Website scanning cannot retrieve backend source files; the pattern below is illustrative.')
    result['context']=None
    result['exact']=False
    if f.get('status')=='False Positive':
        result.update(examples=[],before=None,matched=False,summary='This finding is marked False Positive.',
            action='No vulnerability fix is recommended for this dismissed detection. Review the finding description for the reason.',notes=[],verification=[])
        return result
    if category=='Dependency':
        from analysis.dependency_solution import dependency_solution
        dependency_solution(result,f,source)
        return result
    if source is not None:
        from analysis.source_solution import enrich_source_solution
        enrich_source_solution(result,f,source)
    return result
