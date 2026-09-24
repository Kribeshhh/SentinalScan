import re
from scanner.common import baseline, issue
from scanner.xss_scanner import parameter_urls
from scanner.target import safe_url

PATTERNS = {'MySQL syntax error':r'you have an error in your sql syntax', 'PostgreSQL query error':r'(?:psycopg\w*\.(?:errors|ProgrammingError)|unterminated quoted string|syntax error at or near)', 'SQLite query error':r'(?:sqlite3?\.(?:OperationalError|DatabaseError)|SQLiteException|unrecognized token:)', 'SQL Server query error':r'(?:unclosed quotation mark after the character string|Microsoft.*SQL Server.*Driver)', 'Oracle query error':r'ORA-0(?:1756|0933|0907)'}


def matches(text):
    return {name for name,pattern in PATTERNS.items() if re.search(pattern,text,re.I)}


def run(ctx):
    response = baseline(ctx)
    original = matches(response.text)
    observations = []
    for name,url,_ in parameter_urls(response.url, lambda value:value + "'"):
        probe = ctx['client'].get(url)
        new = matches(probe.text) - original
        row = {'parameter':name,'baseline_status':response.status,'probe_status':probe.status,'length_delta':len(probe.body)-len(response.body),'new_database_error_signatures':sorted(new)}
        observations.append(row)
        if new:
            issue(ctx,'Potential SQL Injection','Medium','SQL Injection',f'Appending one quote to parameter {name} introduced database-specific error signatures: {", ".join(sorted(new))}. Response bodies are not retained.','Use parameterized database queries, validate inputs and suppress database error details. Confirm the suspected issue in an authorized test environment.','Medium',location=safe_url(response.url) + ' [parameter: ' + name + ']')
    return {'parameters':observations,'note':'One quote probe per eligible parameter. Status/length differences alone do not create findings. No boolean, time-delay, UNION or data extraction payloads.'}
