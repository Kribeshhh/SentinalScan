import sys,json,time
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlsplit,parse_qs
sys.path.insert(0,str(Path.cwd()))
from scanner.http_scanner import Response
from scanner.target import validate_target
from scanner import header_scanner as h,xss_scanner as x,sqli_scanner as s,disclosure_scanner as d
from evaluation.run import metrics
rows=[]
def response(body,headers=None,url='https://localhost/?q=fixture'):
 return Response(url,200,headers or [('Content-Type','text/html')],body.encode(),False,[])
def run(name,category,expected,rationale,module,base,reply=None,title=None):
 client=Mock();client.parameter_urls.side_effect=lambda u,f:x.parameter_urls(u,f,{'https://localhost/?q=fixture':[0]});client.get.side_effect=reply if callable(reply) else None;client.get.return_value=reply
 ctx=dict(target=validate_target('https://localhost/?q=fixture',True),response=base,client=client,findings=[])
 module.run(ctx);titles=[f.title for f in ctx['findings']];detected=title in titles if title else bool(titles)
 rows.append(dict(name=name,category=category,expected=expected,detected=detected,ground_truth=rationale,findings=titles,outcome='TP' if expected and detected else 'FN' if expected else 'FP' if detected else 'TN'))
secure=[('Content-Type','text/html'),('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'"),('X-Content-Type-Options','nosniff'),('Referrer-Policy','no-referrer'),('Permissions-Policy','camera=()'),('Strict-Transport-Security','max-age=31536000')]
for name,policy,expected in [('missing framing',"default-src 'self'",True),('restricted framing',"default-src 'self'; frame-ancestors 'none'",False),('wildcard framing',"default-src 'self'; frame-ancestors *",True)]:
 run(name,'Framing protection',expected,'No X-Frame-Options; CSP '+policy,h,response('<p>fixture</p>',[(k,policy if k=='Content-Security-Policy' else v) for k,v in secure]),title='Missing or invalid framing protection')
for kind,expected in [('script',True),('text',False),('json',False)]:
 def reply(url,kind=kind):
  marker=parse_qs(urlsplit(url).query)['q'][0]
  body={'script':'<script>let a="'+marker+'";</script>','text':'<p>'+marker+'</p>','json':'<script type="application/json">'+json.dumps(marker)+'</script>'}[kind]
  return response(body,url=url)
 run('reflection '+kind,'XSS indicators',expected,'Executable script reflection is indicator-positive; HTML text/inert JSON are indicator-negative, not exploit tests.',x,response('<p>baseline</p>'),reply)
for name,body,expected,why in [('new error','sqlite3.OperationalError: fixture',True,'Fixture represents a new database exception after a probe.'),('neutral','generic response',False,'No database error signature.'),('documentation','Documentation: sqlite3.OperationalError is a Python exception.',False,'Authored documentation, not a runtime exception.')]:
 run('SQL '+name,'SQL indicators',expected,why,s,response('baseline'),response(body))
for name,body,expected,why in [('runtime','Traceback (most recent call last)',True,'Authored response represents a runtime stack trace.'),('neutral','generic error',False,'No trace disclosure.'),('tutorial','Tutorial: Traceback (most recent call last)',False,'Authored tutorial text, not runtime disclosure.')]:
 run('disclosure '+name,'Disclosure',expected,why,d,response(body))
result={'unit':'One targeted category/indicator presence decision per controlled response case; not exploitability','sample_size':len(rows),'overall':metrics([(r['expected'],r['detected']) for r in rows]),'categories':{c:metrics([(r['expected'],r['detected']) for r in rows if r['category']==c]) for c in sorted({r['category'] for r in rows})},'cases':rows}
Path('docs/audit/PHASE_22_WEBSITE.json').write_text(json.dumps(result,indent=2));print(json.dumps(result['overall']))
