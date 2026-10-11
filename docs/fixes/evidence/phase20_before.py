import json,sys
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path.cwd()))
from scanner.http_scanner import Response
from scanner.target import validate_target
from scanner import xss_scanner,sqli_scanner
u='http://127.0.0.1/?action=fixture-noop&q=hello'
rows=[]
for m in (xss_scanner,sqli_scanner):
 response=Response(u,200,[('Content-Type','text/html')],b'baseline',False,[])
 client=Mock();client.get.return_value=response
 ctx=dict(target=validate_target(u,True),response=response,client=client,findings=[])
 m.run(ctx)
 rows.append({'module':m.__name__,'original':u,'urls':[c.args[0] for c in client.get.call_args_list],'requests':client.get.call_count})
Path('docs/fixes/PHASE_20_BEFORE.json').write_text(json.dumps(rows,indent=2))
print(rows)
