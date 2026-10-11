import json
from unittest.mock import patch
from scanner.target import validate_target
from scanner.http_scanner import Client,Response
from scanner.common import SkipModule
from scanner import xss_scanner,sqli_scanner,cors_scanner
u='http://127.0.0.1/?action=fixture-noop&q=hello'
records=[]
for module in (xss_scanner,sqli_scanner,cors_scanner):
    client=Client(validate_target(u,True),interval=0)
    ctx=dict(target=client.target,client=client,response=Response(u,200,[('Content-Type','text/html')],b'baseline',False,[]),findings=[])
    with patch('scanner.http_scanner.connect_ip') as connect:
        try:module.run(ctx);status='unexpected completion';reason=''
        except SkipModule as e:status='Skipped';reason=str(e)
        records.append(dict(module=module.__name__,original=u,status=status,reason=reason,requests=client.count,socket_calls=connect.call_count,generated_probe_urls=sorted(client._probe_urls)))
print(json.dumps(records,indent=2))
