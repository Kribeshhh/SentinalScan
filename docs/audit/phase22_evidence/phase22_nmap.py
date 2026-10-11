import sys,json,time
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path.cwd()))
from scanner import port_scanner
from scanner.target import validate_target
calls=[]
def fake(args,**kwargs):
 calls.append(dict(args=args,**kwargs));return SimpleNamespace(stdout=b'<nmaprun><host><ports/></host></nmaprun>')
with patch('scanner.port_scanner.shutil.which',return_value='/trusted/fixture/nmap'),patch('scanner.port_scanner.subprocess.run',side_effect=fake):
 result=port_scanner.run(dict(target=validate_target('http://127.0.0.1/',True),client=SimpleNamespace(end=time.monotonic()+100)))
Path('docs/audit/PHASE_22_NMAP.json').write_text(json.dumps(dict(method='Mock subprocess; no Nmap execution or external target',calls=calls,result=result,inherits_environment='env' not in calls[0],capture_without_byte_limit=calls[0]['capture_output'],shell_enabled=calls[0].get('shell',False)),indent=2))
