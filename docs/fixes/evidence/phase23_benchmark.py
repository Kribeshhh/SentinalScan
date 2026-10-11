import os,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
with tempfile.TemporaryDirectory(prefix='phase13-data-') as td:
 os.environ['SENTINELSCAN_DATA_DIR']=td
 os.environ['SENTINELSCAN_LLM_ENABLED']='false'
 from evaluation.run import main
 main()
