"""Bounded local subprocesses, private HOME, no inherited credentials or shell."""
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

OUTPUT_LIMIT=6*1024*1024
DISK_LIMIT=512*1024*1024


class ToolFailure(ValueError):
    pass


def run_tool(args, work, seconds, output=None):
    work=Path(work)
    home=work/'home';home.mkdir(exist_ok=True,mode=0o700)
    env={'PATH':str(Path(args[0]).parent)+':/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin',
         'HOME':str(home),'TMPDIR':str(work),'LANG':'C.UTF-8',
         'SEMGREP_SEND_METRICS':'off','SEMGREP_ENABLE_VERSION_CHECK':'0',
         'PYTHONNOUSERSITE':'1'}
    if seconds<=0:raise ToolFailure('Analysis time budget exhausted.')
    launcher=[sys.executable,'-I',str(Path(__file__).with_name('limit_exec.py'))]
    process=None;selector=selectors.DefaultSelector();count=0;end=time.monotonic()+seconds;last_check=0
    try:
        process=subprocess.Popen(launcher+list(args),cwd=work,env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        for pipe in (process.stdout,process.stderr):
            os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            if time.monotonic()>end:raise ToolFailure('Analysis timed out.')
            for key,_ in selector.select(.05):
                chunk=os.read(key.fd,65536)
                count+=len(chunk)
                if not chunk:selector.unregister(key.fileobj)
                if count>OUTPUT_LIMIT:raise ToolFailure('Tool output limit exceeded.')
            if time.monotonic()-last_check>.25:
                last_check=time.monotonic();total=0;files=0
                for root,dirs,names in os.walk(work,followlinks=False):
                    for name in names:
                        try:total+=(Path(root)/name).lstat().st_size
                        except FileNotFoundError:pass
                        files+=1
                        if total>DISK_LIMIT or files>20000:raise ToolFailure('Tool workspace limit exceeded.')
                if output and Path(output).exists() and Path(output).stat().st_size>OUTPUT_LIMIT:
                    raise ToolFailure('Tool result limit exceeded.')
        if process.wait()!=0:raise ToolFailure('Tool failed; raw diagnostics are omitted to protect source data.')
        if output:
            path=Path(output)
            if path.is_symlink() or not path.is_file() or path.stat().st_size>OUTPUT_LIMIT:
                raise ToolFailure('Tool result is missing or too large.')
            with path.open('rb') as handle:return handle.read(OUTPUT_LIMIT+1)
        return b''
    except OSError:
        raise ToolFailure('Tool could not be started or its output could not be read.') from None
    finally:
        selector.close()
        if process:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()
            process.stdout.close();process.stderr.close()
