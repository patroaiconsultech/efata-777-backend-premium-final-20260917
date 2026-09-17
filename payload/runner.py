#!/usr/bin/env python3
import os,tempfile,subprocess,signal
from pathlib import Path
from preflight import ident,revalidate
AUTH_LOGIN_TIMEOUT_SECONDS=120; TERM_GRACE_SECONDS=5; KILL_GRACE_SECONDS=3; RECOVERY_TOTAL_DEADLINE_SECONDS=300; AUTO_RETRY_COUNT=0
MAX_STDOUT_BYTES=4096; MAX_STDERR_BYTES=2048; MAX_SINGLE_FIELD_BYTES=2048; MAX_FINAL_JSON_BYTES=16384
def mkroot(parent="/tmp"):
    r=Path(tempfile.mkdtemp(prefix="patroai-stg008-localauth-v2-",dir=parent)); os.chmod(r,0o700)
    for x in ("home/.railway","xdg/config","xdg/cache","xdg/data","tmp","cli","state","evidence"): (r/x).mkdir(parents=True,exist_ok=True)
    return r
def env(r):
    return {"PATH":"/usr/bin:/bin","HOME":str(r/"home"),"RAILWAY_HOME":str(r/"home/.railway"),
    "XDG_CONFIG_HOME":str(r/"xdg/config"),"XDG_CACHE_HOME":str(r/"xdg/cache"),"XDG_DATA_HOME":str(r/"xdg/data"),
    "TMPDIR":str(r/"tmp"),"LC_ALL":"C.UTF-8","STG008_ROOT":str(r)}
def lock(r): return os.open(r/"state/execution.lock",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
def run(cmd,e,t,login=False):
    p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=e,start_new_session=True)
    try: o,x=p.communicate(timeout=t); to=False
    except subprocess.TimeoutExpired:
        to=True; os.killpg(p.pid,signal.SIGTERM)
        try:o,x=p.communicate(timeout=TERM_GRACE_SECONDS)
        except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL); o,x=p.communicate(timeout=KILL_GRACE_SECONDS)
    try: os.killpg(p.pid,0); absent=False
    except ProcessLookupError: absent=True
    return {"exit":p.returncode,"timeout":to,"parent_reaped":p.poll() is not None,"group_absent":absent,
    "stdout_bytes":len(o),"stderr_bytes":len(x),"stderr_content_persisted":False if login else None}
def fake_cycle(r,cli):
    b=ident(cli); fd=lock(r)
    try:
        a=run([str(cli),"login"],env(r),AUTH_LOGIN_TIMEOUT_SECONDS,True)
        if a["timeout"]: return "INCONCLUSIVE/LOGIN_TIMEOUT"
        if a["exit"]!=0:return "INCONCLUSIVE/AUTHENTICATION_FAILED"
        revalidate(cli,b)
        w=run([str(cli),"whoami"],env(r),20); q=run([str(cli),"api","query { __typename }"],env(r),20)
        counts={n:int((r/"state"/n).read_text()) for n in ("login_count","whoami_count","query_count")}
        return "PASS_LOCAL" if w["exit"]==q["exit"]==0 and counts=={"login_count":1,"whoami_count":1,"query_count":1} else "INCONCLUSIVE/INVALID_CHANNEL_RESPONSE"
    finally: os.close(fd)
