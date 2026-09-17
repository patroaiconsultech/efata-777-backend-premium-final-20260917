#!/usr/bin/env python3
import os,sys,json
from pathlib import Path
r=Path(os.environ["STG008_ROOT"]); rh=Path(os.environ["RAILWAY_HOME"]); st=r/"state"
def inc(n):
    p=st/n; v=int(p.read_text()) if p.exists() else 0; p.write_text(str(v+1))
c=sys.argv[1] if len(sys.argv)>1 else ""
if c=="login":
    inc("login_count"); rh.mkdir(parents=True,exist_ok=True); (rh/"session.ok").write_text("ok\n"); print("fake-login-ok"); raise SystemExit(0)
if c=="whoami":
    if not (rh/"session.ok").exists(): raise SystemExit(3)
    inc("whoami_count"); print("fake-user"); raise SystemExit(0)
if c=="api":
    if sys.argv[2:]!=["query { __typename }"] or not (rh/"session.ok").exists(): raise SystemExit(4)
    inc("query_count"); print(json.dumps({"data":{"__typename":"Query"}})); raise SystemExit(0)
if c=="version": print("fake-railway/1"); raise SystemExit(0)
raise SystemExit(64)
