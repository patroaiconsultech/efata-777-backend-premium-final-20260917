#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, os, stat, sys

ROOT = Path(__file__).resolve().parents[1]

PROHIBITED_TRANSIENT = {"__pycache__", ".pytest_cache", "node_modules", "coverage", "dist"}
SECRET_NAME_PATTERNS = (".env", "id_rsa", "id_ed25519", ".pem", ".p12", ".pfx")

def sha256(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()

findings=[]
for p in ROOT.rglob("*"):
    rel=p.relative_to(ROOT).as_posix()
    if p.is_symlink():
        findings.append(["SYMLINK",rel])
    if any(part in PROHIBITED_TRANSIENT for part in p.parts):
        findings.append(["TRANSIENT",rel])
    low=p.name.lower()
    if any(x in low for x in SECRET_NAME_PATTERNS):
        findings.append(["SECRETISH_FILENAME",rel])

result={
    "status":"PASS_LOCAL" if not findings else "FAIL_LOCAL",
    "findings":findings,
    "railway_execution":False,
    "database_execution":False,
    "deploy_execution":False
}
print(json.dumps(result,sort_keys=True))
raise SystemExit(0 if not findings else 2)
