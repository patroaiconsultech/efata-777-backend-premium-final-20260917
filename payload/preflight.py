#!/usr/bin/env python3
import hashlib, os, stat, zipfile, unicodedata
from pathlib import Path, PurePosixPath
class E(RuntimeError): pass
def sha256(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1048576),b""): h.update(b)
    return h.hexdigest()
def ident(p):
    s=os.lstat(p)
    if stat.S_ISLNK(s.st_mode): raise E("SYMLINK_REJECTED")
    if not stat.S_ISREG(s.st_mode): raise E("NOT_REGULAR_FILE")
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,sha256(p))
def revalidate(p,before):
    if ident(p)!=before: raise E("EXECUTABLE_CHANGED_AFTER_VERIFICATION")
def safe_name(n):
    if "\\" in n or (len(n)>1 and n[1]==":"): raise E("UNSAFE_PATH")
    p=PurePosixPath(n)
    if p.is_absolute() or any(x in ("",".","..") for x in p.parts): raise E("UNSAFE_PATH")
    return str(p)
def inspect_zip(p):
    seen=set(); folded=set()
    with zipfile.ZipFile(p) as z:
        if z.testzip(): raise E("ZIP_INTEGRITY_FAIL")
        for i in z.infolist():
            raw=i.filename.rstrip("/")
            if not raw: continue
            n=safe_name(raw); f=unicodedata.normalize("NFC",n).casefold()
            if n in seen or f in folded: raise E("DUPLICATE_OR_COLLISION")
            seen.add(n); folded.add(f)
            mode=(i.external_attr>>16)&0xffff; typ=stat.S_IFMT(mode)
            if typ==stat.S_IFLNK: raise E("ZIP_SYMLINK_REJECTED")
            if typ not in (0,stat.S_IFREG,stat.S_IFDIR): raise E("ZIP_SPECIAL_REJECTED")
            if mode&(stat.S_ISUID|stat.S_ISGID): raise E("ZIP_SETID_REJECTED")
    return {"ZIP_INTEGRITY":True,"FILE_COUNT":len(seen)}
