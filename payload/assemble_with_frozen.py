#!/usr/bin/env python3
import hashlib,shutil,sys
from pathlib import Path
EXPECTED="0c6538dd7df26d6b8ac776a0a9cd87aedf2b6fc5c353665fc772fd4cb77351e9"
def h(p):
    q=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1048576),b""): q.update(b)
    return q.hexdigest()
if len(sys.argv)!=3: raise SystemExit("usage: assemble_with_frozen.py REAL_FROZEN.zip CANDIDATE_ROOT")
src=Path(sys.argv[1]); root=Path(sys.argv[2])
if h(src)!=EXPECTED: print("INCONCLUSIVE / FROZEN_SHA_MISMATCH"); raise SystemExit(2)
dst=root/"frozen/STAGING_008_CHANNEL_DIAGNOSTIC_PREMIUM_FINAL_BUNDLE.zip"; dst.parent.mkdir(exist_ok=True)
shutil.copyfile(src,dst)
if h(dst)!=EXPECTED: dst.unlink(); raise SystemExit("FAIL / POST_COPY_HASH_MISMATCH")
print("FROZEN_BYTES_INSERTED_AND_HASH_CONFIRMED")
