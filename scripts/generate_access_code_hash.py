#!/usr/bin/env python3
"""Generate a PLATFORM_ACCESS_GATE_CODE_HASHES entry without logging the raw code."""
import getpass
import hashlib
import hmac
import os
import sys

secret = os.environ.get("PLATFORM_ACCESS_GATE_SIGNING_SECRET", "")
if len(secret) < 32:
    raise SystemExit("PLATFORM_ACCESS_GATE_SIGNING_SECRET must be set and contain at least 32 characters")

code = getpass.getpass("Access code: ").strip().lower()
if not code:
    raise SystemExit("access code required")

digest = hmac.new(secret.encode(), code.encode(), hashlib.sha256).hexdigest()
sys.stdout.write(digest + "\n")
