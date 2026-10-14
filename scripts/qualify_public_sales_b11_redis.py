#!/usr/bin/env python3
"""Controlled two-process HTTP rehearsal, not a production activation script.

Requires an ISOLATED Redis instance and explicit operator acknowledgement.
Usage:
  PUBLIC_SALES_TEST_REDIS_URL=redis://... \\
  PUBLIC_SALES_TEST_CONFIRM_ISOLATED_REDIS=YES \\
  PYTHONPATH=src python scripts/qualify_public_sales_b11_redis.py

The script launches two LOCAL uvicorn instances with an isolated configuration,
tests both against one explicitly supplied Redis, and shuts them down.
Do not supply production Redis; the test uses the production B1.1 Redis keyspace.
"""
from __future__ import annotations
import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

PREFIX = "/api/v2/public/sales-sessions"
HEADERS = {"Origin": "http://localhost:5173", "Content-Type": "application/json"}

def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def request(port: int, path: str, data: dict | None = None):
    url = f"http://127.0.0.1:{port}{path}"
    payload = json.dumps(data or {}).encode()
    req = urllib.request.Request(url, data=payload, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())

def wait_ready(port, proc):
    for _ in range(80):
        if proc.poll() is not None:
            raise RuntimeError("API process exited before readiness")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/openapi.json", timeout=1) as res:
                if res.status == 200:
                    return
        except (OSError, urllib.error.HTTPError):
            time.sleep(.25)
    raise RuntimeError("API did not become ready")

def main():
    if (os.getenv("PUBLIC_SALES_TEST_CONFIRM_ISOLATED_REDIS") != "YES" or
            not os.getenv("PUBLIC_SALES_TEST_REDIS_URL")):
        raise SystemExit("BLOCKED: supply an isolated test Redis URL and explicit confirmation")
    config = dict(os.environ)
    config.update({
        "PLATFORM_ENVIRONMENT": "production",
        "PLATFORM_ALLOWED_ORIGINS": "http://localhost:5173",
        "PUBLIC_SALES_STORAGE_BACKEND": "redis",
        "PUBLIC_SALES_DISTRIBUTED_APPROVED": "true",
        "PUBLIC_SALES_ENABLED": "true",
        "PUBLIC_SALES_LLM_ENABLED": "false",
        "PUBLIC_SALES_RATE_KEY_SECRET": "isolated-rehearsal-not-a-production-secret-0123456789",
        "PUBLIC_SALES_REDIS_URL": os.environ["PUBLIC_SALES_TEST_REDIS_URL"],
    })
    ports = [_port(), _port()]
    processes = []
    try:
        for port in ports:
            processes.append(subprocess.Popen([
                sys.executable, "-m", "uvicorn", "orkio_v2.main:app",
                "--host", "127.0.0.1", "--port", str(port),
            ], env=config, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for port, proc in zip(ports, processes):
            wait_ready(port, proc)

        p1, p2 = ports
        status, created = request(p1, PREFIX, {"entry_intent": "understand_platform"})
        assert status == 201, ("create", status, created)
        token = created["session_id"]
        status, advanced = request(p2, f"{PREFIX}/{token}/messages", {"action_id":"explore"})
        assert status == 200, ("transition", status, advanced)
        action = advanced["action_options"][0]["id"] if advanced.get("action_options") else None
        if not action:
            raise RuntimeError("Inspect the new action contract before completing the journey")
        status, result = request(p1, f"{PREFIX}/{token}/messages", {"action_id":action})
        assert status == 200, ("complete", status, result)
        status, replay = request(p2, f"{PREFIX}/{token}/messages", {"action_id":action})
        assert status == 409, ("replay", status, replay)

        # A01: invalid/duplicate actions MUST still consume the session budget.
        token = request(p1, PREFIX, {"entry_intent": "understand_platform"})[1]["session_id"]
        codes = [request(ports[i%2], f"{PREFIX}/{token}/messages",
                         {"action_id":"this_action_is_not_valid"})[0] for i in range(16)]
        assert codes[:15] == [409]*15, ("session attempts", codes)
        assert codes[15] == 429, ("session cap", codes)

        print("PASS: two independent HTTP API processes, shared transitions, replay, session limits")
        print("NOT PROVEN: rolling-window recovery, Redis outage, distributed capacity under heavy load")
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in processes:
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()

if __name__ == "__main__":
    main()
