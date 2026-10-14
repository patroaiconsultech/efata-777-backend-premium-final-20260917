#!/usr/bin/env python3
"""AO-01 R-02: rehearsal ONLY on a disposable GitHub Actions Redis.

Does not edit application modules. HTTP requests use synthetic identifiers.
Raw session tokens and secrets MUST NOT be written to evidence.
"""
from __future__ import annotations
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import re
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import time
from urllib.parse import urlsplit
import urllib.error
import urllib.request
import secrets

PREFIX = "/api/v2/public/sales-sessions"
HEADERS = {"Origin": "http://localhost:5173", "Content-Type": "application/json"}
ROOT = Path("r02-evidence")
ROOT.mkdir(exist_ok=True)
EVENTS: list[dict] = []
LEVELS = [4, 8, 16]  # predeclared HTTP parallelism; NO production SLO inferred
CATALOG = {"understand_platform": {"explore": ["operations", "planning"]}}
TEST_RATE_SECRET = "r02-isolated-rate-key-NOT-production-0123456789abcdefghij"

def check_isolation():
    url = os.environ.get("PUBLIC_SALES_TEST_REDIS_URL", "")
    parsed = urlsplit(url)
    if not (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REF_NAME") == "homologacao/b11-redis-isolado"
        and os.environ.get("PUBLIC_SALES_TEST_CONFIRM_ISOLATED_REDIS") == "YES"
        and parsed.scheme == "redis" and parsed.hostname == "127.0.0.1"
        and parsed.port == 6379 and parsed.path == "/15"
        and not parsed.username and not parsed.password and not parsed.query
    ):
        raise RuntimeError("BLOCKED: only disposable GitHub Actions Redis at 127.0.0.1:6379/15")
    cid = os.environ.get("B11_R02_REDIS_CONTAINER", "")
    if len(cid) < 12 or not all(c in "0123456789abcdef" for c in cid):
        raise RuntimeError("BLOCKED: missing/invalid temporary Docker Redis container ID")
    image = subprocess.check_output(
        ["docker", "inspect", "--format", "{{.Config.Image}}", cid],
        text=True, timeout=8
    ).strip()
    if image != "redis:7.4-alpine":
        raise RuntimeError("BLOCKED: container is not the disposable Redis 7.4 service")
    if os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("RAILWAY_SERVICE_ID"):
        raise RuntimeError("BLOCKED: Railway runtime not permitted")
    # Only after the explicit isolated-runner checks can the process use gated store.
    os.environ.update({
        "PUBLIC_SALES_REDIS_URL": url,
        "PUBLIC_SALES_STORAGE_BACKEND": "redis",
        "PUBLIC_SALES_DISTRIBUTED_APPROVED": "true",
        "PUBLIC_SALES_ENABLED": "true",
        "PUBLIC_SALES_LLM_ENABLED": "false",
        "PUBLIC_SALES_RATE_KEY_SECRET": TEST_RATE_SECRET,
    })
    return cid

def emit(scenario, label, expected, observed, **extras):
    row = {"scenario": scenario, "label": label, "expected": expected, "observed": observed, **extras}
    EVENTS.append(row)
    print(json.dumps(row, ensure_ascii=False, separators=(",", ":")), flush=True)

def require(actual, expected, scenario, label):
    emit(scenario, label, expected, actual)
    if actual != expected:
        raise AssertionError(f"{scenario}/{label}: expected={expected!r}, got={actual!r}")

def run(coro):
    return asyncio.run(coro)

def create_eval(store, pre, identity, ip_key, *, ttl=1800, absolute=2700, cap=1000, rate=8, window=600000):
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return store._eval(store._CREATE, [
        f"{pre}:session:{digest}", f"{pre}:capacity", f"{pre}:create:{ip_key}",
    ], ["understand_platform", ttl, absolute, rate, window, cap, digest])

def transition_eval(store, pre, identity, ip_key, action="bad", *, window=600, per_session=3, per_ip=6, ttl=1800):
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return store._eval(store._TRANSITION, [
        f"{pre}:session:{digest}", f"{pre}:message-session:{digest}", f"{pre}:message-client:{ip_key}",
    ], [json.dumps(CATALOG), action, "", window, per_session, per_ip, secrets.token_hex(16), ttl])

def recovery():
    from orkio_v2 import public_sales_redis as store
    scenario = "R-RECOVERY"
    pre = f"efata:public-sales:b11:r02:{secrets.token_hex(14)}"
    # Equivalent production Lua; accelerated expiries only in injected EVAL args.
    # Production HTTP TTL=1800000ms, absolute=2700000ms, create window=600000ms,
    # message window=60000ms; test values 350..2300ms below.
    emit(scenario,"equivalence","same_sha256_Lua", "same_sha256_Lua",
         create_script_sha256=hashlib.sha256(store._CREATE.encode()).hexdigest(),
         transition_script_sha256=hashlib.sha256(store._TRANSITION.encode()).hexdigest(),
         accelerated_time=True, clock="Redis TIME")

    async def journey():
        # Create per-IP window: 2 allowed, first excess blocked; recovery after 750ms.
        a = [secrets.token_hex(12) for _ in range(4)]
        results = [await create_eval(store,pre,a[i],"ip-recovery",ttl=2200,absolute=2800,
                                     window=650,rate=2) for i in range(3)]
        require([x[0] for x in results],[1,1,-1],scenario,"create_ip_block")
        await asyncio.sleep(.82)
        new = await create_eval(store,pre,a[3],"ip-recovery",ttl=2200,absolute=2800,window=650,rate=2)
        require(new[0],1,scenario,"create_ip_window_recovers")
        # Idle expiry: stored hash may remain, but Lua denies transition.
        idle=secrets.token_hex(12)
        await create_eval(store,pre,idle,"idle",ttl=350,absolute=2400)
        await asyncio.sleep(.46)
        x=await transition_eval(store,pre,idle,"ip-idle",window=450,ttl=700)
        require(x[0],-2,scenario,"idle_session_expires")
        # Absolute deadline: activity extends idle but cannot extend final cap.
        abs_token=secrets.token_hex(12)
        creation=await create_eval(store,pre,abs_token,"absolute",ttl=900,absolute=1250)
        await asyncio.sleep(.49)
        advancing=await transition_eval(store,pre,abs_token,"ip-absolute","explore",window=550,ttl=900)
        require(advancing[0],1,scenario,"activity_before_absolute")
        require(advancing[3] <= creation[1] + (1250-900) + 50,True,scenario,"cannot_extend_absolute")
        await asyncio.sleep(.87)
        end=await transition_eval(store,pre,abs_token,"ip-absolute","operations",window=550,ttl=900)
        require(end[0] in (-1,-2),True,scenario,"absolute_expired_cannot_replay")
        # Session quota includes INVALID requests. Count at most 3 within window.
        sess=secrets.token_hex(12)
        await create_eval(store,pre,sess,"session",ttl=2000,absolute=2400)
        s=[await transition_eval(store,pre,sess,"client-sess",window=650,per_session=3,per_ip=30) for _ in range(4)]
        require([x[0] for x in s],[-5,-5,-5,-6],scenario,"session_invalid_consumes_quota")
        await asyncio.sleep(.79)
        restored=await transition_eval(store,pre,sess,"client-sess",window=650,per_session=3,per_ip=30)
        require(restored[0],-5,scenario,"session_message_window_recovers")
        # IP quota spans several sessions, even with invalid actions.
        clients=[secrets.token_hex(12) for _ in range(2)]
        for token in clients:
            await create_eval(store,pre,token,f"create-{token}",ttl=1900,absolute=2500)
        out=[await transition_eval(store,pre,clients[i%2],"shared-ip",window=610,per_session=15,per_ip=3) for i in range(4)]
        require([x[0] for x in out],[-5,-5,-5,-6],scenario,"message_ip_quota_across_sessions")
        await asyncio.sleep(.78)
        restored=await transition_eval(store,pre,clients[0],"shared-ip",window=610,per_session=15,per_ip=3)
        require(restored[0],-5,scenario,"message_ip_window_recovers")
        # Global cap uses Redis atomic ZSET and absolute TTL, not idle TTL.
        cap_pre=f"{pre}:cap"
        items=[secrets.token_hex(12) for _ in range(4)]
        cap=[await create_eval(store,cap_pre,items[i],f"ip-{i}",ttl=700,absolute=1050,cap=3)
             for i in range(4)]
        require([x[0] for x in cap],[1,1,1,-2],scenario,"capacity_denies_excess")
        await asyncio.sleep(1.23)
        reopened=await create_eval(store,cap_pre,secrets.token_hex(12),"cap-reopen",
                                   ttl=700,absolute=1050,cap=3)
        require(reopened[0],1,scenario,"capacity_reopens_after_absolute_expiry")
    run(journey())

def http(port, path, body):
    t=time.perf_counter()
    url=f"http://127.0.0.1:{port}{path}"
    cid=secrets.token_hex(12)
    request_headers=dict(HEADERS)
    request_headers["X-Correlation-ID"]=cid
    req=urllib.request.Request(url,data=json.dumps(body).encode(),headers=request_headers,method="POST")
    try:
        with urllib.request.urlopen(req,timeout=7) as response:
            code, data=response.status, json.loads(response.read(32768))
    except urllib.error.HTTPError as err:
        code, data=err.code, json.loads(err.read(32768))
    elapsed_ms=round((time.perf_counter()-t)*1000,3)
    EVENTS.append({"scenario":"HTTP","endpoint":"create" if path==PREFIX else "transition",
                   "correlation_id":cid,"http_status":code,"latency_ms":elapsed_ms})
    return code,data,elapsed_ms

def listen_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        return s.getsockname()[1]

class APIs:
    def __enter__(self):
        self.ports=[listen_port(),listen_port()]
        self._secrets=[]
        self.procs=[]
        self.streams=[]
        # Minimal environment: never inherit database URLs or organizational secrets.
        allowed = {"PATH","PYTHONPATH","HOME","LANG","LC_ALL","TZ","VIRTUAL_ENV",
                   "LD_LIBRARY_PATH","SSL_CERT_FILE","GITHUB_SHA","PYTHONUNBUFFERED"}
        env={k:v for k,v in os.environ.items() if k in allowed}
        env.update({
            "PLATFORM_ENVIRONMENT":"production",
            "PLATFORM_RELEASE_SHA":os.environ["GITHUB_SHA"],
            "PLATFORM_ALLOWED_ORIGINS":"http://localhost:5173",
            "PLATFORM_INVITATION_TOKEN_SECRET":secrets.token_urlsafe(48),
            "PUBLIC_SALES_STORAGE_BACKEND":"redis",
            "PUBLIC_SALES_DISTRIBUTED_APPROVED":"true",
            "PUBLIC_SALES_ENABLED":"true",
            "PUBLIC_SALES_LLM_ENABLED":"false",
            "PUBLIC_SALES_RATE_KEY_SECRET":TEST_RATE_SECRET,
            "PUBLIC_SALES_REDIS_URL":os.environ["PUBLIC_SALES_TEST_REDIS_URL"],
        })
        # Both processes MUST share the same rate HMAC secret and Redis DB.
        self._secrets=[env["PLATFORM_INVITATION_TOKEN_SECRET"],env["PUBLIC_SALES_RATE_KEY_SECRET"]]
        try:
            for i,port in enumerate(self.ports):
                output=ROOT / f"api-{i+1}.raw"
                stream=open(output,"w",encoding="utf-8")
                self.streams.append(stream)
                proc=subprocess.Popen(
                    [sys.executable,"-m","uvicorn","orkio_v2.main:app",
                     "--host","127.0.0.1","--port",str(port),"--no-access-log"],
                    env=env,stdout=stream,stderr=subprocess.STDOUT)
                self.procs.append(proc)
            for port,proc in zip(self.ports,self.procs):
                for _ in range(80):
                    if proc.poll() is not None:
                        raise RuntimeError("API process exited before readiness")
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/openapi.json",timeout=1) as r:
                            if r.status==200:break
                    except (OSError,urllib.error.HTTPError):
                        time.sleep(.25)
                else:
                    raise RuntimeError("API readiness timed out")
            return self
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def __exit__(self, *_):
        for proc in self.procs:
            if proc.poll() is None:proc.terminate()
        for proc in self.procs:
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        for stream in self.streams:stream.close()
        for i in range(len(self.streams)):
            raw = ROOT / f"api-{i+1}.raw"
            if raw.exists():
                data = raw.read_text(encoding="utf-8", errors="replace")
                for value in self._secrets:
                    if value:data=data.replace(value,"[REDACTED]")
                data = re.sub(r"/api/v2/public/sales-sessions/[A-Za-z0-9_-]{40,128}",
                              "/api/v2/public/sales-sessions/[REDACTED]", data)
                (ROOT / f"api-{i+1}.log").write_text(data,encoding="utf-8")
                raw.unlink()

def outage(cid):
    scenario="R-OUTAGE"
    with APIs() as apis:
        a,b=apis.ports
        status, obj, _=http(a,PREFIX,{"entry_intent":"understand_platform"})
        require(status,201,scenario,"session_before_failure")
        token=obj["session_id"]  # never serialized/logged
        status,_,_=http(b,f"{PREFIX}/{token}/messages",{"action_id":"explore"})
        require(status,200,scenario,"authorized_transition_on_other_instance")
        try:
            subprocess.run(["docker","pause",cid],check=True,capture_output=True,text=True,timeout=8)
            emit(scenario,"redis_fault","paused_container","paused_container",mode="temporary_pause")
            for port,label,path,body in [
                (a,"create_instance_A",PREFIX,{"entry_intent":"understand_platform"}),
                (b,"advance_instance_B",f"{PREFIX}/{token}/messages",{"action_id":"operations"}),
                (a,"advance_instance_A",f"{PREFIX}/{token}/messages",{"action_id":"operations"}),
            ]:
                status,obj,delay=http(port,path,body)
                require(status,503,scenario,label)
                require(obj.get("detail"),"PUBLIC_SALES_SHARED_STORE_UNAVAILABLE",
                        scenario,label+"_controlled_error")
                emit(scenario,label+"_latency_ms","measured",delay)
        finally:
            subprocess.run(["docker","unpause",cid],check=True,capture_output=True,text=True,timeout=8)
            emit(scenario,"redis_restored","unpaused_container","unpaused_container")
        # Redis service still has the original state: explicit distinction from data loss.
        status,_,_=http(a,f"{PREFIX}/{token}/messages",{"action_id":"operations"})
        require(status,200,scenario,"resume_existing_session_after_restore")
        status,_,_=http(b,f"{PREFIX}/{token}/messages",{"action_id":"operations"})
        require(status,409,scenario,"replay_rejected_after_restore")
        status,obj,_=http(b,PREFIX,{"entry_intent":"understand_platform"})
        require(status,201,scenario,"new_session_after_restore")
        require("session_id" in obj,True,scenario,"new_session_response")
        emit(scenario,"persistence_policy","pause_retains_state",
             "pause_retains_state",redis_mode="in_memory_temporary_pause",
             permanent_data_loss="NOT_EXECUTED")

def summary_metrics(latencies):
    if not latencies:return {"n":0}
    v=sorted(latencies)
    def percentile(q):return v[max(0,min(len(v)-1,__import__("math").ceil(q*len(v))-1))]
    return {"n":len(v),"p50_ms":percentile(.50),"p95_ms":percentile(.95),
            "p99_ms":percentile(.99),"max_ms":max(v)}

def load():
    scenario="R-LOAD"
    with APIs() as apis:
        ports=apis.ports
        # Outage step consumed exactly 2 successful creations from same loopback IP.
        # Production create limit: 8 / IP / 600 seconds. 6 remain here.
        created=[]
        total=0
        for level in LEVELS:
            begin=time.perf_counter()
            def work(i):
                return http(ports[i%2],PREFIX,{"entry_intent":"understand_platform"})
            with ThreadPoolExecutor(max_workers=level) as pool:
                results=list(pool.map(work,range(level)))
            elapsed=time.perf_counter()-begin
            counts={str(code):sum(r[0]==code for r in results) for code in {r[0] for r in results}}
            created.extend(r[1]["session_id"] for r in results if r[0]==201)
            total+=counts.get("201",0)
            require(set(r[0] for r in results) <= {201,429},True,scenario,f"create_codes_c{level}")
            require(total <= 6,True,scenario,f"create_ip_bound_c{level}")
            emit(scenario,"create_load","recorded","recorded",
                 concurrency=level,requests=level,duration_s=round(elapsed,3),
                 throughput_rps=round(level/max(elapsed,.001),2),status_counts=counts,
                 latency=summary_metrics([r[2] for r in results]))
        require(total,6,scenario,"ip_quota_exact_6_remaining")
        require(len(created)>=2,True,scenario,"tokens_for_transition_cases")
        # 6 concurrent first actions on same session, at most one transition succeeds.
        token=created[0]
        def race(action,amount):
            with ThreadPoolExecutor(max_workers=amount) as pool:
                return list(pool.map(lambda i:http(ports[i%2],f"{PREFIX}/{token}/messages",
                                                    {"action_id":action}),range(amount)))
        first=race("explore",6)
        codes=[r[0] for r in first]
        require(codes.count(200),1,scenario,"single_first_transition")
        require(all(c in (200,409) for c in codes),True,scenario,"first_transition_codes")
        second=race("operations",6)
        codes=[r[0] for r in second]
        require(codes.count(200),1,scenario,"single_final_transition")
        require(all(c in (200,409) for c in codes),True,scenario,"final_transition_codes")
        emit(scenario,"concurrent_transition_metrics","recorded","recorded",
             concurrency=6, first_statuses={str(x):[r[0] for r in first].count(x) for x in (200,409)},
             final_statuses={str(x):[r[0] for r in second].count(x) for x in (200,409)},
             latency=summary_metrics([r[2] for r in first+second]))
        token=created[1]
        with ThreadPoolExecutor(max_workers=16) as pool:
            invalid=list(pool.map(lambda i:http(ports[i%2],f"{PREFIX}/{token}/messages",
                                                  {"action_id":"invalid_synthetic"}),range(16)))
        count={str(x):[r[0] for r in invalid].count(x) for x in (409,429)}
        require(count["409"],15,scenario,"invalid_uses_session_budget")
        require(count["429"],1,scenario,"invalid_race_session_cap")
        emit(scenario,"invalid_concurrency_metrics","recorded","recorded",
             concurrency=16,status_counts=count,
             latency=summary_metrics([r[2] for r in invalid]))
        # Atomic distributed global-capacity test with reduced cap 3, no HTTP
        # configuration change. Every EVAL invocation operates on a NEW key.
        from orkio_v2 import public_sales_redis as store
        pre=f"efata:public-sales:b11:r02:load:{secrets.token_hex(12)}"
        async def capacity():
            coros=[create_eval(store,pre,secrets.token_hex(12),f"ip{i}",ttl=1500,
                               absolute=2100,cap=3,rate=10)
                   for i in range(32)]
            results=await asyncio.gather(*coros)
            statuses=[x[0] for x in results]
            require(statuses.count(1),3,scenario,"capacity_3_exactly_accepted")
            require(statuses.count(-2),29,scenario,"capacity_29_denied")
        run(capacity())
        emit(scenario,"load_scope","isolated_ephemeral","isolated_ephemeral",
             declared_levels=LEVELS,slo="NOT_DEFINED",production_capacity="NOT_PROVEN")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--scenario",choices=("recovery","outage","load"),required=True)
    args=parser.parse_args()
    scenario=args.scenario.upper()
    started=time.time()
    try:
        cid=check_isolation()
        if args.scenario=="recovery":recovery()
        elif args.scenario=="outage":outage(cid)
        elif args.scenario=="load":load()
        state="PASS"
    except BaseException as exc:
        state="FAIL"
        # No raw URL/session token/secret in error output.
        emit(scenario,"exception","no_exception",type(exc).__name__)
        print(f"FAIL: {type(exc).__name__}; see structured steps above",file=sys.stderr)
    finally:
        artifact={"scenario":scenario,"status":state,
                  "started_at_unix":int(started),"finished_at_unix":int(time.time()),
                  "github_sha":os.environ.get("GITHUB_SHA",""),
                  "github_ref":os.environ.get("GITHUB_REF_NAME",""),
                  "python_version":sys.version.split()[0],
                  "test_redis":"loopback_disposable_db15",
                  "events":EVENTS}
        (ROOT/f"{args.scenario}.json").write_text(json.dumps(artifact,ensure_ascii=False,
                              indent=2)+"\n",encoding="utf-8")
    return 0 if state=="PASS" else 1

if __name__=="__main__":
    sys.exit(main())
