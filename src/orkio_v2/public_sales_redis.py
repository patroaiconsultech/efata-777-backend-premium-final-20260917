"""Redis-backed B1.1 storage and atomic limits; no connection fallback to process memory.

This is a gated candidate. Public activation also requires separate operational
qualification of the Redis service and AO-01 approval.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import ssl

from .services.activation_rate_limit import (
    RedisRateLimitUnavailable,
    _command,
    _redis_connection_parts,
)

_PREFIX = "efata:public-sales:b11:v1"
_TIMEOUT = 1.0
# Redis TIME is authoritative across replicas. All capacity, expiry and rate
# limit checks are part of one atomic script per operation.
_CREATE = r"""
local nowparts=redis.call('TIME')
local now=tonumber(nowparts[1])*1000+math.floor(tonumber(nowparts[2])/1000)
local ttl=tonumber(ARGV[2])
local absolute=tonumber(ARGV[3])
local cutoff=now-tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE',KEYS[2],'-inf',now)
redis.call('ZREMRANGEBYSCORE',KEYS[3],'-inf',cutoff)
if redis.call('ZCARD',KEYS[3])>=tonumber(ARGV[4]) then return {-1,0} end
if redis.call('ZCARD',KEYS[2])>=tonumber(ARGV[6]) then return {-2,0} end
if redis.call('EXISTS',KEYS[1])~=0 then return {-3,0} end
local expires=now+ttl
local final=now+absolute
redis.call('HSET',KEYS[1],'intent',ARGV[1],'step','0','first','','expires',expires,'absolute',final)
redis.call('PEXPIREAT',KEYS[1],final)
redis.call('ZADD',KEYS[2],final,ARGV[7])
redis.call('ZADD',KEYS[3],now,ARGV[7])
redis.call('PEXPIRE',KEYS[3],tonumber(ARGV[5]))
return {1,expires}
""".strip()

_TRANSITION = r"""
local nowparts=redis.call('TIME')
local now=tonumber(nowparts[1])*1000+math.floor(tonumber(nowparts[2])/1000)
-- Apply an atomic client-wide limit even to requests with unknown sessions.
local window=tonumber(ARGV[4])
local cutoff=now-window
redis.call('ZREMRANGEBYSCORE',KEYS[3],'-inf',cutoff)
if redis.call('ZCARD',KEYS[3])>=tonumber(ARGV[6]) then
  return {-6,'','',0}
end
redis.call('ZADD',KEYS[3],now,ARGV[7])
redis.call('PEXPIRE',KEYS[3],window)
local state=redis.call('HGETALL',KEYS[1])
if #state == 0 then return {-1,'','',0} end
local item={}
for i=1,#state,2 do item[state[i]]=state[i+1] end
if now>=tonumber(item.expires) or now>=tonumber(item.absolute) then
  redis.call('DEL',KEYS[1])
  return {-2,'','',0}
end
-- A01: count EVERY request against an existing live session, including
-- invalid, duplicate and completed transitions. Otherwise the two-step
-- editorial journey can never reach the 15-request session budget.
-- This remains atomic with the client limit and the state transition.
redis.call('ZREMRANGEBYSCORE',KEYS[2],'-inf',cutoff)
if redis.call('ZCARD',KEYS[2])>=tonumber(ARGV[5]) then
  return {-6,item.intent,item.first,0}
end
redis.call('ZADD',KEYS[2],now,ARGV[7])
redis.call('PEXPIRE',KEYS[2],window)
local step=tonumber(item.step)
if step >= 2 then return {-3,item.intent,item.first,0} end
local catalog=cjson.decode(ARGV[1])
local branches=catalog[item.intent]
if branches==nil then return {-5,'','',0} end
if ARGV[3]~='' and ARGV[3]~=item.intent then return {-4,item.intent,item.first,0} end
local action=ARGV[2]
if (step==0 and branches[action]==nil) or
   (step==1 and (branches[item.first]==nil or
    (action~=branches[item.first][1] and action~=branches[item.first][2]))) then
  return {-5,item.intent,item.first,0}
end
local expires=math.min(now+tonumber(ARGV[8]),tonumber(item.absolute))
redis.call('HSET',KEYS[1],'expires',expires)
if step==0 then
  redis.call('HSET',KEYS[1],'first',action,'step',1)
  return {1,item.intent,action,expires}
else
  redis.call('HSET',KEYS[1],'step',2)
  return {2,item.intent,item.first,expires}
end
""".strip()

class SharedStoreUnavailable(RuntimeError):
    """The distributed store cannot safely decide a public request."""

def shared_store_gate_ready() -> bool:
    """Explicit approval switch defaults to false, independently of sales visibility."""
    return (
        os.getenv("PUBLIC_SALES_STORAGE_BACKEND", "").lower() == "redis"
        and os.getenv("PUBLIC_SALES_DISTRIBUTED_APPROVED", "false").lower() == "true"
        and bool(os.getenv("PUBLIC_SALES_REDIS_URL", "").strip())
    )

def _hash_dimension(secret: str, dimension: str, value: str) -> str:
    return hmac.new(secret.encode(), f"{dimension}:{value}".encode(), hashlib.sha256).hexdigest()

async def _eval(script: str, keys: list[str], args: list[object]):
    redis_url = os.getenv("PUBLIC_SALES_REDIS_URL", "")
    if not shared_store_gate_ready():
        raise SharedStoreUnavailable("store_not_approved")
    try:
        parts = _redis_connection_parts(redis_url)
    except (RedisRateLimitUnavailable, ValueError) as exc:
        raise SharedStoreUnavailable("invalid_store_config") from exc
    writer = None
    try:
        tls = ssl.create_default_context() if parts["scheme"] == "rediss" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                parts["host"], parts["port"], ssl=tls,
                server_hostname=parts["host"] if tls else None,
            ),
            timeout=_TIMEOUT,
        )
        if parts["password"]:
            auth = ("AUTH", parts["username"], parts["password"]) if parts["username"] else ("AUTH", parts["password"])
            if await asyncio.wait_for(_command(reader, writer, *auth), timeout=_TIMEOUT) != "OK":
                raise SharedStoreUnavailable("auth_failed")
        if parts["db"]:
            if await asyncio.wait_for(_command(reader, writer, "SELECT", parts["db"]), timeout=_TIMEOUT) != "OK":
                raise SharedStoreUnavailable("select_failed")
        result = await asyncio.wait_for(
            _command(reader, writer, "EVAL", script, len(keys), *keys, *args),
            timeout=_TIMEOUT,
        )
        if not isinstance(result, list):
            raise SharedStoreUnavailable("invalid_store_reply")
        return result
    except SharedStoreUnavailable:
        raise
    except (RedisRateLimitUnavailable, OSError, ValueError, EOFError, TimeoutError, asyncio.TimeoutError) as exc:
        raise SharedStoreUnavailable("store_io_unavailable") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

def _result_int(value: object) -> int:
    if isinstance(value, int):
        return value
    raise SharedStoreUnavailable("invalid_store_reply")

def _text(value: object) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SharedStoreUnavailable("invalid_store_reply") from exc
    if isinstance(value, str):
        return value
    raise SharedStoreUnavailable("invalid_store_reply")

async def create_shared_session(*, intent: str, client_ip: str) -> tuple[str,int]:
    secret = os.getenv("PUBLIC_SALES_RATE_KEY_SECRET", "")
    if len(secret) < 32:
        raise SharedStoreUnavailable("missing_key_secret")
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    result = await _eval(_CREATE, [
        f"{_PREFIX}:session:{digest}",
        f"{_PREFIX}:capacity",
        f"{_PREFIX}:create:{_hash_dimension(secret,'ip',client_ip)}",
    ],[intent, 1800000, 2700000, 8, 600000, 1000, digest])
    if len(result) != 2:
        raise SharedStoreUnavailable("invalid_store_reply")
    status, expires = _result_int(result[0]), _result_int(result[1])
    if status == -1:
        return ("rate_limited", 0)
    if status == -2:
        return ("capacity", 0)
    if status != 1 or expires <= 0:
        raise SharedStoreUnavailable("invalid_store_reply")
    return token, expires

async def transition_shared_session(
    *, token: str, action_id: str, intent_hint: str | None,
    client_ip: str, catalog: dict[str, dict[str,list[str]]],
) -> tuple[str,str,str,int]:
    secret = os.getenv("PUBLIC_SALES_RATE_KEY_SECRET", "")
    if len(secret) < 32:
        raise SharedStoreUnavailable("missing_key_secret")
    if not 40 <= len(token) <= 128 or not all(c.isalnum() or c in "-_" for c in token):
        return ("not_found", "", "", 0)
    digest = hashlib.sha256(token.encode()).hexdigest()
    result = await _eval(_TRANSITION, [
        f"{_PREFIX}:session:{digest}",
        f"{_PREFIX}:message-session:{digest}",
        f"{_PREFIX}:message-client:{_hash_dimension(secret,'ip',client_ip)}",
    ],[json.dumps(catalog, separators=(",", ":")), action_id, intent_hint or "", 60000, 15, 60, secrets.token_hex(16), 1800000])
    if len(result) != 4:
        raise SharedStoreUnavailable("invalid_store_reply")
    status = _result_int(result[0])
    intent = _text(result[1])
    first = _text(result[2])
    expires = _result_int(result[3])
    outcome = {-1:"not_found", -2:"expired", -3:"completed", -4:"locked", -5:"invalid", -6:"rate_limited",1:"followup",2:"result"}.get(status)
    if outcome is None:
        raise SharedStoreUnavailable("invalid_store_reply")
    return outcome, intent, first, expires
