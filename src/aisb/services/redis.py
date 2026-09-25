"""Redis/Valkey/KeyDB via redis-cli inside the container.

Structured reads go through server-side Lua returning cjson, so the output is unambiguous
(values with newlines, nil vs "", nested replies) and costs one round trip per batch.
"""

import json
import re
from typing import Any

from .base import Adapter, ServiceError, register

_DETAILS = """
local out = {}
for i, k in ipairs(KEYS) do
  local t = redis.call('TYPE', k)['ok']
  local ok, mem = pcall(redis.call, 'MEMORY', 'USAGE', k)
  out[i] = {key = k, type = t, ttl = redis.call('TTL', k), bytes = ok and mem or cjson.null}
end
return cjson.encode(out)
"""

_GET = """
local k, n = KEYS[1], tonumber(ARGV[1])
local t = redis.call('TYPE', k)['ok']
local v
if t == 'string' then v = redis.call('GET', k)
elseif t == 'hash' then
  local flat, h = redis.call('HSCAN', k, 0, 'COUNT', n), {}
  for i = 1, #flat[2], 2 do h[flat[2][i]] = flat[2][i + 1] end
  v = h
elseif t == 'list' then v = redis.call('LRANGE', k, 0, n - 1)
elseif t == 'set' then v = redis.call('SSCAN', k, 0, 'COUNT', n)[2]
elseif t == 'zset' then
  local flat, z = redis.call('ZRANGE', k, 0, n - 1, 'WITHSCORES'), {}
  for i = 1, #flat, 2 do z[#z + 1] = {member = flat[i], score = tonumber(flat[i + 1])} end
  v = z
elseif t == 'stream' then
  local entries, s = redis.call('XREVRANGE', k, '+', '-', 'COUNT', n), {}
  for i, e in ipairs(entries) do
    local f = {}
    for j = 1, #e[2], 2 do f[e[2][j]] = e[2][j + 1] end
    s[i] = {id = e[1], fields = f}
  end
  v = s
elseif t == 'none' then v = cjson.null
else v = 'unsupported type ' .. t end
local size = ({string = 'STRLEN', hash = 'HLEN', list = 'LLEN', set = 'SCARD', zset = 'ZCARD', stream = 'XLEN'})[t]
return cjson.encode({key = k, type = t, ttl = redis.call('TTL', k), size = size and redis.call(size, k) or cjson.null, value = v})
"""

_CALL = "return cjson.encode(redis.call(unpack(ARGV)))"


def parse_info(text: str) -> dict[str, dict[str, Any]]:
    """INFO output -> {section: {key: value}} with numbers and keyspace entries decoded."""
    out: dict[str, dict[str, Any]] = {}
    section = out.setdefault("server", {})
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("# "):
            section = out.setdefault(line[2:].strip().lower(), {})
        elif ":" in line:
            key, _, value = line.partition(":")
            if "=" in value and "," in value or key.startswith("db"):
                section[key] = {k: _num(v) for k, _, v in (p.partition("=") for p in value.split(","))}
            else:
                section[key] = _num(value)
    return {k: v for k, v in out.items() if v}


def _num(v: str) -> Any:
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v


@register
class Redis(Adapter):
    kind = "redis"
    image_rx = re.compile(r"^(redis|valkey|keydb|dragonfly)")
    env_hints = ("REDIS_", "VALKEY_")
    ports = (6379,)
    scheme = "redis"

    def password(self) -> str | None:
        return self.secret("REDIS_PASSWORD", "VALKEY_PASSWORD", "REDIS_PASS") or self.t.arg("--requirepass")

    def user(self) -> str | None:
        return self.secret("REDIS_USERNAME")

    def cli(self, *args: str, check: bool = True) -> Any:
        last = None
        for binary in ("redis-cli", "valkey-cli", "keydb-cli"):
            res = self.run([binary, *(["--user", self.user()] if self.user() else []), *args],
                           env={"REDISCLI_AUTH": self.password()}, check=False)
            if res.code in (126, 127) or "executable file not found" in res.stdout + res.stderr:
                last = res
                continue
            # redis-cli exits 0 on server errors and prints "(error) ..." / "ERR ..." instead.
            text = res.stdout.strip()
            if check and (not res.ok or re.match(r"^(\(error\) )?(ERR|WRONGTYPE|NOAUTH|NOPERM|NOSCRIPT)\b", text)):
                raise ServiceError(f"redis: {text or res.stderr.strip()}")
            return res
        raise ServiceError(f"redis: no redis-cli in container: {(last.stderr or last.stdout).strip() if last else ''}")

    def lua(self, script: str, keys: list[str], args: list[str] | None = None) -> Any:
        out = self.cli("EVAL", script, str(len(keys)), *keys, *(args or [])).stdout.strip()
        return json.loads(out) if out else None

    def scan(self, pattern: str, *, limit: int, type_: str | None) -> dict[str, Any]:
        args = ["--scan", "--pattern", pattern, "--count", "1000", *(["--type", type_] if type_ else [])]
        keys = [k for k in self.cli(*args).stdout.splitlines() if k]
        truncated = len(keys) > limit
        keys = keys[:limit]
        details: list[dict[str, Any]] = []
        for i in range(0, len(keys), 200):
            details += self.lua(_DETAILS, keys[i:i + 200]) or []
        return {"pattern": pattern, "count": len(keys), "truncated": truncated, "keys": details}

    def get(self, key: str, *, limit: int) -> dict[str, Any]:
        return self.lua(_GET, [key], [str(limit)])

    def command(self, args: list[str]) -> Any:
        """Structured reply via Lua when the command is scriptable; raw redis-cli output otherwise."""
        try:
            return {"reply": self.lua(_CALL, [], args), "via": "lua"}
        except ServiceError as e:
            if not re.search(r"not allowed from script|noscript|Unknown Redis command called from script|"
                             r"This Redis command is not allowed", str(e), re.I):
                raise
        lines = self.cli(*args).stdout.rstrip("\n").splitlines()
        return {"reply": [_num(x) for x in lines] if len(lines) != 1 else _num(lines[0]), "via": "redis-cli"}

    def probe(self) -> str:
        reply = self.cli("PING").stdout.strip()
        if reply != "PONG":
            raise ServiceError(f"redis: PING -> {reply!r}")
        return "PING"

    def info(self, section: str | None = None) -> dict[str, Any]:
        return parse_info(self.cli("INFO", *([section] if section else [])).stdout)

    def stats(self) -> dict[str, Any]:
        i = self.info()
        srv, mem, st, cl = i.get("server", {}), i.get("memory", {}), i.get("stats", {}), i.get("clients", {})
        hits, misses = st.get("keyspace_hits", 0), st.get("keyspace_misses", 0)
        return {
            "version": srv.get("redis_version") or srv.get("valkey_version"),
            "uptime_seconds": srv.get("uptime_in_seconds"),
            "role": i.get("replication", {}).get("role"),
            "clients": {"connected": cl.get("connected_clients"), "blocked": cl.get("blocked_clients")},
            "memory": {"used": mem.get("used_memory_human"), "peak": mem.get("used_memory_peak_human"),
                       "max": mem.get("maxmemory_human"), "policy": mem.get("maxmemory_policy"),
                       "fragmentation": mem.get("mem_fragmentation_ratio")},
            "ops_per_sec": st.get("instantaneous_ops_per_sec"),
            "hit_rate_percent": round(hits * 100 / (hits + misses), 2) if hits + misses else None,
            "evicted_keys": st.get("evicted_keys"), "expired_keys": st.get("expired_keys"),
            "keyspace": i.get("keyspace", {}),
            "persistence": {k: i.get("persistence", {}).get(k) for k in
                            ("rdb_last_bgsave_status", "rdb_changes_since_last_save", "aof_enabled")},
        }
