"""MongoDB via mongosh inside the container. User input travels in env vars, never in the script text."""

import json
import re
from typing import Any

from .base import Adapter, ServiceError, register

_PRELUDE = """
const __env = process.env;
if (__env.AISB_U) db.getSiblingDB(__env.AISB_AUTHDB || 'admin').auth(__env.AISB_U, __env.AISB_P);
db = db.getSiblingDB(__env.AISB_DB);
const __r = (() => { %s })();
const __v = (__r && typeof __r.toArray === 'function') ? __r.toArray() : __r;
print('__AISB__' + EJSON.stringify(__v === undefined ? null : __v, {relaxed: true}));
"""

_FIND = ("return db.getCollection(__env.AISB_C).find(EJSON.parse(__env.AISB_F), EJSON.parse(__env.AISB_PR))"
         ".sort(EJSON.parse(__env.AISB_S)).limit(Number(__env.AISB_N));")
_COLLECTIONS = ("return db.getCollectionInfos().map(c => ({name: c.name, type: c.type, "
                "count: c.type === 'collection' ? db.getCollection(c.name).estimatedDocumentCount() : null}));")
_STATS = ("const s = db.adminCommand({serverStatus: 1}); return {version: s.version, uptime_seconds: s.uptime, "
          "connections: {current: s.connections.current, available: s.connections.available}, "
          "opcounters: s.opcounters, mem_mb: {resident: s.mem.resident, virtual: s.mem.virtual}, "
          "active: db.adminCommand({currentOp: 1, active: true}).inprog.filter(o => o.op !== 'none')"
          ".map(o => ({opid: o.opid, op: o.op, ns: o.ns, seconds: o.secs_running, command: JSON.stringify(o.command).slice(0, 300)}))};")


@register
class Mongo(Adapter):
    kind = "mongo"
    image_rx = re.compile(r"^(mongo|mongodb|percona-server-mongodb)")
    env_hints = ("MONGO_", "MONGODB_")
    ports = (27017,)
    scheme = "mongodb"

    def user(self) -> str | None:
        return self.secret("MONGO_INITDB_ROOT_USERNAME", "MONGODB_ROOT_USER")

    def password(self) -> str | None:
        return self.secret("MONGO_INITDB_ROOT_PASSWORD", "MONGODB_ROOT_PASSWORD")

    def database(self) -> str | None:
        return self.secret("MONGO_INITDB_DATABASE", "MONGODB_DATABASE")

    def js(self, body: str, *, database: str | None = None, **env: str) -> Any:
        full_env = {"AISB_U": self.user(), "AISB_P": self.password(), "AISB_DB": database or self.database() or "test",
                    **{f"AISB_{k.upper()}": v for k, v in env.items()}}
        res = self.run(["mongosh", "--quiet", "--norc", "--eval", _PRELUDE % body], env=full_env, check=False)
        out = res.stdout
        if "__AISB__" not in out:
            if res.code in (126, 127) or "executable file not found" in out + res.stderr:
                raise ServiceError("mongo: mongosh not found in container (images older than mongo:6 ship only the legacy shell)")
            raise ServiceError(f"mongo: {(res.stderr or out).strip()[-2000:]}")
        return json.loads(out.rsplit("__AISB__", 1)[1])

    def find(self, collection: str, *, filter_: str, projection: str, sort: str, limit: int,
             database: str | None) -> list[dict[str, Any]]:
        for label, text in (("filter", filter_), ("projection", projection), ("sort", sort)):
            try:
                json.loads(text)
            except ValueError as e:
                raise ValueError(f"--{label} must be JSON (Extended JSON allowed): {e}") from None
        return self.js(_FIND, database=database, c=collection, f=filter_, pr=projection, s=sort, n=str(limit))

    def collections(self, database: str | None) -> list[dict[str, Any]]:
        return self.js(_COLLECTIONS, database=database)

    def stats(self) -> dict[str, Any]:
        return self.js(_STATS)

    def probe(self) -> str:
        return f"ping ok={self.js('return db.runCommand({ping: 1}).ok')}"
