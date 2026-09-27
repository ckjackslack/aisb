"""Network clients for supply-chain checks (stdlib urllib): OSV vulnerability API, and container registries.

OSV base URL: $AISB_OSV_URL (default https://api.osv.dev). Registry credentials come from ~/.docker/config.json
`auths` when present; otherwise anonymous bearer tokens (Docker Hub, GHCR, Quay, most registries).
"""

import base64
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import state

OSV = os.environ.get("AISB_OSV_URL", "https://api.osv.dev").rstrip("/")
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])


class SupplyError(ValueError):
    pass


def _open(req: urllib.request.Request, timeout: float = 20) -> Any:
    return urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context())


def _json(url: str, body: Any | None = None, *, timeout: float = 30) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json", "User-Agent": "aisb"})
    try:
        with _open(req, timeout) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raise SupplyError(f"{url.split('?')[0]}: HTTP {e.code} {e.reason}") from None
    except OSError as e:
        raise SupplyError(f"{url.split('?')[0]}: {e}") from None


# --- OSV -----------------------------------------------------------------------------------------------

def osv_base() -> str:
    return os.environ.get("AISB_OSV_URL", OSV).rstrip("/")


def osv_ids(queries: Sequence[Mapping[str, Any]], *, chunk: int = 500) -> list[list[str]]:
    out: list[list[str]] = []
    for i in range(0, len(queries), chunk):
        res = _json(f"{osv_base()}/v1/querybatch", {"queries": list(queries[i:i + chunk])})
        out += [[v["id"] for v in (r or {}).get("vulns") or []] for r in (res or {}).get("results") or []]
    return out


def osv_vuln(vid: str, *, ttl: float = 86400) -> dict[str, Any]:
    cache = state.home("cache", "osv") / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', vid)}.json"
    if cache.exists() and time.time() - cache.stat().st_mtime < ttl:
        return json.loads(cache.read_text())
    data = _json(f"{osv_base()}/v1/vulns/{vid}")
    state.write_json(cache, data)
    return data


# --- registries ------------------------------------------------------------------------------------------

def parse_ref(ref: str) -> tuple[str, str, str]:
    """`nginx:1.27` -> (registry-1.docker.io, library/nginx, 1.27); `ghcr.io/a/b@sha256:..` keeps the digest."""
    name, _, digest = ref.partition("@")
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "registry-1.docker.io", name
    tag = "latest"
    last = path.rsplit("/", 1)[-1]
    if ":" in last:
        path, _, tag = path.rpartition(":")
    if registry == "registry-1.docker.io" and "/" not in path:
        path = f"library/{path}"
    return registry, path, digest or tag


def _docker_auth(registry: str) -> str | None:
    cfg = Path(os.environ.get("DOCKER_CONFIG", "~/.docker")).expanduser() / "config.json"
    try:
        auths = json.loads(cfg.read_text()).get("auths") or {}
    except (OSError, ValueError):
        return None
    for key in (registry, f"https://{registry}", "https://index.docker.io/v1/" if "docker.io" in registry else ""):
        if key and (a := auths.get(key)) and a.get("auth"):
            return str(a["auth"])
    return None


def _token(challenge: str, repo: str, basic: str | None) -> str:
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = params.pop("realm", None)
    if not realm:
        raise SupplyError(f"registry sent an unusable auth challenge: {challenge}")
    params.setdefault("scope", f"repository:{repo}:pull")
    url = realm + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "aisb", **({"Authorization": f"Basic {basic}"} if basic else {})})
    try:
        with _open(req) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SupplyError(f"token from {realm}: {e}") from None
    return data.get("token") or data.get("access_token") or ""


def remote_digest(ref: str) -> str:
    """The digest the registry currently serves for a tag (HEAD manifest; index digest for multi-arch)."""
    registry, repo, tag = parse_ref(ref)
    url = f"https://{registry}/v2/{repo}/manifests/{tag}"
    basic = _docker_auth(registry)
    headers = {"Accept": ACCEPT, "User-Agent": "aisb"}
    for attempt in (1, 2):
        req = urllib.request.Request(url, method="HEAD", headers=headers)
        try:
            with _open(req) as r:
                digest = r.headers.get("Docker-Content-Digest")
                if not digest:
                    raise SupplyError(f"{registry} did not return a digest for {repo}:{tag}")
                return digest
        except urllib.error.HTTPError as e:
            challenge = e.headers.get("WWW-Authenticate", "")
            if e.code == 401 and attempt == 1 and challenge.lower().startswith("bearer"):
                headers["Authorization"] = f"Bearer {_token(challenge, repo, basic)}"
                continue
            if e.code == 401 and attempt == 1 and challenge.lower().startswith("basic") and basic:
                headers["Authorization"] = f"Basic {basic}"
                continue
            raise SupplyError(f"{registry}/{repo}:{tag}: HTTP {e.code} {e.reason}") from None
        except OSError as e:
            raise SupplyError(f"{registry}: {e}") from None
    raise SupplyError(f"{registry}/{repo}:{tag}: authentication failed")


def basic_auth(user: str, password: str) -> str:
    return base64.b64encode(f"{user}:{password}".encode()).decode()
