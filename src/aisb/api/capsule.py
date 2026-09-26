"""Bug capsules: everything needed to reproduce a container's situation elsewhere, in one file."""

import io
import json
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Annotated, Any

from ..errors import DockerError, NotFound
from ..models import RunSpec
from ..ops import Resource, Tier, op
from ..transport import SECRET_KEY, redact_env
from ..util import kv, q
from .containers import Containers, runspec_of

VERSION = 1
REDACTED = "<redacted>"


def _add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.mode = len(data), int(time.time()), 0o644
    tar.addfile(info, io.BytesIO(data))


def _add_stream(tar: tarfile.TarFile, name: str, chunks: Any) -> int:
    """Spool a byte stream to a temp file (tar needs the size up front), then add it."""
    with tempfile.TemporaryFile() as tmp:
        size = 0
        for chunk in chunks:
            tmp.write(chunk)
            size += len(chunk)
        tmp.seek(0)
        info = tarfile.TarInfo(name)
        info.size, info.mtime, info.mode = size, int(time.time()), 0o644
        tar.addfile(info, tmp)
    return size


class Capsule(Resource, name="capsule"):
    @op(Tier.READ)
    def create(self, ref: Annotated[str, "container name or id"], out: Annotated[str, "host file (.tar.gz)"], *,
               volumes: Annotated[bool, "include the contents of every mount"] = False,
               db_sample: Annotated[float | None, "for SQL services: include a referentially complete sample (ratio)"] = None,
               image: Annotated[bool, "embed the image itself (large; for offline or private images)"] = False,
               log_lines: Annotated[int, "log lines included"] = 2000) -> dict[str, Any]:
        """Bundle a container's config (secrets redacted), logs, doctor report, DB schema (+sample) and optionally
        its volumes and image into one file that `capsule load` recreates on another machine."""
        from .services import REGISTRY, SQL, Target
        ctr = Containers(self.t)
        info = self.t.json("GET", f"/containers/{q(ref)}/json")
        name = (info.get("Name") or ref).lstrip("/")
        cfg = info.get("Config") or {}
        spec = runspec_of(info)
        redacted = sorted(k for k, _, v in (e.partition("=") for e in spec.get("env", [])) if SECRET_KEY.search(k) and v)
        spec["env"] = [f"{k}={REDACTED}" if k in redacted else f"{k}={v}" for k, _, v in
                       (e.partition("=") for e in spec.get("env", []))]
        try:
            img = self.t.json("GET", f"/images/{q(info.get('Image', ''))}/json") or {}
        except NotFound:
            img = {}
        mounts = [m for m in info.get("Mounts") or [] if m.get("Destination")]
        manifest: dict[str, Any] = {
            "aisb_capsule": VERSION, "created": int(time.time()), "container": name,
            "docker": (self.t.json("GET", "/version") or {}).get("Version"),
            "image": {"ref": cfg.get("Image"), "id": info.get("Image"), "repo_digests": img.get("RepoDigests") or []},
            "redacted_env": redacted, "mounts": [], "db": None, "embedded_image": image,
        }
        path = Path(out).expanduser()
        safe_inspect = {**info, "Config": {**cfg, "Env": redact_env(cfg.get("Env") or [])}}
        with tarfile.open(path, "w:gz") as tar:
            _add(tar, "spec.json", json.dumps(spec, indent=1).encode())
            _add(tar, "inspect.json", json.dumps(safe_inspect, indent=1, default=str).encode())
            _add(tar, "logs.txt", ctr._text(ref, tail=log_lines, timestamps=True,
                                               tty=bool(cfg.get("Tty"))).encode())
            try:
                _add(tar, "doctor.json", json.dumps(ctr.doctor(ref, stats=False), indent=1, default=str).encode())
            except DockerError:
                pass
            cls = REGISTRY.detect(Target.from_inspect(info))[0]
            if cls and issubclass(cls, SQL) and (info.get("State") or {}).get("Running"):
                db = cls(ctr, Target.from_inspect(info))
                buf = bytearray()
                db.dump(buf.extend, schema_only=True)
                _add(tar, "db/schema.sql", bytes(buf))
                manifest["db"] = {"engine": db.kind, "database": db.database(), "sample": None}
                if db_sample:
                    from .services import Db
                    with tempfile.TemporaryDirectory() as d:
                        res = Db(self.t).sample(ref, str(Path(d) / "s.sql"), ratio=db_sample, data_only=True)
                        _add(tar, "db/sample.sql", (Path(d) / "s.sql").read_bytes())
                        manifest["db"]["sample"] = {"ratio": db_sample, "rows": res.get("rows")}
            if volumes:
                for i, m in enumerate(mounts):
                    chunks = self.t.stream("GET", f"/containers/{q(ref)}/archive",
                                           query={"path": m["Destination"]}, timeout=None)
                    size = _add_stream(tar, f"volumes/{i}.tar", chunks)
                    manifest["mounts"].append({"index": i, "destination": m["Destination"], "type": m.get("Type"),
                                               "bytes": size})
            if image and info.get("Image"):
                manifest["image"]["tar_bytes"] = _add_stream(
                    tar, "image.tar", self.t.stream("GET", f"/images/{q(info['Image'])}/get", timeout=None))
            _add(tar, "manifest.json", json.dumps(manifest, indent=1).encode())
        return {"capsule": str(path), "bytes": path.stat().st_size, "container": name, "redacted_env": redacted,
                "mounts": len(manifest["mounts"]), "db": manifest["db"], "embedded_image": image}

    @op(Tier.MUTATE)
    def load(self, file: Annotated[str, "capsule file"], *, name: Annotated[str | None, "container name"] = None,
             env: Annotated[list[str] | None, "KEY=VALUE for redacted secrets"] = None,
             keep_ports: Annotated[bool, "publish the original host ports (may clash)"] = False) -> dict[str, Any]:
        """Recreate a capsule: image (embedded, by digest, or by ref), config, volume contents (into *fresh* volumes),
        then DB schema + sample once the service is ready. Redacted secrets must be supplied with --env."""
        from .services import Svc, adapter
        from .services import SQL
        with tarfile.open(Path(file).expanduser(), "r:gz") as tar:
            members = {m.name: m for m in tar.getmembers()}
            read = lambda n: tar.extractfile(members[n]).read() if n in members else None  # type: ignore[union-attr]  # noqa: E731
            manifest = json.loads(read("manifest.json") or b"{}")
            if manifest.get("aisb_capsule") != VERSION:
                raise ValueError(f"{file} is not an aisb capsule")
            spec_d = json.loads(read("spec.json"))
            if "image.tar" in members:
                self.t.json("POST", "/images/load", data=read("image.tar"), content_type="application/x-tar",
                            timeout=None)
            image_ref = self._ensure_image(manifest["image"])
            new = name or f"{manifest['container']}-capsule"
            supplied = kv(env)
            envs, missing = [], []
            for k, _, v in (e.partition("=") for e in spec_d.get("env", [])):
                if v == REDACTED:
                    if k in supplied:
                        envs.append(f"{k}={supplied[k]}")
                    else:
                        missing.append(k)
                else:
                    envs.append(f"{k}={supplied.get(k, v)}")
            ports = spec_d.get("ports", []) if keep_ports else [p.rsplit(":", 1)[-1] for p in spec_d.get("ports", [])]
            # Never write capsule data into a same-named volume that already exists here: use fresh ones.
            vols = [f"{new}-m{m['index']}:{m['destination']}" for m in manifest.get("mounts", [])]
            spec = RunSpec.from_dict({**{k: v for k, v in spec_d.items() if k not in ("name", "network")},
                                      "image": image_ref, "env": envs, "ports": ports, "volumes": vols,
                                      "labels": {**spec_d.get("labels", {}), "aisb.capsule": manifest["container"]}})
            ctr = Containers(self.t)
            cid = ctr.create_from(spec.merge(name=new))
            restored = 0
            for m in manifest.get("mounts", []):
                data = read(f"volumes/{m['index']}.tar")
                parent = m["destination"].rstrip("/").rsplit("/", 1)[0] or "/"
                self.t.json("PUT", f"/containers/{cid}/archive", query={"path": parent}, data=data,
                            content_type="application/x-tar", timeout=None)
                restored += 1
            self.t.json("POST", f"/containers/{cid}/start")
            db_loaded: Any = None
            if manifest.get("db") and restored:
                db_loaded = "from volumes (the data directory was restored; schema/sample not replayed)"
            elif manifest.get("db") and not self.t.planning:
                ready = Svc(self.t).ready(new, within=180, stable=1.0)
                try:
                    if not ready.get("ok"):
                        raise ValueError(ready.get("reason") or "not ready")
                    db = adapter(self, new, SQL)
                    db.script(read("db/schema.sql") or b"")
                    if "db/sample.sql" in members:
                        db.script(read("db/sample.sql") or b"")
                    db_loaded = {"schema": True, "sample": "db/sample.sql" in members}
                except (DockerError, ValueError) as e:
                    db_loaded = {"error": str(e)[:500]}
        return {"container": new, "image": image_ref, "volumes_restored": restored, "db_loaded": db_loaded,
                "missing_secrets": missing,
                "next": [f"aisb containers doctor {new}"] + ([f"supply secrets: aisb capsule load {file} --env "
                                                                + " --env ".join(f"{k}=..." for k in missing)] if missing else [])}

    def _ensure_image(self, image: dict[str, Any]) -> str:
        from .images import Images
        for candidate in (image.get("id"), *image.get("repo_digests", []), image.get("ref")):
            if not candidate:
                continue
            try:
                self.t.json("GET", f"/images/{q(candidate)}/json")
                return candidate
            except NotFound:
                continue
        for candidate in (*image.get("repo_digests", []), image.get("ref")):
            if candidate:
                try:
                    Images(self.t).pull(candidate)
                    return candidate
                except DockerError:
                    continue
        raise ValueError(f"image {image.get('ref')} is not available and could not be pulled; "
                         "create the capsule with --image to embed it")
