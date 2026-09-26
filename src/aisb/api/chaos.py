"""Fault injection with guaranteed revert, and a stack game day that grades detection, blast radius and recovery."""

import threading
import time
from collections.abc import Callable
from typing import Annotated, Any

from ..errors import DockerError, NotFound
from ..models import RunSpec
from ..ops import Resource, Tier, op
from ..util import q
from .containers import Containers

Ref = Annotated[str, "container name or id"]
Seconds = Annotated[float, "fault duration; reverted automatically afterwards"]
TOOLBOX = "nicolaka/netshoot:v0.13"


class Chaos(Resource, name="chaos"):
    def healthy(self, ref: str) -> tuple[bool, str]:
        """Instant health: adapter probe, else the container's own HEALTHCHECK run now, else running-and-not-paused."""
        from ..services import REGISTRY, Target
        try:
            info = self.t.json("GET", f"/containers/{q(ref)}/json")
        except NotFound:
            return False, "missing"
        st = info.get("State") or {}
        if not st.get("Running") or st.get("Paused") or st.get("Restarting"):
            return False, "paused" if st.get("Paused") else str(st.get("Status"))
        cls = REGISTRY.detect(Target.from_inspect(info))[0]
        if cls is not None and hasattr(cls, "probe"):
            try:
                return True, cls(Containers(self.t), Target.from_inspect(info)).probe()
            except (DockerError, ValueError) as e:
                return False, str(e)[:200]
        test = ((info.get("Config") or {}).get("Healthcheck") or {}).get("Test") or []
        if test and test[0] in ("CMD", "CMD-SHELL"):
            argv = ["sh", "-c", test[1]] if test[0] == "CMD-SHELL" else test[1:]
            res = Containers(self.t).run_in(ref, argv)
            return res.code == 0, f"healthcheck exit {res.code}"
        return True, "running"

    def _hold(self, seconds: float, inject: Callable[[], None], revert: Callable[[], None]) -> None:
        inject()
        try:
            time.sleep(seconds)
        finally:
            revert()  # always, even on Ctrl-C

    @op(Tier.MUTATE)
    def pause(self, ref: Ref, *, seconds: Seconds = 10.0) -> dict[str, Any]:
        """Freeze every process in the container (SIGSTOP-like), then unpause."""
        self._hold(seconds, lambda: self.t.json("POST", f"/containers/{q(ref)}/pause"),
                   lambda: self.t.json("POST", f"/containers/{q(ref)}/unpause"))
        return {"fault": "pause", "container": ref, "seconds": seconds, "reverted": True}

    @op(Tier.MUTATE)
    def disconnect(self, ref: Ref, *, network: Annotated[str | None, "network (default: all user networks)"] = None,
                   seconds: Seconds = 10.0) -> dict[str, Any]:
        """Partition: detach the container from its network(s), then reconnect with the original DNS aliases."""
        info = self.t.json("GET", f"/containers/{q(ref)}/json")
        cid = info.get("Id", ref)
        nets = {n: [a for a in ep.get("Aliases") or [] if not cid.startswith(a)]
                for n, ep in ((info.get("NetworkSettings") or {}).get("Networks") or {}).items()
                if (network is None and n not in ("host", "none")) or n == network}
        if not nets:
            raise ValueError(f"{ref} is not attached to {network or 'any network'}")

        def cut() -> None:
            for n in nets:
                self.t.json("POST", f"/networks/{q(n)}/disconnect", body={"Container": cid, "Force": True})

        def heal() -> None:
            for n, aliases in nets.items():
                self.t.json("POST", f"/networks/{q(n)}/connect",
                            body={"Container": cid, "EndpointConfig": {"Aliases": aliases}})
        self._hold(seconds, cut, heal)
        return {"fault": "disconnect", "container": ref, "networks": list(nets), "seconds": seconds, "reverted": True}

    @op(Tier.MUTATE)
    def latency(self, ref: Ref, *, ms: Annotated[int, "added delay"] = 200, jitter: Annotated[int, "± ms"] = 0,
                loss: Annotated[float, "packet loss %"] = 0.0, seconds: Seconds = 10.0,
                image: Annotated[str, "toolbox image with tc"] = TOOLBOX) -> dict[str, Any]:
        """Degrade the network (delay/jitter/loss) with tc netem from a NET_ADMIN sidecar in the target's namespace."""
        target = self.t.json("GET", f"/containers/{q(ref)}/json")["Id"]
        netem = f"delay {ms}ms {jitter}ms" + (f" loss {loss}%" if loss else "")
        script = (f"nics=$(ls /sys/class/net | grep -v '^lo$'); for i in $nics; do tc qdisc add dev $i root netem {netem} "
                  f"|| exit 3; done; echo injected; sleep {seconds}; for i in $nics; do tc qdisc del dev $i root 2>/dev/null; "
                  f"done; echo reverted")
        ctr = Containers(self.t)
        spec = RunSpec(image=image, cmd=("sh", "-c", script), network=f"container:{target}", cap_add=("NET_ADMIN",),
                       labels={"aisb.chaos": ref})
        cid = ctr.create_from(spec)
        try:
            self.t.json("POST", f"/containers/{cid}/start")
            status = self.t.json("POST", f"/containers/{cid}/wait", timeout=None) or {}
            out = ctr.logs(cid, tail=0)
        finally:
            self.t.json("DELETE", f"/containers/{cid}", query={"force": True})
        if "reverted" not in out.get("output", "") and not self.t.planning:  # interrupted: clean up the qdisc
            fix = RunSpec(image=image, cmd=("sh", "-c", "for i in $(ls /sys/class/net | grep -v '^lo$'); do tc qdisc del dev $i root; done"),
                          network=f"container:{target}", cap_add=("NET_ADMIN",))
            fid = ctr.create_from(fix)
            self.t.json("POST", f"/containers/{fid}/start")
            self.t.json("POST", f"/containers/{fid}/wait", timeout=None)
            self.t.json("DELETE", f"/containers/{fid}", query={"force": True})
        if status.get("StatusCode") not in (0, None):
            text = out.get("output", "").strip()
            hint = (" (the Docker host kernel has no sch_netem module: `modprobe sch_netem` on the host, "
                    "or use pause/disconnect faults)") if "qdisc kind is unknown" in text else ""
            raise ValueError(f"tc failed in the sidecar: {text[-300:]}{hint}")
        return {"fault": "latency", "container": ref, "netem": netem, "seconds": seconds,
                "injected": "injected" in out.get("output", "") or self.t.planning, "reverted": True}

    @op(Tier.MUTATE)
    def kill(self, ref: Ref, *, signal: Annotated[str, "signal to send"] = "KILL") -> dict[str, Any]:
        """Kill the main process (no revert: this tests the restart policy and dependents' resilience)."""
        self.t.json("POST", f"/containers/{q(ref)}/kill", query={"signal": signal})
        return {"fault": "kill", "container": ref, "signal": signal}

    @op(Tier.MUTATE)
    def run(self, stack: Annotated[str, "stack JSON file (must be up)"], *,
            faults: Annotated[list[str] | None, "pause, disconnect, latency (default: pause, disconnect)"] = None,
            service: Annotated[list[str] | None, "only target these services"] = None,
            seconds: Seconds = 8.0, recover_within: Annotated[float, "seconds to wait for full recovery"] = 60.0,
            ) -> dict[str, Any]:
        """Game day: for each service x fault, inject, watch every other service's health (blast radius) and the
        target's own (detection), revert, and time recovery. Returns a report card and a resilience score."""
        from .. import stack as stk
        s = stk.load(stack)
        members = {svc.name: svc.container for svc in s.services.values()}
        chosen = faults or ["pause", "disconnect"]
        if bad := set(chosen) - {"pause", "disconnect", "latency"}:
            raise ValueError(f"unknown faults: {sorted(bad)}")
        if self.t.planning:
            for name in service or s.order:
                for f in chosen:
                    self.t.note(chaos=f, service=name, seconds=seconds)
            return {}
        card = []
        for name in service or s.order:
            for fault in chosen:
                pre = {m: self.healthy(c)[0] for m, c in members.items()}
                if not all(pre.values()):
                    card.append({"service": name, "fault": fault, "skipped": "stack not healthy before the fault",
                                 "unhealthy": [m for m, ok in pre.items() if not ok]})
                    continue
                target = members[name]
                action = {"pause": lambda: self.pause(target, seconds=seconds),
                          "disconnect": lambda: self.disconnect(target, seconds=seconds),
                          "latency": lambda: self.latency(target, ms=300, seconds=seconds)}[fault]
                worker = threading.Thread(target=action, daemon=True)
                worker.start()
                affected: set[str] = set()
                detected = False
                time.sleep(min(1.0, seconds / 4))
                while worker.is_alive():
                    for m, c in members.items():
                        ok, _ = self.healthy(c)
                        if not ok:
                            detected |= m == name
                            if m != name:
                                affected.add(m)
                    time.sleep(0.5)
                worker.join()
                started, recovered = time.monotonic(), False
                while time.monotonic() - started < recover_within:
                    if all(self.healthy(c)[0] for c in members.values()):
                        recovered = True
                        break
                    time.sleep(0.5)
                card.append({"service": name, "fault": fault, "detected": detected,
                             "blast_radius": sorted(affected), "recovered": recovered,
                             "recovery_seconds": round(time.monotonic() - started, 1) if recovered else None})
        graded = [c for c in card if "skipped" not in c]
        score = round(100 * sum(c["recovered"] for c in graded) / len(graded)) if graded else None
        return {"stack": s.name, "score": score, "report": card,
                "findings": [f"{c['fault']} of {c['service']} took down {', '.join(c['blast_radius'])}"
                             for c in graded if c["blast_radius"]] +
                            [f"{c['service']} did not recover within {recover_within}s after {c['fault']}"
                             for c in graded if not c["recovered"]] +
                            [f"{c['fault']} of {c['service']} went undetected by its own health signal"
                             for c in graded if not c["detected"] and c["fault"] != "latency"]}
