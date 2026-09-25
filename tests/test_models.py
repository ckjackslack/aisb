import json
from dataclasses import replace

import pytest

from aisb.api.containers import runspec_of
from aisb.models import Container, Image, RunSpec, parse_port, parse_restart, parse_size
from aisb.util import clip, dig, filters, kv, project, split_cp, to_unix


@pytest.mark.parametrize(("spec", "key", "binding"), [
    ("80", "80/tcp", None),
    ("53/udp", "53/udp", None),
    ("8080:80", "80/tcp", {"HostIp": "", "HostPort": "8080"}),
    ("127.0.0.1:8080:80/tcp", "80/tcp", {"HostIp": "127.0.0.1", "HostPort": "8080"}),
])
def test_parse_port(spec, key, binding):
    assert parse_port(spec) == (key, binding)


@pytest.mark.parametrize("bad", ["", "a:b", "1:2:3:4", "80:http"])
def test_parse_port_rejects(bad):
    with pytest.raises(ValueError):
        parse_port(bad)


@pytest.mark.parametrize(("value", "expected"), [
    ("512m", 512 << 20), ("1g", 1 << 30), ("1.5GiB", int(1.5 * (1 << 30))), ("100", 100), (7, 7),
])
def test_parse_size(value, expected):
    assert parse_size(value) == expected


def test_parse_restart():
    assert parse_restart("on-failure:3") == {"Name": "on-failure", "MaximumRetryCount": 3}
    with pytest.raises(ValueError):
        parse_restart("sometimes")


def test_runspec_to_api_full():
    spec = RunSpec(
        image="nginx", cmd=("nginx", "-g", "daemon off;"), name="web", env=("A=1",),
        ports=("8080:80", "443"), volumes=("/srv:/usr/share/nginx/html:ro", "/cache"),
        labels={"team": "x"}, restart="unless-stopped", memory="256m", cpus=0.5,
        entrypoint="/docker-entrypoint.sh --flag", health_cmd="curl -f localhost",
    )
    api = spec.to_api(auto_remove=True)
    assert api["Cmd"] == ["nginx", "-g", "daemon off;"]
    assert api["Entrypoint"] == ["/docker-entrypoint.sh", "--flag"]
    assert api["Labels"] == {"team": "x", "aisb.managed": "true"}
    assert api["ExposedPorts"] == {"80/tcp": {}, "443/tcp": {}}
    assert api["Volumes"] == {"/cache": {}}
    assert api["Healthcheck"] == {"Test": ["CMD-SHELL", "curl -f localhost"]}
    assert api["HostConfig"] == {
        "Binds": ["/srv:/usr/share/nginx/html:ro"],
        "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]},
        "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
        "Memory": 256 << 20, "NanoCpus": 500_000_000, "AutoRemove": True,
    }
    assert "Tty" not in api and "name" not in api


def test_runspec_minimal_is_lean():
    assert RunSpec("alpine").to_api() == {"Image": "alpine", "Labels": {"aisb.managed": "true"}, "HostConfig": {}}


def test_runspec_load_and_merge(tmp_path):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"image": "a", "cmd": "sleep 5", "env": {"X": "1"}, "labels": {"k": "v"}}))
    spec = RunSpec.load(path).merge(image="b", labels={"j": "w"}, tty=False, name=None)
    assert (spec.image, spec.cmd, spec.env, spec.labels, spec.tty) == ("b", ("sleep", "5"), ("X=1",), {"k": "v", "j": "w"}, False)


def test_runspec_rejects_unknown_keys():
    with pytest.raises(ValueError, match="imag"):
        RunSpec.from_dict({"imag": "typo"})


def test_container_from_api():
    c = Container.from_api({
        "Id": "a" * 64, "Names": ["/web"], "Image": "nginx", "State": "running", "Status": "Up",
        "Ports": [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"},
                  {"IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}, {"PrivatePort": 443, "Type": "tcp"}],
        "Created": 1,
    })
    assert (c.id, c.name, c.ports) == ("a" * 12, "web", ["0.0.0.0:8080->80/tcp", "443/tcp", ":::8080->80/tcp"])


def test_image_from_api_drops_none_tags():
    img = Image.from_api({"Id": "sha256:" + "b" * 64, "RepoTags": ["<none>:<none>"], "Size": 3})
    assert (img.id, img.tags) == ("b" * 12, [])


def test_project_and_dig():
    data = {"State": {"Status": "up", "Health": None}, "Mounts": [{"Source": "/s"}]}
    assert project(data, "State.Status, Mounts.0.Source,Nope.x") == {"State.Status": "up", "Mounts.0.Source": "/s", "Nope.x": None}
    assert project(data, None) is data
    assert dig(data, "Mounts.5") is None


def test_clip_keeps_tail():
    assert clip("abc", 0) == {"output": "abc", "truncated": False}
    out = clip("0123456789", 4)
    assert out["truncated"] and out["output"].endswith("6789") and "6 bytes truncated" in out["output"]


@pytest.mark.parametrize(("value", "expected"), [
    ("now", 1000), ("10m", 400), ("1h", -2600), ("1700000000", 1700000000), (5, 5),
    ("2024-01-01T00:00:00Z", 1704067200), ("2024-01-01T00:00:00", 1704067200),
])
def test_to_unix(value, expected):
    assert to_unix(value, now=1000) == expected


def test_kv_filters_and_split_cp():
    assert kv(["a=1", "b=x=y"]) == {"a": "1", "b": "x=y"}
    with pytest.raises(ValueError):
        kv(["novalue"])
    assert filters(["type=container", "event=die", "event=oom"], label=["x"]) == {
        "type": ["container"], "event": ["die", "oom"], "label": ["x"]}
    assert filters(None) is None
    assert split_cp("web:/etc") == ("web", "/etc")
    assert split_cp("./a:b") == (None, "./a:b")
    assert split_cp("/abs") == (None, "/abs")


def test_runspec_roundtrips_through_inspect():
    spec = RunSpec(
        image="nginx", cmd=("nginx", "-g", "daemon off;"), name="web", env=("A=1",),
        ports=("127.0.0.1:8080:80", "53/udp", "443"), volumes=("/srv:/data:ro", "/cache"), labels={"team": "x"},
        restart="on-failure:3", network="app-net", workdir="/w", user="app", memory="256m", cpus=0.5,
        entrypoint="/entry.sh --flag", tty=True, rm=True, health_cmd="curl -f localhost",
    )
    body = spec.to_api(auto_remove=True)
    inspected = {"Name": "/web", "HostConfig": body.pop("HostConfig"), "Config": body}
    dumped = runspec_of(inspected)
    assert "aisb.managed" not in dumped["labels"]
    assert RunSpec.from_dict(dumped) == replace(spec, memory=str(256 << 20))
