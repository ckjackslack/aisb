"""yamlish (strict YAML subset) edge cases and compose -> stack translation of every supported key."""

import textwrap

import pytest

from aisb import compose, yamlish
from aisb import stack as stk

# --- yamlish: accepted -----------------------------------------------------------------------------------

@pytest.mark.parametrize(("text", "value"), [
    ("a: {x: , y: 1}\n", {"a": {"x": None, "y": 1}}),
    ("a: [[1, 2], {k: v}, []]\n", {"a": [[1, 2], {"k": "v"}, []]}),
    ("a: false\nb: FALSE\nc: ~\nd: NULL\ne: TRUE\n", {"a": False, "b": False, "c": None, "d": None, "e": True}),
    ("n: -12\nf: 1_000.5\ng: .5\nh: 1e3\ni: 0x10\nj: +7\n",
     {"n": -12, "f": 1000.5, "g": 0.5, "h": 1000.0, "i": "0x10", "j": 7}),
    ("'it''s': 1\n\"q k\": 2\n", {"it's": 1, "q k": 2}),
    ("s: |\nt: 1\n", {"s": "", "t": 1}),                              # empty block scalar
    ("s: |+\n  keep\n\n\nt: 1\n", {"s": "keep\n\n\n", "t": 1}),
    ("s: >\n  a\n  b\n\n  c\n", {"s": "a b\n\nc\n"}),
    ("a:\nb: 2\n", {"a": None, "b": 2}),                             # a key with nothing under it
    ("- \n  - x\n- y\n", [["x"], "y"]),                                # empty `-` followed by a nested block
    ("-\n- 1\n", [None, 1]),
    ("- |\n  text\n", ["text\n"]),
    ("- {a: 1}\n- [b]\n", [{"a": 1}, ["b"]]),
    ("k: 'a # not a comment'  # comment\n", {"k": "a # not a comment"}),
    ("k: v\n...\nignored: [\n", {"k": "v"}),                           # explicit end of document
    ("# only comments\n\n", None),
    ("k: v\n---\n# trailing marker with only comments\n", {"k": "v"}),
    ("\tk: v\n", {"k": "v"}),                                          # tabs expand; one top-level mapping
    ('k: "a\\/b \\u00e9"\n', {"k": "a/b \u00e9"}),
    ("url: http://h:1/x\n", {"url": "http://h:1/x"}),
])
def test_accepts(text, value):
    assert yamlish.loads(text) == value


# --- yamlish: rejected with a line number ---------------------------------------------------------------

@pytest.mark.parametrize(("text", "error"), [
    ('k: "bad \\x escape"\n', r"line 1: bad escape"),
    ("k: 'open\n", "line 1: unterminated single-quoted string"),
    ("k: [1] trailing\n", "unexpected text after flow collection"),
    ("k: {a}\n", r"expected key: value in \{...\}"),
    ("k: {a: 1\n", "unterminated flow collection"),
    ("k: v\njust text\n", "line 2: expected `key: value`"),
    ("- a\n  - b\n", "line 2: unexpected indentation"),
    ("- a\nb: 1\n", "line 2: unexpected content 'b: 1'"),
    ("a: *ref\n", "anchors, aliases"),
    ("- &anchor x\n", "anchors, aliases"),
    ("- !tag x\n", "tags"),
    ("a:\n  <<: *base\n", "merge keys"),
    ("---\na: 1\n---\nb: 2\n", "line 3: multiple documents"),
    ("k: 1\nk: 2\n", "line 2: duplicate key 'k'"),
    ('- "open\n', "line 1: unterminated double-quoted string"),
])
def test_rejects(text, error):
    with pytest.raises(yamlish.YAMLError, match=error):
        yamlish.loads(text)


def test_yaml_error_is_a_value_error():
    assert issubclass(yamlish.YAMLError, ValueError)


# --- compose ---------------------------------------------------------------------------------------------

def conv(text: str, tmp_path, **kw):
    return compose.convert(yamlish.loads(textwrap.dedent(text)), base=tmp_path, **kw)


def test_every_supported_key(tmp_path, monkeypatch):
    monkeypatch.setenv("FROM_ENV", "e")
    res = conv("""
        name: My.App
        x-common: {a: 1}
        services:
          web:
            image: nginx:1
            build: .
            entrypoint: ["/bin/sh", "-c"]
            command: [run, "--port", 80]
            working_dir: /srv
            user: "1000"
            hostname: web1
            cap_add: [NET_ADMIN]
            privileged: true
            mem_limit: 512m
            cpus: 1.5
            labels: [team=shop, "tier=front"]
            healthcheck: {test: ["CMD", "curl", "-f", "http://x/a b"]}
            depends_on: [db]
            environment: {DEBUG: true, EMPTY: null, N: 3, FROM_ENV: null}
            x-private: yes
            tty: true
            networks: [default]
            container_name: fixed
            deploy: {replicas: 2}
            frobnicate: 1
          db:
            image: postgres
            entrypoint: /entry.sh --flag
            labels: {a: b}
            healthcheck: {test: "pg_isready"}
          off:
            image: busybox
            healthcheck: {disable: true}
          none:
            image: busybox
            healthcheck: {test: [NONE]}
          weird:
            image: busybox
            healthcheck: {test: [SOMETHING, x]}
            depends_on: {ghost: {condition: service_healthy}, db: {condition: service_started}}
        volumes: {}
        version: "3.9"
        name2: x
    """, tmp_path)
    s, notes = res["stack"], res["notes"]
    web = s["services"]["web"]
    assert s["name"] == "my.app" and "volumes" not in s
    assert web["entrypoint"] == "/bin/sh -c" and web["cmd"] == ["run", "--port", "80"]
    assert (web["workdir"], web["user"], web["hostname"], web["cap_add"], web["privileged"]) == \
        ("/srv", "1000", "web1", ["NET_ADMIN"], True)
    assert (web["memory"], web["cpus"], web["labels"]) == ("512m", 1.5, {"team": "shop", "tier": "front"})
    assert web["health_cmd"] == "curl -f 'http://x/a b'" and web["depends_on"] == ["db"]
    assert web["env"] == {"DEBUG": "true", "N": "3", "FROM_ENV": "e"}      # EMPTY: null = from the (unset) env
    assert any("EMPTY takes its value from the environment" in n for n in notes)
    assert s["services"]["db"]["entrypoint"] == "/entry.sh --flag" and s["services"]["db"]["labels"] == {"a": "b"}
    assert s["services"]["db"]["health_cmd"] == "pg_isready" and "ready" not in s["services"]["db"]
    assert all("health_cmd" not in s["services"][n] for n in ("off", "none", "weird"))
    assert any("`build` is ignored" in n for n in notes)
    assert {"service": "web", "key": "tty"} in res["unsupported"] and {"service": "web", "key": "frobnicate"} in \
        res["unsupported"]
    assert not any(u["key"] in ("networks", "container_name", "deploy", "x-private") for u in res["unsupported"])
    assert res["unsupported_top_level"] == ["name2"]
    with pytest.raises(ValueError, match="ghost"):     # a dependency on an undefined service surfaces at parse
        stk.parse(s)


def test_env_files_and_volumes(tmp_path):
    (tmp_path / "a.env").write_text("A=1\n\n# c\nnoequals\nB='two'\n")
    res = conv("""
        services:
          app:
            image: x
            env_file: [a.env, {path: missing.env}, {path: ""}, {required: false}]
            environment: [C=3]
            volumes:
              - {type: bind, source: /abs, target: /in}
              - {type: volume, source: data, target: /d, read_only: true}
              - {type: tmpfs, target: /t}
              - ~/cache:/cache
              - named:/n
              - /plain
            ports: [{target: 80}, {target: 81, published: 8081, protocol: tcp}, "9000:9000/udp"]
          b:
            build: {context: ./b}
          c:
            build: ./c
            env_file: a.env
    """, tmp_path, name="Override Name")
    app = res["stack"]["services"]["app"]
    assert res["stack"]["name"] == "override-name"
    assert app["env"] == {"A": "1", "B": "two", "C": "3"}
    assert app["volumes"] == ["/abs:/in", "data:/d:ro", "/t", f"{__import__('os').path.expanduser('~/cache')}:/cache",
                              "named:/n", "/plain"]
    assert app["ports"] == ["80", "8081:81", "9000:9000/udp"]
    assert any("missing.env not found" in n for n in res["notes"])
    assert res["stack"]["services"]["b"]["image"] == "override-name-b:latest"
    assert any("images build ./b" in n for n in res["notes"]) and any("images build ./c" in n for n in res["notes"])
    assert res["stack"]["services"]["c"]["env"] == {"A": "1", "B": "two"}


def test_deploy_limits_partial(tmp_path):
    res = conv("""
        services:
          a: {image: x, deploy: {resources: {limits: {cpus: "2"}}}}
          b: {image: x, deploy: {resources: {limits: {memory: 1g}}}}
          c: {image: x, deploy: {resources: {}}}
          d: {image: x, deploy: null}
    """, tmp_path)
    svc = res["stack"]["services"]
    assert svc["a"] == {"image": "x", "cpus": 2.0} and svc["b"] == {"image": "x", "memory": "1g"}
    assert svc["c"] == {"image": "x"} and svc["d"] == {"image": "x"}


def test_healthy_dependency_without_healthcheck_is_probed(tmp_path):
    res = conv("""
        services:
          db: {image: postgres}
          api: {image: api, depends_on: {db: {condition: service_healthy}}}
    """, tmp_path)
    assert res["stack"]["services"]["db"]["ready"] == "probe"


@pytest.mark.parametrize(("text", "error"), [
    ("version: '3'\n", "no `services` mapping"),
    ("services: [a, b]\n", "no `services` mapping"),
    ("services:\n  a: {ports: ['80']}\n", "service a: needs image"),
])
def test_invalid_compose(tmp_path, text, error):
    with pytest.raises(ValueError, match=error):
        compose.convert(yamlish.loads(text), base=tmp_path)


def test_load_errors(tmp_path):
    with pytest.raises(ValueError, match="nope.yaml"):
        compose.load(tmp_path / "nope.yaml")
    (tmp_path / "bad.yaml").write_text("services:\n  a: &x {image: y}\n")
    with pytest.raises(yamlish.YAMLError, match="anchors"):
        compose.load(tmp_path / "bad.yaml")
    (tmp_path / "ok.yaml").write_text("services:\n  a:\n    image: y\n")
    assert compose.load(tmp_path / "ok.yaml")["stack"]["name"] == tmp_path.name.lower().replace("_", "_")


def test_service_with_no_body(tmp_path):
    with pytest.raises(ValueError, match="service a: needs image"):
        conv("services:\n  a:\n", tmp_path)
