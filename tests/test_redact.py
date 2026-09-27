"""Secrets outside env: command-line args, entrypoint, health check and labels are masked in capsules and
can be supplied back by name on load."""

import json

import pytest

from aisb import redact
from test_cch_capsule import SECRETS, Target, members, serve_container, web_info

GH = "ghp_" + "a" * 36


@pytest.mark.parametrize(("argv", "masked", "names"), [
    (["redis-server", "--requirepass", "hunter2"],
     ["redis-server", "--requirepass", "<redacted:arg:--requirepass>"], ["arg:--requirepass"]),
    (["app", "--db-password=hunter2", "--port=80"],
     ["app", "--db-password=<redacted:arg:--db-password>", "--port=80"], ["arg:--db-password"]),
    (["app", "--api-key", "--verbose"], ["app", "--api-key", "--verbose"], []),       # a flag, not a value
    (["app", "--password="], ["app", "--password="], []),                              # empty: nothing to hide
    (["worker", "postgres://app:hunter2@db:5432/shop"],
     ["worker", "postgres://app:<redacted:arg:1>@db:5432/shop"], ["arg:1"]),         # user and host stay readable
    (["deploy", f"--header=Authorization: token {GH}"],
     ["deploy", "--header=Authorization: token <redacted:arg:1>"], ["arg:1"]),
    (["serve", "--port", "8080"], ["serve", "--port", "8080"], []),
    ([], [], []),
])
def test_args(argv, masked, names):
    assert redact.args(argv) == (masked, names)


def test_shell_strings_mask_word_by_word_and_survive_bad_quoting():
    text, names = redact.shell("mysqladmin ping --password=hunter2 -h localhost", prefix="health")
    assert text == "mysqladmin ping '--password=<redacted:health:--password>' -h localhost"
    assert names == ["health:--password"]
    assert redact.shell("echo ok", prefix="health") == ("echo ok", [])
    assert redact.shell(None, prefix="entrypoint") == (None, [])
    text, names = redact.shell("curl 'https://u:hunter2@x/ -o", prefix="entrypoint")  # unbalanced quote
    assert "hunter2" not in text and names == ["entrypoint"]


def test_labels():
    out, names = redact.labels({"team": "shop", "traefik.http.auth.password": "hunter2",
                                "backup.url": "s3://key:hunter2@bucket/x", "empty.secret": ""})
    assert out == {"team": "shop", "traefik.http.auth.password": "<redacted:label:traefik.http.auth.password>",
                   "backup.url": "s3://key:<redacted:label:backup.url>@bucket/x", "empty.secret": ""}
    assert names == ["label:traefik.http.auth.password", "label:backup.url"]


def test_fill_round_trips_and_reports_missing():
    masked, names = redact.args(["redis-server", "--requirepass", "hunter2", "--masterauth=s3"])
    filled = [redact.fill(a, {"arg:--requirepass": "new"}) for a in masked]
    assert [v for v, _ in filled] == ["redis-server", "--requirepass", "new", "--masterauth=<redacted:arg:--masterauth>"]
    assert [m for _, gone in filled for m in gone] == ["arg:--masterauth"]


# --- capsules -------------------------------------------------------------------------------------------------

def secret_info():
    info = web_info()
    info["Config"].update(Cmd=["serve", "--requirepass", "hunter2", "--url=postgres://app:tok-XYZ@db/shop"],
                          Entrypoint=["/entry.sh", "--api-key=s3cr3t-key"],
                          Labels={"team": "shop", "auth.password": "hunter2"},
                          Healthcheck={"Test": ["CMD-SHELL", "check --password=hunter2"]})
    info["Args"] = info["Config"]["Cmd"]
    return info


def test_capsule_masks_args_entrypoint_labels_and_health_everywhere(client, daemon, tmp_path):
    serve_container(daemon, secret_info(), image={"RepoDigests": []})
    out = tmp_path / "c.tgz"
    r = client.capsule.create("web", str(out))
    assert r["redacted"] == ["arg:--requirepass", "arg:3", "entrypoint:--api-key", "health:--password",
                             "label:auth.password"]
    files = members(out)
    for name, data in files.items():
        for secret in SECRETS:
            assert secret.encode() not in data, f"{secret} leaked into {name}"
    spec = json.loads(files["spec.json"])
    assert spec["cmd"] == ["serve", "--requirepass", "<redacted:arg:--requirepass>",
                           "--url=postgres://app:<redacted:arg:3>@db/shop"]  # only the password part
    assert json.loads(files["manifest.json"])["redacted"] == r["redacted"]


def test_capsule_load_refuses_until_command_secrets_are_supplied(client, daemon, tmp_path):
    serve_container(daemon, secret_info(), image={"RepoDigests": []})
    cap = tmp_path / "c.tgz"
    client.capsule.create("web", str(cap))
    daemon.routes.clear()
    daemon.seen.clear()
    tgt = Target(daemon)
    with pytest.raises(ValueError, match="--env arg:--requirepass=... --env arg:3=... --env entrypoint:--api-key="):
        client.capsule.load(str(cap))
    assert not daemon.seen and not tgt.created  # refused before any change, image load included

    r = client.capsule.load(str(cap), env=["arg:--requirepass=pw1", "arg:3=pw2",
                                            "entrypoint:--api-key=k2", "health:--password=pw3"])
    body = tgt.created[0].body
    assert body["Cmd"] == ["serve", "--requirepass", "pw1", "--url=postgres://app:pw2@db/shop"]
    assert body["Entrypoint"] == ["/entry.sh", "--api-key=k2"]
    assert "auth.password" not in body["Labels"] and body["Labels"]["team"] == "shop"  # unsupplied label: left out
    assert "label:auth.password" in r["missing_secrets"]
    assert "<redacted" not in json.dumps(body)


@pytest.mark.parametrize(("test", "masked", "names"), [
    (["CMD", "check", "--token", "t0k"], ["CMD", "check", "--token", "<redacted:health:--token>"], ["health:--token"]),
    (["CMD-SHELL", "curl -fsS http://u:pw1@x/health"], ["CMD-SHELL", "curl -fsS 'http://u:<redacted:health:2>@x/health'"],
     ["health:2"]),
    (["NONE"], ["NONE"], []),
    ([], [], []),
])
def test_healthcheck_forms(test, masked, names):
    assert redact.healthcheck(test) == (masked, names)


def test_a_secret_flag_as_the_last_argument_has_no_value_to_hide():
    assert redact.args(["app", "--password"]) == (["app", "--password"], [])


def test_shell_text_that_does_not_parse_falls_back_to_tokens_only():
    text, names = redact.shell("curl 'https://u:hunter2@x/ -o", prefix="entrypoint")
    assert text == "curl 'https://u:<redacted:entrypoint>@x/ -o" and names == ["entrypoint"]
    assert redact.shell("echo 'unbalanced", prefix="entrypoint") == ("echo 'unbalanced", [])


def test_shell_text_without_secrets_is_returned_untouched():
    assert redact.shell("echo  'a  b'   c", prefix="health") == ("echo  'a  b'   c", [])  # not re-quoted


def test_empty_shell_healthcheck_stays_empty():
    assert redact.healthcheck(["CMD-SHELL", ""]) == (["CMD-SHELL", ""], [])


@pytest.mark.parametrize("key", ["tls.key", "api-key", "app.api-key"])
def test_label_keys_with_dots_and_dashes(key):
    assert redact.labels({key: "v"}) == ({key: f"<redacted:label:{key}>"}, [f"label:{key}"])
