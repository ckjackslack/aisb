"""Man pages: one per resource and special command, valid roff (checked by groff when installed), reproducible."""

import json
import re
import shutil
import subprocess

import pytest

from aisb import manpages
from aisb.cli import SPECIAL, main
from aisb.ops import registry

MACROS = {"TH", "SH", "SS", "TP", "PP", "RS", "RE", "nf", "fi", "br", "BR"}


@pytest.fixture(scope="module")
def pages() -> dict[str, str]:
    return manpages.pages()


def test_one_page_per_resource_and_command(pages):
    assert set(pages) == {"aisb.1", *(f"aisb-{r}.1" for r in registry()), *(f"aisb-{c}.1" for c in SPECIAL)}


def test_every_request_line_is_a_known_macro(pages):
    for name, text in pages.items():
        for line in text.splitlines():
            if line.startswith((".", "'")):
                assert line[1:].split(" ")[0] in MACROS, f"{name}: {line!r}"


def test_every_op_is_documented_with_its_flags(pages):
    for resource, ops in registry().items():
        page = pages[f"aisb-{resource}.1"]
        for o in ops.values():
            assert f".SS {manpages.lit(o.name)} ({o.tier})" in page
            for p in o.params:
                if not (p.positional or p.variadic):
                    assert manpages.lit(p.name.replace("_", "-")) in page, f"{o.qualname} --{p.name}"


def test_overview_has_exit_status_environment_and_resources(pages):
    text = pages["aisb.1"]
    for needle in ("\\fBAISB_AUDIT_KEY\\fR", "\\fB5\\fR", "\\fB\\-\\-ticket\\fR", "See aisb-containers(1).",
                   "\\fBcompletion\\fR"):
        assert needle in text


@pytest.mark.parametrize(("raw", "escaped"), [
    ("a\\b", "a\\eb"),
    (".hidden request", "\\&.hidden request"),
    ("'quoted request", "\\&'quoted request"),
    ("line\n.next", "line\n\\&.next"),
    ("", ""),
])
def test_esc(raw, escaped):
    assert manpages.esc(raw) == escaped


def test_lit_escapes_hyphens():
    assert manpages.lit("--dry-run") == "\\-\\-dry\\-run"


def test_reproducible_with_source_date_epoch(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    first = manpages.pages()
    assert first == manpages.pages() and '"1970-01-01"' in first["aisb.1"].splitlines()[0]


@pytest.mark.skipif(not shutil.which("groff"), reason="groff not installed")
def test_groff_renders_every_page_without_warnings(pages, tmp_path):
    for name, text in pages.items():
        res = subprocess.run(["groff", "-man", "-Tutf8", "-ww", "-z"], input=text, capture_output=True, text=True)
        assert res.returncode == 0 and not res.stderr.strip(), f"{name}: {res.stderr}"
    out = subprocess.run(["groff", "-man", "-Tascii", "-P-cbou"], input=pages["aisb-audit.1"], capture_output=True,
                         text=True).stdout
    assert re.search(r"aisb audit keygen OUT \[--dry-run\]", out)


def test_cli_writes_the_pages(tmp_path, capsys):
    assert main(["docs", "--man", str(tmp_path / "man1")]) == 0
    assert json.loads(capsys.readouterr().out) == {"man": str(tmp_path / "man1"), "pages": len(manpages.pages())}
    assert (tmp_path / "man1" / "aisb.1").read_text().startswith(".TH AISB 1 ")
