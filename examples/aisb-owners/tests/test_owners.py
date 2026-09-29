"""Unit tests that need no Docker: the grouping and the doctor rule are pure functions."""

import pytest

from aisb.insights.triage import Facts
from aisb_owners import LABEL, by_owner, unowned


def row(name: str, owner: str | None = None) -> dict:
    return {"Id": name * 4, "Names": [f"/{name}"], "Labels": {LABEL: owner} if owner is not None else {}}


def test_groups_by_owner_and_lists_the_unowned():
    rows = [row("web", "payments"), row("api", "payments"), row("cache", "platform"), row("tmp"), row("x", " ")]
    assert by_owner(rows) == {"label": LABEL, "owners": {"payments": ["api", "web"], "platform": ["cache"]},
                              "unowned": ["tmp", "x"]}


def test_a_custom_label_and_a_row_without_names():
    assert by_owner([{"Id": "0123456789abcdef", "Labels": {"team": "ops"}}], "team")["owners"] == {"ops": ["0123456789ab"]}


@pytest.mark.parametrize(("labels", "found"), [({}, ["no-owner"]), ({LABEL: "payments"}, []), ({LABEL: ""}, ["no-owner"])])
def test_doctor_rule(labels, found):
    facts = Facts("web", {"Config": {"Labels": labels}, "State": {"Status": "running"}})
    assert [f.code for f in unowned(facts)] == found
