# Pure-Python helpers: input validation, parsing and merging of per-DC results.
import pytest

import badpwd_lookup as b


@pytest.mark.parametrize("name", ["jsmith", "o'brien", "john.smith", "svc-backup$", "ana_maria"])
def test_valid_usernames(name):
    assert b.validate_username(name) == ""


@pytest.mark.parametrize("name", ["", "*", "j*", "CORP\\jsmith", 'x"y', "a;b", "a" * 105, "trailing."])
def test_invalid_usernames(name):
    assert b.validate_username(name) != ""


@pytest.mark.parametrize("dc, ok", [
    ("", True), ("DC01", True), ("dc01.corp.example.com", True),
    ("dc01'; calc", False), ("-dc", False), ("dc 01", False),
])
def test_validate_dc(dc, ok):
    assert (b.validate_dc(dc) == "") is ok


@pytest.mark.parametrize("text, hours", [("24", 24), (" 1 ", 1), ("720", 720), ("0", None),
                                         ("721", None), ("abc", None), ("1.5", None), ("", None)])
def test_parse_hours(text, hours):
    assert b.parse_hours(text) == hours


def test_parse_events_single_object_list_and_empty():
    one = '{"Time":"2026-09-29 10:00:00","EventId":4771,"Computer":"WS1","IP":"10.0.0.5"}'
    assert b.parse_events(one, "DC1") == [{"Time": "2026-09-29 10:00:00", "EventId": 4771,
                                           "Computer": "WS1", "IP": "10.0.0.5", "DC": "DC1"}]
    assert [e["DC"] for e in b.parse_events(f"[{one},{one}]", "DC2")] == ["DC2", "DC2"]
    assert b.parse_events("[]", "DC1") == []
    assert b.parse_events("  \n", "DC1") == []
    with pytest.raises(ValueError):
        b.parse_events("not json", "DC1")


def test_merge_events_dedupes_across_dcs_and_sorts_newest_first():
    ev = lambda t, eid, comp: {"Time": t, "EventId": eid, "Computer": comp, "IP": ""}
    results = {
        "DC1": [ev("2026-09-29 09:00:00", 4740, "WS1"), ev("2026-09-29 08:00:00", 4776, "WS2")],
        "DC2": [ev("2026-09-29 09:00:00", 4740, "WS1"), ev("2026-09-29 10:00:00", 4771, "WS3")],
    }
    merged = b.merge_events(results)
    assert [(e["Time"][11:13], e["EventId"]) for e in merged] == [("10", 4771), ("09", 4740), ("08", 4776)]


def test_scripts_no_longer_cap_events_before_the_user_filter():
    assert "-MaxEvents" not in b.PS_QUERY_ON_DC
    assert b.PS_QUERY_ON_DC.count("StartTime=$since") == 4
    # values reach the wrapper as parameters, not as text pasted into the script
    assert "{" not in b.PS_INVOKE.split("param(")[0]
    assert "$Username, $Hours" in b.PS_INVOKE
