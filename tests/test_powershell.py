# Runs the real PowerShell from badpwd_lookup.py under pwsh, with fake events standing
# in for Get-WinEvent and a local stand-in for Invoke-Command. Skipped without pwsh.
import json
import re
import shutil
import subprocess
from datetime import datetime, timedelta

import pytest

import badpwd_lookup as b

PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(not PWSH, reason="pwsh not installed")

NOW = datetime.now()

# (event id, hours ago, event data)
FAKE_EVENTS = [
    (4740, 1,   {"TargetUserName": "jsmith", "CallerComputerName": "\\\\WS-LOCK"}),
    (4771, 2,   {"TargetUserName": "JSmith", "IpAddress": "::ffff:192.0.2.10"}),         # case differs
    (4776, 3,   {"TargetUserName": "jsmith", "Workstation": "WS-BADPW", "Status": "0xc000006a"}),
    (4776, 3,   {"TargetUserName": "jsmith", "Workstation": "WS-GOODPW", "Status": "0x0"}),  # success
    (4625, 4,   {"TargetUserName": "jsmith", "WorkstationName": "WS-4625", "IpAddress": "-", "LogonType": "3"}),
    (4776, 30,  {"TargetUserName": "jsmith", "Workstation": "WS-OLD", "Status": "0xc000006a"}),  # outside 24h
    (4776, 1,   {"TargetUserName": "someoneelse", "Workstation": "WS-OTHER", "Status": "0xc000006a"}),
    (4776, 1,   {"TargetUserName": "o'brien", "Workstation": "WS-OBRIEN", "Status": "0xc000006a"}),
]
# 1000 newer events for other users: the old -MaxEvents 500 cap would have hidden jsmith's 4776
NOISE = [(4776, 0.5, {"TargetUserName": f"user{i}", "Workstation": "WS-X", "Status": "0xc000006a"})
         for i in range(1000)]


def fake_event_ps(eid, hours_ago, data):
    fields = "".join(f"<Data Name='{k}'>{v.replace(chr(39), '&apos;')}</Data>" for k, v in data.items())
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
           f"<System><EventID>{eid}</EventID></System><EventData>{fields}</EventData></Event>")
    t = (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S")
    xml_ps = xml.replace("'", "''")
    return (f"$e = [PSCustomObject]@{{ Id = {eid}; TimeCreated = [datetime]'{t}' }}; "
            f"$e | Add-Member ScriptMethod ToXml {{ '{xml_ps}' }}.GetNewClosure(); $global:FakeEvents.Add($e)")


MOCKS = """
$global:FakeEvents = [System.Collections.Generic.List[object]]::new()
%s
function global:Get-WinEvent {
    [CmdletBinding()] param([hashtable]$FilterHashtable)
    $global:FakeEvents | Where-Object { $_.Id -eq $FilterHashtable.Id -and $_.TimeCreated -ge $FilterHashtable.StartTime }
}
function global:Invoke-Command {
    [CmdletBinding()] param([string]$ComputerName, [scriptblock]$ScriptBlock, [object[]]$ArgumentList)
    $global:InvokedOn = $ComputerName
    & $ScriptBlock @ArgumentList
}
"""


@pytest.fixture(scope="module")
def mock_file(tmp_path_factory):
    d = tmp_path_factory.mktemp("ps")
    lines = []
    for eid, ago, data in FAKE_EVENTS + NOISE:
        lines.append(fake_event_ps(eid, ago, data))
    (d / "mocks.ps1").write_text(MOCKS % "\n".join(lines))
    (d / "inner.ps1").write_text(b.PS_QUERY_ON_DC)
    (d / "invoke.ps1").write_text(b.PS_INVOKE)
    # Loads the fakes, then calls the real wrapper with the same parameters it gets from the app
    (d / "harness.ps1").write_text(
        "param([string]$InnerPath, [string]$DC, [string]$Username, [int]$Hours)\n"
        f". '{d / 'mocks.ps1'}'\n"
        f"& '{d / 'invoke.ps1'}' -InnerPath $InnerPath -DC $DC -Username $Username -Hours $Hours\n")
    return d


def run_wrapper(d, username, hours=24, dc="DC01"):
    """Call the wrapper with -File and separate arguments, as run_invoke_command does."""
    cmd = [PWSH, "-NoProfile", "-NonInteractive", "-File", str(d / "harness.ps1"),
           "-InnerPath", str(d / "inner.ps1"), "-DC", dc, "-Username", username, "-Hours", str(hours)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    return b.parse_events(r.stdout, dc)


def by_computer(events):
    return {e["Computer"]: e for e in events}


def test_finds_every_failure_for_the_user_in_the_window(mock_file):
    events = by_computer(run_wrapper(mock_file, "jsmith"))
    assert set(events) == {"WS-LOCK", "192.0.2.10", "WS-BADPW", "WS-4625"}
    assert events["WS-LOCK"]["EventId"] == 4740
    assert events["192.0.2.10"]["IP"] == "192.0.2.10"          # ::ffff: stripped, reverse DNS fell back to IP
    assert events["WS-4625"]["LogonType"] == "3"
    assert all(e["DC"] == "DC01" for e in events.values())


def test_successful_ntlm_validation_is_not_reported(mock_file):
    assert "WS-GOODPW" not in by_computer(run_wrapper(mock_file, "jsmith"))


def test_lookback_window_is_respected(mock_file):
    assert "WS-OLD" not in by_computer(run_wrapper(mock_file, "jsmith", hours=24))
    assert "WS-OLD" in by_computer(run_wrapper(mock_file, "jsmith", hours=48))
    assert set(by_computer(run_wrapper(mock_file, "jsmith", hours=1))) <= {"WS-LOCK"}


def test_username_with_apostrophe_is_passed_safely(mock_file):
    assert set(by_computer(run_wrapper(mock_file, "o'brien"))) == {"WS-OBRIEN"}


def test_quote_breakout_attempt_is_just_a_name(mock_file):
    # With the old string pasting, this would have run Write-Output as code
    events = run_wrapper(mock_file, "x'; Write-Output 'INJECTED'; '")
    assert events == []


@pytest.mark.parametrize("name, escaped", [
    ("jsmith", "jsmith"), ("*", "\\2a"), ("a)(cn=*", "a\\29\\28cn=\\2a"), ("b\\s", "b\\5cs"),
])
def test_adsi_fallback_escapes_ldap_filter(name, escaped, tmp_path):
    line = next(l for l in b.PS_GET_USER.splitlines() if "$esc =" in l).strip()
    script = tmp_path / "esc.ps1"
    script.write_text(f"param([string]$Username)\n{line}\n$esc\n")
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script), "-Username", name],
                       capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == escaped, r.stderr
